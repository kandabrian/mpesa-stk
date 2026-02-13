// 📂 server.js — M-Pesa STK Push Service
// Handles: STK push initiation, callback forwarding, status queries
//
// ┌─────────────┐    /pay     ┌─────────────┐   STK Push   ┌──────────────┐
// │   app.js    │ ──────────► │  server.js  │ ────────────► │  Safaricom   │
// │  (port 3000)│             │  (port 5000)│               │  Sandbox API │
// └─────────────┘             └──────┬──────┘               └──────┬───────┘
//                                    │ /callback                   │
//                             ◄──────┴─────────────────────────────┘
//                             (Safaricom POSTs result here)
//                                    │
//                             forward to app.js /mpesa/callback
//                                    │
//                             ┌──────▼──────┐
//                             │  Supabase   │
//                             │ credit_wallet│
//                             └─────────────┘

const express = require("express");
const axios   = require("axios");
const dotenv  = require("dotenv");
const cors    = require("cors");
const helmet  = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan  = require("morgan");

dotenv.config();

const app  = express();
const PORT = process.env.PORT || 5000;
const HOST = "0.0.0.0"; // Render / Railway requires 0.0.0.0

// ── The main app.js server URL (same machine or deployed URL) ──────────────
// In development this is http://localhost:3000
// In production set APP_SERVER_URL in your .env to your Render/Railway URL
const APP_SERVER_URL = process.env.APP_SERVER_URL || "http://localhost:3000";

// ── Security & Middleware ──────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(",") || ["*"],
  credentials: true,
}));
app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const payLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: { success: false, error: "Too many requests. Try again later." },
});

// ── Token Cache ───────────────────────────────────────────────────────────
const tokenCache = { token: null, expiry: null };

async function getAccessToken() {
  const now = Date.now();
  if (tokenCache.token && tokenCache.expiry > now) {
    console.log("🔑 Using cached token");
    return tokenCache.token;
  }

  const auth = Buffer.from(
    `${process.env.CONSUMER_KEY}:${process.env.CONSUMER_SECRET}`
  ).toString("base64");

  const response = await axios.get(
    "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
    { headers: { Authorization: `Basic ${auth}` }, timeout: 10000 }
  );

  tokenCache.token  = response.data.access_token;
  tokenCache.expiry = now + 3590 * 1000; // ~1 hour, expire 9s early
  console.log("🔑 New access token generated");
  return tokenCache.token;
}

// ── Helpers ───────────────────────────────────────────────────────────────
function generateTimestamp() {
  return new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14);
}

function generatePassword(timestamp) {
  return Buffer.from(
    `${process.env.SHORTCODE}${process.env.PASSKEY}${timestamp}`
  ).toString("base64");
}

// ── /pay — Initiate STK Push ───────────────────────────────────────────────
app.post("/pay", payLimiter, async (req, res) => {
  console.log("📱 PAYMENT REQUEST:", {
    ip:        req.ip,
    body:      req.body,
    timestamp: new Date().toISOString(),
  });

  try {
    const { phone, amount, description = "Vumbua Deposit" } = req.body;

    // ── Validation ───────────────────────────────────────────────────────
    if (!phone || !amount) {
      return res.status(400).json({ success: false, error: "Phone and amount are required." });
    }

    const phoneStr = String(phone).replace(/\D/g, "");
    if (!/^254[17]\d{8}$/.test(phoneStr)) {
      return res.status(400).json({
        success: false,
        error: "Invalid phone. Use format: 2547XXXXXXXX or 2541XXXXXXXX",
      });
    }

    const amountNum = Math.floor(parseFloat(amount));
    if (isNaN(amountNum) || amountNum < 1) {
      return res.status(400).json({ success: false, error: "Amount must be at least 1." });
    }

    // ── STK Push ─────────────────────────────────────────────────────────
    const token     = await getAccessToken();
    const timestamp = generateTimestamp();
    const password  = generatePassword(timestamp);

    // CALLBACK_URL must be publicly reachable by Safaricom.
    // In development: use ngrok → set CALLBACK_URL=https://xxxx.ngrok.io/callback
    // In production: set CALLBACK_URL=https://your-render-service.onrender.com/callback
    const callbackUrl = process.env.CALLBACK_URL || `${process.env.SERVER_URL}/callback`;

    const mpesaPayload = {
      BusinessShortCode: process.env.SHORTCODE,
      Password:          password,
      Timestamp:         timestamp,
      TransactionType:   "CustomerPayBillOnline",
      Amount:            amountNum,
      PartyA:            phoneStr,
      PartyB:            process.env.SHORTCODE,
      PhoneNumber:       phoneStr,
      CallBackURL:       callbackUrl,
      AccountReference:  description.substring(0, 12),
      TransactionDesc:   description.substring(0, 13),
    };

    console.log("📤 STK Push payload:", mpesaPayload);

    const mpesaRes = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
      mpesaPayload,
      {
        headers: {
          Authorization:  `Bearer ${token}`,
          "Content-Type": "application/json",
        },
        timeout: 30000,
      }
    );

    const data = mpesaRes.data;
    console.log("✅ Safaricom accepted STK:", data);

    if (data.ResponseCode !== "0") {
      return res.status(502).json({
        success: false,
        error:   data.ResponseDescription || "STK push rejected",
        data,
      });
    }

    res.json({
      success:           true,
      message:           "STK Push sent. Check your phone.",
      CheckoutRequestID: data.CheckoutRequestID,
      MerchantRequestID: data.MerchantRequestID,
      // Also expose as camelCase for legacy callers
      checkoutId:        data.CheckoutRequestID,
      timestamp:         new Date().toISOString(),
    });

  } catch (err) {
    const status  = err.response?.status || 500;
    const message = err.response?.data?.errorMessage || err.message || "Internal server error";
    console.error("❌ STK Push error:", err.response?.data || err.message);
    res.status(status).json({ success: false, error: message, details: err.response?.data });
  }
});

// ── /callback — Receive Safaricom payment result ───────────────────────────
//
// Safaricom POSTs here after the user completes (or cancels) the STK prompt.
// We forward the raw body to app.js /mpesa/callback which does the
// Supabase credit_wallet + transaction update.
//
app.post("/callback", async (req, res) => {
  try {
    const payload = req.body;
    console.log("📩 M-Pesa Callback received:\n", JSON.stringify(payload, null, 2));

    const stkCallback = payload?.Body?.stkCallback || {};
    const resultCode  = stkCallback.ResultCode;
    const resultDesc  = stkCallback.ResultDesc;
    const checkoutId  = stkCallback.CheckoutRequestID;

    console.log(`📋 CheckoutID: ${checkoutId} | ResultCode: ${resultCode} | ${resultDesc}`);

    if (resultCode === 0) {
      const items   = stkCallback.CallbackMetadata?.Item || [];
      const amount  = items.find(i => i.Name === "Amount")?.Value;
      const receipt = items.find(i => i.Name === "MpesaReceiptNumber")?.Value;
      const phone   = items.find(i => i.Name === "PhoneNumber")?.Value;
      console.log(`✅ PAYMENT SUCCESS — Receipt: ${receipt} | KES ${amount} | Phone: ${phone}`);
    } else {
      console.log(`❌ PAYMENT FAILED/CANCELLED — ${resultDesc}`);
    }

    // ── Forward to app.js so it can credit the wallet in Supabase ──────
    try {
      await axios.post(`${APP_SERVER_URL}/mpesa/callback`, payload, {
        headers: { "Content-Type": "application/json" },
        timeout: 10000,
      });
      console.log("✅ Forwarded to app.js /mpesa/callback");
    } catch (fwdErr) {
      // Don't fail the Safaricom acknowledgement if our server is slow
      console.error("⚠️  Forward to app.js failed:", fwdErr.message);
      console.error("   Payload was:", JSON.stringify(payload));
    }

    // ── Always acknowledge Safaricom immediately (they retry on non-200) ─
    res.json({ ResultCode: 0, ResultDesc: "Success" });

  } catch (err) {
    console.error("❌ Callback handler error:", err.message);
    // Still acknowledge so Safaricom doesn't hammer us with retries
    res.json({ ResultCode: 0, ResultDesc: "Success" });
  }
});

// ── /status/:checkoutId — Poll STK Push status ────────────────────────────
// Called by app.js or the dashboard to check if payment completed.
// NOTE: Safaricom sandbox often returns "pending" even after completion —
// the callback above is the reliable source of truth.
app.get("/status/:checkoutId", async (req, res) => {
  try {
    const token       = await getAccessToken();
    const timestamp   = generateTimestamp();
    const password    = generatePassword(timestamp);
    const checkoutId  = req.params.checkoutId;

    const response = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query",
      {
        BusinessShortCode: process.env.SHORTCODE,
        Password:          password,
        Timestamp:         timestamp,
        CheckoutRequestID: checkoutId,
      },
      {
        headers: { Authorization: `Bearer ${token}` },
        timeout: 15000,
      }
    );

    console.log(`📊 Status query [${checkoutId}]:`, response.data);
    res.json(response.data);

  } catch (err) {
    const errData = err.response?.data;
    // ResultCode 1032 = request cancelled by user; 1037 = timeout
    console.error("❌ Status query error:", errData || err.message);
    res.status(err.response?.status || 500).json({
      success: false,
      error:   errData?.errorMessage || err.message,
      details: errData,
    });
  }
});

// ── /token — Expose access token (for debugging / Flutter) ────────────────
app.get("/token", async (req, res) => {
  try {
    const token = await getAccessToken();
    res.json({ access_token: token, expires_in: 3599, token_type: "Bearer" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to get token" });
  }
});

// ── /health ────────────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status:      "healthy",
    service:     "Vumbua M-Pesa STK Service",
    version:     "2.0.0",
    environment: process.env.NODE_ENV || "development",
    uptime:      process.uptime(),
    callback_url: process.env.CALLBACK_URL || "(not set — set CALLBACK_URL in .env)",
    app_server:  APP_SERVER_URL,
    timestamp:   new Date().toISOString(),
  });
});

// ── /metrics ───────────────────────────────────────────────────────────────
app.get("/metrics", (req, res) => {
  res.json({
    uptime:      process.uptime(),
    memory:      process.memoryUsage(),
    nodeVersion: process.version,
    platform:    process.platform,
    timestamp:   new Date().toISOString(),
  });
});

// ── Error handlers ─────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({
    success: false,
    error:   "Internal server error",
    message: process.env.NODE_ENV === "development" ? err.message : undefined,
  });
});

app.use((req, res) => {
  res.status(404).json({ success: false, error: `Endpoint not found: ${req.method} ${req.path}` });
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
  console.log(`\n🚀 Vumbua M-Pesa service running!`);
  console.log(`📡 Environment : ${process.env.NODE_ENV || "development"}`);
  console.log(`🌐 Port        : ${PORT}`);
  console.log(`🔗 App server  : ${APP_SERVER_URL}`);
  console.log(`📞 Callback URL: ${process.env.CALLBACK_URL || "⚠️  NOT SET — set CALLBACK_URL in .env"}`);
  console.log(`🩺 Health      : http://localhost:${PORT}/health\n`);

  if (!process.env.CALLBACK_URL) {
    console.warn("⚠️  WARNING: CALLBACK_URL is not set.");
    console.warn("   Safaricom CANNOT reach a local IP. For local dev:");
    console.warn("   1. Run: npx ngrok http 5000");
    console.warn("   2. Add to .env: CALLBACK_URL=https://<your-ngrok-url>/callback\n");
  }
});

process.on("SIGTERM", () => { console.log("SIGTERM — shutting down"); process.exit(0); });
process.on("SIGINT",  () => { console.log("SIGINT — shutting down");  process.exit(0); });