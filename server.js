// 📂 server.js — M-Pesa STK Push Service for Hugging Face Spaces
const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");

dotenv.config();

// ── Boot Validation ────────────────────────────────────────────────────────
// Check required env vars BEFORE starting anything.
// Set these in Hugging Face Space → Settings → Repository secrets.
const REQUIRED_VARS = [
    "CONSUMER_KEY",
    "CONSUMER_SECRET",
    "SHORTCODE",
    "PASSKEY",
    "CALLBACK_URL",    // Must be: https://kandabrian-mpesa-stk.hf.space/callback
    "APP_SERVER_URL",  // Must be: https://low-lilllie-kandabrian-18be1e15.koyeb.app
];

const missing = REQUIRED_VARS.filter(v => !process.env[v]);
if (missing.length > 0) {
    console.error("❌ FATAL: Missing required env vars:", missing.join(", "));
    console.error("   Go to Hugging Face Space → Settings → Repository secrets and add them.");
    process.exit(1);
}

// ── Validate CALLBACK_URL is publicly reachable ────────────────────────────
// This is the #1 cause of payments not updating. Safaricom cannot reach a
// local/private IP address. It MUST be a public HTTPS URL.
const callbackUrl = process.env.CALLBACK_URL;
if (
    callbackUrl.includes("localhost") ||
    callbackUrl.includes("127.0.0.1") ||
    callbackUrl.match(/^https?:\/\/192\.168\./) ||
    callbackUrl.match(/^https?:\/\/10\./) ||
    callbackUrl.startsWith("http://")
) {
    console.error("❌ FATAL: CALLBACK_URL is not a public HTTPS URL:", callbackUrl);
    console.error("   Safaricom cannot reach a local/private IP or plain HTTP URL.");
    console.error("   Set CALLBACK_URL=https://kandabrian-mpesa-stk.hf.space/callback");
    process.exit(1);
}

// ── Validate APP_SERVER_URL is reachable ───────────────────────────────────
const appServerUrl = process.env.APP_SERVER_URL;
if (
    appServerUrl.includes("localhost") ||
    appServerUrl.includes("127.0.0.1") ||
    appServerUrl.match(/^https?:\/\/192\.168\./)
) {
    console.warn("⚠️  WARNING: APP_SERVER_URL looks like a local address:", appServerUrl);
    console.warn("   Forwarding callbacks to your Koyeb app will fail.");
    console.warn("   Set APP_SERVER_URL=https://low-lilllie-kandabrian-18be1e15.koyeb.app");
}

console.log("========================================");
console.log("🚀 Vumbua M-Pesa Service booting...");
console.log("   CALLBACK_URL  :", callbackUrl);
console.log("   APP_SERVER_URL:", appServerUrl);
console.log("   SHORTCODE     :", process.env.SHORTCODE);
console.log("   CONSUMER_KEY  :", process.env.CONSUMER_KEY?.slice(0, 8) + "***");
console.log("========================================");

// ── App Setup ──────────────────────────────────────────────────────────────
const app = express();

// Hugging Face strictly requires port 7860 and binding to 0.0.0.0
const PORT = process.env.PORT || 7860;
const HOST = "0.0.0.0";

// ── Security & Middleware ──────────────────────────────────────────────────
app.use(
    helmet({
        contentSecurityPolicy: false,
        crossOriginEmbedderPolicy: false,
        frameguard: false,
    })
);

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

// ── M-Pesa Token Cache ─────────────────────────────────────────────────────
const tokenCache = { token: null, expiry: null };

async function getAccessToken() {
    const now = Date.now();
    if (tokenCache.token && tokenCache.expiry > now) {
        return tokenCache.token;
    }

    const auth = Buffer.from(
        `${process.env.CONSUMER_KEY}:${process.env.CONSUMER_SECRET}`
    ).toString("base64");

    const response = await axios.get(
        "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
        { headers: { Authorization: `Basic ${auth}` }, timeout: 10000 }
    );

    tokenCache.token = response.data.access_token;
    tokenCache.expiry = now + 3590 * 1000;
    console.log("🔑 M-Pesa access token refreshed.");
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

// ── ROUTES ────────────────────────────────────────────────────────────────

// 1. Home
app.get("/", (req, res) => {
    res.send(`
    <div style="font-family: sans-serif; text-align: center; padding: 50px;">
      <h1>🚀 Vumbua M-Pesa Service is Live</h1>
      <p>Status: <span style="color: green; font-weight: bold;">Running</span></p>
      <hr style="width: 200px; margin: 20px auto;">
      <p>Health Check: <code>/health</code></p>
      <p>Config Check: <code>/debug</code></p>
      <p>Payment Endpoint: <code>/pay</code> (POST)</p>
    </div>
  `);
});

// 2. /debug — Verify config without exposing secrets
app.get("/debug", (req, res) => {
    const cb = process.env.CALLBACK_URL || "NOT SET";
    const app = process.env.APP_SERVER_URL || "NOT SET";
    const isCallbackOk = cb.startsWith("https://") && !cb.includes("localhost") && !cb.includes("192.168");
    const isAppUrlOk = app.startsWith("https://") && !app.includes("localhost") && !app.includes("192.168");

    res.json({
        status: isCallbackOk && isAppUrlOk ? "✅ All good" : "❌ Config issues detected — payments will NOT update",
        callback_url: cb,
        callback_url_ok: isCallbackOk
            ? "✅ Public HTTPS URL"
            : "❌ NOT a public HTTPS URL — Safaricom cannot deliver payment results!",
        app_server_url: app,
        app_server_url_ok: isAppUrlOk
            ? "✅ Public HTTPS URL"
            : "❌ NOT a public HTTPS URL — forwarding to Koyeb will fail!",
        shortcode: process.env.SHORTCODE || "NOT SET",
        consumer_key_set: process.env.CONSUMER_KEY ? "✅ set" : "❌ NOT SET",
        consumer_secret_set: process.env.CONSUMER_SECRET ? "✅ set" : "❌ NOT SET",
        passkey_set: process.env.PASSKEY ? "✅ set" : "❌ NOT SET",
        token_cached: tokenCache.token ? "✅ yes (active)" : "⚠️  not yet (fetched on first /pay)",
        uptime_seconds: Math.round(process.uptime()),
    });
});

// 3. /pay — Initiate STK Push
app.post("/pay", payLimiter, async (req, res) => {
    try {
        const { phone, amount, description = "Vumbua Deposit" } = req.body;

        if (!phone || !amount) {
            return res.status(400).json({ success: false, error: "Phone and amount are required." });
        }

        const phoneStr = String(phone).replace(/\D/g, "");
        const amountNum = Math.floor(parseFloat(amount));

        if (amountNum < 1) {
            return res.status(400).json({ success: false, error: "Amount must be at least 1." });
        }

        console.log(`💳 STK Push: phone=${phoneStr.slice(0, 6)}***, amount=${amountNum}`);

        const token = await getAccessToken();
        const timestamp = generateTimestamp();
        const password = generatePassword(timestamp);

        // ALWAYS use the validated env var — never a hardcoded fallback.
        // If CALLBACK_URL is wrong, the boot check above will already have crashed the server.
        const cb = process.env.CALLBACK_URL;

        const mpesaPayload = {
            BusinessShortCode: process.env.SHORTCODE,
            Password: password,
            Timestamp: timestamp,
            TransactionType: "CustomerPayBillOnline",
            Amount: amountNum,
            PartyA: phoneStr,
            PartyB: process.env.SHORTCODE,
            PhoneNumber: phoneStr,
            CallBackURL: cb,
            AccountReference: description.substring(0, 12),
            TransactionDesc: description.substring(0, 13),
        };

        console.log("📤 Sending STK Push to Safaricom. CallBackURL:", cb);

        const mpesaRes = await axios.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            mpesaPayload,
            {
                headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
                timeout: 15000,
            }
        );

        const checkoutId = mpesaRes.data.CheckoutRequestID;
        console.log("✅ STK Push sent. CheckoutRequestID:", checkoutId);

        res.json({
            success: true,
            CheckoutRequestID: checkoutId,
            MerchantRequestID: mpesaRes.data.MerchantRequestID,
            message: "STK Push sent successfully.",
        });

    } catch (err) {
        const detail = err.response?.data || err.message;
        console.error("❌ STK Push error:", detail);
        res.status(500).json({ success: false, error: "STK push failed.", detail });
    }
});

// 4. /callback — Receive Safaricom result & forward to Koyeb
app.post("/callback", async (req, res) => {
    const payload = req.body;
    const checkoutId = payload?.Body?.stkCallback?.CheckoutRequestID || "unknown";
    const resultCode = payload?.Body?.stkCallback?.ResultCode;

    console.log(`📩 Callback received | CheckoutRequestID: ${checkoutId} | ResultCode: ${resultCode}`);
    console.log("   Payload:", JSON.stringify(payload, null, 2));

    // Respond to Safaricom IMMEDIATELY — they retry aggressively if you're slow
    res.json({ ResultCode: 0, ResultDesc: "Success" });

    // Forward to Koyeb in the background
    const target = `${process.env.APP_SERVER_URL}/mpesa/callback`;
    console.log("📤 Forwarding to Koyeb:", target);

    try {
        await axios.post(target, payload, {
            headers: { "Content-Type": "application/json" },
            timeout: 10000,
        });
        console.log("✅ Forwarded successfully. Wallet should be credited shortly.");
    } catch (fwdErr) {
        const detail = fwdErr.response?.data || fwdErr.message;
        console.error("❌ Forwarding to Koyeb FAILED:", detail);
        console.error("   Target was:", target);
        console.error("   Check that APP_SERVER_URL is correctly set in HF Secrets.");
    }
});

// 5. /health — Health Check
app.get("/health", (req, res) => {
    res.json({
        status: "healthy",
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        callback_url: process.env.CALLBACK_URL,
        app_server_url: process.env.APP_SERVER_URL,
    });
});

// ── Start Server ───────────────────────────────────────────────────────────
app.listen(PORT, HOST, () => {
    console.log(`\n✅ Vumbua M-Pesa service ready!`);
    console.log(`🌐 Listening on ${HOST}:${PORT}`);
    console.log(`🩺 Health: http://${HOST}:${PORT}/health`);
    console.log(`🔍 Debug:  http://${HOST}:${PORT}/debug\n`);
});