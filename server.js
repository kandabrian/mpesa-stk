// 📂 server.js — M-Pesa STK Push Service
const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");

dotenv.config();

// Ensure all required variables are present
const REQUIRED_VARS = ["CONSUMER_KEY", "CONSUMER_SECRET", "SHORTCODE", "PASSKEY", "CALLBACK_URL", "TILL_NUMBER"];
const missing = REQUIRED_VARS.filter(v => !process.env[v]);
if (missing.length > 0) {
    console.error("FATAL: Missing required env vars:", missing.join(", "));
    process.exit(1);
}

const callbackUrl = process.env.CALLBACK_URL;
if (callbackUrl.includes("localhost") || callbackUrl.includes("127.0.0.1") || callbackUrl.startsWith("http://")) {
    console.warn("WARNING: CALLBACK_URL is not a public HTTPS URL:", callbackUrl);
    console.warn("This is OK for local testing, but will fail in production with Safaricom.");
}

const appServerUrl = process.env.APP_SERVER_URL;

console.log("========================================");
console.log("Vumbua M-Pesa Service booting...");
console.log("   CALLBACK_URL  :", callbackUrl);
console.log("   APP_SERVER_URL:", appServerUrl || "NOT SET (forwarding disabled)");
console.log("   SHORTCODE     :", process.env.SHORTCODE);
console.log("   TILL_NUMBER   :", process.env.TILL_NUMBER);
console.log("========================================");

const app = express();
const PORT = process.env.PORT || 5000;
const HOST = "0.0.0.0";

// Trust proxy for express-rate-limit behind ngrok/Vercel/Koyeb
app.set("trust proxy", 1);

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, frameguard: false }));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(",") || ["*"], credentials: true }));
app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const payLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { success: false, error: "Too many requests." }
});

const tokenCache = { token: null, expiry: null };

// 🔑 Get Access Token with Caching
async function getAccessToken() {
    const now = Date.now();
    if (tokenCache.token && tokenCache.expiry > now) return tokenCache.token;
    
    const auth = Buffer.from(`${process.env.CONSUMER_KEY}:${process.env.CONSUMER_SECRET}`).toString("base64");
    const response = await axios.get(
        "https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
        { headers: { Authorization: `Basic ${auth}` }, timeout: 10000 }
    );
    
    tokenCache.token = response.data.access_token;
    tokenCache.expiry = now + 3590 * 1000; // Cache for slightly less than 1 hour
    console.log("✅ M-Pesa access token refreshed.");
    return tokenCache.token;
}

function generateTimestamp() {
    return new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14);
}

function generatePassword(timestamp) {
    return Buffer.from(`${process.env.SHORTCODE}${process.env.PASSKEY}${timestamp}`).toString("base64");
}

app.get("/", (req, res) => {
    res.send('<div style="font-family:sans-serif;text-align:center;padding:50px"><h1>Vumbua M-Pesa Service</h1><p style="color:green">Running</p><p><code>/health</code> | <code>/debug</code> | <code>POST /pay</code></p></div>');
});

// 📲 STK Push Endpoint
app.post("/pay", payLimiter, async (req, res) => {
    try {
        const { phone, amount, description = "Vumbua Deposit" } = req.body;
        if (!phone || !amount) return res.status(400).json({ success: false, error: "Phone and amount are required." });

        let phoneStr = String(phone).replace(/\D/g, "");
        const amountNum = Math.floor(parseFloat(amount));

        // Format phone to 254XXXXXXXXX
        if (phoneStr.startsWith("0")) {
            phoneStr = "254" + phoneStr.substring(1);
        } else if (phoneStr.startsWith("254") && phoneStr.length === 12) {
            // Already correct
        } else if (phoneStr.length === 9) {
            phoneStr = "254" + phoneStr;
        }

        if (phoneStr.length !== 12 || !phoneStr.startsWith("254")) {
            return res.status(400).json({ success: false, error: "Invalid phone number format. Use 2547XXXXXXXX." });
        }
        if (amountNum < 1) return res.status(400).json({ success: false, error: "Amount must be at least 1." });

        console.log(`📲 STK Push: phone=${phoneStr.slice(0, 6)}***, amount=KES ${amountNum}`);

        const token = await getAccessToken();
        const timestamp = generateTimestamp();
        const password = generatePassword(timestamp);

        const mpesaPayload = {
            BusinessShortCode: process.env.SHORTCODE, 
            Password: password,
            Timestamp: timestamp,
            TransactionType: "CustomerBuyGoodsOnline",
            Amount: amountNum,
            PartyA: phoneStr,
            PartyB: process.env.TILL_NUMBER,
            PhoneNumber: phoneStr,
            CallBackURL: process.env.CALLBACK_URL,
            AccountReference: description.substring(0, 12),
            TransactionDesc: description.substring(0, 13),
        };

        const mpesaRes = await axios.post(
            "https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            mpesaPayload,
            { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, timeout: 15000 }
        );

        res.json({
            success: true,
            CheckoutRequestID: mpesaRes.data.CheckoutRequestID,
            MerchantRequestID: mpesaRes.data.MerchantRequestID,
            message: "STK Push sent."
        });
    } catch (err) {
        const detail = err.response?.data || err.message;
        console.error("❌ STK Push error:", JSON.stringify(detail, null, 2));
        res.status(500).json({ success: false, error: "STK push failed.", detail });
    }
});

// 📩 Callback URL Endpoint
app.post("/callback", async (req, res) => {
    // 1. Acknowledge Safaricom IMMEDIATELY so they don't timeout
    res.json({ ResultCode: 0, ResultDesc: "Success" });

    const payload = req.body;
    const checkoutId = payload?.Body?.stkCallback?.CheckoutRequestID || "unknown";
    const resultCode = payload?.Body?.stkCallback?.ResultCode;
    const resultDesc = payload?.Body?.stkCallback?.ResultDesc;

    console.log(`📩 Callback received | Checkout: ${checkoutId} | Code: ${resultCode}`);

    if (resultCode === 0) {
        const rawItems = payload?.Body?.stkCallback?.CallbackMetadata?.Item || [];
        const metadata = rawItems.reduce((acc, item) => {
            acc[item.Name] = item.Value;
            return acc;
        }, {});
        console.log(`✅ Paid! Receipt: ${metadata.MpesaReceiptNumber}, Amount: ${metadata.Amount}`);
    } else {
        console.log(`❌ Payment failed/cancelled: ${resultDesc}`);
    }

    // 2. Forward RAW payload to main app with secret header
    if (process.env.APP_SERVER_URL) {
        const target = `${process.env.APP_SERVER_URL}/api/mpesa/callback`;
        console.log(`➡️ Forwarding to: ${target}`);

        let attempts = 0;
        const maxAttempts = 3;

        while (attempts < maxAttempts) {
            attempts++;
            try {
                const fwdRes = await axios.post(target, payload, {
                    headers: {
                        "Content-Type": "application/json",
                        "x-mpesa-secret": process.env.MPESA_CALLBACK_SECRET || ""
                    },
                    timeout: 25000
                });
                console.log(`➡️ Forwarded successfully on attempt ${attempts}. Status: ${fwdRes.status}`);
                break;
            } catch (fwdErr) {
                console.error(`❌ Forward attempt ${attempts} FAILED:`, fwdErr.message);
                if (attempts === maxAttempts) {
                    console.error("❌ All forward attempts exhausted.");
                    console.error("❌ Response status:", fwdErr.response?.status);
                    console.error("❌ Response body:", JSON.stringify(fwdErr.response?.data));
                } else {
                    console.log(`⏳ Retrying in 3s...`);
                    await new Promise(r => setTimeout(r, 3000));
                }
            }
        }
    } else {
        console.warn("⚠️ APP_SERVER_URL not set — forwarding disabled");
    }
});

app.get("/health", (req, res) => {
    res.json({ status: "healthy", uptime: process.uptime(), callback_url: process.env.CALLBACK_URL });
});

app.listen(PORT, HOST, () => {
    console.log(`✅ Vumbua M-Pesa service ready on ${HOST}:${PORT}`);
});