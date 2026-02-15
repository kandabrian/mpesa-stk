
// 📂 server.js — M-Pesa STK Push Service for Hugging Face Spaces
const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");

dotenv.config();

const REQUIRED_VARS = ["CONSUMER_KEY","CONSUMER_SECRET","SHORTCODE","PASSKEY","CALLBACK_URL","APP_SERVER_URL"];
const missing = REQUIRED_VARS.filter(v => !process.env[v]);
if (missing.length > 0) {
    console.error("FATAL: Missing required env vars:", missing.join(", "));
    process.exit(1);
}

const callbackUrl = process.env.CALLBACK_URL;
if (callbackUrl.includes("localhost") || callbackUrl.includes("127.0.0.1") || callbackUrl.startsWith("http://")) {
    console.error("FATAL: CALLBACK_URL must be a public HTTPS URL:", callbackUrl);
    process.exit(1);
}

const appServerUrl = process.env.APP_SERVER_URL;

console.log("========================================");
console.log("Vumbua M-Pesa Service booting...");
console.log("   CALLBACK_URL  :", callbackUrl);
console.log("   APP_SERVER_URL:", appServerUrl);
console.log("   SHORTCODE     :", process.env.SHORTCODE);
console.log("========================================");

const app = express();
const PORT = process.env.PORT || 7860;
const HOST = "0.0.0.0";

app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false, frameguard: false }));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS?.split(",") || ["*"], credentials: true }));
app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const payLimiter = rateLimit({ windowMs: 15*60*1000, max: 200, message: { success: false, error: "Too many requests." } });

const tokenCache = { token: null, expiry: null };

async function getAccessToken() {
    const now = Date.now();
    if (tokenCache.token && tokenCache.expiry > now) return tokenCache.token;
    const auth = Buffer.from(`${process.env.CONSUMER_KEY}:${process.env.CONSUMER_SECRET}`).toString("base64");
    const response = await axios.get(
        "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
        { headers: { Authorization: `Basic ${auth}` }, timeout: 10000 }
    );
    tokenCache.token = response.data.access_token;
    tokenCache.expiry = now + 3590*1000;
    console.log("M-Pesa access token refreshed.");
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

app.get("/debug", (req, res) => {
    const cb = process.env.CALLBACK_URL || "NOT SET";
    const au = process.env.APP_SERVER_URL || "NOT SET";
    const cbOk = cb.startsWith("https://") && !cb.includes("localhost");
    const auOk = au.startsWith("https://") && !au.includes("localhost");
    res.json({
        status: cbOk && auOk ? "OK - All good" : "ERROR - Config issues",
        callback_url: cb,
        callback_url_ok: cbOk ? "OK - Public HTTPS" : "ERROR - Not a public HTTPS URL",
        app_server_url: au,
        app_server_url_ok: auOk ? "OK - Public HTTPS" : "ERROR - Not a public HTTPS URL",
        shortcode: process.env.SHORTCODE || "NOT SET",
        consumer_key_set: process.env.CONSUMER_KEY ? "set" : "NOT SET",
        passkey_set: process.env.PASSKEY ? "set" : "NOT SET",
        token_cached: tokenCache.token ? "yes" : "not yet",
        uptime_seconds: Math.round(process.uptime()),
    });
});

app.post("/pay", payLimiter, async (req, res) => {
    try {
        const { phone, amount, description = "Vumbua Deposit" } = req.body;
        if (!phone || !amount) return res.status(400).json({ success: false, error: "Phone and amount are required." });
        const phoneStr = String(phone).replace(/\D/g, "");
        const amountNum = Math.floor(parseFloat(amount));
        if (amountNum < 1) return res.status(400).json({ success: false, error: "Amount must be at least 1." });
        console.log(`STK Push: phone=${phoneStr.slice(0,6)}***, amount=${amountNum}`);
        const token = await getAccessToken();
        const timestamp = generateTimestamp();
        const password = generatePassword(timestamp);
        const cb = process.env.CALLBACK_URL;
        const mpesaPayload = {
            BusinessShortCode: process.env.SHORTCODE, Password: password, Timestamp: timestamp,
            TransactionType: "CustomerPayBillOnline", Amount: amountNum,
            PartyA: phoneStr, PartyB: process.env.SHORTCODE, PhoneNumber: phoneStr,
            CallBackURL: cb, AccountReference: description.substring(0,12), TransactionDesc: description.substring(0,13),
        };
        console.log("Sending STK Push. CallBackURL:", cb);
        const mpesaRes = await axios.post(
            "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            mpesaPayload,
            { headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, timeout: 15000 }
        );
        const checkoutId = mpesaRes.data.CheckoutRequestID;
        console.log("STK Push sent. CheckoutRequestID:", checkoutId);
        res.json({ success: true, CheckoutRequestID: checkoutId, MerchantRequestID: mpesaRes.data.MerchantRequestID, message: "STK Push sent." });
    } catch (err) {
        const detail = err.response?.data || err.message;
        console.error("STK Push error:", detail);
        res.status(500).json({ success: false, error: "STK push failed.", detail });
    }
});

app.post("/callback", async (req, res) => {
    const payload = req.body;
    const checkoutId = payload?.Body?.stkCallback?.CheckoutRequestID || "unknown";
    const resultCode = payload?.Body?.stkCallback?.ResultCode;
    console.log(`Callback received | CheckoutRequestID: ${checkoutId} | ResultCode: ${resultCode}`);
    console.log("Payload:", JSON.stringify(payload, null, 2));
    res.json({ ResultCode: 0, ResultDesc: "Success" });
    const target = `${process.env.APP_SERVER_URL}/mpesa/callback`;
    console.log("Forwarding to Koyeb:", target);
    try {
        await axios.post(target, payload, { headers: { "Content-Type": "application/json" }, timeout: 10000 });
        console.log("Forwarded successfully. Wallet should be credited.");
    } catch (fwdErr) {
        const detail = fwdErr.response?.data || fwdErr.message;
        console.error("Forwarding to Koyeb FAILED:", detail);
        console.error("Target was:", target);
    }
});

app.get("/health", (req, res) => {
    res.json({ status: "healthy", uptime: process.uptime(), timestamp: new Date().toISOString(), callback_url: process.env.CALLBACK_URL, app_server_url: process.env.APP_SERVER_URL });
});

app.listen(PORT, HOST, () => {
    console.log(`Vumbua M-Pesa service ready on ${HOST}:${PORT}`);
    console.log(`Health: http://${HOST}:${PORT}/health`);
    console.log(`Debug:  http://${HOST}:${PORT}/debug`);
});
