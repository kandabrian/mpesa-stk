// 📂 server.js (Render Optimized Version)
const express = require("express");
const axios = require("axios");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");

dotenv.config();

const app = express();

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['*'], // Allow all in production
  credentials: true,
}));

// Rate limiting - increased for production
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // Increased for production
  message: 'Too many requests from this IP, please try again later.',
});
app.use('/pay', limiter);

// Logging
app.use(morgan('combined'));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 5000;
const HOST = '0.0.0.0'; // Render requires 0.0.0.0

// In-memory cache for access tokens
const tokenCache = {
  token: null,
  expiry: null,
};

// Get access token with caching
async function getAccessToken() {
  const now = Date.now();
  
  // Return cached token if still valid
  if (tokenCache.token && tokenCache.expiry > now) {
    console.log('Using cached token');
    return tokenCache.token;
  }

  const auth = Buffer.from(
    `${process.env.CONSUMER_KEY}:${process.env.CONSUMER_SECRET}`
  ).toString("base64");

  try {
    const response = await axios.get(
      "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials",
      { 
        headers: { Authorization: `Basic ${auth}` },
        timeout: 10000,
      }
    );

    // Cache the token (expires in 3599 seconds)
    tokenCache.token = response.data.access_token;
    tokenCache.expiry = now + (3599 * 1000);

    console.log('New access token generated');
    return tokenCache.token;
  } catch (error) {
    console.error('Access token error:', error.message);
    throw new Error('Failed to get access token');
  }
}

// STK Push endpoint with validation
app.post("/pay", async (req, res) => {
  console.log('📱 PAYMENT REQUEST RECEIVED:', {
    ip: req.ip,
    headers: req.headers,
    body: req.body,
    timestamp: new Date().toISOString()
  });

  try {
    const { phone, amount, currency = 'KES', description = 'Payment' } = req.body;

    // Input validation
    if (!phone || !amount) {
      console.log('❌ Validation failed: Missing phone or amount');
      return res.status(400).json({ 
        success: false,
        error: "Phone and amount are required" 
      });
    }

    // Phone validation
    const phoneRegex = /^254[17]\d{8}$/;
    if (!phoneRegex.test(phone)) {
      console.log('❌ Validation failed: Invalid phone format');
      return res.status(400).json({ 
        success: false,
        error: "Invalid phone format. Use: 2547XXXXXXXX or 2541XXXXXXXX" 
      });
    }

    // Amount validation
    const amountNum = parseFloat(amount);
    if (isNaN(amountNum) || amountNum <= 0) {
      console.log('❌ Validation failed: Invalid amount');
      return res.status(400).json({ 
        success: false,
        error: "Amount must be a positive number" 
      });
    }

    console.log(`💳 Processing payment: ${phone} - ${currency} ${amount}`);

    // Get access token
    const token = await getAccessToken();

    // Generate timestamp and password
    const timestamp = new Date()
      .toISOString()
      .replace(/[^0-9]/g, "")
      .slice(0, 14);
    
    const password = Buffer.from(
      `${process.env.SHORTCODE}${process.env.PASSKEY}${timestamp}`
    ).toString("base64");

    // Prepare M-Pesa request
    const mpesaRequest = {
      BusinessShortCode: process.env.SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: "CustomerPayBillOnline",
      Amount: amountNum,
      PartyA: phone,
      PartyB: process.env.SHORTCODE,
      PhoneNumber: phone,
      CallBackURL: process.env.CALLBACK_URL || `${process.env.SERVER_URL}/callback`,
      AccountReference: description.substring(0, 12),
      TransactionDesc: description,
    };

    console.log('📤 Sending to M-Pesa API:', mpesaRequest);

    // Send to M-Pesa API
    const response = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
      mpesaRequest,
      { 
        headers: { 
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        timeout: 30000
      }
    );

    console.log("✅ M-Pesa API Response:", response.data);

    // Return success response
    res.json({
      success: true,
      message: "STK Push initiated successfully",
      data: response.data,
      timestamp: new Date().toISOString(),
    });

  } catch (error) {
    console.error("❌ Payment error:", error.message);
    
    let statusCode = 500;
    let errorMessage = "Internal server error";
    let errorDetails = null;

    if (error.response) {
      // M-Pesa API error
      statusCode = error.response.status;
      errorMessage = error.response.data?.errorMessage || error.response.statusText;
      errorDetails = error.response.data;
      console.error('M-Pesa API Error:', error.response.data);
    } else if (error.request) {
      // No response received
      errorMessage = "Could not reach M-Pesa API";
      console.error('No response from M-Pesa API');
    } else {
      // Other errors
      errorMessage = error.message;
      console.error('Other error:', error);
    }

    res.status(statusCode).json({
      success: false,
      error: errorMessage,
      details: errorDetails,
      timestamp: new Date().toISOString(),
    });
  }
});

// Callback endpoint for M-Pesa
app.post("/callback", (req, res) => {
  try {
    const callbackData = req.body;
    console.log("📱 M-Pesa Callback Received:", JSON.stringify(callbackData, null, 2));

    // Process callback
    const resultCode = callbackData.Body?.stkCallback?.ResultCode;
    const resultDesc = callbackData.Body?.stkCallback?.ResultDesc;

    if (resultCode === 0) {
      console.log("✅ Payment Successful!");
      
      // Extract transaction details
      const items = callbackData.Body.stkCallback.CallbackMetadata?.Item || [];
      const amount = items.find(i => i.Name === "Amount")?.Value;
      const receipt = items.find(i => i.Name === "MpesaReceiptNumber")?.Value;
      const phone = items.find(i => i.Name === "PhoneNumber")?.Value;
      const date = items.find(i => i.Name === "TransactionDate")?.Value;

      console.log(`📝 Receipt: ${receipt}, Amount: ${amount}, Phone: ${phone}, Date: ${date}`);

      // Here you would:
      // 1. Update your database
      // 2. Send notification to user
      // 3. Process the exchange
    } else {
      console.log(`❌ Payment Failed: ${resultDesc}`);
    }

    // Always respond to M-Pesa
    res.json({
      ResultCode: 0,
      ResultDesc: "Success",
    });
  } catch (error) {
    console.error("Callback processing error:", error);
    res.json({ ResultCode: 0, ResultDesc: "Success" }); // Still respond success
  }
});

// Token endpoint for Flutter app
app.get("/token", async (req, res) => {
  try {
    const token = await getAccessToken();
    res.json({
      access_token: token,
      expires_in: 3599,
      token_type: "Bearer",
    });
  } catch (error) {
    res.status(500).json({ error: "Failed to get token" });
  }
});

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({
    status: "healthy",
    service: "M-Pesa STK Push API",
    version: "1.0.0",
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || "development",
    uptime: process.uptime(),
  });
});

// Status check endpoint
app.get("/status/:checkoutId", async (req, res) => {
  try {
    const token = await getAccessToken();
    const checkoutId = req.params.checkoutId;

    const response = await axios.post(
      "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query",
      {
        BusinessShortCode: process.env.SHORTCODE,
        Password: Buffer.from(
          `${process.env.SHORTCODE}${process.env.PASSKEY}${new Date()
            .toISOString()
            .replace(/[^0-9]/g, "")
            .slice(0, 14)}`
        ).toString("base64"),
        Timestamp: new Date()
          .toISOString()
          .replace(/[^0-9]/g, "")
          .slice(0, 14),
        CheckoutRequestID: checkoutId,
      },
      {
        headers: { Authorization: `Bearer ${token}` },
      }
    );

    res.json(response.data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Metrics endpoint for monitoring
app.get("/metrics", (req, res) => {
  res.json({
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    timestamp: new Date().toISOString(),
    nodeVersion: process.version,
    platform: process.platform,
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({
    success: false,
    error: "Internal server error",
    message: process.env.NODE_ENV === 'development' ? err.message : undefined,
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: "Endpoint not found",
  });
});

// Start server (Render compatible)
app.listen(PORT, HOST, () => {
  console.log(`🚀 Server started successfully!`);
  console.log(`📡 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 Port: ${PORT}`);
  console.log(`🩺 Health: http://localhost:${PORT}/health`);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received. Shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received. Shutting down gracefully...');
  process.exit(0);
});