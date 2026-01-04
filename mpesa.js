const axios = require('axios');

// 🔑 Get access token
async function getAccessToken() {
  const url =
    'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials';

  const auth = Buffer.from(
    process.env.CONSUMER_KEY + ':' + process.env.CONSUMER_SECRET
  ).toString('base64');

  const response = await axios.get(url, {
    headers: {
      Authorization: `Basic ${auth}`
    }
  });

  return response.data.access_token;
}

// 📲 STK Push
async function stkPush(phone, amount) {
  const token = await getAccessToken();

  const timestamp = new Date()
    .toISOString()
    .replace(/[^0-9]/g, '')
    .slice(0, -3);

  const password = Buffer.from(
    process.env.SHORTCODE + process.env.PASSKEY + timestamp
  ).toString('base64');

  const response = await axios.post(
    'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
    {
      BusinessShortCode: process.env.SHORTCODE,
      Password: password,
      Timestamp: timestamp,
      TransactionType: 'CustomerPayBillOnline',
      Amount: amount,
      PartyA: phone,
      PartyB: process.env.SHORTCODE,
      PhoneNumber: phone,
      CallBackURL: process.env.CALLBACK_URL,
      AccountReference: 'USD-CREDIT',
      TransactionDesc: 'Buy USD Credit'
    },
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );

  return response.data;
}

module.exports = { stkPush };
