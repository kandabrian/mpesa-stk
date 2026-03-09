const axios = require('axios');

// 🔑 Get access token (Production)
async function getAccessToken() {
    const url = 'https://api.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials';

    const auth = Buffer.from(
        process.env.CONSUMER_KEY + ':' + process.env.CONSUMER_SECRET
    ).toString('base64');

    const response = await axios.get(url, {
        headers: { Authorization: `Basic ${auth}` },
        timeout: 10000
    });

    return response.data.access_token;
}

// 📲 STK Push (Production)
async function stkPush(phone, amount) {
    const token = await getAccessToken();

    const timestamp = new Date()
        .toISOString()
        .replace(/[^0-9]/g, '')
        .slice(0, 14);

    const password = Buffer.from(
        process.env.SHORTCODE + process.env.PASSKEY + timestamp
    ).toString('base64');

    const partyB = process.env.STORE_NUMBER || process.env.SHORTCODE;

    const response = await axios.post(
        'https://api.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
        {
            BusinessShortCode: process.env.SHORTCODE,
            Password: password,
            Timestamp: timestamp,
            TransactionType: 'CustomerBuyGoodsOnline',
            Amount: amount,
            PartyA: phone,
            PartyB: partyB,
            PhoneNumber: phone,
            CallBackURL: process.env.CALLBACK_URL,
            AccountReference: 'Vumbua',
            TransactionDesc: 'Vumbua Deposit'
        },
        {
            headers: { Authorization: `Bearer ${token}` },
            timeout: 15000
        }
    );

    return response.data;
}

module.exports = { stkPush };