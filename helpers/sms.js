// helpers/sms.js — SMS via SMSAlert
const axios = require('axios');

async function sendSms(phone, message) {
  try {
    await axios.post('https://www.smsalert.co.in/api/push.json', null, {
      params: {
        apikey:      process.env.SMSALERT_API_KEY,
        sender:      'WHPECM',
        mobileno:    phone,
        text:        message,
        route:       'transscrub',
        template_id: '1707164361822841747'
      },
      timeout: 10000
    });
    console.log(`[SMS] Sent to ${phone}`);
  } catch(e) {
    console.error('[SMS] Failed:', e.message);
  }
}

module.exports = { sendSms };
