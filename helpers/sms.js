// helpers/sms.js — SMS via SMSAlert with DLT template routing
const axios = require('axios');

// DLT approved template IDs
const TEMPLATES = {
  otp:              '1707164361822841747', // Login OTP (existing WHPLoginPass template)
  markPaidOtp:      '1707177951693466126', // Branch Mark Paid OTP - new approved template
  enrolUpi:         '1707177944216513670', // Enrolment Success - UPI - template #10
  enrolStore:       '1707177944226842360', // Enrolment Success - Store - template #11
  mandateLink:      '1707177944335144547', // UPI Mandate Link - template #6
  schemeActive:     '1707177944342071213', // Scheme Activated - template #5
  reminder:         '1707177944355425301', // Payment Reminder - template #2
  autoDebitSuccess: '1707177944381570622', // Auto-debit Success - template #1
  autoDebitFailed:  '1707177944406782086', // Auto-debit Failed - template #8
  halted:           '1707177944411338921', // Subscription Halted - template #4
  matured:          '1707177944419180619', // Scheme Matured - template #7
  discontinued:     '1707177944427332534', // Discontinued - template #3
};

async function sendSms(phone, message, templateKey) {
  try {
    const templateId = TEMPLATES[templateKey] || TEMPLATES.otp;
    await axios.post('https://www.smsalert.co.in/api/push.json', null, {
      params: {
        apikey:      process.env.SMSALERT_API_KEY,
        sender:      'WHPECM',
        mobileno:    phone,
        text:        message,
        route:       'transscrub',
        template_id: templateId
      },
      timeout: 10000
    });
    console.log(`[SMS] Sent to ${phone} [${templateKey || 'otp'}]`);
  } catch(e) {
    console.error('[SMS] Failed:', e.message);
  }
}

module.exports = { sendSms, TEMPLATES };
