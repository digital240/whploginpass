// helpers/sms.js — SMS via SMSAlert with DLT template routing
const axios = require('axios');

// DLT approved template IDs — all verified
const TEMPLATES = {
  otp:              '1707164361822841747', // Login OTP
  enrolUpi:         '1707177944216513670', // Enrolment Success - UPI
  enrolStore:       '1707177944226842360', // Enrolment Success - Store
  mandateLink:      '1707177944335144547', // UPI Mandate Link
  schemeActive:     '1707177944342071213', // Scheme Activated
  reminder:         '1707177944355425301', // Payment Reminder
  autoDebitSuccess: '1707177944381570622', // Auto-debit Success
  autoDebitFailed:  '1707177944406782086', // Auto-debit Failed
  halted:           '1707177944411338921', // Subscription Halted
  matured:          '1707177944419180619', // Scheme Matured
  discontinued:     '1707177944427332534', // Discontinued
};

// ── Message builders — text must match DLT approved template exactly ──
const SMS = {
  otp: (otp) =>
    `Dear user, your WHP Jewellers otp code is ${otp}`,

  enrolUpi: (enrolmentId, amt, payMo, redeemable) =>
    `Dear Customer, you have enrolled in WHP Golden Moments Scheme. ID: ${enrolmentId}. Monthly: Rs.${amt} x ${payMo} months. Redeemable: Rs.${redeemable}. - WHP Jewellers`,

  enrolStore: (enrolmentId, amt) =>
    `Dear Customer, you have enrolled in WHP Golden Moments Scheme. ID: ${enrolmentId}. Monthly: Rs.${amt}. Please pay at your nearest WHP branch. - WHP Jewellers`,

  mandateLink: (shortUrl) =>
    `Dear Customer, approve your WHP GMS UPI autopay mandate to activate your scheme. Click: ${shortUrl} - WHP Jewellers`,

  schemeActive: (enrolmentId, amt) =>
    `Dear Customer, your WHP GMS scheme ${enrolmentId} is now ACTIVE! Rs.${amt} will be auto-debited every month. - WHP Jewellers`,

  reminder: (amt, enrolmentId, dueDate, payLink) =>
    `Dear Customer, your WHP GMS payment of Rs.${amt} for scheme ${enrolmentId} is due on ${dueDate}. Pay now: ${payLink} or set up autopay. - WHP Jewellers`,

  autoDebitSuccess: (amt, enrolmentId, monthNum, remaining) =>
    `Dear Customer, Rs.${amt} collected via UPI for WHP GMS scheme ${enrolmentId} Month ${monthNum}. ${remaining} payment's remaining. - WHP Jewellers`,

  autoDebitFailed: (amt, monthNum) =>
    `Dear Customer, your WHP GMS payment of Rs.${amt} for Month ${monthNum} could not be collected. Please pay at branch or retry. - WHP Jewellers`,

  halted: () =>
    `Dear Customer, your WHP GMS UPI autopay has been paused due to multiple failures. Please visit your nearest WHP branch. - WHP Jewellers`,

  matured: (enrolmentId, redeemable) =>
    `Dear Customer, your WHP GMS scheme ${enrolmentId} is now MATURED! Visit your nearest WHP branch to redeem Rs.${redeemable}. - WHP Jewellers`,

  discontinued: (enrolmentId) =>
    `Dear Customer, your WHP GMS scheme ${enrolmentId} has been discontinued. Refund will be processed within 30 days. Contact branch for details. - WHP Jewellers`,
};

// ── Core send function ────────────────────────────────
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
    console.log(`[SMS] Sent to ${phone} [${templateKey}]`);
  } catch(e) {
    console.error('[SMS] Failed:', e.message);
  }
}

module.exports = { sendSms, TEMPLATES, SMS };
