// helpers/sms.js — SMS via SMSAlert with DLT template routing
const axios = require('axios');

const TEMPLATES = {
  otp:              '1707164361822841747', // Login OTP
  markPaidOtp:      '1707177951693466126', // Branch mark paid OTP
  enrolUpi:         '1707177944216513670', // Enrolment - UPI
  enrolStore:       '1707177944226842360', // Enrolment - Store
  mandateLink:      '1707177944335144547', // UPI Mandate Link
  schemeActive:     '1707177944342071213', // Scheme Activated
  reminder:         '1707177954096584065', // Payment Reminder (gms.whpjewellers.com approved)
  autoDebitSuccess: '1707177944381570622', // UPI Auto-debit Success
  storePaySuccess:  '1707177969896672521', // Store Payment Success
  autoDebitFailed:  '1707177944406782086', // Auto-debit Failed
  halted:           '1707177944411338921', // Subscription Halted
  matured:          '1707177944419180619', // Scheme Matured
  discontinued:     '1707177944427332534', // Discontinued
  lateFee:          '1707177969904961261', // Late Fee Applied
};

const SMS = {
  otp: (otp) =>
    `Dear user, your WHP Jewellers otp code is ${otp}`,

  markPaidOtp: (enrolmentId, monthLabel, otp) =>
    `Dear Customer, WHP branch manager is processing payment for scheme ${enrolmentId} Month ${monthLabel}. OTP: ${otp}. Valid 5 mins. Share only with staff - WHP Jewellers`,

  enrolUpi: (enrolmentId, amt, payMo, redeemable) =>
    `Dear Customer, you have enrolled in WHP Golden Moments Scheme. ID: ${enrolmentId}. Monthly: Rs.${amt} x ${payMo} months. Redeemable: Rs.${redeemable}. - WHP Jewellers`,

  enrolStore: (enrolmentId, amt) =>
    `Dear Customer, you have enrolled in WHP Golden Moments Scheme. ID: ${enrolmentId}. Monthly: Rs.${amt}. Please pay at your nearest WHP branch. - WHP Jewellers`,

  mandateLink: (shortUrl) =>
    `Dear Customer, approve your WHP GMS UPI autopay mandate to activate your scheme. Click: ${shortUrl} - WHP Jewellers`,

  schemeActive: (enrolmentId, amt) =>
    `Dear Customer, your WHP GMS scheme ${enrolmentId} is now ACTIVE! Rs.${amt} will be auto-debited every month. - WHP Jewellers`,

  reminder: (amt, enrolmentId, dueDate, payLink) =>
    `Dear Customer, your WHP GMS payment of Rs.${Math.round(parseFloat(amt))} for scheme ${enrolmentId} is due on ${dueDate}. Pay now: ${payLink} or set up autopay. - WHP Jewellers`,

  autoDebitSuccess: (amt, enrolmentId, monthLabel, remaining) =>
    `Dear Customer, Rs.${amt} collected via UPI for WHP GMS scheme ${enrolmentId} Month ${monthLabel}. ${remaining} payment(s) remaining. - WHP Jewellers`,

  storePaySuccess: (amt, enrolmentId, monthLabel, remaining) =>
    `Dear Customer, Rs.${amt} collected at WHP branch for GMS scheme ${enrolmentId} Month ${monthLabel}. ${remaining} payment(s) remaining. - WHP Jewellers`,

  autoDebitFailed: (amt, monthLabel) =>
    `Dear Customer, your WHP GMS payment of Rs.${amt} for Month ${monthLabel} could not be collected. Please pay at branch or retry. - WHP Jewellers`,

  halted: () =>
    `Dear Customer, your WHP GMS UPI autopay has been paused due to multiple failures. Please visit your nearest WHP branch. - WHP Jewellers`,

  matured: (enrolmentId, redeemable) =>
    `Dear Customer, your WHP GMS scheme ${enrolmentId} is now MATURED! Visit your nearest WHP branch to redeem Rs.${redeemable}. - WHP Jewellers`,

  discontinued: (enrolmentId) =>
    `Dear Customer, your WHP GMS scheme ${enrolmentId} has been discontinued. Refund will be processed within 30 days. Contact branch for details. - WHP Jewellers`,

  lateFee: (amt, enrolmentId, monthLabel) =>
    `Dear Customer, a late fee of Rs.${amt} has been applied to your WHP GMS scheme ${enrolmentId} for Month ${monthLabel}. - WHP Jewellers`,
};

async function sendSms(phone, message, templateKey) {
  try {
    const templateId = TEMPLATES[templateKey] || TEMPLATES.otp;
    console.log(`[SMS] Sending [${templateKey}] to ${phone}`);
    const response = await axios.post('https://www.smsalert.co.in/api/push.json', null, {
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
    if (e.response) {
      console.error('[SMS] Error body:', JSON.stringify(e.response.data));
    }
  }
}

module.exports = { sendSms, TEMPLATES, SMS };
