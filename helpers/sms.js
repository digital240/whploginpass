// helpers/sms.js — SMS via SMSAlert with DLT template routing
const axios = require('axios');

const TEMPLATES = {
  otp:              '1707164361822841747',
  enrolUpi:         '1707177944216513670',
  enrolStore:       '1707177944226842360',
  mandateLink:      '1707177944335144547',
  schemeActive:     '1707177944342071213',
  reminder:         '1707177944355425301',
  autoDebitSuccess: '1707177944381570622',
  autoDebitFailed:  '1707177944406782086',
  halted:           '1707177944411338921',
  matured:          '1707177944419180619',
  discontinued:     '1707177944427332534',
};

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

 autoDebitSuccess: (amt, enrolmentId, monthLabel, remaining) =>
   `Dear Customer, Rs.${amt} collected via UPI for WHP GMS scheme ${enrolmentId} Month ${monthLabel}. ${remaining} payment(s) remaining. - WHP Jewellers`,

  autoDebitFailed: (amt, monthLabel) =>
    `Dear Customer, your WHP GMS payment of Rs.${amt} for Month ${monthLabel} could not be collected. Please pay at branch or retry. - WHP Jewellers`,

  halted: () =>
    `Dear Customer, your WHP GMS UPI autopay has been paused due to multiple failures. Please visit your nearest WHP branch. - WHP Jewellers`,

  matured: (enrolmentId, redeemable) =>
    `Dear Customer, your WHP GMS scheme ${enrolmentId} is now MATURED! Visit your nearest WHP branch to redeem Rs.${redeemable}. - WHP Jewellers`,

  discontinued: (enrolmentId) =>
    `Dear Customer, your WHP GMS scheme ${enrolmentId} has been discontinued. Refund will be processed within 30 days. Contact branch for details. - WHP Jewellers`,
};

async function sendSms(phone, message, templateKey) {
  try {
    const templateId = TEMPLATES[templateKey] || TEMPLATES.otp;

    // ── Debug log — print exact text being sent
    console.log(`[SMS] Sending [${templateKey}] to ${phone}`);
    console.log(`[SMS] Text: "${message}"`);
    console.log(`[SMS] Template ID: ${templateId}`);

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
    console.log(`[SMS] Response:`, JSON.stringify(response.data));
  } catch(e) {
    console.error('[SMS] Failed:', e.message);
    // ── Print full error response from SMSAlert
    if (e.response) {
      console.error('[SMS] Status:', e.response.status);
      console.error('[SMS] Error body:', JSON.stringify(e.response.data));
    }
  }
}

module.exports = { sendSms, TEMPLATES, SMS };
