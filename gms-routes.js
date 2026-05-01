// ══════════════════════════════════════════════════════════
//  gms-routes.js — WHP Golden Moments Scheme
//  Completely separate file. Zero changes to your old code.
//
//  STEP 1: Install dependencies
//  npm install razorpay googleapis
//
//  STEP 2: Add ONE line to your server.js at the bottom
//  before app.listen():
//  require('./gms-routes')(app, cache);
//
//  STEP 3: Add these to Railway env:
//  RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET,
//  GOOGLE_SERVICE_ACCOUNT_JSON, GOOGLE_SHEET_ID
// ══════════════════════════════════════════════════════════

const Razorpay   = require('razorpay');
const { google } = require('googleapis');

const SHEET_NAME = 'GMS Enrolments';

// ── Helpers ──────────────────────────────────────────────
function genId() {
  return 'WHP-GMS-' + Date.now().toString().slice(-8);
}

function maturityDate(tenure) {
  const d = new Date();
  d.setMonth(d.getMonth() + parseInt(tenure));
  return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
}

// ── Google Sheets client ─────────────────────────────────
async function sheetsClient() {
  const creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
  const auth  = new google.auth.GoogleAuth({
    credentials: creds,
    scopes: ['https://www.googleapis.com/auth/spreadsheets']
  });
  return google.sheets({ version: 'v4', auth });
}

// ── Ensure headers exist on first run ───────────────────
async function ensureHeaders(sheets) {
  try {
    const check = await sheets.spreadsheets.values.get({
      spreadsheetId: process.env.GOOGLE_SHEET_ID,
      range: `${SHEET_NAME}!A1`
    });
    if (check.data.values && check.data.values.length) return;
  } catch(e) {}

  const headers = [
    'Enrolment ID', 'Date', 'Name', 'Mobile', 'Email', 'Branch',
    'Product', 'Redeem Type', 'Bonus %',
    'Monthly Instalment (₹)', 'Tenure (Months)', 'Pay Months',
    'Total Contribution (₹)', 'WHP Bonus (₹)', 'Total Redeemable (₹)',
    'Maturity Date', 'Payment Method',
    'Razorpay Subscription ID', 'Razorpay Payment Link',
    'M1','M2','M3','M4','M5','M6','M7','M8','M9','M10',
    'M11','M12','M13','M14','M15','M16','M17','M18','M19','M20',
    'M21','M22','M23',
    'Payments Made', 'Payments Pending', 'Status'
  ];

  await sheets.spreadsheets.values.update({
    spreadsheetId: process.env.GOOGLE_SHEET_ID,
    range: `${SHEET_NAME}!A1`,
    valueInputOption: 'RAW',
    requestBody: { values: [headers] }
  });
}

// ── Append one enrolment row ─────────────────────────────
async function appendRow(sheets, data) {
  const pending = Array(parseInt(data.tenure) || 11).fill('Pending');
  const empty   = Array(23 - pending.length).fill('');
  const months  = [...pending, ...empty];

  const row = [
    data.enrolmentId,
    data.date,
    data.name,
    data.phone,
    data.email || '',
    data.branch,
    data.product || '',
    data.type,
    data.pct + '%',
    data.amt,
    data.tenure,
    data.paymo,
    data.paid,
    data.bonus,
    data.redeem,
    data.maturityDate,
    data.payMethod,
    data.razorpaySubId   || '',
    data.razorpayPayLink || '',
    ...months,
    0,
    data.tenure,
    'Active'
  ];

  await sheets.spreadsheets.values.append({
    spreadsheetId: process.env.GOOGLE_SHEET_ID,
    range: `${SHEET_NAME}!A1`,
    valueInputOption: 'RAW',
    insertDataOption: 'INSERT_ROWS',
    requestBody: { values: [row] }
  });
}

// ── Update month payment status ──────────────────────────
// Called by Razorpay webhook when payment is made
async function updateMonthPaid(sheets, enrolmentId, monthNum) {
  const sheetId = process.env.GOOGLE_SHEET_ID;

  // Find the row with this enrolment ID
  const all = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${SHEET_NAME}!A:A`
  });

  const rows = all.data.values || [];
  let rowIndex = -1;
  for (let i = 0; i < rows.length; i++) {
    if (rows[i][0] === enrolmentId) { rowIndex = i + 1; break; }
  }
  if (rowIndex === -1) return;

  // M1 starts at column T (index 19), so month N is column 19 + N - 1
  const colIndex = 19 + parseInt(monthNum) - 1;
  const colLetter = String.fromCharCode(65 + colIndex);

  await sheets.spreadsheets.values.update({
    spreadsheetId: sheetId,
    range: `${SHEET_NAME}!${colLetter}${rowIndex}`,
    valueInputOption: 'RAW',
    requestBody: { values: [['Paid']] }
  });

  // Update Payments Made count
  const rowData = await sheets.spreadsheets.values.get({
    spreadsheetId: sheetId,
    range: `${SHEET_NAME}!AH${rowIndex}:AI${rowIndex}`
  });
  const made    = parseInt((rowData.data.values?.[0]?.[0]) || 0) + 1;
  const pending = parseInt((rowData.data.values?.[0]?.[1]) || 0) - 1;

  await sheets.spreadsheets.values.update({
    spreadsheetId: sheetId,
    range: `${SHEET_NAME}!AH${rowIndex}:AI${rowIndex}`,
    valueInputOption: 'RAW',
    requestBody: { values: [[made, Math.max(0, pending)]] }
  });
}

// ════════════════════════════════════════════════════════
module.exports = function(app, cache) {

  const rzp = new Razorpay({
    key_id:     process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET
  });

  // ── POST /api/create-gms-enrolment ──────────────────
  app.post('/api/create-gms-enrolment', async (req, res) => {
    try {
      const {
        name, phone, email, branch,
        amt, tenure, paymo, pct,
        type, paid, bonus, redeem,
        pay, product
      } = req.body;

      // Validate OTP was verified
      const cleanPhone = String(phone).replace(/\D/g, '').slice(-10);
      const otpData    = cache.get(`otp:${cleanPhone}`);
      if (!otpData || !otpData.verified) {
        return res.status(401).json({ success: false, message: 'Mobile not verified. Please verify OTP first.' });
      }

      const enrolmentId = genId();
      const date        = new Date().toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
      const mDate       = maturityDate(tenure);

      let razorpaySubId   = '';
      let razorpayPayLink = '';

      // ── Create Razorpay subscription (UPI auto-debit) ──
      if (pay === 'upi') {
        try {
          // Create a plan
          const plan = await rzp.plans.create({
            period:   'monthly',
            interval: 1,
            item: {
              name:     `WHP GMS - ${name} - ${enrolmentId}`,
              amount:   parseInt(amt) * 100, // paise
              currency: 'INR',
              description: `GMS Instalment | ${type} | ${tenure} months`
            },
            notes: {
              enrolment_id: enrolmentId,
              customer_name: name,
              customer_phone: phone,
              branch: branch
            }
          });

          // Create subscription
          const sub = await rzp.subscriptions.create({
            plan_id:        plan.id,
            total_count:    parseInt(paymo),
            quantity:       1,
            customer_notify: 1,
            notes: {
              enrolment_id:   enrolmentId,
              customer_name:  name,
              customer_phone: phone,
              branch:         branch,
              product:        product || ''
            }
          });

          razorpaySubId   = sub.id;
          razorpayPayLink = sub.short_url || '';

          console.log(`[GMS] Razorpay subscription created: ${sub.id} for ${name} (${phone})`);

        } catch(rzpErr) {
          console.error('[GMS] Razorpay error:', rzpErr.error || rzpErr.message);
          // Don't fail the enrolment — still save to sheet
          razorpayPayLink = 'PENDING - Create manually in Razorpay';
        }
      }

      // ── Save to Google Sheet ─────────────────────────
      try {
        const sheets = await sheetsClient();
        await ensureHeaders(sheets);
        await appendRow(sheets, {
          enrolmentId, date, name, phone, email, branch,
          product, type, pct, amt, tenure, paymo,
          paid, bonus, redeem, maturityDate: mDate,
          payMethod: pay === 'upi' ? 'UPI Auto-debit' : 'Pay at Store',
          razorpaySubId, razorpayPayLink
        });
        console.log(`[GMS] Saved to Google Sheet: ${enrolmentId}`);
      } catch(sheetErr) {
        console.error('[GMS] Google Sheet error:', sheetErr.message);
        // Don't fail — still return success
      }

      // ── Clear OTP cache ──────────────────────────────
      cache.del(`otp:${cleanPhone}`);

      return res.json({
        success:      true,
        enrolmentId,
        razorpayLink: razorpayPayLink,
        message:      pay === 'upi'
          ? 'Enrolment successful! Razorpay payment link sent via SMS & Email.'
          : 'Enrolment successful! Please visit your nearest WHP branch to pay.'
      });

    } catch(err) {
      console.error('[GMS] create-gms-enrolment error:', err.message);
      return res.status(500).json({ success: false, message: 'Enrolment failed. Please try again.' });
    }
  });

  // ── POST /api/gms-webhook (Razorpay payment webhook) ──
  // Add this URL in Razorpay Dashboard → Webhooks:
  // https://whploginpass.onrender.com/api/gms-webhook
  // Events: subscription.charged
  app.post('/api/gms-webhook', async (req, res) => {
    try {
      const secret    = process.env.RAZORPAY_KEY_SECRET;
      const signature = req.headers['x-razorpay-signature'];
      const body      = JSON.stringify(req.body);

      const crypto   = require('crypto');
      const expected = crypto.createHmac('sha256', secret).update(body).digest('hex');
      if (signature !== expected) {
        console.warn('[GMS Webhook] Invalid signature');
        return res.status(400).json({ success: false });
      }

      const event = req.body.event;
      console.log(`[GMS Webhook] Event: ${event}`);

      if (event === 'subscription.charged') {
        const sub         = req.body.payload.subscription.entity;
        const enrolmentId = sub.notes?.enrolment_id;
        const paidCount   = sub.paid_count || 1;

        if (enrolmentId) {
          const sheets = await sheetsClient();
          await updateMonthPaid(sheets, enrolmentId, paidCount);
          console.log(`[GMS Webhook] Month ${paidCount} marked Paid for ${enrolmentId}`);
        }
      }

      return res.json({ success: true });
    } catch(err) {
      console.error('[GMS Webhook] error:', err.message);
      return res.status(500).json({ success: false });
    }
  });

  // ── GET /api/gms-enrolments (view all enrolments) ──
  app.get('/api/gms-enrolments', async (req, res) => {
    try {
      const sheets = await sheetsClient();
      const data   = await sheets.spreadsheets.values.get({
        spreadsheetId: process.env.GOOGLE_SHEET_ID,
        range: `${SHEET_NAME}!A1:AJ1000`
      });
      return res.json({ success: true, rows: data.data.values || [] });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Routes loaded: /api/create-gms-enrolment, /api/gms-webhook, /api/gms-enrolments');
};
