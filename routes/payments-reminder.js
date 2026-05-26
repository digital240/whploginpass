// routes/payments-reminder.js — Pay Now, Setup Autopay, SMS Reminders
const db       = require('../db');
const crypto   = require('crypto');
const Razorpay = require('razorpay');
const { sendSms, SMS } = require('../helpers/sms');

const rzp = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

function generatePayToken(enrolmentId, monthNum) {
  const secret = process.env.WLP_TOKEN_SECRET || 'whpgms2026';
  return crypto.createHmac('sha256', secret)
    .update(`${enrolmentId}:${monthNum}:paylink`)
    .digest('hex')
    .slice(0, 16); // 6 chars — matches DLT sample length
}
function fmtDue(d) {
  const dd   = String(d.getDate()).padStart(2, '0');
  const mm   = String(d.getMonth() + 1).padStart(2, '0');
  const yyyy = d.getFullYear();
  return `${dd}/${mm}/${yyyy}`;
}

async function getCurrentPendingMonth(enrolmentId) {
  const [rows] = await db.query(
    "SELECT * FROM gms_payments WHERE enrolment_id=? AND status='Pending' ORDER BY month_num ASC LIMIT 1",
    [enrolmentId]
  );
  return rows[0] || null;
}

module.exports = function(app, cache) {

  // ── GET /api/gms/pay-link/:token ─────────────────────
  app.get('/api/gms/pay-link/:token', async (req, res) => {
    try {
      const { token } = req.params;
     const [tokenRows] = await db.query(
  'SELECT * FROM gms_pay_tokens WHERE token=? AND expires_at > NOW()',
  [token]
);
if (!tokenRows.length) return res.status(404).json({ success: false, message: 'Payment link expired or invalid.' });
const { enrolment_id: enrolmentId, month_num: monthNum } = tokenRows[0];
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];
      const [payRows] = await db.query("SELECT * FROM gms_payments WHERE enrolment_id=? AND month_num=?", [enrolmentId, monthNum]);
      const pay = payRows[0];
      return res.json({ success: true, enrolmentId, monthNum, amount: enrol.instalment_amt, name: enrol.name, phone: enrol.phone, alreadyPaid: pay?.status === 'Paid', status: pay?.status || 'Pending' });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/create-pay-order ───────────────────
  app.post('/api/gms/create-pay-order', async (req, res) => {
    try {
      const { token } = req.body;
      if (!token) return res.status(400).json({ success: false, message: 'Token required.' });
      const [tokenRows] = await db.query(
  'SELECT * FROM gms_pay_tokens WHERE token=? AND expires_at > NOW()',
  [token]
);
if (!tokenRows.length) return res.status(404).json({ success: false, message: 'Payment link expired.' });
const { enrolment_id: enrolmentId, month_num: monthNum } = tokenRows[0];
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];
      const [payRows] = await db.query("SELECT * FROM gms_payments WHERE enrolment_id=? AND month_num=? AND status='Paid'", [enrolmentId, monthNum]);
      if (payRows.length) return res.status(400).json({ success: false, message: 'This month is already paid.' });
      const order = await rzp.orders.create({ amount: Math.round(parseFloat(enrol.instalment_amt) * 100), currency: 'INR', notes: { enrolmentId, monthNum: String(monthNum), type: 'gms_monthly' } });
      return res.json({ success: true, orderId: order.id, amountPaise: order.amount, enrolmentId, monthNum, name: enrol.name, phone: enrol.phone, email: enrol.email || '' });
    } catch(err) {
      console.error('[GMS] create-pay-order error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/verify-pay-order ───────────────────
  app.post('/api/gms/verify-pay-order', async (req, res) => {
    try {
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature, enrolmentId, monthNum } = req.body;
      const body     = razorpay_order_id + '|' + razorpay_payment_id;
      const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body).digest('hex');
      if (expected !== razorpay_signature) return res.status(400).json({ success: false, message: 'Payment verification failed.' });

      const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!enrolRows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = enrolRows[0];

      await db.query(
        `UPDATE gms_payments SET status='Paid', paid_at=NOW(), pay_method='UPI One-time', collected_branch=?, razorpay_payment_id=?, notes='Paid via SMS link' WHERE enrolment_id=? AND month_num=?`,
        [enrol.preferred_branch || 'Online', razorpay_payment_id, enrolmentId, monthNum]
      );

      // ── Mark as UPI Single Payment
      await db.query(
        "UPDATE gms_enrolments SET pay_method='UPI Single Payment' WHERE enrolment_id=? AND razorpay_sub_status != 'active'",
        [enrolmentId]
      );

      const [countRows] = await db.query("SELECT COUNT(*) as paid FROM gms_payments WHERE enrolment_id=? AND status='Paid'", [enrolmentId]);
      const made    = countRows[0].paid;
      const pending = enrol.pay_months - made;
      const allDone = pending <= 0;
      const status  = allDone ? 'Matured' : 'Active';

      await db.query('UPDATE gms_enrolments SET payments_made=?, payments_pending=?, status=? WHERE enrolment_id=?', [made, Math.max(0, pending), status, enrolmentId]);
      await db.query('INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)', [enrolmentId, `Month ${monthNum} Paid via SMS link`, 'Customer', enrol.preferred_branch || 'Online', `Payment ID: ${razorpay_payment_id}`]);

      const MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      function getMonthLabel(enrolDate, mn) {
        const start = new Date(enrolDate);
        const d = new Date(start.getFullYear(), start.getMonth() + (mn - 1), 1);
        return MONTH_NAMES[d.getMonth()] + ' ' + d.getFullYear();
      }

      if (allDone) {
        await sendSms(enrol.phone, SMS.matured(enrolmentId, Math.round(parseFloat(enrol.total_redeemable))), 'matured');
      } else {
        const ml = getMonthLabel(enrol.enrolment_date || enrol.created_at, monthNum);
        await sendSms(enrol.phone, SMS.autoDebitSuccess(Math.round(parseFloat(enrol.instalment_amt)), enrolmentId, ml, Math.max(0, pending)), 'autoDebitSuccess');
      }

      return res.json({ success: true, made, pending: Math.max(0, pending), allDone, message: 'Payment successful!' });
    } catch(err) {
      console.error('[GMS] verify-pay-order error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/setup-autopay-link ─────────────────
  app.post('/api/gms/setup-autopay-link', async (req, res) => {
    try {
      const { token } = req.body;
      if (!token) return res.status(400).json({ success: false, message: 'Token required.' });
     const [tokenRows] = await db.query(
  'SELECT * FROM gms_pay_tokens WHERE token=? AND expires_at > NOW()', [token]
);
if (!tokenRows.length) return res.status(404).json({ success: false, message: 'Payment link expired.' });
const enrolmentId = tokenRows[0].enrolment_id;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      if (enrol.pay_method === 'UPI Auto-debit' && enrol.razorpay_sub_status === 'active') return res.status(400).json({ success: false, message: 'Autopay is already active.' });
      if (enrol.razorpay_subscription_id && enrol.razorpay_sub_status !== 'active') {
        try { await rzp.subscriptions.cancel(enrol.razorpay_subscription_id, { cancel_at_cycle_end: false }); } catch(e) {}
      }

      const remainingMonths = parseInt(enrol.payments_pending) || 0;
      if (remainingMonths === 0) return res.status(400).json({ success: false, message: 'No remaining payments.' });

      const pendingPay = await getCurrentPendingMonth(enrolmentId);
      const chargeNow  = pendingPay !== null;
      const plan = await rzp.plans.create({ period: process.env.GMS_PLAN_PERIOD || 'monthly', interval: 1, item: { name: `WHP GMS ${enrolmentId}`, amount: Math.round(parseFloat(enrol.instalment_amt) * 100), currency: 'INR' } });
      const startAt = chargeNow ? Math.floor(Date.now() / 1000) + 60 : Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60);
      const subscription = await rzp.subscriptions.create({ plan_id: plan.id, total_count: remainingMonths, quantity: 1, start_at: startAt, customer_notify: 1, notes: { enrolmentId, type: 'gms_autopay_smslink' } });

      await db.query(`UPDATE gms_enrolments SET pay_method='UPI Auto-debit', razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created' WHERE enrolment_id=?`, [plan.id, subscription.id, enrolmentId]);
      await db.query('INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)', [enrolmentId, 'Autopay Setup via SMS Link', enrol.phone, enrol.preferred_branch || 'Online', `Sub: ${subscription.id}. ChargeNow: ${chargeNow}`]);
      await sendSms(enrol.phone, SMS.mandateLink(subscription.short_url), 'mandateLink');

      return res.json({ success: true, subscriptionId: subscription.id, chargeNow, message: 'Autopay setup initiated.' });
    } catch(err) {
      console.error('[GMS] setup-autopay-link error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/setup-autopay ──────────────────────
  app.post('/api/gms/setup-autopay', async (req, res) => {
    try {
      const userToken = req.headers['x-user-token'];
      if (!userToken) return res.status(401).json({ success: false, message: 'Not logged in.' });
      const { getUserFromToken } = require('../helpers/auth');
      const user = await getUserFromToken(userToken);
      if (!user) return res.status(401).json({ success: false, message: 'Not logged in.' });

      const { enrolmentId } = req.body;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      if (enrol.phone !== user.mobile && enrol.user_id !== user.user_id) return res.status(403).json({ success: false, message: 'Not your scheme.' });
      if (enrol.pay_method === 'UPI Auto-debit' && enrol.razorpay_sub_status === 'active') return res.status(400).json({ success: false, message: 'Autopay is already active for this scheme.' });

      const currentPending  = await getCurrentPendingMonth(enrolmentId);
      const chargeNow       = currentPending !== null;
      const remainingMonths = parseInt(enrol.payments_pending) || 0;
      if (remainingMonths === 0) return res.status(400).json({ success: false, message: 'No remaining payments — scheme is complete.' });

      if (enrol.razorpay_subscription_id && enrol.razorpay_sub_status !== 'active') {
        try { await rzp.subscriptions.cancel(enrol.razorpay_subscription_id, { cancel_at_cycle_end: false }); console.log(`[GMS] Cancelled old subscription ${enrol.razorpay_subscription_id}`); } catch(e) {}
      }

      const plan = await rzp.plans.create({ period: process.env.GMS_PLAN_PERIOD || 'monthly', interval: 1, item: { name: `WHP GMS ${enrolmentId}`, amount: Math.round(parseFloat(enrol.instalment_amt) * 100), currency: 'INR' } });
      const startAt = chargeNow ? Math.floor(Date.now() / 1000) + 60 : Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60);
      const subscription = await rzp.subscriptions.create({ plan_id: plan.id, total_count: remainingMonths, quantity: 1, start_at: startAt, customer_notify: 1, notes: { enrolmentId, type: 'gms_setup_autopay' } });

      await db.query(`UPDATE gms_enrolments SET pay_method='UPI Auto-debit', razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created' WHERE enrolment_id=?`, [plan.id, subscription.id, enrolmentId]);
      await db.query('INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)', [enrolmentId, 'Autopay Setup', user.mobile, enrol.preferred_branch || 'Online', `Subscription: ${subscription.id}. Charge now: ${chargeNow}`]);
      await sendSms(enrol.phone, SMS.mandateLink(subscription.short_url), 'mandateLink');

      return res.json({ success: true, subscriptionId: subscription.id, shortUrl: subscription.short_url, chargeNow, message: chargeNow ? 'Autopay setup initiated. Current month will be charged immediately.' : 'Autopay setup initiated. Will start from next month.' });
    } catch(err) {
      console.error('[GMS] setup-autopay error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/send-reminders (cron trigger) ──────
  app.post('/api/gms/send-reminders', async (req, res) => {
    const secret = req.headers['x-cron-secret'];
    if (secret !== process.env.GMS_CRON_SECRET) return res.status(403).json({ success: false, message: 'Unauthorized.' });

    try {
      const today    = new Date();
      const in5Days  = new Date(today); in5Days.setDate(today.getDate() + 5);
      const todayDay = today.getDate();
      const in5Day   = in5Days.getDate();

      // ── Include UPI Single Payment + Store + any UPI not active
      const [enrolments] = await db.query(
        `SELECT * FROM gms_enrolments 
         WHERE status='Active' AND payments_pending > 0
         AND (
           pay_method IN ('Pay at Store', 'UPI One-time', 'UPI Single Payment')
           OR (pay_method = 'UPI Auto-debit' AND razorpay_sub_status != 'active')
         )`
      );

      let sent5day = 0, sentToday = 0;

      for (const enrol of enrolments) {
        const enrollDate = new Date(enrol.enrolment_date || enrol.created_at);
        const dueDay     = enrollDate.getDate();
      // Due today OR overdue (due date already passed this month)
const isDueIn5   = dueDay === in5Day;
const isDueToday = dueDay === todayDay;
const isOverdue  = dueDay < todayDay; // due date already passed this month

if (!isDueIn5 && !isDueToday && !isOverdue) continue;

        const pendingPay = await getCurrentPendingMonth(enrol.enrolment_id);
        if (!pendingPay) continue;

       const token = generatePayToken(enrol.enrolment_id, pendingPay.month_num);
await db.query(
  `INSERT INTO gms_pay_tokens (token, enrolment_id, month_num, expires_at)
   VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 7 DAY))
   ON DUPLICATE KEY UPDATE expires_at=DATE_ADD(NOW(), INTERVAL 7 DAY)`,
  [token, enrol.enrolment_id, pendingPay.month_num]
);

        const BASE_URL = process.env.GMS_BASE_URL || 'https://gms.whpjewellers.com';
        const payUrl   = `${BASE_URL}/pay/${token}`;
        const dueStr   = isDueToday ? fmtDue(today) : fmtDue(in5Days);

        await sendSms(enrol.phone, SMS.reminder(Math.round(parseFloat(enrol.instalment_amt)), enrol.enrolment_id, dueStr, payUrl), 'reminder');

        if (isDueIn5)   sent5day++;
        if (isDueToday) sentToday++;

        console.log(`[GMS Reminder] Sent to ${enrol.phone} for ${enrol.enrolment_id} M${pendingPay.month_num}`);
        await db.query('INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)', [enrol.enrolment_id, 'Payment Reminder Sent', 'system', 'Auto', `Due on ${dueStr}. Month ${pendingPay.month_num}. SMS sent to ${enrol.phone}`]);
      }

      return res.json({ success: true, sent5day, sentToday, total: sent5day + sentToday, message: `Reminders sent: ${sent5day} (5-day), ${sentToday} (due today)` });
    } catch(err) {
      console.error('[GMS] send-reminders error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/switch-to-store ───────────────────
  app.post('/api/gms/switch-to-store', async (req, res) => {
    try {
      const userToken = req.headers['x-user-token'];
      if (!userToken) return res.status(401).json({ success: false, message: 'Not logged in.' });
      const { getUserFromToken } = require('../helpers/auth');
      const user = await getUserFromToken(userToken);
      if (!user) return res.status(401).json({ success: false, message: 'Not logged in.' });

      const { enrolmentId } = req.body;
      if (!enrolmentId) return res.status(400).json({ success: false, message: 'enrolmentId required.' });

      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      if (enrol.phone !== user.mobile && enrol.user_id !== user.user_id) return res.status(403).json({ success: false, message: 'Not your scheme.' });
      if (enrol.pay_method !== 'UPI Auto-debit') return res.status(400).json({ success: false, message: 'This scheme is not on UPI autopay.' });
      if (enrol.status !== 'Active') return res.status(400).json({ success: false, message: 'Can only switch active schemes.' });

      if (enrol.razorpay_subscription_id) {
        try { await rzp.subscriptions.cancel(enrol.razorpay_subscription_id, { cancel_at_cycle_end: false }); } catch(e) {}
      }

      await db.query(`UPDATE gms_enrolments SET pay_method='Pay at Store', razorpay_sub_status='cancelled' WHERE enrolment_id=?`, [enrolmentId]);
      await db.query('INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)', [enrolmentId, 'Switched to Store Payment', user.mobile, enrol.preferred_branch || 'Online', `UPI subscription ${enrol.razorpay_subscription_id || 'N/A'} cancelled by customer`]);

      return res.json({ success: true, message: 'Switched to store payment. Please visit your branch for future payments.' });
    } catch(err) {
      console.error('[GMS] switch-to-store error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/activate-scheme ───────────────────
  app.post('/api/gms/activate-scheme', async (req, res) => {
    try {
      const { subscriptionId, enrolmentId } = req.body;
      if (!enrolmentId && !subscriptionId) return res.status(400).json({ success: false });

      let query = 'SELECT * FROM gms_enrolments WHERE ';
      let param;
      if (enrolmentId) { query += 'enrolment_id=?'; param = enrolmentId; }
      else             { query += 'razorpay_subscription_id=?'; param = subscriptionId; }

      const [rows] = await db.query(query, [param]);
      if (!rows.length) return res.status(404).json({ success: false });
      const enrol = rows[0];

      if (enrol.status === 'Active') return res.json({ success: true, already: true, message: 'Already active.' });

      await db.query(`UPDATE gms_enrolments SET status='Active', razorpay_sub_status='active' WHERE enrolment_id=?`, [enrol.enrolment_id]);

      if (!enrol.user_id) {
        const [userRows] = await db.query('SELECT user_id FROM gms_users WHERE mobile=? LIMIT 1', [enrol.phone]);
        if (userRows.length) await db.query('UPDATE gms_enrolments SET user_id=? WHERE enrolment_id=?', [userRows[0].user_id, enrol.enrolment_id]);
      }

      await db.query('INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)', [enrol.enrolment_id, 'Scheme Activated', 'Customer', enrol.preferred_branch || 'Online', 'Activated after UPI mandate completion']);
      await sendSms(enrol.phone, SMS.schemeActive(enrol.enrolment_id, Math.round(parseFloat(enrol.instalment_amt))), 'schemeActive');

      console.log(`[GMS] Scheme activated: ${enrol.enrolment_id}`);
      return res.json({ success: true, message: 'Scheme activated!' });
    } catch(err) {
      console.error('[GMS] activate-scheme error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Payment reminder routes loaded');
};
