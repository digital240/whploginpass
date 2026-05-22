// routes/payments-reminder.js — Pay Now, Setup Autopay, SMS Reminders
const db       = require('../db');
const crypto   = require('crypto');
const Razorpay = require('razorpay');
const { sendSms } = require('../helpers/sms');

const rzp = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// Generate a secure pay token for SMS links (no login needed)
function generatePayToken(enrolmentId, monthNum) {
  const secret = process.env.WLP_TOKEN_SECRET || 'whpgms2026';
  return crypto.createHmac('sha256', secret)
    .update(`${enrolmentId}:${monthNum}:paylink`)
    .digest('hex')
    .slice(0, 32);
}

// Get current pending month for an enrolment
async function getCurrentPendingMonth(enrolmentId) {
  const [rows] = await db.query(
    "SELECT * FROM gms_payments WHERE enrolment_id=? AND status='Pending' ORDER BY month_num ASC LIMIT 1",
    [enrolmentId]
  );
  return rows[0] || null;
}

module.exports = function(app, cache) {

  // ── GET /api/gms/pay-link/:token ─────────────────────
  // Returns pay info for tokenized link (no login needed)
  app.get('/api/gms/pay-link/:token', async (req, res) => {
    try {
      const { token } = req.params;
      // Find enrolment by token stored in cache or DB
      const cached = cache.get(`paylink:${token}`);
      if (!cached) return res.status(404).json({ success: false, message: 'Payment link expired or invalid.' });

      const { enrolmentId, monthNum } = cached;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      // Check if this month is still pending
      const [payRows] = await db.query(
        "SELECT * FROM gms_payments WHERE enrolment_id=? AND month_num=?",
        [enrolmentId, monthNum]
      );
      const pay = payRows[0];

      return res.json({
        success: true,
        enrolmentId,
        monthNum,
        amount: enrol.instalment_amt,
        name: enrol.name,
        phone: enrol.phone,
        alreadyPaid: pay?.status === 'Paid',
        status: pay?.status || 'Pending'
      });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/create-pay-order ───────────────────
  // Creates Razorpay order for one-time payment (no login needed, uses token)
  app.post('/api/gms/create-pay-order', async (req, res) => {
    try {
      const { token } = req.body;
      if (!token) return res.status(400).json({ success: false, message: 'Token required.' });

      const cached = cache.get(`paylink:${token}`);
      if (!cached) return res.status(404).json({ success: false, message: 'Payment link expired.' });

      const { enrolmentId, monthNum } = cached;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      // Check not already paid
      const [payRows] = await db.query(
        "SELECT * FROM gms_payments WHERE enrolment_id=? AND month_num=? AND status='Paid'",
        [enrolmentId, monthNum]
      );
      if (payRows.length) return res.status(400).json({ success: false, message: 'This month is already paid.' });

      // Create Razorpay order
      const order = await rzp.orders.create({
        amount:   Math.round(parseFloat(enrol.instalment_amt) * 100),
        currency: 'INR',
        notes:    { enrolmentId, monthNum: String(monthNum), type: 'gms_monthly' }
      });

      return res.json({
        success: true,
        orderId:     order.id,
        amountPaise: order.amount,
        enrolmentId,
        monthNum,
        name:  enrol.name,
        phone: enrol.phone,
        email: enrol.email || ''
      });
    } catch(err) {
      console.error('[GMS] create-pay-order error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/verify-pay-order ───────────────────
  // Verifies payment and marks month paid (no login needed)
  app.post('/api/gms/verify-pay-order', async (req, res) => {
    try {
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature, enrolmentId, monthNum } = req.body;

      // Verify signature
      const body = razorpay_order_id + '|' + razorpay_payment_id;
      const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(body).digest('hex');
      if (expected !== razorpay_signature) {
        return res.status(400).json({ success: false, message: 'Payment verification failed.' });
      }

      const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!enrolRows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = enrolRows[0];

      // Mark month paid
      await db.query(
        `UPDATE gms_payments SET status='Paid', paid_at=NOW(),
         pay_method='UPI One-time', collected_branch=?, razorpay_payment_id=?, notes='Paid via SMS link'
         WHERE enrolment_id=? AND month_num=?`,
        [enrol.preferred_branch || 'Online', razorpay_payment_id, enrolmentId, monthNum]
      );

      // Update enrolment counts
      const [countRows] = await db.query(
        "SELECT COUNT(*) as paid FROM gms_payments WHERE enrolment_id=? AND status='Paid'",
        [enrolmentId]
      );
      const made    = countRows[0].paid;
      const pending = enrol.pay_months - made;
      const allDone = pending <= 0;
      const status  = allDone ? 'Matured' : 'Active';

      await db.query(
        'UPDATE gms_enrolments SET payments_made=?, payments_pending=?, status=? WHERE enrolment_id=?',
        [made, Math.max(0, pending), status, enrolmentId]
      );

      // Audit log
      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, `Month ${monthNum} Paid via SMS link`, 'Customer', enrol.preferred_branch || 'Online',
         `Payment ID: ${razorpay_payment_id}`]
      );

      // SMS confirmation
      const msg = allDone
        ? `Dear Customer, your WHP GMS scheme ${enrolmentId} is now MATURED! Our team will contact you shortly. - WHP Jewellers`
        : `Dear Customer, month ${monthNum} payment of Rs.${enrol.instalment_amt} received for WHP GMS scheme ${enrolmentId}. ${Math.max(0,pending)} payment(s) remaining. - WHP Jewellers`;
      await sendSms(enrol.phone, msg);

      return res.json({ success: true, made, pending: Math.max(0,pending), allDone, message: 'Payment successful!' });
    } catch(err) {
      console.error('[GMS] verify-pay-order error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/setup-autopay-link ───────────────────
  // Setup autopay from SMS pay link — no login needed, uses token
  app.post('/api/gms/setup-autopay-link', async (req, res) => {
    try {
      const { token } = req.body;
      if (!token) return res.status(400).json({ success: false, message: 'Token required.' });

      const cached = cache.get(`paylink:${token}`);
      if (!cached) return res.status(404).json({ success: false, message: 'Payment link expired.' });

      const { enrolmentId, monthNum } = cached;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      // Only block if already truly active
      if (enrol.pay_method === 'UPI Auto-debit' && enrol.razorpay_sub_status === 'active') {
        return res.status(400).json({ success: false, message: 'Autopay is already active.' });
      }

      // Cancel existing incomplete subscription if any
      if (enrol.razorpay_subscription_id && enrol.razorpay_sub_status !== 'active') {
        try {
          await rzp.subscriptions.cancel(enrol.razorpay_subscription_id, { cancel_at_cycle_end: false });
        } catch(e) { console.log('[GMS] Old sub cancel (ok):', e.message); }
      }

      const remainingMonths = parseInt(enrol.payments_pending) || 0;
      if (remainingMonths === 0) {
        return res.status(400).json({ success: false, message: 'No remaining payments.' });
      }

      // Check if current month pending — charge immediately
      const pendingPay = await getCurrentPendingMonth(enrolmentId);
      const chargeNow  = pendingPay !== null;

      // Create plan
      const plan = await rzp.plans.create({
        period: process.env.GMS_PLAN_PERIOD || 'monthly', interval: 1,
        item: {
          name:     `WHP GMS ${enrolmentId}`,
          amount:   Math.round(parseFloat(enrol.instalment_amt) * 100),
          currency: 'INR'
        }
      });

      const startAt = chargeNow
        ? Math.floor(Date.now() / 1000) + 60
        : Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60);

      const subscription = await rzp.subscriptions.create({
        plan_id: plan.id, total_count: remainingMonths, quantity: 1,
        start_at: startAt, customer_notify: 1,
        notes: { enrolmentId, type: 'gms_autopay_smslink' }
      });

      await db.query(
        `UPDATE gms_enrolments SET pay_method='UPI Auto-debit',
         razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created'
         WHERE enrolment_id=?`,
        [plan.id, subscription.id, enrolmentId]
      );

      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, 'Autopay Setup via SMS Link', enrol.phone, enrol.preferred_branch || 'Online',
         `Sub: ${subscription.id}. ChargeNow: ${chargeNow}`]
      );

      return res.json({
        success: true,
        subscriptionId: subscription.id,
        chargeNow,
        message: 'Autopay setup initiated.'
      });
    } catch(err) {
      console.error('[GMS] setup-autopay-link error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/setup-autopay ──────────────────────
  // Customer sets up UPI subscription for remaining months
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

      // Verify ownership
      if (enrol.phone !== user.mobile && enrol.user_id !== user.user_id) {
        return res.status(403).json({ success: false, message: 'Not your scheme.' });
      }

      // Only block if subscription is actually active
      if (enrol.pay_method === 'UPI Auto-debit' && enrol.razorpay_sub_status === 'active') {
        return res.status(400).json({ success: false, message: 'Autopay is already active for this scheme.' });
      }

      // Check current month status
      const currentPending = await getCurrentPendingMonth(enrolmentId);
      const chargeNow = currentPending !== null; // true = current month pending, charge immediately

      // Calculate remaining months
      const remainingMonths = parseInt(enrol.payments_pending) || 0;
      if (remainingMonths === 0) {
        return res.status(400).json({ success: false, message: 'No remaining payments — scheme is complete.' });
      }

      // Cancel existing incomplete subscription if any
      if (enrol.razorpay_subscription_id && enrol.razorpay_sub_status !== 'active') {
        try {
          await rzp.subscriptions.cancel(enrol.razorpay_subscription_id, { cancel_at_cycle_end: false });
          console.log(`[GMS] Cancelled old incomplete subscription ${enrol.razorpay_subscription_id}`);
        } catch(e) {
          console.log('[GMS] Old subscription cancel (ok):', e.message);
        }
      }

      // Create Razorpay plan
      const plan = await rzp.plans.create({
        period:   process.env.GMS_PLAN_PERIOD || 'monthly',
        interval: 1,
        item: {
          name:     `WHP GMS ${enrolmentId}`,
          amount:   Math.round(parseFloat(enrol.instalment_amt) * 100),
          currency: 'INR'
        }
      });

      // Create subscription for remaining months
      // If current month pending → total_count = remainingMonths (includes current)
      // If current month paid → total_count = remainingMonths (future only)
      const startAt = chargeNow
        ? Math.floor(Date.now() / 1000) + 60 // start in 1 min (immediate)
        : Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60); // start next month

      const subscription = await rzp.subscriptions.create({
        plan_id:     plan.id,
        total_count: remainingMonths,
        quantity:    1,
        start_at:    startAt,
        customer_notify: 1,
        notes: { enrolmentId, type: 'gms_setup_autopay' }
      });

      // Update enrolment
      await db.query(
        `UPDATE gms_enrolments SET pay_method='UPI Auto-debit',
         razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created'
         WHERE enrolment_id=?`,
        [plan.id, subscription.id, enrolmentId]
      );

      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, 'Autopay Setup', user.mobile, enrol.preferred_branch || 'Online',
         `Subscription: ${subscription.id}. Charge now: ${chargeNow}`]
      );

      return res.json({
        success: true,
        subscriptionId: subscription.id,
        shortUrl:       subscription.short_url,
        chargeNow,
        message: chargeNow
          ? 'Autopay setup initiated. Current month will be charged immediately.'
          : 'Autopay setup initiated. Will start from next month.'
      });
    } catch(err) {
      console.error('[GMS] setup-autopay error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/send-reminders (cron trigger) ──────
  // Called daily by cron — sends SMS for due in 5 days + due today
  app.post('/api/gms/send-reminders', async (req, res) => {
    // Simple secret check
    const secret = req.headers['x-cron-secret'];
    if (secret !== process.env.GMS_CRON_SECRET) {
      return res.status(403).json({ success: false, message: 'Unauthorized.' });
    }

    try {
      const today    = new Date();
      const in5Days  = new Date(today); in5Days.setDate(today.getDate() + 5);
      const todayDay = today.getDate();
      const in5Day   = in5Days.getDate();

      // Get all active non-UPI enrolments
      const [enrolments] = await db.query(
        `SELECT * FROM gms_enrolments 
         WHERE status='Active' AND pay_method != 'UPI Auto-debit'
         AND payments_pending > 0`
      );

      let sent5day = 0, sentToday = 0;

      for (const enrol of enrolments) {
        const enrollDate = new Date(enrol.enrolment_date || enrol.created_at);
        const dueDay     = enrollDate.getDate(); // same day each month

        const isDueIn5  = dueDay === in5Day;
        const isDueToday = dueDay === todayDay;

        if (!isDueIn5 && !isDueToday) continue;

        // Find current pending month
        const pendingPay = await getCurrentPendingMonth(enrol.enrolment_id);
        if (!pendingPay) continue;

        // Generate pay token (valid 7 days)
        const token = generatePayToken(enrol.enrolment_id, pendingPay.month_num);
        cache.set(`paylink:${token}`, {
          enrolmentId: enrol.enrolment_id,
          monthNum:    pendingPay.month_num
        }, 7 * 24 * 60 * 60); // 7 days

        const BASE_URL   = process.env.GMS_BASE_URL || 'https://gms.whpjewellers.com';
        const payUrl     = `${BASE_URL}/pay?t=${token}`;
        const profileUrl = `${BASE_URL}/my-profile`;
        const amt        = Number(enrol.instalment_amt).toLocaleString('en-IN');
        const dueStr     = isDueToday ? 'today' : 'in 5 days';

        const sms = isDueToday
          ? `Dear Customer, your WHP GMS payment of Rs.${amt} for scheme ${enrol.enrolment_id} is due today. Pay now: ${payUrl} or set up autopay: ${profileUrl} - WHP Jewellers`
          : `Dear Customer, your WHP GMS payment of Rs.${amt} for scheme ${enrol.enrolment_id} is due ${dueStr}. Pay now: ${payUrl} or set up autopay: ${profileUrl} - WHP Jewellers`;

        await sendSms(enrol.phone, sms);

        if (isDueIn5)   sent5day++;
        if (isDueToday) sentToday++;

        console.log(`[GMS Reminder] Sent to ${enrol.phone} for ${enrol.enrolment_id} M${pendingPay.month_num}`);
      }

      return res.json({
        success: true,
        sent5day,
        sentToday,
        total: sent5day + sentToday,
        message: `Reminders sent: ${sent5day} (5-day), ${sentToday} (due today)`
      });
    } catch(err) {
      console.error('[GMS] send-reminders error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/switch-to-store ───────────────────
  // Customer cancels UPI autopay and switches to store payment
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

      // Verify ownership
      if (enrol.phone !== user.mobile && enrol.user_id !== user.user_id) {
        return res.status(403).json({ success: false, message: 'Not your scheme.' });
      }

      if (enrol.pay_method !== 'UPI Auto-debit') {
        return res.status(400).json({ success: false, message: 'This scheme is not on UPI autopay.' });
      }

      if (enrol.status !== 'Active') {
        return res.status(400).json({ success: false, message: 'Can only switch active schemes.' });
      }

      // Cancel Razorpay subscription
      if (enrol.razorpay_subscription_id) {
        try {
          await rzp.subscriptions.cancel(enrol.razorpay_subscription_id, { cancel_at_cycle_end: false });
          console.log(`[GMS] Cancelled subscription ${enrol.razorpay_subscription_id}`);
        } catch(e) {
          console.log('[GMS] Razorpay cancel error (continuing):', e.message);
        }
      }

      // Update enrolment — switch to store payment
      await db.query(
        `UPDATE gms_enrolments SET 
         pay_method='Pay at Store',
         razorpay_sub_status='cancelled'
         WHERE enrolment_id=?`,
        [enrolmentId]
      );

      // Audit log
      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, 'Switched to Store Payment', user.mobile, enrol.preferred_branch || 'Online',
         `UPI subscription ${enrol.razorpay_subscription_id || 'N/A'} cancelled by customer`]
      );

      // SMS to customer
      await sendSms(enrol.phone,
        `Dear Customer, your WHP GMS scheme ${enrolmentId} has been switched to store payment. Please visit your nearest WHP branch to make monthly payments. - WHP Jewellers`
      );

      return res.json({
        success: true,
        message: 'Switched to store payment. Please visit your branch for future payments.'
      });
    } catch(err) {
      console.error('[GMS] switch-to-store error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/activate-scheme ───────────────────
  // Called after customer completes UPI mandate — activates scheme immediately
  app.post('/api/gms/activate-scheme', async (req, res) => {
    try {
      const { subscriptionId, enrolmentId } = req.body;
      if (!enrolmentId && !subscriptionId) return res.status(400).json({ success: false });

      // Find enrolment
      let query = 'SELECT * FROM gms_enrolments WHERE ';
      let param;
      if (enrolmentId) { query += 'enrolment_id=?'; param = enrolmentId; }
      else { query += 'razorpay_subscription_id=?'; param = subscriptionId; }

      const [rows] = await db.query(query, [param]);
      if (!rows.length) return res.status(404).json({ success: false });
      const enrol = rows[0];

      // Only activate if Draft or authenticated
      if (enrol.status === 'Active') return res.json({ success: true, already: true, message: 'Already active.' });

      await db.query(
        `UPDATE gms_enrolments SET status='Active', razorpay_sub_status='active'
         WHERE enrolment_id=?`,
        [enrol.enrolment_id]
      );

      // Link user account by phone if not linked
      if (!enrol.user_id) {
        const [userRows] = await db.query(
          'SELECT user_id FROM gms_users WHERE mobile=? LIMIT 1', [enrol.phone]
        );
        if (userRows.length) {
          await db.query('UPDATE gms_enrolments SET user_id=? WHERE enrolment_id=?',
            [userRows[0].user_id, enrol.enrolment_id]);
        }
      }

      // Audit
      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrol.enrolment_id, 'Scheme Activated', 'Customer', enrol.preferred_branch || 'Online',
         'Activated after UPI mandate completion']
      );

      console.log(`[GMS] Scheme activated: ${enrol.enrolment_id}`);
      return res.json({ success: true, message: 'Scheme activated!' });
    } catch(err) {
      console.error('[GMS] activate-scheme error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Payment reminder routes loaded');
};
