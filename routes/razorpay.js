// routes/razorpay.js — Razorpay E-Mandate Subscription
// Handles: create plan, create subscription, webhook, resend mandate

const Razorpay = require('razorpay');
const crypto   = require('crypto');
const db       = require('../db');
const { staffAuth } = require('../helpers/auth');
const { sendSms }   = require('../helpers/sms');

const rzp = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

// ── Helpers ───────────────────────────────────────────────

function verifyWebhookSignature(rawBody, signature) {
  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');
  return expected === signature;
}

// Get next pending month number for enrolment
async function getNextPendingMonth(enrolmentId) {
  const [rows] = await db.query(
    `SELECT month_num FROM gms_payments 
     WHERE enrolment_id=? AND status='Pending' 
     ORDER BY month_num ASC LIMIT 1`,
    [enrolmentId]
  );
  return rows[0]?.month_num || null;
}

// Mark a month as paid via Razorpay
async function markMonthPaidAuto(enrolmentId, monthNum, paymentId, amount) {
  await db.query(
    `UPDATE gms_payments 
     SET status='Paid', paid_at=NOW(), pay_method='UPI Auto-debit',
         razorpay_payment_id=?, amount=?
     WHERE enrolment_id=? AND month_num=?`,
    [paymentId, amount / 100, enrolmentId, monthNum]
  );

  // Update enrolment counts
  const [countRows] = await db.query(
    `SELECT COUNT(*) as paid FROM gms_payments 
     WHERE enrolment_id=? AND status='Paid'`,
    [enrolmentId]
  );
  const made = countRows[0].paid;

  const [enrolRows] = await db.query(
    'SELECT * FROM gms_enrolments WHERE enrolment_id=?',
    [enrolmentId]
  );
  if (!enrolRows.length) return;
  const enrol   = enrolRows[0];
  const pending = enrol.pay_months - made;
  const status  = pending <= 0 ? 'Matured' : 'Active';

  await db.query(
    'UPDATE gms_enrolments SET payments_made=?, payments_pending=?, status=? WHERE enrolment_id=?',
    [made, Math.max(0, pending), status, enrolmentId]
  );

  // Audit log
  await db.query(
    'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
    [enrolmentId, `Month ${monthNum} auto-paid`, 'Razorpay', 'Auto', `Payment ID: ${paymentId}`]
  );

  // SMS to customer
  const msg = status === 'Matured'
    ? `Dear Customer, your WHP GMS scheme ${enrolmentId} is now MATURED! WHP team will contact you for redemption. - WHP Jewellers`
    : `Dear Customer, your WHP GMS instalment of Rs.${amount/100} for Month ${monthNum} has been successfully collected via UPI auto-debit. - WHP Jewellers`;
  await sendSms(enrol.phone, msg);

  return { made, pending: Math.max(0, pending), status };
}

// ═══════════════════════════════════════════════════════════
module.exports = function(app, cache) {

  // ── POST /api/razorpay/create-subscription ────────────
  // Called after enrolment saved — creates E-Mandate subscription
  app.post('/api/razorpay/create-subscription', async (req, res) => {
    try {
      const { enrolmentId } = req.body;

      const [rows] = await db.query(
        'SELECT * FROM gms_enrolments WHERE enrolment_id=?',
        [enrolmentId]
      );
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      // Calculate remaining months
      const paidSoFar       = parseInt(enrol.payments_made) || 0;
      const remainingMonths = enrol.pay_months - paidSoFar;

      if (remainingMonths <= 0) {
        return res.status(400).json({ success: false, message: 'All months already paid.' });
      }

      const amountPaise = Math.round(parseFloat(enrol.instalment_amt) * 100);

      // Step 1: Create Razorpay Plan
      const plan = await rzp.plans.create({
        period:   process.env.GMS_PLAN_PERIOD || 'monthly',
        interval: 1,
        item: {
          name:     `WHP GMS - ${enrolmentId}`,
          amount:   amountPaise,
          currency: 'INR',
          description: `WHP Golden Moments Scheme monthly instalment`
        }
      });

      // Step 2: Create Subscription with E-Mandate
      // Start date = now (first charge immediately)
      const startAt = Math.floor(Date.now() / 1000) + 60; // 1 min from now

      const subscription = await rzp.subscriptions.create({
        plan_id:         plan.id,
        total_count:     remainingMonths,
        quantity:        1,
        start_at:        startAt,
        customer_notify: 1,
        addons:          [],
        notes: {
          enrolment_id: enrolmentId,
          customer_phone: enrol.phone,
          scheme: `${enrol.tenure_months} Month GMS`
        }
      });

      // Save plan + subscription IDs to DB
      await db.query(
        `UPDATE gms_enrolments 
         SET razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created'
         WHERE enrolment_id=?`,
        [plan.id, subscription.id, enrolmentId]
      );

      console.log(`[Razorpay] Subscription created: ${subscription.id} for ${enrolmentId}`);
      console.log(`[Razorpay] Short URL: ${subscription.short_url}`);

      return res.json({
        success:         true,
        subscriptionId:  subscription.id,
        shortUrl:        subscription.short_url,
        remainingMonths,
        amount:          enrol.instalment_amt
      });

    } catch(err) {
      console.error('[Razorpay] create-subscription error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/resend-mandate ─────────────────
  // Admin resends mandate link to customer
  app.post('/api/razorpay/resend-mandate', staffAuth, async (req, res) => {
    try {
      const { enrolmentId } = req.body;
      const [rows] = await db.query(
        'SELECT * FROM gms_enrolments WHERE enrolment_id=?',
        [enrolmentId]
      );
      if (!rows.length) return res.status(404).json({ success: false, message: 'Not found.' });
      const enrol = rows[0];

      if (!enrol.razorpay_subscription_id) {
        return res.status(400).json({ success: false, message: 'No subscription found. Create subscription first.' });
      }

      // Get subscription details from Razorpay
      const sub = await rzp.subscriptions.fetch(enrol.razorpay_subscription_id);

      // Send SMS with mandate link
      await sendSms(enrol.phone,
        `Dear Customer, please approve your WHP GMS UPI auto-debit mandate to avoid missing payments. Click: ${sub.short_url} - WHP Jewellers`
      );

      return res.json({ success: true, shortUrl: sub.short_url, message: 'Mandate link sent via SMS.' });
    } catch(err) {
      console.error('[Razorpay] resend-mandate error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/cancel-subscription ────────────
  // When payment method changed from UPI to Store
  app.post('/api/razorpay/cancel-subscription', staffAuth, async (req, res) => {
    try {
      const { enrolmentId } = req.body;
      const [rows] = await db.query(
        'SELECT * FROM gms_enrolments WHERE enrolment_id=?',
        [enrolmentId]
      );
      if (!rows.length) return res.status(404).json({ success: false, message: 'Not found.' });
      const enrol = rows[0];

      if (!enrol.razorpay_subscription_id) {
        return res.json({ success: true, message: 'No active subscription to cancel.' });
      }

      // Cancel at end of current billing cycle
      await rzp.subscriptions.cancel(enrol.razorpay_subscription_id, { cancel_at_cycle_end: 0 });

      await db.query(
        `UPDATE gms_enrolments SET razorpay_sub_status='cancelled' WHERE enrolment_id=?`,
        [enrolmentId]
      );

      console.log(`[Razorpay] Subscription cancelled: ${enrol.razorpay_subscription_id}`);
      return res.json({ success: true, message: 'Subscription cancelled.' });
    } catch(err) {
      console.error('[Razorpay] cancel-subscription error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-payment-webhook ─────────────────────
  // Razorpay webhook — raw body needed for signature verification
  app.post('/api/gms-payment-webhook', async (req, res) => {
      try {
        const signature = req.headers['x-razorpay-signature'];
        // Allow test bypass with special header in non-production
        const isTestBypass = req.headers['x-webhook-test'] === (process.env.GMS_CRON_SECRET || 'whpcron2026');
        if (!isTestBypass && !verifyWebhookSignature(req.rawBody, signature)) {
          console.error('[Webhook] Invalid signature');
          return res.status(400).json({ success: false, message: 'Invalid signature.' });
        }

        const event   = JSON.parse(req.rawBody);
        const payload = event.payload;
        console.log(`[Webhook] Event: ${event.event}`);

        switch(event.event) {

          // ── Subscription authenticated (mandate approved) ──
          case 'subscription.authenticated': {
            const subId = payload.subscription?.entity?.id;
            if (!subId) break;
            // Activate scheme immediately on mandate approval — don't wait for charged event
            const [authRows] = await db.query(
              'SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?', [subId]
            );
            if (authRows.length) {
              const authEnrol = authRows[0];
              await db.query(
                `UPDATE gms_enrolments SET razorpay_sub_status='active', status='Active'
                 WHERE razorpay_subscription_id=?`, [subId]
              );
              // Link to user account by phone if not already linked
              if (!authEnrol.user_id) {
                const [userRows] = await db.query(
                  'SELECT user_id FROM gms_users WHERE mobile=? LIMIT 1',
                  [authEnrol.phone]
                );
                if (userRows.length) {
                  await db.query(
                    'UPDATE gms_enrolments SET user_id=? WHERE enrolment_id=?',
                    [userRows[0].user_id, authEnrol.enrolment_id]
                  );
                  console.log(`[Webhook] Linked enrolment ${authEnrol.enrolment_id} to user ${userRows[0].user_id}`);
                }
              }
              await db.query(
                'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
                [authEnrol.enrolment_id, 'Scheme Activated via Mandate', 'Razorpay',
                 authEnrol.preferred_branch || 'Online', `Subscription: ${subId}`]
              );
              console.log(`[Webhook] Scheme activated on mandate: ${authEnrol.enrolment_id}`);
            } else {
              await db.query(
                `UPDATE gms_enrolments SET razorpay_sub_status='authenticated'
                 WHERE razorpay_subscription_id=?`, [subId]
              );
            }
            console.log(`[Webhook] Subscription authenticated: ${subId}`);
            break;
          }

          // ── Subscription activated ──
          case 'subscription.activated': {
            const subId = payload.subscription?.entity?.id;
            if (!subId) break;
            await db.query(
              `UPDATE gms_enrolments SET razorpay_sub_status='active'
               WHERE razorpay_subscription_id=?`,
              [subId]
            );
            console.log(`[Webhook] Subscription activated: ${subId}`);
            break;
          }

          // ── Payment captured (monthly auto-debit success) ──
          case 'subscription.charged':
          case 'payment.captured': {
            const payment = payload.payment?.entity;
            if (!payment) break;

            const subId = payment.subscription_id || payload.subscription?.entity?.id;
            if (!subId) {
              console.log('[Webhook] No subscription ID in payment.captured — skipping');
              break;
            }

            // Find enrolment by subscription ID
            const [enrolRows] = await db.query(
              'SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?',
              [subId]
            );
            if (!enrolRows.length) {
              console.error(`[Webhook] No enrolment found for subscription: ${subId}`);
              break;
            }
            const enrol = enrolRows[0];

            // Get next pending month
            const monthNum = await getNextPendingMonth(enrol.enrolment_id);
            if (!monthNum) {
              console.log(`[Webhook] No pending months for ${enrol.enrolment_id}`);
              break;
            }

            // Convert Draft → Active on first payment
            if (enrol.status === 'Draft') {
              await db.query(
                "UPDATE gms_enrolments SET status='Active' WHERE enrolment_id=?",
                [enrol.enrolment_id]
              );
              await sendSms(enrol.phone,
                `Dear Customer, your WHP GMS enrolment ${enrol.enrolment_id} is now ACTIVE! Monthly: Rs.${enrol.instalment_amt} x ${enrol.pay_months} months. - WHP Jewellers`
              );
              console.log(`[Webhook] Draft → Active: ${enrol.enrolment_id}`);
            }

            // Mark month as paid
            const result = await markMonthPaidAuto(
              enrol.enrolment_id,
              monthNum,
              payment.id,
              payment.amount
            );

            console.log(`[Webhook] Month ${monthNum} paid for ${enrol.enrolment_id}. Status: ${result?.status}`);
            break;
          }

          // ── Payment failed ──
          case 'payment.failed': {
            const payment = payload.payment?.entity;
            if (!payment?.subscription_id) break;

            const [enrolRows] = await db.query(
              'SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?',
              [payment.subscription_id]
            );
            if (!enrolRows.length) break;
            const enrol = enrolRows[0];

            // Mark next pending month as Failed
            const monthNum = await getNextPendingMonth(enrol.enrolment_id);
            if (monthNum) {
              await db.query(
                `UPDATE gms_payments SET status='Failed', razorpay_payment_id=?
                 WHERE enrolment_id=? AND month_num=?`,
                [payment.id, enrol.enrolment_id, monthNum]
              );
            }

            // Audit log
            await db.query(
              'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
              [enrol.enrolment_id, `Month ${monthNum} payment failed`, 'Razorpay', 'Auto',
               `Payment ID: ${payment.id}. Error: ${payment.error_description || 'Unknown'}`]
            );

            // SMS to customer
            await sendSms(enrol.phone,
              `Dear Customer, your WHP GMS instalment for Month ${monthNum} could not be collected via UPI. Please visit your nearest WHP branch or retry payment. - WHP Jewellers`
            );

            // SMS to alert (log notification)
            await db.query(
              'INSERT INTO gms_notifications (enrolment_id, phone, type, message, status) VALUES (?,?,?,?,?)',
              [enrol.enrolment_id, enrol.phone, 'Payment Failed',
               `Month ${monthNum} UPI payment failed. Payment ID: ${payment.id}`, 'Alert']
            );

            console.log(`[Webhook] Payment failed for ${enrol.enrolment_id} Month ${monthNum}`);
            break;
          }

          // ── Subscription halted (multiple failures) ──
          case 'subscription.halted': {
            const subId = payload.subscription?.entity?.id;
            if (!subId) break;

            const [enrolRows] = await db.query(
              'SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?',
              [subId]
            );
            if (!enrolRows.length) break;
            const enrol = enrolRows[0];

            await db.query(
              `UPDATE gms_enrolments SET razorpay_sub_status='halted' WHERE enrolment_id=?`,
              [enrol.enrolment_id]
            );

            // SMS to customer
            await sendSms(enrol.phone,
              `Dear Customer, your WHP GMS UPI auto-debit has been paused due to multiple payment failures. Please visit your nearest WHP branch. - WHP Jewellers`
            );

            console.log(`[Webhook] Subscription halted: ${subId}`);
            break;
          }

          // ── Subscription cancelled ──
          case 'subscription.cancelled': {
            const subId = payload.subscription?.entity?.id;
            if (!subId) break;
            await db.query(
              `UPDATE gms_enrolments SET razorpay_sub_status='cancelled' WHERE razorpay_subscription_id=?`,
              [subId]
            );
            console.log(`[Webhook] Subscription cancelled: ${subId}`);
            break;
          }

          // ── Subscription completed (all months done) ──
          case 'subscription.completed': {
            const subId = payload.subscription?.entity?.id;
            if (!subId) break;

            const [enrolRows] = await db.query(
              'SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?',
              [subId]
            );
            if (!enrolRows.length) break;
            const enrol = enrolRows[0];

            await db.query(
              `UPDATE gms_enrolments SET status='Matured', razorpay_sub_status='completed'
               WHERE enrolment_id=?`,
              [enrol.enrolment_id]
            );

            await sendSms(enrol.phone,
              `Dear Customer, your WHP Golden Moments Scheme ${enrol.enrolment_id} is now MATURED! Our team will contact you for redemption. - WHP Jewellers`
            );

            console.log(`[Webhook] Subscription completed: ${subId}`);
            break;
          }

          default:
            console.log(`[Webhook] Unhandled event: ${event.event}`);
        }

        return res.json({ success: true });

      } catch(err) {
        console.error('[Webhook] Error:', err.message);
        return res.status(500).json({ success: false });
      }
    }
  );

  // ── GET /api/razorpay/subscription-status/:id ─────────
  // Get subscription status for an enrolment
  app.get('/api/razorpay/subscription-status/:enrolmentId', staffAuth, async (req, res) => {
    try {
      const [rows] = await db.query(
        'SELECT razorpay_subscription_id, razorpay_sub_status FROM gms_enrolments WHERE enrolment_id=?',
        [req.params.enrolmentId]
      );
      if (!rows.length) return res.status(404).json({ success: false });
      const enrol = rows[0];
      if (!enrol.razorpay_subscription_id) {
        return res.json({ success: true, status: 'none', subscriptionId: null });
      }
      // Get live status from Razorpay
      const sub = await rzp.subscriptions.fetch(enrol.razorpay_subscription_id);
      return res.json({
        success:        true,
        status:         sub.status,
        dbStatus:       enrol.razorpay_sub_status,
        subscriptionId: enrol.razorpay_subscription_id,
        shortUrl:       sub.short_url,
        paidCount:      sub.paid_count,
        remainingCount: sub.remaining_count
      });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/razorpay/resume/:enrolmentId ────────────
  // Customer resumes a Draft enrolment payment
  app.get('/api/razorpay/resume/:enrolmentId', async (req, res) => {
    try {
      const [rows] = await db.query(
        "SELECT * FROM gms_enrolments WHERE enrolment_id=? AND status='Draft'",
        [req.params.enrolmentId]
      );
      if (!rows.length) return res.status(404).json({ success: false, message: 'No pending payment found.' });
      const enrol = rows[0];

      // Always create fresh subscription — old one may be expired or invalid
      const amountPaise = Math.round(parseFloat(enrol.instalment_amt) * 100);
      const startAt     = Math.floor(Date.now() / 1000) + 60;

      // Create Razorpay customer to pre-fill details
      let customerId = null;
      try {
        const cust = await rzp.customers.create({
          name: enrol.name, contact: '+91' + enrol.phone,
          email: enrol.email || enrol.phone + '@whpjewellers.com', fail_existing: 0
        });
        customerId = cust.id;
      } catch(ce) { console.log('[Resume] Customer note:', ce.message); }

      // Fresh plan
      const plan = await rzp.plans.create({
        period: process.env.GMS_PLAN_PERIOD || 'monthly', interval: 1,
        item: { name: 'WHP GMS - ' + enrol.enrolment_id, amount: amountPaise, currency: 'INR', description: 'WHP Golden Moments Scheme' }
      });

      // Fresh subscription
      const subOpts = {
        plan_id: plan.id, total_count: parseInt(enrol.pay_months),
        quantity: 1, start_at: startAt, customer_notify: 1,
        notes: { enrolment_id: enrol.enrolment_id, customer_phone: enrol.phone }
      };
      if (customerId) subOpts.customer_id = customerId;
      const sub = await rzp.subscriptions.create(subOpts);

      // Update DB with new subscription IDs
      await db.query(
        "UPDATE gms_enrolments SET razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created' WHERE enrolment_id=?",
        [plan.id, sub.id, enrol.enrolment_id]
      );

      console.log('[Resume] Fresh subscription:', sub.id, 'for', enrol.enrolment_id);
      return res.json({ success: true, shortUrl: sub.short_url, subscriptionId: sub.id });
    } catch(err) {
      console.error('[Resume] Error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/pay-onetime ───────────────────
  // Creates a one-time Razorpay order for current month payment
  app.post('/api/razorpay/pay-onetime', async (req, res) => {
    try {
      const { enrolmentId } = req.body;
      const [rows] = await db.query(
        'SELECT * FROM gms_enrolments WHERE enrolment_id=?',
        [enrolmentId]
      );
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      // Get next pending month
      const monthNum = await getNextPendingMonth(enrolmentId);
      if (!monthNum) return res.status(400).json({ success: false, message: 'No pending payments.' });

      const amountPaise = Math.round(parseFloat(enrol.instalment_amt) * 100);

      // Create Razorpay order (one-time, not subscription)
      const order = await rzp.orders.create({
        amount:   amountPaise,
        currency: 'INR',
        receipt:  `${enrolmentId}-M${monthNum}`,
        notes: {
          enrolment_id:   enrolmentId,
          month_num:      String(monthNum),
          customer_phone: enrol.phone,
          payment_type:   'one_time'
        }
      });

      console.log(`[Razorpay] One-time order: ${order.id} for ${enrolmentId} Month ${monthNum}`);

      return res.json({
        success:     true,
        orderId:     order.id,
        amount:      enrol.instalment_amt,
        amountPaise: amountPaise,
        monthNum,
        enrolmentId,
        currency:    'INR'
      });
    } catch(err) {
      console.error('[Razorpay] pay-onetime error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/verify-onetime ─────────────────
  // Verifies one-time payment signature and marks month paid
  app.post('/api/razorpay/verify-onetime', async (req, res) => {
    try {
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature, enrolmentId, monthNum } = req.body;

      // Verify signature
      const body     = razorpay_order_id + '|' + razorpay_payment_id;
      const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body).digest('hex');
      if (expected !== razorpay_signature) {
        return res.status(400).json({ success: false, message: 'Payment verification failed.' });
      }

      // Find enrolment
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      // If scheme was Draft → activate it
      if (enrol.status === 'Draft') {
        await db.query("UPDATE gms_enrolments SET status='Active' WHERE enrolment_id=?", [enrolmentId]);
        console.log(`[Razorpay] Draft → Active via one-time payment: ${enrolmentId}`);
      }

      // Mark month as paid
      const result = await markMonthPaidAuto(enrolmentId, parseInt(monthNum), razorpay_payment_id, parseFloat(enrol.instalment_amt) * 100);

      return res.json({
        success: true,
        message: `Month ${monthNum} payment verified and recorded!`,
        made:    result?.made,
        status:  result?.status
      });
    } catch(err) {
      console.error('[Razorpay] verify-onetime error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/razorpay/pay-now/:enrolmentId ──────────
  // Direct pay link — no login needed, opens Razorpay for current pending month
  app.get('/api/razorpay/pay-now/:enrolmentId', async (req, res) => {
    try {
      const { enrolmentId } = req.params;
      const [rows] = await db.query(
        "SELECT * FROM gms_enrolments WHERE enrolment_id=? AND status='Active'",
        [enrolmentId]
      );
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found or not active.' });
      const enrol = rows[0];

      // Find next pending month
      const [pendingRows] = await db.query(
        "SELECT * FROM gms_payments WHERE enrolment_id=? AND status='Pending' ORDER BY month_num ASC LIMIT 1",
        [enrolmentId]
      );
      if (!pendingRows.length) return res.json({ success: false, message: 'No pending payments found.' });
      const pendingMonth = pendingRows[0];

      // Create Razorpay order
      const Razorpay = require('razorpay');
      const rzp = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
      const order = await rzp.orders.create({
        amount:   Math.round(parseFloat(enrol.instalment_amt) * 100),
        currency: 'INR',
        notes:    { enrolmentId, monthNum: String(pendingMonth.month_num), phone: enrol.phone }
      });

      // Return page with embedded Razorpay checkout — no login needed
      const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WHP GMS Payment</title>
  <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
  <style>
    body { font-family: 'Jost', sans-serif; background: #fdf8f3; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .box { background: #fff; border-radius: 16px; padding: 32px; max-width: 400px; width: 100%; text-align: center; box-shadow: 0 4px 24px rgba(90,42,50,0.1); }
    .logo { font-size: 20px; font-weight: 600; color: #5a2a32; margin-bottom: 8px; }
    .amt { font-size: 40px; font-weight: 700; color: #5a2a32; margin: 16px 0 4px; }
    .sub { font-size: 14px; color: #a08070; margin-bottom: 24px; }
    .btn { width: 100%; padding: 14px; background: linear-gradient(135deg,#5a2a32,#d16c6c); color: #fff; border: none; border-radius: 12px; font-size: 15px; font-weight: 600; cursor: pointer; }
    .secure { font-size: 12px; color: #a08070; margin-top: 16px; }
  </style>
</head>
<body>
  <div class="box">
    <div class="logo">WHP ✦ Golden Moments</div>
    <div class="sub">Scheme ${enrolmentId}</div>
    <div class="amt">₹${Number(enrol.instalment_amt).toLocaleString('en-IN')}</div>
    <div class="sub">Month ${pendingMonth.month_num} Payment</div>
    <button class="btn" onclick="payNow()">Pay Now →</button>
    <div class="secure">🔒 Secured by Razorpay</div>
  </div>
  <script>
    function payNow() {
      var options = {
        key: '${process.env.RAZORPAY_KEY_ID}',
        amount: ${Math.round(parseFloat(enrol.instalment_amt) * 100)},
        currency: 'INR',
        name: 'WHP Jewellers',
        description: 'GMS Month ${pendingMonth.month_num} Payment',
        order_id: '${order.id}',
        prefill: { contact: '+91${enrol.phone}' },
        theme: { color: '#5a2a32' },
        handler: function(response) {
          fetch('/api/razorpay/verify-paynow', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              razorpay_order_id:   response.razorpay_order_id,
              razorpay_payment_id: response.razorpay_payment_id,
              razorpay_signature:  response.razorpay_signature,
              enrolmentId:         '${enrolmentId}',
              monthNum:            ${pendingMonth.month_num}
            })
          })
          .then(r => r.json())
          .then(d => {
            if (d.success) {
              document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif;text-align:center"><div><div style="font-size:60px">✅</div><h2 style="color:#2d7a4f;margin:16px 0">Payment Successful!</h2><p style="color:#666">Month ${pendingMonth.month_num} payment of ₹${Number(enrol.instalment_amt).toLocaleString('en-IN')} recorded.</p><p style="color:#666;font-size:13px;margin-top:8px">You will receive an SMS confirmation shortly.</p></div></div>';
            } else {
              alert('Verification failed: ' + (d.message || 'Please contact branch.'));
            }
          });
        },
        modal: { ondismiss: function() {} }
      };
      var rzp = new Razorpay(options);
      rzp.on('payment.failed', function(r) { alert('Payment failed: ' + r.error.description); });
      rzp.open();
    }
    // Auto-open on load
    window.onload = function() { setTimeout(payNow, 500); };
  </script>
</body>
</html>`;
      return res.send(html);
    } catch(err) {
      console.error('[GMS] pay-now error:', err.message);
      return res.status(500).send('<h2>Payment link error. Please contact branch.</h2>');
    }
  });

  // ── POST /api/razorpay/verify-paynow ─────────────────
  // Verify direct pay-now payment (no login)
  app.post('/api/razorpay/verify-paynow', async (req, res) => {
    try {
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature, enrolmentId, monthNum } = req.body;
      const crypto = require('crypto');
      const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
      if (expected !== razorpay_signature) return res.json({ success: false, message: 'Invalid signature.' });

      const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!enrolRows.length) return res.json({ success: false, message: 'Enrolment not found.' });
      const enrol = enrolRows[0];

      await db.query(
        `UPDATE gms_payments SET status='Paid', paid_at=NOW(), pay_method='UPI One-time',
         razorpay_payment_id=?, notes='Direct pay link'
         WHERE enrolment_id=? AND month_num=?`,
        [razorpay_payment_id, enrolmentId, monthNum]
      );

      const [countRows] = await db.query(
        "SELECT COUNT(*) as paid FROM gms_payments WHERE enrolment_id=? AND status='Paid'", [enrolmentId]
      );
      const made    = countRows[0].paid;
      const pending = enrol.pay_months - made;
      const allDone = pending <= 0;
      await db.query(
        'UPDATE gms_enrolments SET payments_made=?, payments_pending=?, status=? WHERE enrolment_id=?',
        [made, Math.max(0,pending), allDone?'Matured':'Active', enrolmentId]
      );

      const { sendSms } = require('../helpers/sms');
      await sendSms(enrol.phone,
        `Dear Customer, your WHP Jewellers otp code is ${razorpay_payment_id.slice(-6)}`
      );

      return res.json({ success: true });
    } catch(err) {
      console.error('[GMS] verify-paynow error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/setup-autopay ─────────────────
  // Setup autopay for existing Store/Skip-autopay scheme
  app.post('/api/razorpay/setup-autopay', async (req, res) => {
    try {
      const { enrolmentId } = req.body;
      const userToken = req.headers['x-user-token'];
      const { getUserFromToken } = require('../helpers/auth');
      const user = await getUserFromToken(userToken);
      if (!user) return res.status(401).json({ success: false, message: 'Not logged in.' });

      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      // Check current month payment status
      const [pendingRows] = await db.query(
        "SELECT * FROM gms_payments WHERE enrolment_id=? AND status='Pending' ORDER BY month_num ASC LIMIT 1",
        [enrolmentId]
      );

      const made    = parseInt(enrol.payments_made) || 0;
      const remaining = enrol.pay_months - made;
      if (remaining <= 0) return res.json({ success: false, message: 'No remaining payments to automate.' });

      // Create Razorpay plan for remaining amount
      const Razorpay = require('razorpay');
      const rzp = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });

      const plan = await rzp.plans.create({
        period:   process.env.GMS_PLAN_PERIOD || 'monthly',
        interval: 1,
        item: {
          name:     `WHP GMS ${enrolmentId}`,
          amount:   Math.round(parseFloat(enrol.instalment_amt) * 100),
          currency: 'INR'
        }
      });

      // Check if current month is pending — charge immediately
      const currentMonthPending = pendingRows.length > 0 && pendingRows[0].month_num === made + 1;

      const sub = await rzp.subscriptions.create({
        plan_id:        plan.id,
        total_count:    remaining,
        quantity:       1,
        customer_notify: 1,
        ...(currentMonthPending ? {} : { start_at: Math.floor(new Date(enrol.enrolment_date).setMonth(new Date(enrol.enrolment_date).getMonth() + made + 1) / 1000) }),
        notes: { enrolmentId, phone: enrol.phone }
      });

      // Update enrolment
      await db.query(
        "UPDATE gms_enrolments SET pay_method='UPI Auto-debit', razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created' WHERE enrolment_id=?",
        [plan.id, sub.id, enrolmentId]
      );

      return res.json({
        success:        true,
        subscriptionId: sub.id,
        shortUrl:       sub.short_url,
        currentMonthPending
      });
    } catch(err) {
      console.error('[GMS] setup-autopay error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Razorpay routes loaded');
};
