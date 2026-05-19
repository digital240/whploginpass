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
        period:   'monthly',
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
  app.post('/api/gms-payment-webhook',
    (req, res, next) => {
      // Collect raw body for signature verification
      let rawBody = '';
      req.on('data', chunk => { rawBody += chunk; });
      req.on('end', () => { req.rawBody = rawBody; next(); });
    },
    async (req, res) => {
      try {
        const signature = req.headers['x-razorpay-signature'];
        if (!verifyWebhookSignature(req.rawBody, signature)) {
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
            await db.query(
              `UPDATE gms_enrolments SET razorpay_sub_status='authenticated' 
               WHERE razorpay_subscription_id=?`,
              [subId]
            );
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
      if (!enrol.razorpay_subscription_id) {
        return res.status(400).json({ success: false, message: 'No subscription found.' });
      }
      const sub = await rzp.subscriptions.fetch(enrol.razorpay_subscription_id);
      return res.json({ success: true, shortUrl: sub.short_url, status: sub.status });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Razorpay routes loaded');
};
