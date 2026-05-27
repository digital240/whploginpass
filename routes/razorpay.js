// routes/razorpay.js — Razorpay E-Mandate Subscription
const Razorpay = require('razorpay');
const crypto   = require('crypto');
const db       = require('../db');
const { staffAuth }    = require('../helpers/auth');
const { sendSms, SMS } = require('../helpers/sms');

const rzp = new Razorpay({
  key_id:     process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

const MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function getMonthLabel(enrolDate, monthNum) {
  const start = new Date(enrolDate);
  const d = new Date(start.getFullYear(), start.getMonth() + (monthNum - 1), 1);
  return MONTH_NAMES[d.getMonth()] + ' ' + d.getFullYear();
}

function verifyWebhookSignature(rawBody, signature) {
  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');
  return expected === signature;
}

async function getNextPendingMonth(enrolmentId) {
  const [rows] = await db.query(
    `SELECT month_num FROM gms_payments 
     WHERE enrolment_id=? AND status='Pending' 
     ORDER BY month_num ASC LIMIT 1`,
    [enrolmentId]
  );
  return rows[0]?.month_num || null;
}

async function markMonthPaidAuto(enrolmentId, monthNum, paymentId, amount) {
  await db.query(
    `UPDATE gms_payments 
     SET status='Paid', paid_at=NOW(), pay_method='UPI Auto-debit',
         razorpay_payment_id=?, amount=?
     WHERE enrolment_id=? AND month_num=?`,
    [paymentId, amount / 100, enrolmentId, monthNum]
  );

  const [countRows] = await db.query(
    `SELECT COUNT(*) as paid FROM gms_payments WHERE enrolment_id=? AND status='Paid'`,
    [enrolmentId]
  );
  const made = countRows[0].paid;

  const [enrolRows] = await db.query(
    'SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]
  );
  if (!enrolRows.length) return;
  const enrol   = enrolRows[0];
  const pending = enrol.pay_months - made;
  const status  = pending <= 0 ? 'Matured' : 'Active';

  await db.query(
    'UPDATE gms_enrolments SET payments_made=?, payments_pending=?, status=? WHERE enrolment_id=?',
    [made, Math.max(0, pending), status, enrolmentId]
  );

  await db.query(
    'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
    [enrolmentId, `Month ${monthNum} auto-paid`, 'Razorpay', 'Auto', `Payment ID: ${paymentId}`]
  );

  if (status === 'Matured') {
    await sendSms(enrol.phone, SMS.matured(enrolmentId, Math.round(parseFloat(enrol.total_redeemable))), 'matured');
  } else {
    const monthLabel = getMonthLabel(enrol.enrolment_date || enrol.created_at, monthNum);
    const amt        = amount > 1000 ? Math.round(amount / 100) : Math.round(amount);
    await sendSms(enrol.phone, SMS.autoDebitSuccess(amt, enrolmentId, monthLabel, Math.max(0, pending)), 'autoDebitSuccess');
  }

  return { made, pending: Math.max(0, pending), status };
}

// ── Autopay nudge — schedules mandateLink SMS 2 hours after single payment ──
async function sendAutopayNudge(enrolmentId, phone) {
  try {
    const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
    const fe = rows[0];
    if (!fe) return;
    if (fe.razorpay_sub_status === 'active') return;

    let shortUrl = null;

    if (fe.razorpay_subscription_id) {
      const sub = await rzp.subscriptions.fetch(fe.razorpay_subscription_id);
      if (['created', 'authenticated', 'pending'].includes(sub.status)) {
        shortUrl = sub.short_url;
      } else {
        // ── Old subscription expired — create fresh one for nudge
        console.log(`[GMS] Old sub ${sub.status} — creating fresh for nudge`);
        const plan = await rzp.plans.create({
          period: process.env.GMS_PLAN_PERIOD || 'monthly', interval: 1,
          item: { name: `WHP GMS ${enrolmentId}`, amount: Math.round(parseFloat(fe.instalment_amt) * 100), currency: 'INR' }
        });
        const newSub = await rzp.subscriptions.create({
          plan_id: plan.id, total_count: parseInt(fe.payments_pending) || 1,
          quantity: 1, start_at: Math.floor(Date.now() / 1000) + 60,
          customer_notify: 1, notes: { enrolmentId, type: 'nudge_refresh' }
        });
        await db.query(
          "UPDATE gms_enrolments SET razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created' WHERE enrolment_id=?",
          [plan.id, newSub.id, enrolmentId]
        );
        shortUrl = newSub.short_url;
        console.log(`[GMS] Fresh subscription for nudge: ${newSub.id}`);
      }
    }

     if (shortUrl) {
      // ── Nudge 1 — 5 minutes after payment
      await db.query(
        `INSERT INTO gms_pending_nudges (enrolment_id, phone, short_url, send_after, expires_at, nudge_count)
         VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 5 MINUTE), DATE_ADD(NOW(), INTERVAL 30 DAY), 1)
         ON DUPLICATE KEY UPDATE short_url=VALUES(short_url), send_after=DATE_ADD(NOW(), INTERVAL 5 MINUTE), expires_at=DATE_ADD(NOW(), INTERVAL 30 DAY), sent=0, nudge_count=1`,
        [enrolmentId, phone, shortUrl]
      );
      console.log(`[GMS] Autopay nudge 1 scheduled for ${phone} in 5 minutes`);
    }
  } catch(e) {
    console.log('[GMS] Autopay nudge schedule (non-critical):', e.message);
  }
}

// ═══════════════════════════════════════════════════════════
module.exports = function(app, cache) {

  // ── POST /api/razorpay/create-subscription ────────────
  app.post('/api/razorpay/create-subscription', async (req, res) => {
    try {
      const { enrolmentId } = req.body;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      const paidSoFar       = parseInt(enrol.payments_made) || 0;
      const remainingMonths = enrol.pay_months - paidSoFar;
      if (remainingMonths <= 0) return res.status(400).json({ success: false, message: 'All months already paid.' });

      const amountPaise = Math.round(parseFloat(enrol.instalment_amt) * 100);
      const plan = await rzp.plans.create({
        period: process.env.GMS_PLAN_PERIOD || 'monthly', interval: 1,
        item: { name: `WHP GMS - ${enrolmentId}`, amount: amountPaise, currency: 'INR', description: 'WHP Golden Moments Scheme monthly instalment' }
      });

      const startAt      = Math.floor(Date.now() / 1000) + 60;
      const subscription = await rzp.subscriptions.create({
        plan_id: plan.id, total_count: remainingMonths, quantity: 1,
        start_at: startAt, customer_notify: 1, addons: [],
        notes: { enrolment_id: enrolmentId, customer_phone: enrol.phone, scheme: `${enrol.tenure_months} Month GMS` }
      });

      await db.query(
        `UPDATE gms_enrolments SET razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created' WHERE enrolment_id=?`,
        [plan.id, subscription.id, enrolmentId]
      );

      console.log(`[Razorpay] Subscription created: ${subscription.id} for ${enrolmentId}`);
      return res.json({ success: true, subscriptionId: subscription.id, shortUrl: subscription.short_url, remainingMonths, amount: enrol.instalment_amt });
    } catch(err) {
      console.error('[Razorpay] create-subscription error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/resend-mandate ─────────────────
  app.post('/api/razorpay/resend-mandate', staffAuth, async (req, res) => {
    try {
      const { enrolmentId } = req.body;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Not found.' });
      const enrol = rows[0];
      if (!enrol.razorpay_subscription_id) return res.status(400).json({ success: false, message: 'No subscription found.' });
      const sub = await rzp.subscriptions.fetch(enrol.razorpay_subscription_id);
      await sendSms(enrol.phone, SMS.mandateLink(sub.short_url), 'mandateLink');
      return res.json({ success: true, shortUrl: sub.short_url, message: 'Mandate link sent via SMS.' });
    } catch(err) {
      console.error('[Razorpay] resend-mandate error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/cancel-subscription ────────────
  app.post('/api/razorpay/cancel-subscription', staffAuth, async (req, res) => {
    try {
      const { enrolmentId } = req.body;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Not found.' });
      const enrol = rows[0];
      if (!enrol.razorpay_subscription_id) return res.json({ success: true, message: 'No active subscription to cancel.' });
      await rzp.subscriptions.cancel(enrol.razorpay_subscription_id, { cancel_at_cycle_end: 0 });
      await db.query(`UPDATE gms_enrolments SET razorpay_sub_status='cancelled' WHERE enrolment_id=?`, [enrolmentId]);
      console.log(`[Razorpay] Subscription cancelled: ${enrol.razorpay_subscription_id}`);
      return res.json({ success: true, message: 'Subscription cancelled.' });
    } catch(err) {
      console.error('[Razorpay] cancel-subscription error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-payment-webhook ─────────────────────
  app.post('/api/gms-payment-webhook', async (req, res) => {
    try {
      const signature    = req.headers['x-razorpay-signature'];
      const isTestBypass = req.headers['x-webhook-test'] === (process.env.GMS_CRON_SECRET || 'whpcron2026');
      if (!isTestBypass && !verifyWebhookSignature(req.rawBody, signature)) {
        console.error('[Webhook] Invalid signature');
        return res.status(400).json({ success: false, message: 'Invalid signature.' });
      }

      const event   = JSON.parse(req.rawBody);
      const payload = event.payload;
      console.log(`[Webhook] Event: ${event.event}`);

      switch(event.event) {

        case 'subscription.authenticated': {
          const subId = payload.subscription?.entity?.id;
          if (!subId) break;
          const [authRows] = await db.query('SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?', [subId]);
          if (authRows.length) {
            const authEnrol = authRows[0];
            await db.query(
              `UPDATE gms_enrolments SET razorpay_sub_status='active', status='Active', pay_method='UPI Auto-debit' WHERE razorpay_subscription_id=?`,
              [subId]
            );
            if (!authEnrol.user_id) {
              const [userRows] = await db.query('SELECT user_id FROM gms_users WHERE mobile=? LIMIT 1', [authEnrol.phone]);
              if (userRows.length) {
                await db.query('UPDATE gms_enrolments SET user_id=? WHERE enrolment_id=?', [userRows[0].user_id, authEnrol.enrolment_id]);
              }
            }
            await db.query(
              'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
              [authEnrol.enrolment_id, 'Scheme Activated via Mandate', 'Razorpay', authEnrol.preferred_branch || 'Online', `Subscription: ${subId}`]
            );
            await sendSms(authEnrol.phone, SMS.schemeActive(authEnrol.enrolment_id, Math.round(parseFloat(authEnrol.instalment_amt))), 'schemeActive');
            // Cancel any pending nudges — autopay is now active
            await db.query("UPDATE gms_pending_nudges SET sent=1 WHERE enrolment_id=? AND sent=0", [authEnrol.enrolment_id]);
            console.log(`[Webhook] Scheme activated on mandate: ${authEnrol.enrolment_id}`);
          } else {
            await db.query(`UPDATE gms_enrolments SET razorpay_sub_status='authenticated' WHERE razorpay_subscription_id=?`, [subId]);
          }
          break;
        }

        case 'subscription.activated': {
          const subId = payload.subscription?.entity?.id;
          if (!subId) break;
          await db.query(`UPDATE gms_enrolments SET razorpay_sub_status='active' WHERE razorpay_subscription_id=?`, [subId]);
          console.log(`[Webhook] Subscription activated: ${subId}`);
          break;
        }

        case 'subscription.charged':
        case 'payment.captured': {
          const payment = payload.payment?.entity;
          if (!payment) break;
          const subId = payment.subscription_id || payload.subscription?.entity?.id;
          if (!subId) { console.log('[Webhook] No subscription ID — skipping'); break; }

          const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?', [subId]);
          if (!enrolRows.length) { console.error(`[Webhook] No enrolment for subscription: ${subId}`); break; }
          const enrol = enrolRows[0];

          const monthNum = await getNextPendingMonth(enrol.enrolment_id);
          if (!monthNum) { console.log(`[Webhook] No pending months for ${enrol.enrolment_id}`); break; }

          if (enrol.status === 'Draft') {
            await db.query("UPDATE gms_enrolments SET status='Active' WHERE enrolment_id=?", [enrol.enrolment_id]);
            await sendSms(enrol.phone, SMS.enrolUpi(enrol.enrolment_id, Math.round(parseFloat(enrol.instalment_amt)), enrol.pay_months, Math.round(parseFloat(enrol.total_redeemable))), 'enrolUpi');
            console.log(`[Webhook] Draft → Active: ${enrol.enrolment_id}`);
          }

          const result = await markMonthPaidAuto(enrol.enrolment_id, monthNum, payment.id, payment.amount);
          console.log(`[Webhook] Month ${monthNum} paid for ${enrol.enrolment_id}. Status: ${result?.status}`);
          break;
        }

        case 'payment.failed': {
          const payment = payload.payment?.entity;
          if (!payment?.subscription_id) break;
          const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?', [payment.subscription_id]);
          if (!enrolRows.length) break;
          const enrol = enrolRows[0];
          const monthNum = await getNextPendingMonth(enrol.enrolment_id);
          if (monthNum) {
            await db.query(`UPDATE gms_payments SET status='Failed', razorpay_payment_id=? WHERE enrolment_id=? AND month_num=?`, [payment.id, enrol.enrolment_id, monthNum]);
          }
          await db.query(
            'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
            [enrol.enrolment_id, `Month ${monthNum} payment failed`, 'Razorpay', 'Auto', `Payment ID: ${payment.id}. Error: ${payment.error_description || 'Unknown'}`]
          );
          const failMonthLabel = getMonthLabel(enrol.enrolment_date || enrol.created_at, monthNum);
          await sendSms(enrol.phone, SMS.autoDebitFailed(Math.round(parseFloat(enrol.instalment_amt)), failMonthLabel), 'autoDebitFailed');
          await db.query(
            'INSERT INTO gms_notifications (enrolment_id, phone, type, message, status) VALUES (?,?,?,?,?)',
            [enrol.enrolment_id, enrol.phone, 'Payment Failed', `Month ${monthNum} UPI payment failed. Payment ID: ${payment.id}`, 'Alert']
          );
          console.log(`[Webhook] Payment failed for ${enrol.enrolment_id} Month ${monthNum}`);
          break;
        }

        case 'subscription.halted': {
          const subId = payload.subscription?.entity?.id;
          if (!subId) break;
          const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?', [subId]);
          if (!enrolRows.length) break;
          const enrol = enrolRows[0];
          await db.query(`UPDATE gms_enrolments SET razorpay_sub_status='halted' WHERE enrolment_id=?`, [enrol.enrolment_id]);
          await sendSms(enrol.phone, SMS.halted(), 'halted');
          console.log(`[Webhook] Subscription halted: ${subId}`);
          break;
        }

        case 'subscription.cancelled': {
          const subId = payload.subscription?.entity?.id;
          if (!subId) break;
          await db.query(`UPDATE gms_enrolments SET razorpay_sub_status='cancelled' WHERE razorpay_subscription_id=?`, [subId]);
          console.log(`[Webhook] Subscription cancelled: ${subId}`);
          break;
        }

        case 'subscription.completed': {
          const subId = payload.subscription?.entity?.id;
          if (!subId) break;
          const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE razorpay_subscription_id=?', [subId]);
          if (!enrolRows.length) break;
          const enrol = enrolRows[0];
          await db.query(`UPDATE gms_enrolments SET status='Matured', razorpay_sub_status='completed' WHERE enrolment_id=?`, [enrol.enrolment_id]);
          await sendSms(enrol.phone, SMS.matured(enrol.enrolment_id, Math.round(parseFloat(enrol.total_redeemable))), 'matured');
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
  });

  // ── GET /api/razorpay/subscription-status/:id ─────────
  app.get('/api/razorpay/subscription-status/:enrolmentId', staffAuth, async (req, res) => {
    try {
      const [rows] = await db.query('SELECT razorpay_subscription_id, razorpay_sub_status FROM gms_enrolments WHERE enrolment_id=?', [req.params.enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false });
      const enrol = rows[0];
      if (!enrol.razorpay_subscription_id) return res.json({ success: true, status: 'none', subscriptionId: null });
      const sub = await rzp.subscriptions.fetch(enrol.razorpay_subscription_id);
      return res.json({ success: true, status: sub.status, dbStatus: enrol.razorpay_sub_status, subscriptionId: enrol.razorpay_subscription_id, shortUrl: sub.short_url, paidCount: sub.paid_count, remainingCount: sub.remaining_count });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/razorpay/resume/:enrolmentId ────────────
  app.get('/api/razorpay/resume/:enrolmentId', async (req, res) => {
    try {
      const [rows] = await db.query("SELECT * FROM gms_enrolments WHERE enrolment_id=? AND status='Draft'", [req.params.enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'No pending payment found.' });
      const enrol = rows[0];

      const amountPaise = Math.round(parseFloat(enrol.instalment_amt) * 100);
      const startAt     = Math.floor(Date.now() / 1000) + 60;

      let customerId = null;
      try {
        const cust = await rzp.customers.create({ name: enrol.name, contact: '+91' + enrol.phone, email: enrol.email || enrol.phone + '@whpjewellers.com', fail_existing: 0 });
        customerId = cust.id;
      } catch(ce) { console.log('[Resume] Customer note:', ce.message); }

      const plan = await rzp.plans.create({
        period: process.env.GMS_PLAN_PERIOD || 'monthly', interval: 1,
        item: { name: 'WHP GMS - ' + enrol.enrolment_id, amount: amountPaise, currency: 'INR', description: 'WHP Golden Moments Scheme' }
      });

      const subOpts = { plan_id: plan.id, total_count: parseInt(enrol.pay_months), quantity: 1, start_at: startAt, customer_notify: 1, notes: { enrolment_id: enrol.enrolment_id, customer_phone: enrol.phone } };
      if (customerId) subOpts.customer_id = customerId;
      const sub = await rzp.subscriptions.create(subOpts);

      await db.query("UPDATE gms_enrolments SET razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created' WHERE enrolment_id=?", [plan.id, sub.id, enrol.enrolment_id]);
      console.log('[Resume] Fresh subscription:', sub.id, 'for', enrol.enrolment_id);
      return res.json({ success: true, shortUrl: sub.short_url, subscriptionId: sub.id });
    } catch(err) {
      console.error('[Resume] Error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/pay-onetime ───────────────────
  app.post('/api/razorpay/pay-onetime', async (req, res) => {
    try {
      const { enrolmentId } = req.body;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];
      const monthNum = await getNextPendingMonth(enrolmentId);
      if (!monthNum) return res.status(400).json({ success: false, message: 'No pending payments.' });
      const amountPaise = Math.round(parseFloat(enrol.instalment_amt) * 100);
      const order = await rzp.orders.create({ amount: amountPaise, currency: 'INR', receipt: `${enrolmentId}-M${monthNum}`, notes: { enrolment_id: enrolmentId, month_num: String(monthNum), customer_phone: enrol.phone, payment_type: 'one_time' } });
      console.log(`[Razorpay] One-time order: ${order.id} for ${enrolmentId} Month ${monthNum}`);
      return res.json({ success: true, orderId: order.id, amount: enrol.instalment_amt, amountPaise, monthNum, enrolmentId, currency: 'INR' });
    } catch(err) {
      console.error('[Razorpay] pay-onetime error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/verify-onetime ─────────────────
  app.post('/api/razorpay/verify-onetime', async (req, res) => {
    try {
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature, enrolmentId, monthNum } = req.body;
      const body     = razorpay_order_id + '|' + razorpay_payment_id;
      const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(body).digest('hex');
      if (expected !== razorpay_signature) return res.status(400).json({ success: false, message: 'Payment verification failed.' });

      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      if (enrol.status === 'Draft') {
        await db.query("UPDATE gms_enrolments SET status='Active' WHERE enrolment_id=?", [enrolmentId]);
        console.log(`[Razorpay] Draft → Active via one-time: ${enrolmentId}`);
      }

      // ── Mark as UPI Single Payment
      await db.query(
        "UPDATE gms_enrolments SET pay_method='UPI Single Payment' WHERE enrolment_id=? AND razorpay_sub_status != 'active'",
        [enrolmentId]
      );

      const result = await markMonthPaidAuto(enrolmentId, parseInt(monthNum), razorpay_payment_id, parseFloat(enrol.instalment_amt) * 100);

      // ── Schedule autopay nudge for 2 hours later
      if (result?.status !== 'Matured') {
        await sendAutopayNudge(enrolmentId, enrol.phone);
      }

      return res.json({ success: true, message: `Month ${monthNum} payment verified!`, made: result?.made, status: result?.status });
    } catch(err) {
      console.error('[Razorpay] verify-onetime error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/razorpay/pay-now/:enrolmentId ──────────
  app.get('/api/razorpay/pay-now/:enrolmentId', async (req, res) => {
    try {
      const { enrolmentId } = req.params;
      const [rows] = await db.query("SELECT * FROM gms_enrolments WHERE enrolment_id=? AND status='Active'", [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found or not active.' });
      const enrol = rows[0];
      const [pendingRows] = await db.query("SELECT * FROM gms_payments WHERE enrolment_id=? AND status='Pending' ORDER BY month_num ASC LIMIT 1", [enrolmentId]);
      if (!pendingRows.length) return res.json({ success: false, message: 'No pending payments found.' });
      const pendingMonth = pendingRows[0];
      const order = await rzp.orders.create({ amount: Math.round(parseFloat(enrol.instalment_amt) * 100), currency: 'INR', notes: { enrolmentId, monthNum: String(pendingMonth.month_num), phone: enrol.phone } });

      const html = `<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WHP GMS Payment</title>
  <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
  <style>
    body{font-family:'Jost',sans-serif;background:#fdf8f3;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
    .box{background:#fff;border-radius:16px;padding:32px;max-width:400px;width:100%;text-align:center;box-shadow:0 4px 24px rgba(90,42,50,0.1)}
    .logo{font-size:20px;font-weight:600;color:#5a2a32;margin-bottom:8px}
    .amt{font-size:40px;font-weight:700;color:#5a2a32;margin:16px 0 4px}
    .sub{font-size:14px;color:#a08070;margin-bottom:24px}
    .btn{width:100%;padding:14px;background:linear-gradient(135deg,#5a2a32,#d16c6c);color:#fff;border:none;border-radius:12px;font-size:15px;font-weight:600;cursor:pointer}
    .secure{font-size:12px;color:#a08070;margin-top:16px}
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
    function payNow(){
      var options={
        key:'${process.env.RAZORPAY_KEY_ID}',
        amount:${Math.round(parseFloat(enrol.instalment_amt)*100)},
        currency:'INR',name:'WHP Jewellers',
        description:'GMS Month ${pendingMonth.month_num} Payment',
        order_id:'${order.id}',
        prefill:{contact:'+91${enrol.phone}'},
        theme:{color:'#5a2a32'},
        handler:function(response){
          fetch('/api/razorpay/verify-paynow',{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({razorpay_order_id:response.razorpay_order_id,razorpay_payment_id:response.razorpay_payment_id,razorpay_signature:response.razorpay_signature,enrolmentId:'${enrolmentId}',monthNum:${pendingMonth.month_num}})
          }).then(r=>r.json()).then(d=>{
            if(d.success){document.body.innerHTML='<div style="display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:sans-serif;text-align:center"><div><div style="font-size:60px">✅</div><h2 style="color:#2d7a4f;margin:16px 0">Payment Successful!</h2><p style="color:#666">Month ${pendingMonth.month_num} payment of ₹${Number(enrol.instalment_amt).toLocaleString('en-IN')} recorded.</p></div></div>';}
            else{alert('Verification failed: '+(d.message||'Please contact branch.'));}
          });
        },modal:{ondismiss:function(){}}
      };
      var rzp2=new Razorpay(options);
      rzp2.on('payment.failed',function(r){alert('Payment failed: '+r.error.description);});
      rzp2.open();
    }
    window.onload=function(){setTimeout(payNow,500);};
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
  app.post('/api/razorpay/verify-paynow', async (req, res) => {
    try {
      const { razorpay_order_id, razorpay_payment_id, razorpay_signature, enrolmentId, monthNum } = req.body;
      const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(razorpay_order_id + '|' + razorpay_payment_id).digest('hex');
      if (expected !== razorpay_signature) return res.json({ success: false, message: 'Invalid signature.' });

      const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!enrolRows.length) return res.json({ success: false, message: 'Enrolment not found.' });
      const enrol = enrolRows[0];

      await db.query(
        `UPDATE gms_payments SET status='Paid', paid_at=NOW(), pay_method='UPI One-time', razorpay_payment_id=?, notes='Direct pay link' WHERE enrolment_id=? AND month_num=?`,
        [razorpay_payment_id, enrolmentId, monthNum]
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
      await db.query('UPDATE gms_enrolments SET payments_made=?, payments_pending=?, status=? WHERE enrolment_id=?', [made, Math.max(0, pending), allDone ? 'Matured' : 'Active', enrolmentId]);

      if (allDone) {
        await sendSms(enrol.phone, SMS.matured(enrolmentId, Math.round(parseFloat(enrol.total_redeemable))), 'matured');
      } else {
        const pnMonthLabel = getMonthLabel(enrol.enrolment_date || enrol.created_at, monthNum);
        await sendSms(enrol.phone, SMS.autoDebitSuccess(Math.round(parseFloat(enrol.instalment_amt)), enrolmentId, pnMonthLabel, Math.max(0, pending)), 'autoDebitSuccess');
        // ── Schedule autopay nudge 2 hours later
        await sendAutopayNudge(enrolmentId, enrol.phone);
      }

      return res.json({ success: true });
    } catch(err) {
      console.error('[GMS] verify-paynow error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/razorpay/setup-autopay ─────────────────
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

      const [pendingRows] = await db.query("SELECT * FROM gms_payments WHERE enrolment_id=? AND status='Pending' ORDER BY month_num ASC LIMIT 1", [enrolmentId]);
      const made      = parseInt(enrol.payments_made) || 0;
      const remaining = enrol.pay_months - made;
      if (remaining <= 0) return res.json({ success: false, message: 'No remaining payments to automate.' });

      const plan = await rzp.plans.create({
        period: process.env.GMS_PLAN_PERIOD || 'monthly', interval: 1,
        item: { name: `WHP GMS ${enrolmentId}`, amount: Math.round(parseFloat(enrol.instalment_amt) * 100), currency: 'INR' }
      });

      const currentMonthPending = pendingRows.length > 0 && pendingRows[0].month_num === made + 1;
      const sub = await rzp.subscriptions.create({
        plan_id: plan.id, total_count: remaining, quantity: 1, customer_notify: 1,
        ...(currentMonthPending ? {} : { start_at: Math.floor(new Date(enrol.enrolment_date).setMonth(new Date(enrol.enrolment_date).getMonth() + made + 1) / 1000) }),
        notes: { enrolmentId, phone: enrol.phone }
      });

      await db.query(
        "UPDATE gms_enrolments SET pay_method='UPI Auto-debit', razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created' WHERE enrolment_id=?",
        [plan.id, sub.id, enrolmentId]
      );

      // No mandateLink SMS — Razorpay checkout opens directly in browser
      return res.json({ success: true, subscriptionId: sub.id, shortUrl: sub.short_url, currentMonthPending });
    } catch(err) {
      console.error('[GMS] setup-autopay error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Razorpay routes loaded');
};
