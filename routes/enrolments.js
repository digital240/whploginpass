// routes/enrolments.js — Create, list, search, detail
const db      = require('../db');
const { staffAuth }                           = require('../helpers/auth');
const { sendSms }                             = require('../helpers/sms');
const { genId, cleanPhone, toMysqlDate, createPaymentSchedule } = require('../helpers/utils');

module.exports = function(app, cache) {

  // ── POST /api/create-gms-enrolment ──────────────────
  app.post('/api/create-gms-enrolment', async (req, res) => {
    try {
      const {
        name, phone, email, address1, address2, city, state, pincode,
        dob, identity, branch, product_title, product_sku, product_url,
        amt, tenure, paymo, pct, type, paid, bonus, redeem, pay, maturity_date
      } = req.body;

      const cp = cleanPhone(phone);

      // Allow if OTP verified OR logged-in session
      const otpData   = cache.get(`otp:${cp}`);
      const userToken = req.headers['x-user-token'] || req.body?.userToken;
      let sessionValid = false;
      if (userToken) {
        const now = new Date().toISOString().slice(0,19).replace('T',' ');
        const [sr] = await db.query(
          'SELECT u.user_id FROM gms_users u JOIN gms_user_sessions s ON u.user_id=s.user_id WHERE s.token=? AND s.expires_at>? AND u.mobile=?',
          [userToken, now, cp]
        );
        sessionValid = sr.length > 0;
      }
      if (!otpData?.verified && !sessionValid) {
        return res.status(401).json({ success: false, message: 'Mobile not verified.' });
      }

      const today = new Date().toISOString().split('T')[0];
      const mDate = toMysqlDate(maturity_date, tenure);

      // ── For UPI: check if draft already exists for this phone ──
      if (pay === 'upi') {
        const [existing] = await db.query(
          `SELECT enrolment_id, razorpay_subscription_id FROM gms_enrolments 
           WHERE phone=? AND status='Draft' AND pay_method='UPI Auto-debit'
           ORDER BY created_at DESC LIMIT 1`,
          [cp]
        );
        if (existing.length && existing[0].razorpay_subscription_id) {
          // Reuse existing draft + subscription
          console.log(`[GMS] Reusing draft: ${existing[0].enrolment_id}`);
          try {
            const Razorpay = require('razorpay');
            const rzp = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
            const sub = await rzp.subscriptions.fetch(existing[0].razorpay_subscription_id);
            return res.json({
              success:      true,
              enrolmentId:  existing[0].enrolment_id,
              message:      'Resuming your enrolment…',
              razorpay:     { shortUrl: sub.short_url, subscriptionId: sub.id }
            });
          } catch(e) {
            // If fetch fails, delete old draft and create new
            await db.query("DELETE FROM gms_enrolments WHERE enrolment_id=?", [existing[0].enrolment_id]);
          }
        }
      }

      const enrolmentId = genId();

      // For UPI → save as Draft first, convert to Active after payment
      // For Store → save as Active immediately
      const initialStatus = pay === 'upi' ? 'Draft' : 'Active';

      await db.query(`
        INSERT INTO gms_enrolments (
          enrolment_id, name, phone, email, address1, address2, city, state, pincode,
          dob, identity_proof, preferred_branch, product_title, product_sku, product_url,
          redeem_type, bonus_pct, instalment_amt, tenure_months, pay_months,
          total_contribution, whp_bonus, total_redeemable,
          maturity_date, enrolment_date, pay_method, payments_pending, status
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
        [enrolmentId, name, cp, email||'', address1||'', address2||'', city||'', state||'', pincode||'',
         dob||null, identity||'', branch||'', product_title||'', product_sku||'', product_url||'',
         type, pct, amt, tenure, paymo, paid, bonus, redeem,
         mDate, today, pay==='upi'?'UPI Auto-debit':'Pay at Store', paymo, initialStatus]
      );

      await createPaymentSchedule(enrolmentId, amt, paymo, today);
      await db.query('UPDATE gms_half_registrations SET converted=1 WHERE phone=? AND converted=0', [cp]);

      // Sync address to user profile if logged in
      if (userToken && sessionValid) {
        try {
          const [sr] = await db.query(
            'SELECT u.user_id FROM gms_user_sessions s JOIN gms_users u ON s.user_id=u.user_id WHERE s.token=? AND u.mobile=?',
            [userToken, cp]
          );
          if (sr.length) {
            await db.query(
              `UPDATE gms_users SET address1=COALESCE(NULLIF(?,''),address1), address2=?,
               city=COALESCE(NULLIF(?,''),city), state=COALESCE(NULLIF(?,''),state),
               pincode=COALESCE(NULLIF(?,''),pincode) WHERE user_id=?`,
              [address1||'', address2||'', city||'', state||'', pincode||'', sr[0].user_id]
            );
          }
        } catch(e) { console.log('[GMS] Address sync error:', e.message); }
      }

      // ── Store payment → send SMS immediately ──
      if (pay !== 'upi') {
        await db.query(
          'INSERT INTO gms_notifications (enrolment_id, phone, type, message, status) VALUES (?,?,?,?,?)',
          [enrolmentId, cp, 'Enrolment', `Enrolled. Monthly: Rs.${amt}. Tenure: ${tenure}mo. Maturity: ${mDate}`, 'Sent']
        );
        await sendSms(cp,
          `Dear Customer, you have successfully enrolled in WHP Golden Moments Scheme. Enrolment ID: ${enrolmentId}. Monthly: Rs.${amt} x ${paymo} months. Maturity: ${mDate}. - WHP Jewellers`
        );
        cache.del(`otp:${cp}`);
        return res.json({ success: true, enrolmentId, message: 'Enrolment successful!', razorpay: null });
      }

      // ── UPI payment → create Razorpay subscription ──
      let razorpayShortUrl = null;
      let razorpaySubId    = null;

      try {
        const Razorpay = require('razorpay');
        const rzp = new Razorpay({
          key_id:     process.env.RAZORPAY_KEY_ID,
          key_secret: process.env.RAZORPAY_KEY_SECRET
        });

        const amountPaise = Math.round(parseFloat(amt) * 100);
        const startAt     = Math.floor(Date.now() / 1000) + 60;

        // Create Razorpay customer to pre-fill contact details
        let razorpayCustomerId = null;
        try {
          const custRes = await rzp.customers.create({
            name:          name,
            email:         email || `${cp}@whpjewellers.com`,
            contact:       `+91${cp}`,
            fail_existing: 0
          });
          razorpayCustomerId = custRes.id;
          console.log(`[GMS] Razorpay customer: ${razorpayCustomerId}`);
        } catch(ce) {
          console.log('[GMS] Customer create note:', ce.message);
        }

        // Create plan
        const plan = await rzp.plans.create({
          period: 'monthly', interval: 1,
          item: {
            name:        `WHP GMS - ${enrolmentId}`,
            amount:      amountPaise,
            currency:    'INR',
            description: `WHP Golden Moments Scheme - ${tenure} months`
          }
        });

        // Create subscription with customer pre-filled
        const subOptions = {
          plan_id:         plan.id,
          total_count:     parseInt(paymo),
          quantity:        1,
          start_at:        startAt,
          customer_notify: 1,
          notes: {
            enrolment_id:   enrolmentId,
            customer_phone: cp,
            customer_name:  name,
            scheme:         `${tenure} Month GMS`
          }
        };
        if (razorpayCustomerId) subOptions.customer_id = razorpayCustomerId;

        const subscription = await rzp.subscriptions.create(subOptions);
        razorpayShortUrl   = subscription.short_url;
        razorpaySubId      = subscription.id;

        // Save plan + subscription IDs
        await db.query(
          `UPDATE gms_enrolments 
           SET razorpay_plan_id=?, razorpay_subscription_id=?, razorpay_sub_status='created'
           WHERE enrolment_id=?`,
          [plan.id, subscription.id, enrolmentId]
        );

        console.log(`[GMS] Subscription created: ${subscription.id} for ${enrolmentId}`);

        // Send mandate link via SMS as backup
        await sendSms(cp,
          `Dear Customer, complete your WHP GMS enrolment by approving the UPI mandate: ${subscription.short_url} - WHP Jewellers`
        );

      } catch(rzpErr) {
        console.error('[GMS] Razorpay error:', rzpErr.message);
        // Razorpay failed — convert to store payment so enrolment is not lost
        await db.query(
          `UPDATE gms_enrolments SET status='Active', pay_method='Pay at Store' WHERE enrolment_id=?`,
          [enrolmentId]
        );
        await sendSms(cp,
          `Dear Customer, enrolled in WHP GMS. Enrolment ID: ${enrolmentId}. Monthly: Rs.${amt}. Please pay at store. - WHP Jewellers`
        );
        cache.del(`otp:${cp}`);
        return res.json({ success: true, enrolmentId, message: 'Enrolment successful! Please pay at store.', razorpay: null });
      }

      cache.del(`otp:${cp}`);

      return res.json({
        success:     true,
        enrolmentId,
        message:     'Enrolment created! Please approve UPI mandate.',
        razorpay:    { shortUrl: razorpayShortUrl, subscriptionId: razorpaySubId }
      });

    } catch(err) {
      console.error('[GMS] enrolment error:', err.message);
      return res.status(500).json({ success: false, message: 'Enrolment failed. Please try again.' });
    }
  });

  // ── GET /api/gms-enrolments ──────────────────────────
  app.get('/api/gms-enrolments', staffAuth, async (req, res) => {
    try {
      let query = "SELECT * FROM gms_enrolments WHERE status != 'Draft'";
      const params = [];
      if (req.staff.role === 'branch' && req.staff.branch) {
        query += ' AND preferred_branch=?';
        params.push(req.staff.branch);
      }
      query += ' ORDER BY created_at DESC';
      const [rows] = await db.query(query, params);
      return res.json({ success: true, rows, role: req.staff.role, branch: req.staff.branch });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-enrolment/:id ───────────────────────
  app.get('/api/gms-enrolment/:id', staffAuth, async (req, res) => {
    try {
      const [rows]     = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [req.params.id]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Not found.' });
      const [payments] = await db.query('SELECT * FROM gms_payments WHERE enrolment_id=? ORDER BY month_num', [req.params.id]);
      const [fees]     = await db.query('SELECT * FROM gms_late_fees WHERE enrolment_id=?', [req.params.id]);
      return res.json({ success: true, enrolment: rows[0], payments, fees });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-search ──────────────────────────────
  app.get('/api/gms-search', staffAuth, async (req, res) => {
    try {
      const q = '%' + (req.query.q||'') + '%';
      const [rows] = await db.query(
        `SELECT * FROM gms_enrolments WHERE status != 'Draft' 
         AND (enrolment_id LIKE ? OR phone LIKE ? OR name LIKE ?) 
         ORDER BY created_at DESC LIMIT 50`,
        [q, q, q]
      );
      return res.json({ success: true, rows });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-save-half ──────────────────────────
  app.post('/api/gms-save-half', async (req, res) => {
    try {
      const { phone, name, email, product_title, product_sku, redeem_type, instalment, tenure, branch, step } = req.body;
      const cp = cleanPhone(phone);
      if (!cp) return res.json({ success: false });
      await db.query(
        `INSERT INTO gms_half_registrations (phone, name, email, product_title, product_sku, redeem_type, instalment, tenure, branch, step_reached)
         VALUES (?,?,?,?,?,?,?,?,?,?)
         ON DUPLICATE KEY UPDATE name=VALUES(name), email=VALUES(email), step_reached=VALUES(step_reached), updated_at=NOW()`,
        [cp, name||'', email||'', product_title||'', product_sku||'', redeem_type||'', instalment||0, tenure||11, branch||'', step||'form_started']
      );
      return res.json({ success: true });
    } catch(e) { return res.json({ success: false }); }
  });

  // ── POST /api/gms-customer-lookup ────────────────────
  app.post('/api/gms-customer-lookup', async (req, res) => {
    try {
      const cp      = cleanPhone(req.body.phone);
      const otpData = cache.get(`otp:${cp}`);
      if (!otpData?.verified) return res.status(401).json({ success: false, message: 'OTP not verified.' });
      const [enrolments] = await db.query(
        "SELECT * FROM gms_enrolments WHERE phone=? AND status != 'Draft' ORDER BY created_at DESC",
        [cp]
      );
      const result = [];
      for (const e of enrolments) {
        const [payments] = await db.query('SELECT * FROM gms_payments WHERE enrolment_id=? ORDER BY month_num', [e.enrolment_id]);
        result.push({ ...e, payments });
      }
      return res.json({ success: true, enrolments: result });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Enrolment routes loaded');
};
