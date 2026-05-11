// routes/app-auth.js — Mobile App OTP Login
const { sendSms }                             = require('../helpers/sms');
const { generateOtp, cleanPhone }             = require('../helpers/utils');
const { getUserFromToken, createUserSession } = require('../helpers/auth');
const db                                      = require('../db');

// SMS Template ID for app (change this later when you get new DLT template)
const APP_TEMPLATE_ID = '1707163577173453876';
const APP_OTP_MESSAGE = (otp) => `Dear User, Your WHP Jewellers website verification code is ${otp}`;

module.exports = function(app, cache) {

  // ── POST /api/app/send-otp ───────────────────────────
  app.post('/api/app/send-otp', async (req, res) => {
    try {
      const mobile = cleanPhone(req.body.phone);
      if (mobile.length !== 10)
        return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });

      // Rate limiting
      const attempts = cache.get(`app_otp_req:${mobile}`) || 0;
      if (attempts >= 3)
        return res.status(429).json({ success: false, message: 'Too many OTP requests. Wait 10 minutes.' });
      cache.set(`app_otp_req:${mobile}`, attempts + 1, 600);

      const otp = generateOtp();
      cache.set(`app_otp:${mobile}`, { otp, verified: false }, 600);
      cache.set(`app_otp_attempts:${mobile}`, 0, 600);

      await sendSms(mobile, APP_OTP_MESSAGE(otp));

      const [rows] = await db.query(
        'SELECT id FROM app_customers WHERE mobile=?', [mobile]
      );

      return res.json({
        success: true,
        message: `OTP sent to +91 ${mobile}`,
        isRegistered: rows.length > 0
      });
    } catch (err) {
      console.error('[APP send-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Failed to send OTP.' });
    }
  });

  // ── POST /api/app/verify-otp ─────────────────────────
  app.post('/api/app/verify-otp', async (req, res) => {
    try {
      const mobile  = cleanPhone(req.body.phone);
      const { otp } = req.body;
      const stored  = cache.get(`app_otp:${mobile}`);
      let attempts  = cache.get(`app_otp_attempts:${mobile}`) || 0;

      if (!stored)
        return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
      if (attempts >= 5) {
        cache.del(`app_otp:${mobile}`);
        return res.status(429).json({ success: false, message: 'Too many wrong attempts. Request a new OTP.' });
      }
      if (String(stored.otp) !== String(otp)) {
        cache.set(`app_otp_attempts:${mobile}`, attempts + 1, 600);
        return res.status(400).json({ success: false, message: `Incorrect OTP. ${5 - attempts - 1} attempt(s) left.` });
      }

      // OTP correct
      cache.set(`app_otp:${mobile}`, { otp, verified: true }, 300);

      const [rows] = await db.query(
        'SELECT * FROM app_customers WHERE mobile=?', [mobile]
      );

      if (!rows.length) {
        return res.json({
          success: true,
          verified: true,
          needsRegistration: true,
          phone: mobile
        });
      }

      const customer  = rows[0];
      const token = require('crypto').randomBytes(32).toString('hex');
      await db.query(
        `INSERT INTO app_sessions (customer_id, mobile, token, expires_at)
         VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))`,
        [customer.id, mobile, token]
      );

      return res.json({
        success: true,
        verified: true,
        needsRegistration: false,
        token,
        customer: {
          id:     customer.id,
          mobile: customer.mobile,
          name:   customer.name  || null,
          email:  customer.email || null,
          photo:  customer.photo || null,
        }
      });
    } catch (err) {
      console.error('[APP verify-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Verification failed.' });
    }
  });

  // ── POST /api/app/register ───────────────────────────
  app.post('/api/app/register', async (req, res) => {
    try {
      const { name, email } = req.body;
      const mobile = cleanPhone(req.body.phone);

      if (!mobile || !name)
        return res.status(400).json({ success: false, message: 'Name and mobile are required.' });

      const stored = cache.get(`app_otp:${mobile}`);
      if (!stored?.verified)
        return res.status(401).json({ success: false, message: 'Mobile not verified.' });

      const [existing] = await db.query(
        'SELECT id FROM app_customers WHERE mobile=?', [mobile]
      );
      if (existing.length)
        return res.status(400).json({ success: false, message: 'Mobile already registered.' });

      const [result] = await db.query(
        'INSERT INTO app_customers (mobile, name, email, created_at) VALUES (?,?,?,NOW())',
        [mobile, name.trim(), (email || '').trim()]
      );

      const token = require('crypto').randomBytes(32).toString('hex');
      await db.query(
        `INSERT INTO app_sessions (customer_id, mobile, token, expires_at)
         VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 30 DAY))`,
        [result.insertId, mobile, token]
      );

      return res.json({
        success: true,
        token,
        customer: {
          id:     result.insertId,
          mobile,
          name:   name.trim(),
          email:  (email || '').trim(),
          photo:  null,
        }
      });
    } catch (err) {
      console.error('[APP register]', err.message);
      return res.status(500).json({ success: false, message: 'Registration failed.' });
    }
  });

  // ── GET /api/app/check-session ───────────────────────
  app.get('/api/app/check-session', async (req, res) => {
    try {
      const token = req.headers['x-app-token'];
      if (!token) return res.json({ loggedIn: false });

      const [rows] = await db.query(
        `SELECT c.* FROM app_customers c
         JOIN app_sessions s ON s.customer_id = c.id
         WHERE s.token=? AND s.expires_at > NOW()`,
        [token]
      );

      if (!rows.length) return res.json({ loggedIn: false });

      return res.json({
        loggedIn: true,
        customer: {
          id:     rows[0].id,
          mobile: rows[0].mobile,
          name:   rows[0].name  || null,
          email:  rows[0].email || null,
          photo:  rows[0].photo || null,
        }
      });
    } catch (err) {
      return res.json({ loggedIn: false });
    }
  });

  // ── POST /api/app/logout ─────────────────────────────
  app.post('/api/app/logout', async (req, res) => {
    try {
      const token = req.headers['x-app-token'];
      if (token) await db.query('DELETE FROM app_sessions WHERE token=?', [token]);
      return res.json({ success: true });
    } catch (err) {
      return res.json({ success: true });
    }
  });

  console.log('[APP] Auth routes loaded');
};
