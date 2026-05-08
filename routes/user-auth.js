// routes/user-auth.js — Customer OTP, register, login, logout
const db                              = require('../db');
const { getUserFromToken, createUserSession } = require('../helpers/auth');
const { sendSms }                     = require('../helpers/sms');
const { generateOtp, cleanPhone }     = require('../helpers/utils');

module.exports = function(app, cache) {

  // ── POST /api/gms/send-otp ───────────────────────────
  app.post('/api/gms/send-otp', async (req, res) => {
    try {
      const mobile = cleanPhone(req.body.phone);
      if (mobile.length !== 10) return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });

      const attempts = cache.get(`gms_otp_req:${mobile}`) || 0;
      if (attempts >= 3) return res.status(429).json({ success: false, message: 'Too many OTP requests. Wait 10 minutes.' });
      cache.set(`gms_otp_req:${mobile}`, attempts + 1, 600);

      const otp = generateOtp();
      cache.set(`gms_otp:${mobile}`, { otp, verified: false }, 600);
      cache.set(`otp:${mobile}`,     { phone: mobile, verified: false }, 600);
      cache.set(`gms_otp_attempts:${mobile}`, 0, 600);

      await sendSms(mobile, `Dear user, your WHP Jewellers otp code is ${otp}`);

      const [rows] = await db.query('SELECT user_id FROM gms_users WHERE mobile=?', [mobile]);
      return res.json({ success: true, message: `OTP sent to +91 ${mobile}`, isRegistered: rows.length > 0 });
    } catch(err) {
      console.error('[GMS send-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Failed to send OTP.' });
    }
  });

  // ── POST /api/gms/verify-otp ─────────────────────────
  app.post('/api/gms/verify-otp', async (req, res) => {
    try {
      const mobile   = cleanPhone(req.body.phone);
      const { otp }  = req.body;
      const stored   = cache.get(`gms_otp:${mobile}`);
      let attempts   = cache.get(`gms_otp_attempts:${mobile}`) || 0;

      if (!stored)       return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
      if (attempts >= 3) { cache.del(`gms_otp:${mobile}`); return res.status(429).json({ success: false, message: 'Too many wrong attempts. Request a new OTP.' }); }
      if (String(stored.otp) !== String(otp)) {
        cache.set(`gms_otp_attempts:${mobile}`, attempts + 1, 600);
        return res.status(400).json({ success: false, message: `Incorrect OTP. ${3-attempts-1} attempt(s) left.` });
      }

      // OTP correct — mark verified in both cache keys
      cache.set(`gms_otp:${mobile}`, { otp, verified: true }, 300);
      cache.set(`otp:${mobile}`,     { phone: mobile, verified: true }, 300);

      const [rows] = await db.query('SELECT * FROM gms_users WHERE mobile=?', [mobile]);
      if (!rows.length) return res.json({ success: true, verified: true, needsRegistration: true, phone: mobile });

      const user      = rows[0];
      const userToken = await createUserSession(user.user_id);
      return res.json({
        success: true, verified: true, needsRegistration: false,
        userToken,
        user: { user_id: user.user_id, first_name: user.first_name, last_name: user.last_name, mobile: user.mobile, email: user.email }
      });
    } catch(err) {
      console.error('[GMS verify-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Verification failed.' });
    }
  });

  // ── POST /api/gms/register ───────────────────────────
  app.post('/api/gms/register', async (req, res) => {
    try {
      const { firstName, lastName, email } = req.body;
      const mobile = cleanPhone(req.body.phone);
      if (!mobile || !firstName) return res.status(400).json({ success: false, message: 'First name and mobile are required.' });

      const stored = cache.get(`gms_otp:${mobile}`);
      if (!stored?.verified) return res.status(401).json({ success: false, message: 'Mobile not verified.' });

      const [existing] = await db.query('SELECT user_id FROM gms_users WHERE mobile=?', [mobile]);
      if (existing.length) return res.status(400).json({ success: false, message: 'Mobile already registered. Please login.' });

      const [result] = await db.query(
        'INSERT INTO gms_users (first_name, last_name, mobile, email) VALUES (?,?,?,?)',
        [firstName.trim(), (lastName||'').trim(), mobile, (email||'').trim()]
      );
      const userToken = await createUserSession(result.insertId);
      cache.set(`otp:${mobile}`, { phone: mobile, verified: true }, 300);

      return res.json({
        success: true, userToken,
        user: { user_id: result.insertId, first_name: firstName.trim(), last_name: (lastName||'').trim(), mobile, email: (email||'').trim() }
      });
    } catch(err) {
      console.error('[GMS register]', err.message);
      return res.status(500).json({ success: false, message: 'Registration failed.' });
    }
  });

  // ── GET /api/gms/check-session ───────────────────────
  app.get('/api/gms/check-session', async (req, res) => {
    try {
      const user = await getUserFromToken(req.headers['x-user-token']);
      if (!user) return res.json({ loggedIn: false });
      return res.json({
        loggedIn: true,
        user: { user_id: user.user_id, first_name: user.first_name, last_name: user.last_name, mobile: user.mobile, email: user.email }
      });
    } catch(err) { return res.json({ loggedIn: false }); }
  });

  // ── POST /api/gms/logout ─────────────────────────────
  app.post('/api/gms/logout', async (req, res) => {
    try {
      const token = req.headers['x-user-token'] || req.body?.userToken;
      if (token) await db.query('DELETE FROM gms_user_sessions WHERE token=?', [token]);
      return res.json({ success: true });
    } catch(err) { return res.json({ success: true }); }
  });

  console.log('[GMS] User auth routes loaded');
};
