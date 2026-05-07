// gms-user-routes.js — WHP GMS Customer Auth & Profile
// Add to server.js: require('./gms-user-routes')(app, cache);

const crypto = require('crypto');
const axios  = require('axios');
const db     = require('./db');

// ── Helpers ──────────────────────────────────────────────────────

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function generateToken() {
  return crypto.randomBytes(48).toString('hex');
}

function cleanPhone(phone) {
  return String(phone || '').replace(/\D/g, '').slice(-10);
}

async function sendSms(phone, message) {
  try {
    await axios.post('https://www.smsalert.co.in/api/push.json', null, {
    params: {
  apikey:      process.env.SMSALERT_API_KEY,
  sender:      'WHPECM',
  mobileno:    phone,
  text:        message,
  route:       'transscrub',
  template_id: '1707164361822841747'
},
      timeout: 10000
    });
    console.log(`[GMS User SMS] Sent to ${phone}`);
  } catch (e) {
    console.error('[GMS User SMS] Failed:', e.message);
  }
}

// ── Session helpers ───────────────────────────────────────────────

async function getUserFromToken(token) {
  if (!token) return null;
  try {
    const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
    const [rows] = await db.query(
      `SELECT u.* FROM gms_users u
       JOIN gms_user_sessions s ON u.user_id = s.user_id
       WHERE s.token = ? AND s.expires_at > ?`,
      [token, now]
    );
    return rows[0] || null;
  } catch (e) {
    return null;
  }
}

async function createSession(userId) {
  const token     = generateToken();
  const expiry    = new Date(Date.now() + 30 * 24 * 3600 * 1000);
  const expiryStr = expiry.toISOString().slice(0, 19).replace('T', ' ');
  await db.query(
    'INSERT INTO gms_user_sessions (token, user_id, expires_at) VALUES (?, ?, ?)',
    [token, userId, expiryStr]
  );
  return token;
}

// ═══════════════════════════════════════════════════════════════════
module.exports = function(app, cache) {

  // ── POST /api/gms/send-otp ─────────────────────────────────────
  // Used for both login and register
  // Returns isRegistered so frontend knows which form to show
  app.post('/api/gms/send-otp', async (req, res) => {
    try {
      const mobile = cleanPhone(req.body.phone);
      if (mobile.length !== 10) {
        return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });
      }

      // Rate limit: max 3 OTP requests per 10 min
      const attempts = cache.get(`gms_otp_req:${mobile}`) || 0;
      if (attempts >= 3) {
        return res.status(429).json({ success: false, message: 'Too many OTP requests. Wait 10 minutes.' });
      }
      cache.set(`gms_otp_req:${mobile}`, attempts + 1, 600);

      const otp = generateOtp();
      cache.set(`gms_otp:${mobile}`, { otp, verified: false }, 600);
      cache.set(`gms_otp_attempts:${mobile}`, 0, 600);

      await sendSms(mobile,
        `Dear user, your WHP Jewellers otp code is ${otp}`
      );

      // Tell frontend if mobile is already registered
      const [rows] = await db.query(
        'SELECT user_id FROM gms_users WHERE mobile = ?',
        [mobile]
      );

      console.log(`[GMS User] OTP sent to ${mobile} | registered: ${rows.length > 0}`);
      return res.json({
        success:      true,
        message:      `OTP sent to +91 ${mobile}`,
        isRegistered: rows.length > 0
      });

    } catch (err) {
      console.error('[GMS send-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Failed to send OTP. Try again.' });
    }
  });

  // ── POST /api/gms/verify-otp ───────────────────────────────────
  // If registered  → create session → return userToken + user data
  // If not registered → return needsRegistration: true
  app.post('/api/gms/verify-otp', async (req, res) => {
    try {
      const mobile = cleanPhone(req.body.phone);
      const { otp } = req.body;

      if (!mobile || !otp) {
        return res.status(400).json({ success: false, message: 'Phone and OTP are required.' });
      }

      const stored   = cache.get(`gms_otp:${mobile}`);
      let   attempts = cache.get(`gms_otp_attempts:${mobile}`) || 0;

      if (!stored) {
        return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
      }
      if (attempts >= 3) {
        cache.del(`gms_otp:${mobile}`);
        return res.status(429).json({ success: false, message: 'Too many wrong attempts. Request a new OTP.' });
      }
      if (String(stored.otp) !== String(otp)) {
        cache.set(`gms_otp_attempts:${mobile}`, attempts + 1, 600);
        const left = 3 - attempts - 1;
        return res.status(400).json({ success: false, message: `Incorrect OTP. ${left} attempt(s) left.` });
      }

      // OTP correct
      cache.set(`gms_otp:${mobile}`, { otp, verified: true }, 300);
      cache.set(`otp:${mobile}`, { phone: mobile, verified: true }, 300); // keeps existing enrol route working

      const [rows] = await db.query('SELECT * FROM gms_users WHERE mobile = ?', [mobile]);

      if (rows.length === 0) {
        return res.json({
          success:           true,
          verified:          true,
          needsRegistration: true,
          phone:             mobile
        });
      }

      const user      = rows[0];
      const userToken = await createSession(user.user_id);

      console.log(`[GMS User] Login: ${user.first_name} ${user.last_name} (${mobile})`);
      return res.json({
        success:           true,
        verified:          true,
        needsRegistration: false,
        userToken,
        user: {
          user_id:    user.user_id,
          first_name: user.first_name,
          last_name:  user.last_name,
          mobile:     user.mobile,
          email:      user.email
        }
      });

    } catch (err) {
      console.error('[GMS verify-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Verification failed. Try again.' });
    }
  });

  // ── POST /api/gms/register ─────────────────────────────────────
  // Creates new user after OTP verified — auto logs in
  app.post('/api/gms/register', async (req, res) => {
    try {
      const { firstName, lastName, email } = req.body;
      const mobile = cleanPhone(req.body.phone);

      if (!mobile || !firstName) {
        return res.status(400).json({ success: false, message: 'First name and mobile are required.' });
      }

      const stored = cache.get(`gms_otp:${mobile}`);
      if (!stored || !stored.verified) {
        return res.status(401).json({ success: false, message: 'Mobile not verified. Please verify OTP first.' });
      }

      const [existing] = await db.query(
        'SELECT user_id FROM gms_users WHERE mobile = ?', [mobile]
      );
      if (existing.length > 0) {
        return res.status(400).json({ success: false, message: 'This mobile is already registered. Please login.' });
      }

      const [result] = await db.query(
        'INSERT INTO gms_users (first_name, last_name, mobile, email) VALUES (?, ?, ?, ?)',
        [firstName.trim(), (lastName || '').trim(), mobile, (email || '').trim()]
      );

      const userToken = await createSession(result.insertId);
      cache.set(`otp:${mobile}`, { phone: mobile, verified: true }, 300);

      console.log(`[GMS User] Registered: ${firstName} ${lastName} (${mobile})`);
      return res.json({
        success: true,
        userToken,
        user: {
          user_id:    result.insertId,
          first_name: firstName.trim(),
          last_name:  (lastName || '').trim(),
          mobile,
          email:      (email || '').trim()
        }
      });

    } catch (err) {
      console.error('[GMS register]', err.message);
      return res.status(500).json({ success: false, message: 'Registration failed. Try again.' });
    }
  });

  // ── GET /api/gms/me ────────────────────────────────────────────
  // Returns user info + all enrolments with payments
  app.get('/api/gms/me', async (req, res) => {
    try {
      const token = req.headers['x-user-token'];
      const user  = await getUserFromToken(token);
      if (!user) return res.status(401).json({ success: false, message: 'Not logged in.' });

      const [enrolments] = await db.query(
        `SELECT * FROM gms_enrolments
         WHERE user_id = ? OR phone = ?
         ORDER BY created_at DESC`,
        [user.user_id, user.mobile]
      );

      const enriched = [];
      for (const enrol of enrolments) {
        const [payments] = await db.query(
          'SELECT * FROM gms_payments WHERE enrolment_id = ? ORDER BY month_num',
          [enrol.enrolment_id]
        );
        enriched.push({ ...enrol, payments });
      }

     return res.json({
  success: true,
  user: {
    user_id:          user.user_id,
    first_name:       user.first_name,
    last_name:        user.last_name,
    mobile:           user.mobile,
    email:            user.email,
    secondary_mobile: user.secondary_mobile,
    address1:         user.address1,
    address2:         user.address2,
    city:             user.city,
    state:            user.state,
    pincode:          user.pincode,
    photo_url:        user.photo_url,
    member_since:     user.created_at
  },
        enrolments: enriched
      });

    } catch (err) {
      console.error('[GMS /me]', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms/check-session ─────────────────────────────────
  app.get('/api/gms/check-session', async (req, res) => {
    try {
      const token = req.headers['x-user-token'];
      const user  = await getUserFromToken(token);
      if (!user) return res.json({ loggedIn: false });
      return res.json({
        loggedIn: true,
        user: {
          user_id:    user.user_id,
          first_name: user.first_name,
          last_name:  user.last_name,
          mobile:     user.mobile,
          email:      user.email
        }
      });
    } catch (err) {
      return res.json({ loggedIn: false });
    }
  });

  // ── POST /api/gms/logout ───────────────────────────────────────
  app.post('/api/gms/logout', async (req, res) => {
    try {
      const token = req.headers['x-user-token'] || req.body?.userToken;
      if (token) await db.query('DELETE FROM gms_user_sessions WHERE token = ?', [token]);
      return res.json({ success: true });
    } catch (err) {
      return res.json({ success: true });
    }
  });

 
 // ── POST /api/gms/update-profile ──────────────────────────────
  app.post('/api/gms/update-profile', async (req, res) => {
    try {
      const token = req.headers['x-user-token'];
      const user  = await getUserFromToken(token);
      if (!user) return res.status(401).json({ success: false, message: 'Not logged in.' });
      const { email, address1, address2, city, state, pincode, photo_url } = req.body;
      await db.query(
        `UPDATE gms_users SET
          email=COALESCE(NULLIF(?,''),email), address1=COALESCE(NULLIF(?,''),address1),
          address2=?, city=COALESCE(NULLIF(?,''),city), state=COALESCE(NULLIF(?,''),state),
          pincode=COALESCE(NULLIF(?,''),pincode), photo_url=COALESCE(NULLIF(?,''),photo_url)
         WHERE user_id=?`,
        [email||'', address1||'', address2||'', city||'', state||'', pincode||'', photo_url||'', user.user_id]
      );
      const [rows] = await db.query('SELECT * FROM gms_users WHERE user_id=?', [user.user_id]);
      return res.json({ success: true, message: 'Profile updated.', user: rows[0] });
    } catch (err) {
      return res.status(500).json({ success: false, message: 'Update failed.' });
    }
  });

  // ── POST /api/gms/send-secondary-otp ─────────────────────────
  app.post('/api/gms/send-secondary-otp', async (req, res) => {
    try {
      const token = req.headers['x-user-token'];
      const user  = await getUserFromToken(token);
      if (!user) return res.status(401).json({ success: false, message: 'Not logged in.' });
      const secondary = cleanPhone(req.body.phone);
      if (secondary.length !== 10) return res.status(400).json({ success: false, message: 'Enter valid 10-digit number.' });
      if (secondary === user.mobile) return res.status(400).json({ success: false, message: 'Cannot be same as primary number.' });
      const otp = generateOtp();
      cache.set(`gms_sec_otp:${user.user_id}:${secondary}`, { otp }, 600);
      await sendSms(secondary, `Dear user, your WHP Jewellers otp code is ${otp}`);
      return res.json({ success: true, message: `OTP sent to +91 ${secondary}` });
    } catch (err) {
      return res.status(500).json({ success: false, message: 'Failed to send OTP.' });
    }
  });

  // ── POST /api/gms/verify-secondary-otp ───────────────────────
  app.post('/api/gms/verify-secondary-otp', async (req, res) => {
    try {
      const token = req.headers['x-user-token'];
      const user  = await getUserFromToken(token);
      if (!user) return res.status(401).json({ success: false, message: 'Not logged in.' });
      const secondary = cleanPhone(req.body.phone);
      const { otp }   = req.body;
      const stored    = cache.get(`gms_sec_otp:${user.user_id}:${secondary}`);
      if (!stored) return res.status(400).json({ success: false, message: 'OTP expired.' });
      if (String(stored.otp) !== String(otp)) return res.status(400).json({ success: false, message: 'Incorrect OTP.' });
      await db.query('UPDATE gms_users SET secondary_mobile=? WHERE user_id=?', [secondary, user.user_id]);
      cache.del(`gms_sec_otp:${user.user_id}:${secondary}`);
      return res.json({ success: true, message: 'Secondary number saved.' });
    } catch (err) {
      return res.status(500).json({ success: false, message: 'Verification failed.' });
    }
  });

  console.log('[GMS User] Auth routes loaded');
};
