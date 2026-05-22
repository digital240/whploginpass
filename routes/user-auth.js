// routes/user-auth.js — Customer OTP, register, login, logout
// Shopify sync: existing Shopify customers auto-login, new GMS users push to Shopify

const db    = require('../db');
const axios = require('axios');
const { getUserFromToken, createUserSession } = require('../helpers/auth');
const { sendSms }                 = require('../helpers/sms');
const { generateOtp, cleanPhone } = require('../helpers/utils');

// ── Shopify helpers ───────────────────────────────────────
function shopifyHeaders() {
  return {
    'X-Shopify-Access-Token': process.env.SHOPIFY_ACCESS_TOKEN,
    'Content-Type': 'application/json'
  };
}
function shopifyBase() {
  return `https://${process.env.SHOPIFY_SHOP_DOMAIN}/admin/api/2024-01`;
}

async function findShopifyCustomer(mobile) {
  try {
    const base    = shopifyBase();
    const headers = shopifyHeaders();
    for (const q of [`phone:+91${mobile}`, `phone:${mobile}`]) {
      const res = await axios.get(
        `${base}/customers/search.json?query=${encodeURIComponent(q)}&fields=id,first_name,last_name,email,phone`,
        { headers, timeout: 8000 }
      );
      if (res.data.customers?.length) return res.data.customers[0];
    }
    return null;
  } catch(e) {
    console.error('[Shopify] Search error:', e.message);
    return null;
  }
}

async function createShopifyCustomer(user) {
  try {
    const res = await axios.post(`${shopifyBase()}/customers.json`, {
      customer: {
        first_name: user.first_name, last_name: user.last_name || '',
        email: user.email || '', phone: `+91${user.mobile}`,
        verified_email: !!(user.email),
        send_email_welcome: false, tags: 'gms-member'
      }
    }, { headers: shopifyHeaders(), timeout: 10000 });
    return res.data.customer?.id || null;
  } catch(e) {
    console.error('[Shopify] Create error:', e.message);
    return null;
  }
}

// ═══════════════════════════════════════════════════════════
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
      cache.set(`gms_otp:${mobile}`,          { otp, verified: false }, 600);
      cache.set(`otp:${mobile}`,              { phone: mobile, verified: false }, 600);
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
      const mobile  = cleanPhone(req.body.phone);
      const { otp } = req.body;
      const stored  = cache.get(`gms_otp:${mobile}`);
      let attempts  = cache.get(`gms_otp_attempts:${mobile}`) || 0;

      if (!stored) return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
      if (attempts >= 3) {
        cache.del(`gms_otp:${mobile}`);
        return res.status(429).json({ success: false, message: 'Too many wrong attempts. Request a new OTP.' });
      }
      if (String(stored.otp) !== String(otp)) {
        cache.set(`gms_otp_attempts:${mobile}`, attempts + 1, 600);
        return res.status(400).json({ success: false, message: `Incorrect OTP. ${3-attempts-1} attempt(s) left.` });
      }

      // OTP correct
      cache.set(`gms_otp:${mobile}`, { otp, verified: true }, 300);
      cache.set(`otp:${mobile}`,     { phone: mobile, verified: true }, 300);

      // Step 1: Check gms_users
      const [rows] = await db.query('SELECT * FROM gms_users WHERE mobile=?', [mobile]);
      if (rows.length) {
        const user      = rows[0];
        const userToken = await createUserSession(user.user_id);
        console.log(`[GMS] Login: ${user.first_name} (${mobile})`);
        return res.json({
          success: true, verified: true, needsRegistration: false, userToken,
          user: { user_id: user.user_id, first_name: user.first_name, last_name: user.last_name, mobile: user.mobile, email: user.email }
        });
      }

      // Step 2: Not in GMS — check Shopify
      console.log(`[GMS] Not in gms_users, checking Shopify for +91${mobile}`);
      const sc = await findShopifyCustomer(mobile);

      if (sc) {
        // Found in Shopify — auto-create gms_users + login (no registration form!)
        console.log(`[GMS] Found in Shopify: ${sc.first_name} (id: ${sc.id})`);
        const [result] = await db.query(
          'INSERT INTO gms_users (first_name, last_name, mobile, email, shopify_customer_id) VALUES (?,?,?,?,?)',
          [sc.first_name||'', sc.last_name||'', mobile, sc.email||'', String(sc.id)]
        );
        const userToken = await createUserSession(result.insertId);
        console.log(`[GMS] Auto-imported from Shopify: ${sc.first_name} (${mobile})`);
        return res.json({
          success: true, verified: true, needsRegistration: false,
          autoImported: true, userToken,
          user: { user_id: result.insertId, first_name: sc.first_name||'', last_name: sc.last_name||'', mobile, email: sc.email||'' }
        });
      }

      // Step 3: Not found anywhere — show registration form
      console.log(`[GMS] Not found anywhere — registration needed for ${mobile}`);
      return res.json({ success: true, verified: true, needsRegistration: true, phone: mobile });

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

      // Save to gms_users
      const [result] = await db.query(
        'INSERT INTO gms_users (first_name, last_name, mobile, email) VALUES (?,?,?,?)',
        [firstName.trim(), (lastName||'').trim(), mobile, (email||'').trim()]
      );

      // Push to Shopify in background (non-blocking)
      createShopifyCustomer({ first_name: firstName.trim(), last_name: (lastName||'').trim(), mobile, email: (email||'').trim() })
        .then(shopifyId => {
          if (shopifyId) {
            db.query('UPDATE gms_users SET shopify_customer_id=? WHERE user_id=?', [String(shopifyId), result.insertId])
              .then(() => console.log(`[GMS] Shopify customer created: ${shopifyId}`))
              .catch(e => console.error('[GMS] Shopify ID save error:', e.message));
          }
        }).catch(e => console.error('[GMS] Shopify push error:', e.message));

      const userToken = await createUserSession(result.insertId);
      cache.set(`otp:${mobile}`, { phone: mobile, verified: true }, 300);
      console.log(`[GMS] Registered: ${firstName} (${mobile})`);
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

  // ── POST /api/gms/auto-login-after-enrol ────────────
  // Called after enrolment — phone already OTP verified, auto login or create account
  app.post('/api/gms/auto-login-after-enrol', async (req, res) => {
    try {
      const { phone, name, email, enrolmentId } = req.body;
      const cp = cleanPhone(phone);
      if (!cp) return res.status(400).json({ success: false, message: 'Invalid phone.' });

      // Check if user exists
      const [rows] = await db.query('SELECT * FROM gms_users WHERE mobile=?', [cp]);

      let userId;
      if (rows.length) {
        // Existing user — just login
        userId = rows[0].user_id;
        console.log(`[GMS] Auto-login existing user: ${cp}`);
      } else {
        // New user — create account from enrolment data
        const nameParts = (name || '').trim().split(' ');
        const firstName = nameParts[0] || '';
        const lastName  = nameParts.slice(1).join(' ') || '';
        const [result] = await db.query(
          'INSERT INTO gms_users (first_name, last_name, mobile, email) VALUES (?,?,?,?)',
          [firstName, lastName, cp, email || '']
        );
        userId = result.insertId;
        console.log(`[GMS] Auto-created user for: ${cp}`);
      }

      // Link enrolment to user
      if (enrolmentId) {
        await db.query(
          'UPDATE gms_enrolments SET user_id=? WHERE enrolment_id=? AND (user_id IS NULL OR user_id=0)',
          [userId, enrolmentId]
        );
      }

      // Create session token
      const userToken = await createUserSession(userId);
      const [userRows] = await db.query('SELECT * FROM gms_users WHERE user_id=?', [userId]);

      return res.json({
        success: true,
        token: userToken,
        user: {
          user_id:    userRows[0].user_id,
          first_name: userRows[0].first_name,
          last_name:  userRows[0].last_name,
          mobile:     userRows[0].mobile,
          email:      userRows[0].email
        }
      });
    } catch(err) {
      console.error('[GMS] auto-login-after-enrol error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] User auth routes loaded');
};
