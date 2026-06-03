// routes/app-auth.js — WHP Mobile App Authentication
// Token stored in app_sessions (revokable)
// Shopify = single source of truth for customer data
// Tags: gms-member (GMS portal login), whp-app (mobile app login)

const crypto  = require('crypto');
const axios   = require('axios');
const db      = require('../db');
const { sendSms, SMS } = require('../helpers/sms');

const SHOPIFY_DOMAIN  = process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_TOKEN   = process.env.SHOPIFY_ADMIN_TOKEN;
const OTP_EXPIRY_MIN  = 2;
const MAX_ATTEMPTS    = 5;
const LOCK_MINUTES    = 15;
const SESSION_DAYS    = 30;
const APP_TAG         = 'whp-app';

// ── Shopify Admin API helpers ────────────────────────────

async function shopifyGet(path) {
  const res = await axios.get(`https://${SHOPIFY_DOMAIN}/admin/api/2024-04/${path}`, {
    headers: { 'X-Shopify-Access-Token': SHOPIFY_TOKEN }
  });
  return res.data;
}

async function shopifyPut(path, body) {
  const res = await axios.put(`https://${SHOPIFY_DOMAIN}/admin/api/2024-04/${path}`, body, {
    headers: { 'X-Shopify-Access-Token': SHOPIFY_TOKEN, 'Content-Type': 'application/json' }
  });
  return res.data;
}

async function shopifyPost(path, body) {
  const res = await axios.post(`https://${SHOPIFY_DOMAIN}/admin/api/2024-04/${path}`, body, {
    headers: { 'X-Shopify-Access-Token': SHOPIFY_TOKEN, 'Content-Type': 'application/json' }
  });
  return res.data;
}

// Find Shopify customer by phone
async function findShopifyCustomer(mobile) {
  const data = await shopifyGet(`customers/search.json?query=phone:+91${mobile}&limit=1`);
  return data.customers?.[0] || null;
}

// Create Shopify customer
async function createShopifyCustomer(mobile) {
  const data = await shopifyPost('customers.json', {
    customer: {
      phone: `+91${mobile}`,
      first_name: 'WHP',
      last_name:  'Customer',
      verified_email: false,
      send_email_welcome: false,
      tags: APP_TAG,
    }
  });
  return data.customer;
}

// Add tag to Shopify customer without removing existing tags
async function addShopifyTag(shopifyId, newTag) {
  const data = await shopifyGet(`customers/${shopifyId}.json`);
  const existing = data.customer?.tags || '';
  const tagList  = existing.split(',').map(t => t.trim()).filter(Boolean);
  if (tagList.includes(newTag)) return; // already tagged
  tagList.push(newTag);
  await shopifyPut(`customers/${shopifyId}.json`, {
    customer: { id: shopifyId, tags: tagList.join(', ') }
  });
  console.log(`[APP AUTH] Added tag "${newTag}" to Shopify customer ${shopifyId}`);
}

// ── Session token helpers ────────────────────────────────

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function createSession(customerId, mobile) {
  const token     = generateToken();
  const expiresAt = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await db.query(
    `INSERT INTO app_sessions (customer_id, mobile, token, expires_at, created_at)
     VALUES (?, ?, ?, ?, NOW())`,
    [customerId, mobile, token, expiresAt]
  );
  return token;
}

async function getSession(token) {
  const [rows] = await db.query(
    `SELECT s.*, c.name, c.email, c.photo, c.shopify_id
     FROM app_sessions s
     JOIN app_customers c ON c.id = s.customer_id
     WHERE s.token = ? AND s.expires_at > NOW()
     LIMIT 1`,
    [token]
  );
  return rows[0] || null;
}

// ── Auth middleware ──────────────────────────────────────

async function appAuth(req, res, next) {
  const header = req.headers['x-app-token'] || req.headers['authorization'];
  const token  = header?.startsWith('Bearer ') ? header.slice(7) : header;
  if (!token) return res.status(401).json({ success: false, message: 'No token provided.' });

  const session = await getSession(token).catch(() => null);
  if (!session) return res.status(401).json({ success: false, message: 'Invalid or expired session.' });

  req.appUser = session;
  next();
}

// ════════════════════════════════════════════════════════
module.exports = (app, cache) => {

  // ── POST /api/app/send-otp ───────────────────────────
  app.post('/api/app/send-otp', async (req, res) => {
    try {
      const mobile = (req.body.phone || '').replace(/\D/g, '').slice(-10);
      if (!/^[6-9]\d{9}$/.test(mobile)) {
        return res.status(400).json({ success: false, message: 'Invalid mobile number.' });
      }

      // Check lock
      const [lockRows] = await db.query(
        `SELECT attempts, locked_until FROM app_otps WHERE phone = ? LIMIT 1`,
        [mobile]
      );
      if (lockRows[0]?.locked_until && new Date(lockRows[0].locked_until) > new Date()) {
        return res.status(429).json({ success: false, message: 'Too many attempts. Try again in 15 minutes.' });
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();

      await db.query(
        `INSERT INTO app_otps (phone, otp, expires_at, attempts, locked_until)
         VALUES (?, ?, DATE_ADD(NOW(), INTERVAL ? MINUTE), 0, NULL)
         ON DUPLICATE KEY UPDATE
           otp          = VALUES(otp),
           expires_at   = VALUES(expires_at),
           attempts     = 0,
           locked_until = NULL`,
        [mobile, otp, OTP_EXPIRY_MIN]
      );

      await sendSms(mobile, SMS.otp(otp), 'otp');
      console.log(`[APP AUTH] OTP sent to ${mobile}`);
      res.json({ success: true, message: 'OTP sent.' });

    } catch (err) {
      console.error('[APP AUTH] send-otp error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to send OTP.' });
    }
  });


  // ── POST /api/app/verify-otp ─────────────────────────
  app.post('/api/app/verify-otp', async (req, res) => {
    try {
      const mobile = (req.body.phone || '').replace(/\D/g, '').slice(-10);
      const otp    = (req.body.otp   || '').trim();

      if (!mobile || !/^\d{6}$/.test(otp)) {
        return res.status(400).json({ success: false, message: 'Phone and 6-digit OTP required.' });
      }

      // Fetch OTP record
      const [rows] = await db.query(
        `SELECT * FROM app_otps WHERE phone = ? LIMIT 1`, [mobile]
      );
      const record = rows[0];

      // Locked?
      if (record?.locked_until && new Date(record.locked_until) > new Date()) {
        return res.status(429).json({ success: false, message: 'Too many attempts. Try again in 15 minutes.' });
      }

      const expired = !record || new Date(record.expires_at) < new Date();
      const wrong   = !record || record.otp !== otp;

      if (expired || wrong) {
        if (record) {
          const newAttempts = (record.attempts || 0) + 1;
          if (newAttempts >= MAX_ATTEMPTS) {
            await db.query(
              `UPDATE app_otps SET attempts = ?, locked_until = DATE_ADD(NOW(), INTERVAL ${LOCK_MINUTES} MINUTE) WHERE phone = ?`,
              [newAttempts, mobile]
            );
          } else {
            await db.query(
              `UPDATE app_otps SET attempts = ? WHERE phone = ?`,
              [newAttempts, mobile]
            );
          }
        }
        return res.status(401).json({
          success: false,
          message: expired ? 'OTP expired. Request a new one.' : 'Incorrect OTP.'
        });
      }

      // ✅ OTP valid — clear it
      await db.query(`DELETE FROM app_otps WHERE phone = ?`, [mobile]);

      // ── Customer lookup / creation ────────────────────

      // 1. Check app_customers
      const [appRows] = await db.query(
        `SELECT * FROM app_customers WHERE mobile = ? LIMIT 1`, [mobile]
      );
      let appCustomer = appRows[0];

      if (!appCustomer) {
        // 2. Check Shopify
        let shopifyCustomer = await findShopifyCustomer(mobile);

        if (!shopifyCustomer) {
          // 3. New to WHP entirely — create in Shopify first
          shopifyCustomer = await createShopifyCustomer(mobile);
          console.log(`[APP AUTH] Created Shopify customer ${shopifyCustomer.id} for ${mobile}`);
        } else {
          // 4. Exists in Shopify — add whp-app tag
          await addShopifyTag(shopifyCustomer.id, APP_TAG);
          console.log(`[APP AUTH] Found Shopify customer ${shopifyCustomer.id} for ${mobile}`);
        }

        // 5. Create app_customers record
        const fullName = [shopifyCustomer.first_name, shopifyCustomer.last_name].filter(Boolean).join(' ') || 'WHP Customer';
        await db.query(
          `INSERT INTO app_customers (mobile, name, email, shopify_id, created_at)
           VALUES (?, ?, ?, ?, NOW())`,
          [mobile, fullName, shopifyCustomer.email || '', shopifyCustomer.id]
        );

        const [newRows] = await db.query(
          `SELECT * FROM app_customers WHERE mobile = ? LIMIT 1`, [mobile]
        );
        appCustomer = newRows[0];
      } else {
        // Existing app customer — ensure whp-app tag is on Shopify
        if (appCustomer.shopify_id) {
          await addShopifyTag(appCustomer.shopify_id, APP_TAG).catch(() => {});
        }
      }

      // ── Create session ────────────────────────────────
      const token = await createSession(appCustomer.id, mobile);

      res.json({
        success: true,
        token,
        customer: {
          id:         appCustomer.id,
          mobile:     appCustomer.mobile,
          name:       appCustomer.name,
          email:      appCustomer.email,
          shopify_id: appCustomer.shopify_id,
        }
      });

    } catch (err) {
      console.error('[APP AUTH] verify-otp error:', err.message);
      res.status(500).json({ success: false, message: 'Verification failed.' });
    }
  });


  // ── GET /api/app/me ──────────────────────────────────
  app.get('/api/app/me', appAuth, async (req, res) => {
    const u = req.appUser;
    res.json({
      success: true,
      customer: {
        id:         u.customer_id,
        mobile:     u.mobile,
        name:       u.name,
        email:      u.email,
        photo:      u.photo,
        shopify_id: u.shopify_id,
      }
    });
  });


  // ── PUT /api/app/profile ─────────────────────────────
  app.put('/api/app/profile', appAuth, async (req, res) => {
    try {
      const { name, email } = req.body;
      await db.query(
        `UPDATE app_customers SET name = ?, email = ? WHERE id = ?`,
        [name || '', email || '', req.appUser.customer_id]
      );

      // Sync to Shopify
      if (req.appUser.shopify_id) {
        const [first_name, ...rest] = (name || '').split(' ');
        const last_name = rest.join(' ');
        await shopifyPut(`customers/${req.appUser.shopify_id}.json`, {
          customer: { id: req.appUser.shopify_id, first_name, last_name, email }
        }).catch(e => console.warn('[APP AUTH] Shopify sync failed:', e.message));
      }

      res.json({ success: true, message: 'Profile updated.' });
    } catch (err) {
      console.error('[APP AUTH] profile error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to update profile.' });
    }
  });


  // ── POST /api/app/logout ─────────────────────────────
  app.post('/api/app/logout', appAuth, async (req, res) => {
    try {
      const header = req.headers['x-app-token'] || req.headers['authorization'];
      const token  = header?.startsWith('Bearer ') ? header.slice(7) : header;
      await db.query(`DELETE FROM app_sessions WHERE token = ?`, [token]);
      console.log(`[APP AUTH] Logout: customer ${req.appUser.customer_id}`);
      res.json({ success: true, message: 'Logged out.' });
    } catch (err) {
      res.status(500).json({ success: false, message: 'Logout failed.' });
    }
  });

};

// Export middleware for use in other route files
module.exports.appAuth = appAuth;
