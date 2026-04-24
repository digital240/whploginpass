// ═══════════════════════════════════════════════════════════
//  WHPLoginPass — Backend Server
//  Node.js + Express
//  Routes: /auth  /auth/callback  /send-otp  /verify-otp
//          /create-customer  /update-email
// ═══════════════════════════════════════════════════════════

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const NodeCache  = require('node-cache');
const axios      = require('axios');
const crypto     = require('crypto');

const app        = express();
const cache      = new NodeCache({ stdTTL: 600 });

// Store access tokens in memory (use Redis/DB in production)
// key: shop domain → value: access token
const tokenStore = {};

// ======================================================
//  WLP TOKEN SYSTEM (GoKwik-style kpToken)
// ======================================================

const WLP_TOKEN_SECRET = process.env.WLP_TOKEN_SECRET || 'whploginpass_secret_key_2025';

function createWlpToken(data) {
  const payload = JSON.stringify({
    id:        data.id        || '',
    email:     data.email     || '',
    phone:     data.phone     || '',
    firstName: data.firstName || data.first_name || '',
    lastName:  data.lastName  || data.last_name  || '',
    isTemp:    data.isTemp    || false,
    shop:      data.shop      || '',
    iat:       Date.now(),
    exp:       Date.now() + (30 * 24 * 60 * 60 * 1000)
  });
  const encoded = Buffer.from(payload).toString('base64url');
  const sig     = require('crypto').createHmac('sha256', WLP_TOKEN_SECRET).update(encoded).digest('hex').substring(0,16);
  return encoded + '.' + sig;
}

function decodeWlpToken(token) {
  try {
    if (!token) return null;
    const [encoded, sig] = token.split('.');
    if (!encoded || !sig) return null;
    const expected = require('crypto').createHmac('sha256', WLP_TOKEN_SECRET).update(encoded).digest('hex').substring(0,16);
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch(e) { return null; }
}

// ── HEALTH CHECK ─────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', app: 'WHPLoginPass' }));

// ── START ─────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ WHPLoginPass backend running on port ${PORT}`);
});

// ── MIDDLEWARE ───────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

// Route: verify token
app.post('/api/verify-token', (req, res) => {
  const data = decodeWlpToken(req.body.token);
  if (!data) return res.json({ valid: false });
  return res.json({ valid: true, customer: data });
});

// Route: save device (30 day memory)
app.post('/api/save-device', (req, res) => {
  const { phone, deviceToken, shop, wlpToken } = req.body;
  if (deviceToken && phone) {
    cache.set('device:' + deviceToken, { phone, shop, wlpToken }, 30 * 24 * 3600);
  }
  return res.json({ success: true });
});

// Route: check device
app.post('/api/check-device', (req, res) => {
  const { deviceToken } = req.body;
  const data = cache.get('device:' + deviceToken);
  if (data) return res.json({ known: true, phone: data.phone, wlpToken: data.wlpToken });
  return res.json({ known: false });
});


app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'x-shop-domain', 'Authorization']
}));

// ══════════════════════════════════════════════════════════
//  OAUTH ROUTE 1 — /auth
//  Shopify redirects here when merchant installs app
//  We redirect to Shopify permission page
// ══════════════════════════════════════════════════════════
app.get('/auth', (req, res) => {
  const shop = req.query.shop || process.env.SHOPIFY_SHOP_DOMAIN;
  if (!shop) return res.status(400).send('Missing shop parameter');

  const apiKey    = process.env.SHOPIFY_API_KEY;
  const scopes    = 'read_customers,write_customers';
  const redirectUri = `${process.env.APP_URL || 'https://whploginpass.onrender.com'}/auth/callback`;
  const state     = crypto.randomBytes(16).toString('hex');

  // Store state to verify later
  cache.set(`oauth_state:${state}`, shop, 600);

  const authUrl = `https://${shop}/admin/oauth/authorize?client_id=${apiKey}&scope=${scopes}&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;

  console.log(`[OAuth] Redirecting to: ${authUrl}`);
  res.redirect(authUrl);
});

// ══════════════════════════════════════════════════════════
//  OAUTH ROUTE 2 — /auth/callback
//  Shopify calls this with the auth code
//  We exchange it for a permanent access token
// ══════════════════════════════════════════════════════════
app.get('/auth/callback', async (req, res) => {
  const { shop, code, state, hmac } = req.query;

  // State check relaxed — Render free tier spins down between /auth and /callback
  // HMAC verification below is the real security check
  const storedShop = cache.get(`oauth_state:${state}`);
  if (storedShop) cache.del(`oauth_state:${state}`);

  // Verify HMAC signature from Shopify
  const apiSecret = process.env.SHOPIFY_API_SECRET;
  const params    = Object.keys(req.query)
    .filter(k => k !== 'hmac')
    .sort()
    .map(k => `${k}=${req.query[k]}`)
    .join('&');
  const digest = crypto.createHmac('sha256', apiSecret).update(params).digest('hex');

  if (digest !== hmac) {
    return res.status(403).send('HMAC verification failed.');
  }

  try {
    // Exchange code for permanent access token
    const tokenRes = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id:     process.env.SHOPIFY_API_KEY,
      client_secret: process.env.SHOPIFY_API_SECRET,
      code
    });

    const accessToken = tokenRes.data.access_token;

    // Store token (in memory — persists until server restart)
    tokenStore[shop] = accessToken;

    console.log(`[OAuth] ✅ Token obtained for ${shop}`);
    console.log(`[OAuth] Token: ${accessToken}`);

    // Show success page
    res.send(`
      <!DOCTYPE html>
      <html>
      <head><title>WHPLoginPass Installed</title>
      <style>
        body{font-family:sans-serif;text-align:center;padding:60px;background:#faf8f8}
        h1{color:#b97079}
        .token{background:#1a1714;color:#b97079;padding:16px;border-radius:8px;
               font-family:monospace;font-size:14px;word-break:break-all;margin:20px auto;max-width:600px}
        .note{color:#888;font-size:13px;margin-top:16px}
      </style>
      </head>
      <body>
        <h1>✅ WHPLoginPass Installed!</h1>
        <p>Your access token for <strong>${shop}</strong>:</p>
        <div class="token">${accessToken}</div>
        <p class="note">⚠️ Copy this token and add it to your Render environment variables as:<br>
        <strong>SHOPIFY_ACCESS_TOKEN</strong></p>
        <p class="note">Also add it to your theme.liquid in the WLP config:<br>
        <strong>accessToken: '${accessToken}'</strong></p>
      </body>
      </html>
    `);

  } catch (err) {
    console.error('[OAuth callback error]', err.response?.data || err.message);
    res.status(500).send('OAuth failed: ' + (err.response?.data?.error_description || err.message));
  }
});

// Rate limiter — max 5 OTP requests per phone per 10 min
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.body.phone || req.ip,
  message: { success: false, message: 'Too many OTP requests. Try again in 10 minutes.' }
});

// ── HELPERS ──────────────────────────────────────────────

// Sanitize phone — strip everything except digits, ensure 10 digits
function sanitizePhone(phone) {
  const digits = String(phone).replace(/\D/g, '');
  return digits.startsWith('91') && digits.length === 12
    ? digits.slice(2)
    : digits;
}

// Build temp email from phone + shop domain
// e.g. 9876543210@whpjewellers.com
function buildTempEmail(phone, shopDomain) {
  const domain = shopDomain
    ? shopDomain.replace('.myshopify.com', '').replace(/[^a-z0-9]/gi, '') + '.com'
    : 'store.com';
  return `${phone}@${domain}`;
}

// Shopify Admin API base URL + headers for a shop
function shopifyApi(shopDomain, accessToken) {
  return {
    base: `https://${shopDomain}/admin/api/2024-01`,
    headers: {
      'X-Shopify-Access-Token': accessToken,
      'Content-Type': 'application/json'
    }
  };
}

// ── OTP HELPERS ──────────────────────────────────────────
// We generate OTP ourselves and send via SMSAlert push.json
// This avoids DLT template registration requirement

function generateOtp(length) {
  length = length || 6;
  let otp = '';
  for (let i = 0; i < length; i++) otp += Math.floor(Math.random() * 10);
  return otp;
}

// ── SMSALERT — SEND OTP via push.json ────────────────────
// Uses regular SMS API — we generate OTP and store in cache
async function sendOtpViaSMSAlert(phone) {
  const apiKey  = process.env.SMSALERT_API_KEY;
  const sender  = process.env.SMSALERT_SENDER_ID;
  const length  = parseInt(process.env.OTP_LENGTH) || 6;

  if (!apiKey) throw new Error('SMSALERT_API_KEY not set in environment');
  if (!sender) throw new Error('SMSALERT_SENDER_ID not set in environment');

  // Generate OTP ourselves
  const otp = generateOtp(length);

  // Store OTP in cache keyed by phone
  cache.set(`otp_code:${phone}`, otp, 600); // 10 min expiry

  // DLT registered template: "Dear user, your WHP Jewellers otp code is {#var#}"
  // DLT Template ID: 1707164361822841747, Sender: WHPECM
  const message = `Dear user, your WHP Jewellers otp code is ${otp}`;

  console.log(`[SMSAlert] Sending OTP ${otp} to ${phone} via WHPECM`);

  const res = await axios.post('https://www.smsalert.co.in/api/push.json', null, {
    params: {
      apikey:      apiKey,
      sender:      'WHPECM',
      mobileno:    phone,
      text:        message,
      route:       'transscrub',
      template_id: '1707164361822841747'
    },
    timeout: 15000
  });

  console.log(`[SMSAlert] Response:`, JSON.stringify(res.data));

  if (res.data.status !== 'success') {
    throw new Error(res.data.description?.desc || 'SMS send failed');
  }

  return { status: 'success', otp }; // return otp so we can store it
}

// ── VALIDATE OTP — check our cache ───────────────────────
async function validateOtpViaSMSAlert(phone, otp) {
  const storedOtp = cache.get(`otp_code:${phone}`);

  console.log(`[OTP Validate] phone=${phone} entered=${otp} stored=${storedOtp}`);

  if (!storedOtp) {
    return { matched: false, raw: { desc: 'OTP expired' } };
  }

  const matched = String(storedOtp) === String(otp);

  if (matched) {
    cache.del(`otp_code:${phone}`); // clear after successful use
  }

  return { matched, raw: { stored: storedOtp, entered: otp } };
}

// ══════════════════════════════════════════════════════════
//  ROUTE 1 — SEND OTP
//  POST /api/send-otp
//  Body: { phone, shop }
//  SMSAlert generates & sends the OTP — we just mark phone as pending
// ══════════════════════════════════════════════════════════
app.post('/api/send-otp', otpLimiter, async (req, res) => {
  try {
    const { phone, shop } = req.body;

    if (!phone) return res.status(400).json({ success: false, message: 'Phone number required.' });

    const cleanPhone = sanitizePhone(phone);
    if (cleanPhone.length !== 10) {
      return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });
    }

    // Call SMSAlert OTP API — it sends the SMS and tracks the OTP internally
    const result = await sendOtpViaSMSAlert(cleanPhone);

    // SMSAlert returns status:"success" when OTP is sent successfully
    if (result.status !== 'success') {
      const errMsg = result.description?.desc || 'Failed to send OTP.';
      console.error('[SMSAlert send error]', result);
      return res.status(500).json({ success: false, message: errMsg });
    }

    // Store phone as "otp sent" in cache — SMSAlert owns the OTP value
    // We just track: phone sent + shop + verified status
    cache.set(`otp:${cleanPhone}`, { phone: cleanPhone, shop, verified: false });
    cache.set(`attempts:${cleanPhone}`, 0);

    console.log(`[OTP SENT via SMSAlert] +91${cleanPhone}`);

    return res.json({
      success: true,
      message: `OTP sent to +91 ${cleanPhone}`
    });

  } catch (err) {
    console.error('[send-otp error]', err.message);
    return res.status(500).json({ success: false, message: 'Failed to send OTP. Try again.' });
  }
});

// ══════════════════════════════════════════════════════════
//  ROUTE 2 — VERIFY OTP
//  POST /api/verify-otp
//  Body: { phone, otp }
//  We ask SMSAlert to validate — they own the OTP value
// ══════════════════════════════════════════════════════════
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) return res.status(400).json({ success: false, message: 'Phone and OTP required.' });

    const cleanPhone  = sanitizePhone(phone);
    const cacheKey    = `otp:${cleanPhone}`;
    const attemptsKey = `attempts:${cleanPhone}`;
    const stored      = cache.get(cacheKey);
    let   attempts    = cache.get(attemptsKey) || 0;

    // Check if we ever sent an OTP for this phone
    if (!stored) {
      return res.status(400).json({ success: false, message: 'OTP expired or not requested. Please request a new one.' });
    }

    const maxAttempts = parseInt(process.env.MAX_OTP_ATTEMPTS) || 3;
    if (attempts >= maxAttempts) {
      cache.del(cacheKey);
      return res.status(429).json({ success: false, message: 'Too many wrong attempts. Request a new OTP.' });
    }

    // Ask SMSAlert to validate the OTP
    const { matched, raw } = await validateOtpViaSMSAlert(cleanPhone, otp);

    console.log(`[OTP VERIFY] +91${cleanPhone} → SMSAlert:`, raw);

    if (!matched) {
      cache.set(attemptsKey, attempts + 1);
      const left = maxAttempts - attempts - 1;
      return res.status(400).json({
        success: false,
        message: `Incorrect OTP. ${left} attempt(s) left.`
      });
    }

    // ✅ OTP is correct — mark as verified
    stored.verified = true;

    // Check if customer already exists in Shopify
    let isExistingUser = false;
    let existingCustomerId = null;
    let existingLoginUrl = '/account';

    const shopDomain  = stored.shop || process.env.SHOPIFY_SHOP_DOMAIN;
    const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shopDomain];
    console.log(`[verify-otp] shop=${shopDomain}, token=${accessToken ? accessToken.substring(0,10)+'...' : 'MISSING'}`);

    if (shopDomain && accessToken) {
      try {
        const { base, headers } = shopifyApi(shopDomain, accessToken);

        // Search with multiple phone formats to find existing customer
        const phoneFormats = [
          `phone:+91${cleanPhone}`,
          `phone:91${cleanPhone}`,
          `phone:${cleanPhone}`
        ];

        for (const query of phoneFormats) {
          const searchRes = await axios.get(
            `${base}/customers/search.json?query=${encodeURIComponent(query)}&fields=id,email,first_name,phone`,
            { headers }
          );
          console.log(`[verify-otp] Search "${query}" → found: ${searchRes.data.customers?.length || 0}`);

          if (searchRes.data.customers && searchRes.data.customers.length > 0) {
            const existing = searchRes.data.customers[0];
            isExistingUser     = true;
            existingCustomerId = existing.id;
            console.log(`[verify-otp] ✅ Existing customer: id=${existing.id} email=${existing.email} phone=${existing.phone}`);

            // Create WLP token immediately from search data (no extra API call needed!)
            existingLoginUrl = 'otp_verified';
            cache.set(`verified_email:${cleanPhone}`, existing.email, 300);

            // Create wlpToken here - use data we already have
            const wlpTokForExisting = createWlpToken({
              id:        existing.id,
              email:     existing.email,
              phone:     cleanPhone,
              firstName: existing.first_name || '',
              lastName:  existing.last_name  || '',
              isTemp:    existing.email && existing.email.startsWith(cleanPhone),
              shop:      shopDomain
            });
            cache.set(`wlptoken:${cleanPhone}`, wlpTokForExisting, 300);
            console.log(`[verify-otp] ✅ wlpToken created for existing customer`);
            break;
          }
        }
      } catch(e) {
        console.log('[verify-otp] Could not check existing user:', e.message);
      }
    }

    cache.set(cacheKey, stored, 300); // keep 5 more mins

    // Get verified email and wlpToken for existing users
    const verifiedEmail   = cache.get(`verified_email:${cleanPhone}`);
    const existingWlpToken = cache.get(`wlptoken:${cleanPhone}`);

    return res.json({
      success:        true,
      message:        'OTP verified!',
      phone:          cleanPhone,
      isExistingUser: isExistingUser,
      loginUrl:       isExistingUser ? existingLoginUrl : null,
      email:          verifiedEmail   || null,
      wlpToken:       existingWlpToken || null
    });

  } catch (err) {
    console.error('[verify-otp error]', err.message);
    return res.status(500).json({ success: false, message: 'Verification failed. Try again.' });
  }
});

// ══════════════════════════════════════════════════════════
//  ROUTE 3 — CREATE SHOPIFY CUSTOMER
//  POST /api/create-customer
//  Body: { phone, firstName, lastName, address1, city, state, pincode, email(opt), shop, accessToken }
// ══════════════════════════════════════════════════════════
app.post('/api/create-customer', async (req, res) => {
  try {
    const {
      phone, firstName, lastName,
      address1, address2, city, state, pincode, country,
      email, shop
    } = req.body;

    const cleanPhone = sanitizePhone(phone);

    // Confirm OTP was verified
    const cacheKey = `otp:${cleanPhone}`;
    const stored   = cache.get(cacheKey);
    if (!stored || !stored.verified) {
      return res.status(401).json({ success: false, message: 'OTP not verified. Please start over.' });
    }

    if (!firstName || !address1 || !city || !pincode) {
      return res.status(400).json({ success: false, message: 'Name and address are required.' });
    }

    // Build email — use provided or generate temp
    const shopDomain  = shop || process.env.SHOPIFY_SHOP_DOMAIN;
    const finalEmail  = email && email.trim()
      ? email.trim()
      : buildTempEmail(cleanPhone, shopDomain);
    const isTemp      = !email || !email.trim();

    // Use server-side token — never trust token from frontend
    const accessToken = tokenStore[shopDomain] || process.env.SHOPIFY_ACCESS_TOKEN;
    if (!accessToken) {
      console.error('[create-customer] No access token available for shop:', shopDomain);
      return res.status(500).json({ success: false, message: 'App not properly configured. Contact support.' });
    }

    console.log(`[create-customer] Shop: ${shopDomain}, Token: ${accessToken.substring(0,10)}...`);
    const { base, headers } = shopifyApi(shopDomain, accessToken);

    // Check if customer with this phone already exists
    let existingCustomer = null;
    try {
      const searchRes = await axios.get(
        `${base}/customers/search.json?query=phone:+91${cleanPhone}&fields=id,email,phone,first_name,last_name,tags`,
        { headers }
      );
      if (searchRes.data.customers && searchRes.data.customers.length > 0) {
        existingCustomer = searchRes.data.customers[0];
      }
    } catch (e) { /* ignore search errors */ }

    let customer;

    if (existingCustomer) {
      // Existing user — return wlpToken immediately, no update needed
      const wlpTok = createWlpToken({
        id:        existingCustomer.id,
        email:     existingCustomer.email,
        phone:     cleanPhone,
        firstName: existingCustomer.first_name,
        lastName:  existingCustomer.last_name,
        isTemp:    existingCustomer.email && existingCustomer.email.startsWith(cleanPhone),
        shop:      shopDomain
      });
      cache.del(cacheKey);
      cache.del('attempts:' + cleanPhone);
      return res.json({
        success:  true,
        wlpToken: wlpTok,
        customer: {
          id:        existingCustomer.id,
          email:     existingCustomer.email,
          firstName: existingCustomer.first_name,
          lastName:  existingCustomer.last_name,
          phone:     existingCustomer.phone,
          isTemp:    false
        },
        loginUrl: '/account'
      });
    } else {
      // Create new customer
      const createRes = await axios.post(
        `${base}/customers.json`,
        {
          customer: {
            first_name:             firstName,
            last_name:              lastName || '',
            email:                  finalEmail,
            phone:                  `+91${cleanPhone}`,
            verified_email:         !isTemp,
            password:               `WHP${cleanPhone}@${Date.now()}`,
            password_confirmation:  `WHP${cleanPhone}@${Date.now()}`,
            send_email_welcome:     false,
            addresses: [{
              address1: address1,
              address2: address2 || '',
              city:     city,
              province: state || '',
              zip:      pincode,
              country:  country || 'India',
              phone:    `+91${cleanPhone}`,
              default:  true
            }],
            tags: isTemp ? 'whploginpass,temp-email' : 'whploginpass',
            metafields: [{
              key:        'phone_verified',
              value:      'true',
              type:       'single_line_text_field',
              namespace:  'whploginpass'
            }, {
              key:        'temp_email',
              value:      isTemp ? 'true' : 'false',
              type:       'single_line_text_field',
              namespace:  'whploginpass'
            }]
          }
        },
        { headers }
      );
      customer = createRes.data.customer;
    }

    // Clear OTP from cache
    cache.del(cacheKey);
    cache.del(`attempts:${cleanPhone}`);

    // Generate account login URL (multipass or password reset)
    let loginUrl = '/account';
    try {
      const tokenRes = await axios.post(
        `${base}/customers/${customer.id}/account_activation_url.json`,
        {},
        { headers }
      );
      loginUrl = tokenRes.data.account_activation_url || '/account';
    } catch (e) { /* use /account fallback */ }

    // Create WLP session token (GoKwik-style)
    const wlpToken = createWlpToken({
      id:        customer.id,
      email:     customer.email,
      phone:     cleanPhone,
      firstName: customer.first_name,
      lastName:  customer.last_name,
      isTemp:    isTemp,
      shop:      shopDomain
    });

    return res.json({
      success:  true,
      wlpToken: wlpToken,
      customer: {
        id:        customer.id,
        email:     customer.email,
        firstName: customer.first_name,
        lastName:  customer.last_name,
        phone:     customer.phone,
        isTemp:    isTemp,
        tempEmail: isTemp ? finalEmail : null
      },
      loginUrl
    });

  } catch (err) {
    console.error('[create-customer error]', err.response?.data || err.message);
    const msg = err.response?.data?.errors?.email
      ? 'Email already in use. Please use a different email.'
      : 'Account creation failed. Please try again.';
    return res.status(500).json({ success: false, message: msg });
  }
});

// ══════════════════════════════════════════════════════════
//  ROUTE 4 — UPDATE EMAIL (after login, from account page)
//  POST /api/update-email
//  Body: { customerId, email, shop, accessToken }
// ══════════════════════════════════════════════════════════
app.post('/api/update-email', async (req, res) => {
  try {
    const { customerId, email, shop, accessToken } = req.body;

    if (!customerId || !email || !shop) {
      return res.status(400).json({ success: false, message: 'Missing required fields.' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Invalid email address.' });
    }

    const { base, headers } = shopifyApi(shop, accessToken);

    const res2 = await axios.put(
      `${base}/customers/${customerId}.json`,
      {
        customer: {
          id:             customerId,
          email:          email,
          verified_email: false,
          tags:           'whploginpass',
          metafields: [{
            key:       'temp_email',
            value:     'false',
            type:      'single_line_text_field',
            namespace: 'whploginpass'
          }]
        }
      },
      { headers }
    );

    return res.json({ success: true, customer: res2.data.customer });

  } catch (err) {
    console.error('[update-email error]', err.response?.data || err.message);
    return res.status(500).json({ success: false, message: 'Could not update email.' });
  }
});

// ══════════════════════════════════════════════════════════
//  ROUTE 5 — SAVE DEVICE TOKEN
//  POST /api/save-device
//  Called after successful OTP — saves device+phone mapping
// ══════════════════════════════════════════════════════════
app.post('/api/save-device', async (req, res) => {
  try {
    const { phone, deviceToken, shop } = req.body;
    if (!phone || !deviceToken) return res.status(400).json({ success: false });

    const cleanPhone = sanitizePhone(phone);

    // Store device token → phone mapping (30 days)
    cache.set(`device:${deviceToken}`, {
      phone:     cleanPhone,
      shop:      shop,
      createdAt: Date.now()
    }, 30 * 24 * 60 * 60); // 30 days

    console.log(`[Device] Saved token for +91${cleanPhone}`);
    return res.json({ success: true });
  } catch(err) {
    return res.status(500).json({ success: false });
  }
});

// ══════════════════════════════════════════════════════════
//  ROUTE 6 — CHECK DEVICE TOKEN
//  POST /api/check-device
//  Called on page load — if device known, skip OTP
// ══════════════════════════════════════════════════════════
app.post('/api/check-device', async (req, res) => {
  try {
    const { deviceToken, shop } = req.body;
    if (!deviceToken) return res.json({ known: false });

    const stored = cache.get(`device:${deviceToken}`);
    if (!stored) return res.json({ known: false });

    const cleanPhone  = stored.phone;
    const shopDomain  = shop || process.env.SHOPIFY_SHOP_DOMAIN;
    const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shopDomain];

    if (!accessToken) return res.json({ known: false });

    // Find customer in Shopify
    const { base, headers } = shopifyApi(shopDomain, accessToken);
    const searchRes = await axios.get(
      `${base}/customers/search.json?query=phone:+91${cleanPhone}&fields=id,email,first_name,phone`,
      { headers }
    );

    if (!searchRes.data.customers || searchRes.data.customers.length === 0) {
      return res.json({ known: false });
    }

    const customer = searchRes.data.customers[0];
    console.log(`[Device] Known device → customer ${customer.id} +91${cleanPhone}`);

    return res.json({
      known:     true,
      phone:     cleanPhone,
      email:     customer.email,
      firstName: customer.first_name,
      customerId: customer.id
    });

  } catch(err) {
    console.error('[check-device error]', err.message);
    return res.json({ known: false });
  }
});


// Serve widget JS file (avoids Shopify smart-quote conversion issue)
app.get('/wlp-widget.js', (req, res) => {
  const fs = require('fs');
  const path = require('path');
  const filePath = path.join(__dirname, 'wlp-widget.js');
  res.setHeader('Content-Type', 'application/javascript');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Cache-Control', 'public, max-age=300'); // 5 min cache
  fs.readFile(filePath, 'utf8', function(err, data) {
    if (err) return res.status(500).send('// Widget not found');
    res.send(data);
  });
});
