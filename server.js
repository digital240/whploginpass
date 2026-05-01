// WHPLoginPass — Backend Server
require('dotenv').config();
const express   = require('express');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const axios     = require('axios');
const crypto    = require('crypto');

const app   = express();
const cache = new NodeCache({ stdTTL: 600 });
const tokenStore = {};

// ── CORS — must be FIRST before all routes ──────────────
app.use(function(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-shop-domain');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// ── MIDDLEWARE ──────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());

// ── WLP TOKEN SYSTEM ────────────────────────────────────
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
  const sig     = crypto.createHmac('sha256', WLP_TOKEN_SECRET).update(encoded).digest('hex').substring(0,16);
  return encoded + '.' + sig;
}

function decodeWlpToken(token) {
  try {
    if (!token) return null;
    const [encoded, sig] = token.split('.');
    if (!encoded || !sig) return null;
    const expected = crypto.createHmac('sha256', WLP_TOKEN_SECRET).update(encoded).digest('hex').substring(0,16);
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch(e) { return null; }
}

// ── HELPERS ─────────────────────────────────────────────
function sanitizePhone(phone) {
  const digits = String(phone).replace(/\D/g, '');
  return digits.startsWith('91') && digits.length === 12 ? digits.slice(2) : digits;
}

function buildTempEmail(phone, shopDomain) {
  const domain = shopDomain
    ? shopDomain.replace('.myshopify.com', '').replace(/[^a-z0-9]/gi, '') + '.com'
    : 'store.com';
  return `${phone}@${domain}`;
}

function shopifyApi(shopDomain, accessToken) {
  return {
    base: `https://${shopDomain}/admin/api/2024-01`,
    headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' }
  };
}

function generateOtp(length) {
  length = length || 6;
  let otp = '';
  for (let i = 0; i < length; i++) otp += Math.floor(Math.random() * 10);
  return otp;
}

// ── SMSALERT ─────────────────────────────────────────────
async function sendOtpViaSMSAlert(phone) {
  const apiKey = process.env.SMSALERT_API_KEY;
  const sender = process.env.SMSALERT_SENDER_ID;
  const length = parseInt(process.env.OTP_LENGTH) || 6;
  if (!apiKey) throw new Error('SMSALERT_API_KEY not set');
  if (!sender) throw new Error('SMSALERT_SENDER_ID not set');
  const otp = generateOtp(length);
  cache.set(`otp_code:${phone}`, otp, 600);
  const message = `Dear user, your WHP Jewellers otp code is ${otp}`;
  console.log(`[SMSAlert] Sending OTP ${otp} to ${phone} via WHPECM`);
  const res = await axios.post('https://www.smsalert.co.in/api/push.json', null, {
    params: { apikey: apiKey, sender: 'WHPECM', mobileno: phone, text: message, route: 'transscrub', template_id: '1707164361822841747' },
    timeout: 15000
  });
  console.log(`[SMSAlert] Response:`, JSON.stringify(res.data));
  if (res.data.status !== 'success') throw new Error(res.data.description?.desc || 'SMS send failed');
  return { status: 'success', otp };
}

async function validateOtp(phone, otp) {
  const storedOtp = cache.get(`otp_code:${phone}`);
  console.log(`[OTP Validate] phone=${phone} entered=${otp} stored=${storedOtp}`);
  if (!storedOtp) return { matched: false, raw: { desc: 'OTP expired' } };
  const matched = String(storedOtp) === String(otp);
  if (matched) cache.del(`otp_code:${phone}`);
  return { matched, raw: { stored: storedOtp, entered: otp } };
}

// ── RATE LIMITER ─────────────────────────────────────────
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, max: 5,
  keyGenerator: (req) => req.body.phone || req.ip,
  message: { success: false, message: 'Too many OTP requests. Try again in 10 minutes.' }
});

// ══════════════════════════════════════════════════════════
//  ROUTES
// ══════════════════════════════════════════════════════════

// Health check
app.get('/health', (req, res) => res.json({ status: 'ok', app: 'WHPLoginPass', cors: 'enabled' }));

// Verify WLP token
app.post('/api/verify-token', (req, res) => {
  const data = decodeWlpToken(req.body.token);
  if (!data) return res.json({ valid: false });
  return res.json({ valid: true, customer: data });
});

// Save device (30 day memory)
app.post('/api/save-device', (req, res) => {
  const { phone, deviceToken, shop, wlpToken } = req.body;
  if (deviceToken && phone) {
    cache.set('device:' + deviceToken, { phone, shop, wlpToken }, 30 * 24 * 3600);
    console.log(`[Device] Saved: ${deviceToken} -> ${phone}`);
  }
  return res.json({ success: true });
});

// Check device
app.post('/api/check-device', (req, res) => {
  const { deviceToken } = req.body;
  const data = cache.get('device:' + deviceToken);
  if (data) {
    console.log(`[Device] Found: ${deviceToken} -> ${data.phone}`);
    return res.json({ known: true, phone: data.phone, wlpToken: data.wlpToken || null });
  }
  return res.json({ known: false });
});

// OAuth
app.get('/auth', (req, res) => {
  const shop = req.query.shop || process.env.SHOPIFY_SHOP_DOMAIN;
  if (!shop) return res.status(400).send('Missing shop parameter');
  const state = crypto.randomBytes(16).toString('hex');
  cache.set(`oauth_state:${state}`, shop, 600);
  const redirectUri = `${process.env.APP_URL || 'https://whploginpass.onrender.com'}/auth/callback`;
  const authUrl = `https://${shop}/admin/oauth/authorize?client_id=${process.env.SHOPIFY_API_KEY}&scope=read_customers,write_customers&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`;
  console.log(`[OAuth] Redirecting to: ${authUrl}`);
  res.redirect(authUrl);
});

app.get('/auth/callback', async (req, res) => {
  const { shop, code, state, hmac } = req.query;
  const apiSecret = process.env.SHOPIFY_API_SECRET;
  const params = Object.keys(req.query).filter(k => k !== 'hmac').sort().map(k => `${k}=${req.query[k]}`).join('&');
  const digest = crypto.createHmac('sha256', apiSecret).update(params).digest('hex');
  if (digest !== hmac) return res.status(403).send('HMAC verification failed.');
  try {
    const tokenRes = await axios.post(`https://${shop}/admin/oauth/access_token`, {
      client_id: process.env.SHOPIFY_API_KEY, client_secret: apiSecret, code
    });
    const accessToken = tokenRes.data.access_token;
    tokenStore[shop] = accessToken;
    console.log(`[OAuth] Token for ${shop}: ${accessToken}`);
    res.send(`<h1>Installed!</h1><p>Token: <code>${accessToken}</code></p><p>Add as SHOPIFY_ACCESS_TOKEN in Render.</p>`);
  } catch (err) {
    res.status(500).send('OAuth failed: ' + err.message);
  }
});

// Send OTP
app.post('/api/send-otp', otpLimiter, async (req, res) => {
  try {
    const { phone, shop } = req.body;
    if (!phone) return res.status(400).json({ success: false, message: 'Phone number required.' });
    const cleanPhone = sanitizePhone(phone);
    if (cleanPhone.length !== 10) return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });
    await sendOtpViaSMSAlert(cleanPhone);
    cache.set(`otp:${cleanPhone}`, { phone: cleanPhone, shop, verified: false });
    cache.set(`attempts:${cleanPhone}`, 0);
    console.log(`[OTP SENT via SMSAlert] +91${cleanPhone}`);
    return res.json({ success: true, message: `OTP sent to +91 ${cleanPhone}` });
  } catch (err) {
    console.error('[send-otp error]', err.message);
    return res.status(500).json({ success: false, message: 'Failed to send OTP. Try again.' });
  }
});

// Verify OTP
app.post('/api/verify-otp', async (req, res) => {
  try {
    const { phone, otp } = req.body;
    if (!phone || !otp) return res.status(400).json({ success: false, message: 'Phone and OTP required.' });
    const cleanPhone  = sanitizePhone(phone);
    const cacheKey    = `otp:${cleanPhone}`;
    const stored      = cache.get(cacheKey);
    let   attempts    = cache.get(`attempts:${cleanPhone}`) || 0;
    if (!stored) return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
    const maxAttempts = parseInt(process.env.MAX_OTP_ATTEMPTS) || 3;
    if (attempts >= maxAttempts) {
      cache.del(cacheKey);
      return res.status(429).json({ success: false, message: 'Too many wrong attempts. Request a new OTP.' });
    }
    const { matched, raw } = await validateOtp(cleanPhone, otp);
    console.log(`[OTP VERIFY] +91${cleanPhone} -> SMSAlert:`, raw);
    if (!matched) {
      cache.set(`attempts:${cleanPhone}`, attempts + 1);
      const left = maxAttempts - attempts - 1;
      return res.status(400).json({ success: false, message: `Incorrect OTP. ${left} attempt(s) left.` });
    }

    // OTP correct - check if existing customer
    stored.verified = true;
    let isExistingUser = false;
    let wlpToken = null;
    let verifiedEmail = null;

    const shopDomain  = stored.shop || process.env.SHOPIFY_SHOP_DOMAIN;
    const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shopDomain];
    console.log(`[verify-otp] shop=${shopDomain}, token=${accessToken ? accessToken.substring(0,10)+'...' : 'MISSING'}`);

    if (shopDomain && accessToken) {
      try {
        const { base, headers } = shopifyApi(shopDomain, accessToken);
        for (const query of [`phone:+91${cleanPhone}`, `phone:${cleanPhone}`]) {
          const searchRes = await axios.get(
            `${base}/customers/search.json?query=${encodeURIComponent(query)}&fields=id,email,first_name,last_name,phone`,
            { headers }
          );
          console.log(`[verify-otp] Search "${query}" -> found: ${searchRes.data.customers?.length || 0}`);
          if (searchRes.data.customers && searchRes.data.customers.length > 0) {
            const existing = searchRes.data.customers[0];
            isExistingUser = true;
            verifiedEmail  = existing.email;
            console.log(`[verify-otp] Existing customer: id=${existing.id} email=${existing.email}`);
            wlpToken = createWlpToken({
              id: existing.id, email: existing.email, phone: cleanPhone,
              firstName: existing.first_name || '', lastName: existing.last_name || '',
              isTemp: existing.email && existing.email.startsWith(cleanPhone),
              shop: shopDomain
            });
            console.log(`[verify-otp] wlpToken created`);
            break;
          }
        }
      } catch(e) {
        console.log('[verify-otp] Customer search error:', e.message);
      }
    }

    cache.set(cacheKey, stored, 300);
    return res.json({
      success: true, message: 'OTP verified!', phone: cleanPhone,
      isExistingUser, email: verifiedEmail, wlpToken
    });
  } catch (err) {
    console.error('[verify-otp error]', err.message);
    return res.status(500).json({ success: false, message: 'Verification failed. Try again.' });
  }
});

// Create customer
app.post('/api/create-customer', async (req, res) => {
  try {
    const { phone, firstName, lastName, address1, address2, city, state, pincode, country, email, shop } = req.body;
    const cleanPhone = sanitizePhone(phone);
    const cacheKey   = `otp:${cleanPhone}`;
    const stored     = cache.get(cacheKey);
    if (!stored || !stored.verified) return res.status(401).json({ success: false, message: 'OTP not verified. Please start over.' });
    if (!firstName || !address1 || !city || !pincode) return res.status(400).json({ success: false, message: 'Name and address are required.' });

    const shopDomain  = shop || process.env.SHOPIFY_SHOP_DOMAIN;
    const finalEmail  = email && email.trim() ? email.trim() : buildTempEmail(cleanPhone, shopDomain);
    const isTemp      = !email || !email.trim();
    const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shopDomain];
    if (!accessToken) return res.status(500).json({ success: false, message: 'App not configured.' });

    console.log(`[create-customer] Shop: ${shopDomain}, Token: ${accessToken.substring(0,10)}...`);
    const { base, headers } = shopifyApi(shopDomain, accessToken);

    // Check existing
    let existingCustomer = null;
    try {
      const searchRes = await axios.get(`${base}/customers/search.json?query=phone:+91${cleanPhone}&fields=id,email,first_name,last_name`, { headers });
      if (searchRes.data.customers && searchRes.data.customers.length > 0) existingCustomer = searchRes.data.customers[0];
    } catch(e) {}

    if (existingCustomer) {
      const wlpTok = createWlpToken({ id: existingCustomer.id, email: existingCustomer.email, phone: cleanPhone, firstName: existingCustomer.first_name, lastName: existingCustomer.last_name, isTemp: false, shop: shopDomain });
      cache.del(cacheKey);
      return res.json({ success: true, wlpToken: wlpTok, customer: { id: existingCustomer.id, email: existingCustomer.email, firstName: existingCustomer.first_name, isTemp: false }, loginUrl: '/account' });
    }

    // Create new
    const createRes = await axios.post(`${base}/customers.json`, {
      customer: {
        first_name: firstName, last_name: lastName || '', email: finalEmail,
        phone: `+91${cleanPhone}`, verified_email: !isTemp,
        send_email_welcome: false,
        addresses: [{ address1, address2: address2||'', city, province: state||'', zip: pincode, country: country||'India', phone: `+91${cleanPhone}`, default: true }],
        tags: isTemp ? 'whploginpass,temp-email' : 'whploginpass'
      }
    }, { headers });

    const customer = createRes.data.customer;
    cache.del(cacheKey);
    cache.del(`attempts:${cleanPhone}`);

    let loginUrl = '/account';
    try {
      const actRes = await axios.post(`${base}/customers/${customer.id}/account_activation_url.json`, {}, { headers });
      loginUrl = actRes.data.account_activation_url || '/account';
    } catch(e) {}

    const wlpToken = createWlpToken({ id: customer.id, email: customer.email, phone: cleanPhone, firstName: customer.first_name, lastName: customer.last_name, isTemp, shop: shopDomain });

    return res.json({ success: true, wlpToken, customer: { id: customer.id, email: customer.email, firstName: customer.first_name, lastName: customer.last_name, isTemp, tempEmail: isTemp ? finalEmail : null }, loginUrl });
  } catch (err) {
    console.error('[create-customer error]', err.response?.data || err.message);
    const msg = err.response?.data?.errors?.email ? 'Email already in use. Please use a different email.' : 'Account creation failed. Please try again.';
    return res.status(500).json({ success: false, message: msg });
  }
});

// Get customer orders
app.post('/api/get-orders', async (req, res) => {
  try {
    const { customerId, shop } = req.body;
    if (!customerId) return res.json({ success: false, orders: [] });
    const shopDomain  = shop || process.env.SHOPIFY_SHOP_DOMAIN;
    const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shopDomain];
    if (!accessToken) return res.json({ success: false, orders: [] });
    const { base, headers } = shopifyApi(shopDomain, accessToken);
    const ordersRes = await axios.get(
      `${base}/customers/${customerId}/orders.json?status=any&fields=id,order_number,created_at,total_price,fulfillment_status,financial_status&limit=20`,
      { headers }
    );
    return res.json({ success: true, orders: ordersRes.data.orders || [] });
  } catch(err) {
    console.error('[get-orders error]', err.message);
    return res.json({ success: false, orders: [] });
  }
});

// Update email
app.post('/api/update-email', async (req, res) => {
  try {
    const { customerId, email, shop } = req.body;
    if (!customerId || !email) return res.status(400).json({ success: false, message: 'Missing fields.' });
    const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shop];
    const { base, headers } = shopifyApi(shop, accessToken);
    const r = await axios.put(`${base}/customers/${customerId}.json`, { customer: { id: customerId, email, verified_email: false, tags: 'whploginpass' } }, { headers });
    return res.json({ success: true, customer: r.data.customer });
  } catch (err) {
    return res.status(500).json({ success: false, message: 'Could not update email.' });
  }
});

const PORT = process.env.PORT || 4000;

// GMS Scheme routes
require('./gms-routes')(app, cache);

app.listen(PORT, () => console.log(`WHPLoginPass running on port ${PORT}`));
