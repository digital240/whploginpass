// wlp-routes.js — WHPLoginPass Shopify OTP & Customer Routes
// Extracted from old server.js — all non-GMS routes live here

const axios  = require('axios');
const crypto = require('crypto');

const WLP_TOKEN_SECRET = process.env.WLP_TOKEN_SECRET || 'whploginpass_secret_key_2025';
const CUSTOMER_API_CLIENT_ID = process.env.CUSTOMER_API_CLIENT_ID || 'ab642c75-5da0-4f16-94d3-8ef1d7aa5679';
const CUSTOMER_API_SHOP_ID   = process.env.CUSTOMER_API_SHOP_ID   || '75385176202';

const tokenStore = {};

// ── WLP Token ─────────────────────────────────────────────
function createWlpToken(data) {
  const payload = JSON.stringify({
    id: data.id||'', email: data.email||'', phone: data.phone||'',
    firstName: data.firstName||data.first_name||'',
    lastName:  data.lastName||data.last_name||'',
    isTemp: data.isTemp||false, shop: data.shop||'',
    iat: Date.now(), exp: Date.now()+(30*24*60*60*1000)
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

// ── Helpers ───────────────────────────────────────────────
function sanitizePhone(phone) {
  const digits = String(phone).replace(/\D/g, '');
  return digits.startsWith('91') && digits.length === 12 ? digits.slice(2) : digits;
}

function buildTempEmail(phone, shopDomain) {
  const domain = shopDomain
    ? shopDomain.replace('.myshopify.com','').replace(/[^a-z0-9]/gi,'') + '.com'
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

function generatePKCE() {
  const verifier  = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

async function sendOtpViaSMSAlert(phone) {
  const apiKey = process.env.SMSALERT_API_KEY;
  const length = parseInt(process.env.OTP_LENGTH) || 6;
  if (!apiKey) throw new Error('SMSALERT_API_KEY not set');
  const otp = generateOtp(length);
  const res = await axios.post('https://www.smsalert.co.in/api/push.json', null, {
    params: { apikey: apiKey, sender: 'WHPECM', mobileno: phone, text: `Dear user, your WHP Jewellers otp code is ${otp}`, route: 'transscrub', template_id: '1707164361822841747' },
    timeout: 15000
  });
  if (res.data.status !== 'success') throw new Error(res.data.description?.desc || 'SMS send failed');
  return { status: 'success', otp };
}

async function validateOtp(phone, otp, cache) {
  const storedOtp = cache.get(`otp_code:${phone}`);
  if (!storedOtp) return { matched: false };
  const matched = String(storedOtp) === String(otp);
  if (matched) cache.del(`otp_code:${phone}`);
  return { matched };
}

// ═══════════════════════════════════════════════════════════
module.exports = function(app, cache) {

  // ── Customer Account OAuth ────────────────────────────
  app.post('/api/customer-auth/start', async (req, res) => {
    try {
      const { phone, shop, wlpToken } = req.body;
      const cleanPhone = sanitizePhone(phone || '');
      const cached = cache.get('wlptoken:'+cleanPhone) || cache.get('verified_email:'+cleanPhone) || cache.get('otp:'+cleanPhone);
      let tokenValid = !!cached;
      if (!tokenValid && wlpToken) {
        const decoded = decodeWlpToken(wlpToken);
        if (decoded && decoded.phone === cleanPhone) tokenValid = true;
      }
      if (!tokenValid) return res.status(401).json({ success: false, message: 'Session not verified.' });

      const { verifier, challenge } = generatePKCE();
      const state = crypto.randomBytes(16).toString('hex');
      const nonce = crypto.randomBytes(16).toString('hex');
      cache.set('pkce:'+state, { verifier, phone: cleanPhone, nonce }, 300);
      const redirectUri = process.env.APP_URL + '/auth/customer/callback';
      const authUrl = `https://shopify.com/authentication/${CUSTOMER_API_SHOP_ID}/oauth/authorize`
        + `?client_id=${CUSTOMER_API_CLIENT_ID}&response_type=code`
        + `&redirect_uri=${encodeURIComponent(redirectUri)}`
        + `&scope=openid+email+customer-account-api:full`
        + `&state=${state}&nonce=${nonce}`
        + `&code_challenge=${challenge}&code_challenge_method=S256&locale=en-IN`;
      return res.json({ success: true, authUrl });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  app.get('/auth/customer/callback', async (req, res) => {
    try {
      const { code, state, error } = req.query;
      if (error) return res.redirect('/?wlp_error=' + encodeURIComponent(error));
      const pkceData = cache.get('pkce:'+state);
      if (!pkceData) return res.redirect('/?wlp_error=invalid_state');
      cache.del('pkce:'+state);
      const { verifier, phone } = pkceData;
      const redirectUri = process.env.APP_URL + '/auth/customer/callback';
      const tokenRes = await axios.post(
        `https://shopify.com/authentication/${CUSTOMER_API_SHOP_ID}/oauth/token`,
        new URLSearchParams({ grant_type:'authorization_code', client_id:CUSTOMER_API_CLIENT_ID, redirect_uri:redirectUri, code, code_verifier:verifier }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      const { access_token, refresh_token, expires_in } = tokenRes.data;
      cache.set('customer_token:'+phone, { accessToken:access_token, refreshToken:refresh_token, expiresAt:Date.now()+(expires_in*1000) }, expires_in);
      const shopDomain = process.env.SHOPIFY_SHOP_DOMAIN || 's0xb6f-su.myshopify.com';
      res.redirect(`https://${shopDomain}/?wlp_customer_login=success&wlp_phone=${encodeURIComponent(phone)}`);
    } catch(err) {
      res.redirect('/?wlp_error=token_exchange_failed');
    }
  });

  app.post('/api/customer-auth/get-token', (req, res) => {
    const cleanPhone = sanitizePhone(req.body.phone || '');
    const tokenData  = cache.get('customer_token:'+cleanPhone);
    if (!tokenData) return res.json({ success: false, message: 'No token found.' });
    return res.json({ success: true, accessToken: tokenData.accessToken });
  });

  // ── WLP Token ─────────────────────────────────────────
  app.post('/api/verify-token', (req, res) => {
    const data = decodeWlpToken(req.body.token);
    if (!data) return res.json({ valid: false });
    return res.json({ valid: true, customer: data });
  });

  // ── Device memory ─────────────────────────────────────
  app.post('/api/save-device', (req, res) => {
    const { phone, deviceToken, shop, wlpToken } = req.body;
    if (deviceToken && phone) cache.set('device:'+deviceToken, { phone, shop, wlpToken }, 30*24*3600);
    return res.json({ success: true });
  });

  app.post('/api/check-device', (req, res) => {
    const data = cache.get('device:'+req.body.deviceToken);
    if (data) return res.json({ known: true, phone: data.phone, wlpToken: data.wlpToken||null });
    return res.json({ known: false });
  });

  // ── Shopify OAuth ─────────────────────────────────────
  app.get('/auth', (req, res) => {
    const shop = req.query.shop || process.env.SHOPIFY_SHOP_DOMAIN;
    if (!shop) return res.status(400).send('Missing shop parameter');
    const state = crypto.randomBytes(16).toString('hex');
    cache.set(`oauth_state:${state}`, shop, 600);
    const redirectUri = `${process.env.APP_URL || 'https://whploginpass.onrender.com'}/auth/callback`;
    res.redirect(`https://${shop}/admin/oauth/authorize?client_id=${process.env.SHOPIFY_API_KEY}&scope=read_customers,write_customers&redirect_uri=${encodeURIComponent(redirectUri)}&state=${state}`);
  });

  app.get('/auth/callback', async (req, res) => {
    const { shop, code, state, hmac } = req.query;
    const apiSecret = process.env.SHOPIFY_API_SECRET;
    const params  = Object.keys(req.query).filter(k=>k!=='hmac').sort().map(k=>`${k}=${req.query[k]}`).join('&');
    const digest  = crypto.createHmac('sha256', apiSecret).update(params).digest('hex');
    if (digest !== hmac) return res.status(403).send('HMAC verification failed.');
    try {
      const tokenRes = await axios.post(`https://${shop}/admin/oauth/access_token`, { client_id: process.env.SHOPIFY_API_KEY, client_secret: apiSecret, code });
      tokenStore[shop] = tokenRes.data.access_token;
      res.send(`<h1>Installed!</h1><p>Token: <code>${tokenRes.data.access_token}</code></p>`);
    } catch(err) { res.status(500).send('OAuth failed: ' + err.message); }
  });

  // ── Send OTP (Shopify widget) ─────────────────────────
  app.post('/api/send-otp', async (req, res) => {
    try {
      const { phone, shop } = req.body;
      if (!phone) return res.status(400).json({ success: false, message: 'Phone number required.' });
      const cleanPhone = sanitizePhone(phone);
      if (cleanPhone.length !== 10) return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });
      const result = await sendOtpViaSMSAlert(cleanPhone);
      cache.set(`otp_code:${cleanPhone}`, result.otp, 600);
      cache.set(`otp:${cleanPhone}`, { phone: cleanPhone, shop, verified: false });
      cache.set(`attempts:${cleanPhone}`, 0);
      return res.json({ success: true, message: `OTP sent to +91 ${cleanPhone}` });
    } catch(err) {
      return res.status(500).json({ success: false, message: 'Failed to send OTP.' });
    }
  });

  // ── Verify OTP (Shopify widget) ───────────────────────
  app.post('/api/verify-otp', async (req, res) => {
    try {
      const { phone, otp } = req.body;
      if (!phone || !otp) return res.status(400).json({ success: false, message: 'Phone and OTP required.' });
      const cleanPhone = sanitizePhone(phone);
      const cacheKey   = `otp:${cleanPhone}`;
      const stored     = cache.get(cacheKey);
      let attempts     = cache.get(`attempts:${cleanPhone}`) || 0;
      if (!stored) return res.status(400).json({ success: false, message: 'OTP expired.' });
      const maxAttempts = parseInt(process.env.MAX_OTP_ATTEMPTS) || 3;
      if (attempts >= maxAttempts) { cache.del(cacheKey); return res.status(429).json({ success: false, message: 'Too many attempts. Request a new OTP.' }); }
      const { matched } = await validateOtp(cleanPhone, otp, cache);
      if (!matched) {
        cache.set(`attempts:${cleanPhone}`, attempts + 1);
        return res.status(400).json({ success: false, message: `Incorrect OTP. ${maxAttempts-attempts-1} attempt(s) left.` });
      }
      stored.verified = true;
      let isExistingUser = false, wlpToken = null, verifiedEmail = null;
      const shopDomain  = stored.shop || process.env.SHOPIFY_SHOP_DOMAIN;
      const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shopDomain];
      if (shopDomain && accessToken) {
        try {
          const { base, headers } = shopifyApi(shopDomain, accessToken);
          for (const q of [`phone:+91${cleanPhone}`, `phone:${cleanPhone}`]) {
            const sr = await axios.get(`${base}/customers/search.json?query=${encodeURIComponent(q)}&fields=id,email,first_name,last_name,phone`, { headers });
            if (sr.data.customers?.length) {
              const ex = sr.data.customers[0];
              isExistingUser = true; verifiedEmail = ex.email;
              wlpToken = createWlpToken({ id:ex.id, email:ex.email, phone:cleanPhone, firstName:ex.first_name||'', lastName:ex.last_name||'', isTemp:ex.email?.startsWith(cleanPhone), shop:shopDomain });
              break;
            }
          }
        } catch(e) { console.log('[verify-otp] Customer search error:', e.message); }
      }
      cache.set(cacheKey, stored, 300);
      return res.json({ success: true, message: 'OTP verified!', phone: cleanPhone, isExistingUser, email: verifiedEmail, wlpToken });
    } catch(err) {
      return res.status(500).json({ success: false, message: 'Verification failed.' });
    }
  });

  // ── Create customer ───────────────────────────────────
  app.post('/api/create-customer', async (req, res) => {
    try {
      const { phone, firstName, lastName, address1, address2, city, state, pincode, country, email, shop } = req.body;
      const cleanPhone  = sanitizePhone(phone);
      const cacheKey    = `otp:${cleanPhone}`;
      const stored      = cache.get(cacheKey);
      if (!stored?.verified) return res.status(401).json({ success: false, message: 'OTP not verified.' });
      if (!firstName||!address1||!city||!pincode) return res.status(400).json({ success: false, message: 'Name and address are required.' });
      const shopDomain  = shop || process.env.SHOPIFY_SHOP_DOMAIN;
      const finalEmail  = email?.trim() || buildTempEmail(cleanPhone, shopDomain);
      const isTemp      = !email?.trim();
      const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shopDomain];
      if (!accessToken) return res.status(500).json({ success: false, message: 'App not configured.' });
      const { base, headers } = shopifyApi(shopDomain, accessToken);
      let existingCustomer = null;
      try {
        const sr = await axios.get(`${base}/customers/search.json?query=phone:+91${cleanPhone}&fields=id,email,first_name,last_name`, { headers });
        if (sr.data.customers?.length) existingCustomer = sr.data.customers[0];
      } catch(e) {}
      if (existingCustomer) {
        const wlpTok = createWlpToken({ id:existingCustomer.id, email:existingCustomer.email, phone:cleanPhone, firstName:existingCustomer.first_name, lastName:existingCustomer.last_name, isTemp:false, shop:shopDomain });
        cache.del(cacheKey);
        return res.json({ success:true, wlpToken:wlpTok, customer:{ id:existingCustomer.id, email:existingCustomer.email, firstName:existingCustomer.first_name, isTemp:false }, loginUrl:'/account' });
      }
      const createRes = await axios.post(`${base}/customers.json`, {
        customer: { first_name:firstName, last_name:lastName||'', email:finalEmail, phone:`+91${cleanPhone}`, verified_email:!isTemp, send_email_welcome:false,
          addresses:[{ address1, address2:address2||'', city, province:state||'', zip:pincode, country:country||'India', phone:`+91${cleanPhone}`, default:true }],
          tags: isTemp ? 'whploginpass,temp-email' : 'whploginpass' }
      }, { headers });
      const customer = createRes.data.customer;
      cache.del(cacheKey); cache.del(`attempts:${cleanPhone}`);
      let loginUrl = '/account';
      try { const ar = await axios.post(`${base}/customers/${customer.id}/account_activation_url.json`, {}, { headers }); loginUrl = ar.data.account_activation_url || '/account'; } catch(e) {}
      const wlpToken = createWlpToken({ id:customer.id, email:customer.email, phone:cleanPhone, firstName:customer.first_name, lastName:customer.last_name, isTemp, shop:shopDomain });
      return res.json({ success:true, wlpToken, customer:{ id:customer.id, email:customer.email, firstName:customer.first_name, lastName:customer.last_name, isTemp, tempEmail:isTemp?finalEmail:null }, loginUrl });
    } catch(err) {
      const msg = err.response?.data?.errors?.email ? 'Email already in use.' : 'Account creation failed.';
      return res.status(500).json({ success: false, message: msg });
    }
  });

  // ── Get orders ────────────────────────────────────────
  app.post('/api/get-orders', async (req, res) => {
    try {
      const { customerId, shop } = req.body;
      if (!customerId) return res.json({ success: false, orders: [] });
      const shopDomain  = shop || process.env.SHOPIFY_SHOP_DOMAIN;
      const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shopDomain];
      if (!accessToken) return res.json({ success: false, orders: [] });
      const { base, headers } = shopifyApi(shopDomain, accessToken);
      const ordersRes = await axios.get(`${base}/customers/${customerId}/orders.json?status=any&fields=id,order_number,created_at,total_price,fulfillment_status,financial_status&limit=20`, { headers });
      return res.json({ success: true, orders: ordersRes.data.orders || [] });
    } catch(err) { return res.json({ success: false, orders: [] }); }
  });

  // ── Update email ──────────────────────────────────────
  app.post('/api/update-email', async (req, res) => {
    try {
      const { customerId, email, shop } = req.body;
      if (!customerId || !email) return res.status(400).json({ success: false, message: 'Missing fields.' });
      const accessToken = process.env.SHOPIFY_ACCESS_TOKEN || tokenStore[shop];
      const { base, headers } = shopifyApi(shop, accessToken);
      const r = await axios.put(`${base}/customers/${customerId}.json`, { customer: { id:customerId, email, verified_email:false, tags:'whploginpass' } }, { headers });
      return res.json({ success: true, customer: r.data.customer });
    } catch(err) { return res.status(500).json({ success: false, message: 'Could not update email.' }); }
  });

  console.log('[WLP] Shopify routes loaded');
};
