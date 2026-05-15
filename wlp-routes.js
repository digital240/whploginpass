// wlp-routes.js — WHPLoginPass Shopify OTP & Customer Routes
// Updated: Storefront API replaces Admin API — no SHOPIFY_ACCESS_TOKEN needed

const axios  = require('axios');
const crypto = require('crypto');

const WLP_TOKEN_SECRET       = process.env.WLP_TOKEN_SECRET || 'whploginpass_secret_key_2025';
const CUSTOMER_API_CLIENT_ID = process.env.CUSTOMER_API_CLIENT_ID || 'ab642c75-5da0-4f16-94d3-8ef1d7aa5679';
const CUSTOMER_API_SHOP_ID   = process.env.CUSTOMER_API_SHOP_ID   || '75385176202';

// ── Storefront API Config ─────────────────────────────────
const STOREFRONT_TOKEN = process.env.SHOPIFY_STOREFRONT_TOKEN;
const SHOPIFY_DOMAIN   = process.env.SHOPIFY_SHOP_DOMAIN || 's0xb6f-su.myshopify.com';
const STOREFRONT_URL   = `https://${SHOPIFY_DOMAIN}/api/2026-04/graphql.json`;

async function storefrontQuery(query, variables) {
  const res = await axios.post(STOREFRONT_URL, { query, variables }, {
    headers: {
      'Content-Type': 'application/json',
      'X-Shopify-Storefront-Access-Token': STOREFRONT_TOKEN,
    },
    timeout: 15000,
  });
  return res.data;
}

// Deterministic password — same every time for same phone, never stored in DB
function generateCustomerPassword(phone) {
  return crypto.createHmac('sha256', WLP_TOKEN_SECRET)
    .update(`wlp_customer_${phone}`)
    .digest('hex')
    .substring(0, 24);
}

function buildTempEmail(phone) {
  return `wlp_${phone}@whpjewellers.noemail`;
}

// ── WLP Token ─────────────────────────────────────────────
function createWlpToken(data) {
  const payload = JSON.stringify({
    id:        data.id        || '',
    email:     data.email     || '',
    phone:     data.phone     || '',
    firstName: data.firstName || data.first_name  || '',
    lastName:  data.lastName  || data.last_name   || '',
    isTemp:    data.isTemp    || false,
    shop:      data.shop      || '',
    iat: Date.now(),
    exp: Date.now() + (30 * 24 * 60 * 60 * 1000),
  });
  const encoded = Buffer.from(payload).toString('base64url');
  const sig     = crypto.createHmac('sha256', WLP_TOKEN_SECRET).update(encoded).digest('hex').substring(0, 16);
  return encoded + '.' + sig;
}

function decodeWlpToken(token) {
  try {
    if (!token) return null;
    const [encoded, sig] = token.split('.');
    if (!encoded || !sig) return null;
    const expected = crypto.createHmac('sha256', WLP_TOKEN_SECRET).update(encoded).digest('hex').substring(0, 16);
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
    params: {
      apikey:      apiKey,
      sender:      'WHPECM',
      mobileno:    phone,
      text:        `Dear user, your WHP Jewellers otp code is ${otp}`,
      route:       'transscrub',
      template_id: '1707164361822841747',
    },
    timeout: 15000,
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

// ── Storefront: Get customer access token ─────────────────
async function getStorefrontAccessToken(phone) {
  const tempEmail = buildTempEmail(phone);
  const password  = generateCustomerPassword(phone);

  const data = await storefrontQuery(`
    mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
      customerAccessTokenCreate(input: $input) {
        customerAccessToken { accessToken expiresAt }
        customerUserErrors { code message }
      }
    }
  `, { input: { email: tempEmail, password } });

  return data.data?.customerAccessTokenCreate?.customerAccessToken?.accessToken || null;
}

// ═══════════════════════════════════════════════════════════
module.exports = function(app, cache) {

  // ── Customer Account OAuth ────────────────────────────
  app.post('/api/customer-auth/start', async (req, res) => {
    try {
      const { phone, shop, wlpToken } = req.body;
      const cleanPhone = sanitizePhone(phone || '');
      const cached = cache.get('wlptoken:' + cleanPhone) || cache.get('verified_email:' + cleanPhone) || cache.get('otp:' + cleanPhone);
      let tokenValid = !!cached;
      if (!tokenValid && wlpToken) {
        const decoded = decodeWlpToken(wlpToken);
        if (decoded && decoded.phone === cleanPhone) tokenValid = true;
      }
      if (!tokenValid) return res.status(401).json({ success: false, message: 'Session not verified.' });

      const { verifier, challenge } = generatePKCE();
      const state = crypto.randomBytes(16).toString('hex');
      const nonce = crypto.randomBytes(16).toString('hex');
      cache.set('pkce:' + state, { verifier, phone: cleanPhone, nonce }, 300);
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
      const pkceData = cache.get('pkce:' + state);
      if (!pkceData) return res.redirect('/?wlp_error=invalid_state');
      cache.del('pkce:' + state);
      const { verifier, phone } = pkceData;
      const redirectUri = process.env.APP_URL + '/auth/customer/callback';
      const tokenRes = await axios.post(
        `https://shopify.com/authentication/${CUSTOMER_API_SHOP_ID}/oauth/token`,
        new URLSearchParams({ grant_type: 'authorization_code', client_id: CUSTOMER_API_CLIENT_ID, redirect_uri: redirectUri, code, code_verifier: verifier }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      const { access_token, refresh_token, expires_in } = tokenRes.data;
      cache.set('customer_token:' + phone, { accessToken: access_token, refreshToken: refresh_token, expiresAt: Date.now() + (expires_in * 1000) }, expires_in);
      res.redirect(`https://${SHOPIFY_DOMAIN}/?wlp_customer_login=success&wlp_phone=${encodeURIComponent(phone)}`);
    } catch(err) {
      res.redirect('/?wlp_error=token_exchange_failed');
    }
  });

  app.post('/api/customer-auth/get-token', (req, res) => {
    const cleanPhone = sanitizePhone(req.body.phone || '');
    const tokenData  = cache.get('customer_token:' + cleanPhone);
    if (!tokenData) return res.json({ success: false, message: 'No token found.' });
    return res.json({ success: true, accessToken: tokenData.accessToken });
  });

  // ── WLP Token verify ──────────────────────────────────
  app.post('/api/verify-token', (req, res) => {
    const data = decodeWlpToken(req.body.token);
    if (!data) return res.json({ valid: false });
    return res.json({ valid: true, customer: data });
  });

  // ── Device memory ─────────────────────────────────────
  app.post('/api/save-device', (req, res) => {
    const { phone, deviceToken, shop, wlpToken } = req.body;
    if (deviceToken && phone) cache.set('device:' + deviceToken, { phone, shop, wlpToken }, 30 * 24 * 3600);
    return res.json({ success: true });
  });

  app.post('/api/check-device', (req, res) => {
    const data = cache.get('device:' + req.body.deviceToken);
    if (data) return res.json({ known: true, phone: data.phone, wlpToken: data.wlpToken || null });
    return res.json({ known: false });
  });

  // ── Send OTP ──────────────────────────────────────────
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
      console.error('[send-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Failed to send OTP.' });
    }
  });

  // ── Verify OTP ────────────────────────────────────────
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
      if (attempts >= maxAttempts) {
        cache.del(cacheKey);
        return res.status(429).json({ success: false, message: 'Too many attempts. Request a new OTP.' });
      }

      const { matched } = await validateOtp(cleanPhone, otp, cache);
      if (!matched) {
        cache.set(`attempts:${cleanPhone}`, attempts + 1);
        return res.status(400).json({ success: false, message: `Incorrect OTP. ${maxAttempts - attempts - 1} attempt(s) left.` });
      }

      stored.verified = true;
      cache.set(cacheKey, stored, 300);

      const password  = generateCustomerPassword(cleanPhone);
      const tempEmail = buildTempEmail(cleanPhone);

      // Try to create customer via Storefront API
      const createData = await storefrontQuery(`
        mutation customerCreate($input: CustomerCreateInput!) {
          customerCreate(input: $input) {
            customer { id email firstName lastName }
            customerUserErrors { code field message }
          }
        }
      `, {
        input: {
          email:            tempEmail,
          password,
          phone:            `+91${cleanPhone}`,
          acceptsMarketing: false,
        }
      });

      const errors      = createData.data?.customerCreate?.customerUserErrors ?? [];
      const newCustomer = createData.data?.customerCreate?.customer;

      let isExistingUser = false;
      let customerId     = null;
      let customerEmail  = tempEmail;
      let firstName      = '';
      let lastName       = '';

      if (newCustomer) {
        // Brand new customer created
        isExistingUser = false;
        customerId     = newCustomer.id;
        customerEmail  = newCustomer.email;

      } else if (errors.some(e => e.code === 'TAKEN')) {
        // Customer already exists — get access token and fetch details
        isExistingUser = true;

        const tokenData = await storefrontQuery(`
          mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
            customerAccessTokenCreate(input: $input) {
              customerAccessToken { accessToken }
              customerUserErrors { code message }
            }
          }
        `, { input: { email: tempEmail, password } });

        const accessToken = tokenData.data?.customerAccessTokenCreate?.customerAccessToken?.accessToken;

        if (accessToken) {
          const meData = await storefrontQuery(`
            query getCustomer($token: String!) {
              customer(customerAccessToken: $token) {
                id email firstName lastName
              }
            }
          `, { token: accessToken });

          const existing = meData.data?.customer;
          if (existing) {
            customerId    = existing.id;
            customerEmail = existing.email;
            firstName     = existing.firstName || '';
            lastName      = existing.lastName  || '';
          }
        }

      } else {
        // Some other error
        console.error('[verify-otp] customerCreate errors:', errors);
        return res.status(500).json({ success: false, message: 'Account setup failed.' });
      }

      const isTemp    = customerEmail === tempEmail;
      const wlpToken  = customerId ? createWlpToken({
        id: customerId, email: customerEmail, phone: cleanPhone,
        firstName, lastName, isTemp, shop: SHOPIFY_DOMAIN,
      }) : null;

      return res.json({
        success:        true,
        message:        'OTP verified!',
        phone:          cleanPhone,
        isExistingUser,
        isNew:          !isExistingUser,
        email:          isTemp ? null : customerEmail,
        wlpToken,
      });

    } catch(err) {
      console.error('[verify-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Verification failed.' });
    }
  });

  // ── Create / complete customer profile ────────────────
  app.post('/api/create-customer', async (req, res) => {
    try {
      const { phone, firstName, lastName, email } = req.body;
      const cleanPhone = sanitizePhone(phone);
      const cacheKey   = `otp:${cleanPhone}`;
      const stored     = cache.get(cacheKey);

      if (!stored?.verified) return res.status(401).json({ success: false, message: 'OTP not verified.' });
      if (!firstName) return res.status(400).json({ success: false, message: 'First name is required.' });

      const password   = generateCustomerPassword(cleanPhone);
      const tempEmail  = buildTempEmail(cleanPhone);
      const finalEmail = email?.trim() || tempEmail;
      const isTemp     = !email?.trim();

      // Get customer access token
      const tokenData = await storefrontQuery(`
        mutation customerAccessTokenCreate($input: CustomerAccessTokenCreateInput!) {
          customerAccessTokenCreate(input: $input) {
            customerAccessToken { accessToken }
            customerUserErrors { code message }
          }
        }
      `, { input: { email: tempEmail, password } });

      const customerAccessToken = tokenData.data?.customerAccessTokenCreate?.customerAccessToken?.accessToken;

      if (!customerAccessToken) {
        console.error('[create-customer] Could not get customer access token');
        return res.status(500).json({ success: false, message: 'Could not authenticate customer.' });
      }

      // Update customer name + email via Storefront API
      const updateData = await storefrontQuery(`
        mutation customerUpdate($customerAccessToken: String!, $customer: CustomerUpdateInput!) {
          customerUpdate(customerAccessToken: $customerAccessToken, customer: $customer) {
            customer { id email firstName lastName }
            customerUserErrors { code message }
          }
        }
      `, {
        customerAccessToken,
        customer: {
          firstName: firstName.trim(),
          lastName:  lastName?.trim() || '',
          email:     finalEmail,
        }
      });

      const updated      = updateData.data?.customerUpdate?.customer;
      const updateErrors = updateData.data?.customerUpdate?.customerUserErrors ?? [];

      if (updateErrors.length) {
        console.error('[create-customer] update errors:', updateErrors);
      }

      const customerId = updated?.id || `phone_${cleanPhone}`;
      cache.del(cacheKey);
      cache.del(`attempts:${cleanPhone}`);

      const wlpToken = createWlpToken({
        id:        customerId,
        email:     finalEmail,
        phone:     cleanPhone,
        firstName: firstName.trim(),
        lastName:  lastName?.trim() || '',
        isTemp,
        shop:      SHOPIFY_DOMAIN,
      });

      return res.json({
        success:  true,
        wlpToken,
        customer: {
          id:        customerId,
          email:     finalEmail,
          firstName: firstName.trim(),
          lastName:  lastName?.trim() || '',
          isTemp,
          tempEmail: isTemp ? tempEmail : null,
        },
        loginUrl: '/account',
      });

    } catch(err) {
      console.error('[create-customer]', err.message);
      return res.status(500).json({ success: false, message: 'Account creation failed.' });
    }
  });

  // ── Get orders (via Storefront API) ──────────────────
  app.post('/api/get-orders', async (req, res) => {
    try {
      const { phone } = req.body;
      if (!phone) return res.json({ success: false, orders: [] });
      const cleanPhone = sanitizePhone(phone);

      const accessToken = await getStorefrontAccessToken(cleanPhone);
      if (!accessToken) return res.json({ success: false, orders: [] });

      const data = await storefrontQuery(`
        query getOrders($token: String!) {
          customer(customerAccessToken: $token) {
            orders(first: 20, sortKey: PROCESSED_AT, reverse: true) {
              edges {
                node {
                  id
                  orderNumber
                  processedAt
                  fulfillmentStatus
                  financialStatus
                  currentTotalPrice { amount currencyCode }
                }
              }
            }
          }
        }
      `, { token: accessToken });

      const orders = data.data?.customer?.orders?.edges?.map(e => e.node) || [];
      return res.json({ success: true, orders });

    } catch(err) {
      console.error('[get-orders]', err.message);
      return res.json({ success: false, orders: [] });
    }
  });

  // ── Update email ──────────────────────────────────────
  app.post('/api/update-email', async (req, res) => {
    try {
      const { phone, email } = req.body;
      if (!phone || !email) return res.status(400).json({ success: false, message: 'Missing fields.' });
      const cleanPhone = sanitizePhone(phone);

      const customerAccessToken = await getStorefrontAccessToken(cleanPhone);
      if (!customerAccessToken) {
        return res.status(401).json({ success: false, message: 'Could not authenticate.' });
      }

      const updateData = await storefrontQuery(`
        mutation customerUpdate($customerAccessToken: String!, $customer: CustomerUpdateInput!) {
          customerUpdate(customerAccessToken: $customerAccessToken, customer: $customer) {
            customer { id email }
            customerUserErrors { code message }
          }
        }
      `, { customerAccessToken, customer: { email } });

      const updated = updateData.data?.customerUpdate?.customer;
      const errors  = updateData.data?.customerUpdate?.customerUserErrors ?? [];

      if (errors.length) {
        return res.status(422).json({ success: false, message: errors.map(e => e.message).join(', ') });
      }

      return res.json({ success: true, customer: updated });

    } catch(err) {
      console.error('[update-email]', err.message);
      return res.status(500).json({ success: false, message: 'Could not update email.' });
    }
  });

  console.log('[WLP] Routes loaded — Storefront API mode');
};
