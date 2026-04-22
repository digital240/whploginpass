// ═══════════════════════════════════════════════════════════
//  WHPLoginPass — Backend Server
//  Node.js + Express
//  Routes: /send-otp  /verify-otp  /create-customer  /update-email
// ═══════════════════════════════════════════════════════════

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const NodeCache  = require('node-cache');
const axios      = require('axios');

const app   = express();
const cache = new NodeCache({ stdTTL: 600 }); // 10 min default TTL

// ── MIDDLEWARE ───────────────────────────────────────────
app.use(helmet());
app.use(express.json());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS === '*'
    ? '*'
    : process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()),
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'x-shop-domain']
}));

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

// ── SMSALERT — SEND OTP ───────────────────────────────────
// Uses SMSAlert's built-in OTP API (mverify.json)
// SMSAlert generates & tracks the OTP — we don't store it ourselves
async function sendOtpViaSMSAlert(phone) {
  const apiKey   = process.env.SMSALERT_API_KEY;
  const sender   = process.env.SMSALERT_SENDER_ID;
  const validity = process.env.OTP_EXPIRY_MINUTES || 10;
  const length   = process.env.OTP_LENGTH || 6;

  // Template with [otp] tag — SMSAlert fills in the actual OTP
  const template = encodeURIComponent(
    `Your WHPLoginPass OTP is [otp length="${length}" validity="${validity}"]. Valid for ${validity} minutes. Do not share with anyone.`
  );

  const url = `http://www.smsalert.co.in/api/mverify.json?apikey=${apiKey}&sender=${sender}&mobileno=${phone}&template=${template}`;

  const res = await axios.post(url);
  return res.data;
}

// ── SMSALERT — VALIDATE OTP ───────────────────────────────
// SMSAlert validates the OTP on their server — we just ask them
async function validateOtpViaSMSAlert(phone, otp) {
  const apiKey = process.env.SMSALERT_API_KEY;
  const url    = `http://www.smsalert.co.in/api/mverify.json?apikey=${apiKey}&mobileno=${phone}&code=${otp}`;

  const res  = await axios.post(url);
  const data = res.data;

  // SMSAlert returns status:"success" + desc:"Code Matched." on success
  // and status:"success" + desc:"Code does not match." on failure
  const matched =
    data.status === 'success' &&
    data.description &&
    String(data.description.desc).toLowerCase().includes('matched');

  return { raw: data, matched };
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
    cache.set(cacheKey, stored, 300); // keep 5 more mins to complete profile

    return res.json({ success: true, message: 'OTP verified!', phone: cleanPhone });

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
      email, shop, accessToken
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
    const finalEmail = email && email.trim()
      ? email.trim()
      : buildTempEmail(cleanPhone, shop);

    const isTemp = !email || !email.trim();

    const { base, headers } = shopifyApi(shop, accessToken);

    // Check if customer with this phone or email already exists
    let existingCustomer = null;
    try {
      const searchRes = await axios.get(
        `${base}/customers/search.json?query=phone:+91${cleanPhone}&fields=id,email,phone,first_name,last_name`,
        { headers }
      );
      if (searchRes.data.customers && searchRes.data.customers.length > 0) {
        existingCustomer = searchRes.data.customers[0];
      }
    } catch (e) { /* ignore search errors */ }

    let customer;

    if (existingCustomer) {
      // Update existing customer
      const updateRes = await axios.put(
        `${base}/customers/${existingCustomer.id}.json`,
        {
          customer: {
            id:         existingCustomer.id,
            first_name: firstName,
            last_name:  lastName || '',
            phone:      `+91${cleanPhone}`,
            email:      existingCustomer.email.includes('@') && !existingCustomer.email.startsWith(cleanPhone)
              ? existingCustomer.email  // keep real email
              : finalEmail,
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
            tags: isTemp ? 'whploginpass,temp-email' : 'whploginpass'
          }
        },
        { headers }
      );
      customer = updateRes.data.customer;
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

    return res.json({
      success:    true,
      customer:   {
        id:         customer.id,
        email:      customer.email,
        firstName:  customer.first_name,
        lastName:   customer.last_name,
        phone:      customer.phone,
        isTemp:     isTemp,
        tempEmail:  isTemp ? finalEmail : null
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

// ── HEALTH CHECK ─────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', app: 'WHPLoginPass' }));

// ── START ─────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`✅ WHPLoginPass backend running on port ${PORT}`);
});
