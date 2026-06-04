// server.js — WHP GMS Backend Entry Point
require('dotenv').config();
const express   = require('express');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');
const path      = require('path');

const app   = express();
const cache = new NodeCache({ stdTTL: 600 });

// ── DB connection check ──────────────────────────────────
const db = require('./db');
db.query('SELECT 1')
  .then(() => console.log('✅ DB Connected'))
  .catch(err => console.log('❌ DB Error:', err.message));

// ── CORS — must be first ─────────────────────────────────
app.use(function(req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-shop-domain, x-user-token, x-staff-token, x-app-token');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// ── Middleware ───────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));

// !! Webhook raw body — MUST be before express.json()
// Reads raw body first, then parses JSON manually so express.json() is skipped
app.use('/api/gms-payment-webhook', (req, res, next) => {
  let rawBody = '';
  req.on('data', chunk => { rawBody += chunk; });
  req.on('end', () => {
    req.rawBody = rawBody;
    try { req.body = JSON.parse(rawBody); } catch(e) { req.body = {}; }
    next();
// routes/mobile-shop.js — Shopify product proxy for mobile app
// Uses Admin API token (server-side only — never exposed to app)

const axios = require('axios');

const SHOPIFY_DOMAIN        = process.env.SHOPIFY_SHOP_DOMAIN;
const SHOPIFY_CLIENT_ID     = process.env.SHOPIFY_MOBILE_CLIENT_ID;
const SHOPIFY_CLIENT_SECRET = process.env.SHOPIFY_MOBILE_CLIENT_SECRET;

// ── Token cache (same pattern as app-auth.js) ────────────
let _token = null, _tokenExpiry = 0;

async function getShopifyToken() {
  if (_token && Date.now() < _tokenExpiry - 5 * 60 * 1000) return _token;
  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: SHOPIFY_CLIENT_ID,
    client_secret: SHOPIFY_CLIENT_SECRET,
});
});

app.use((req, res, next) => {
  if (req.path === '/api/gms-payment-webhook') return next();
  express.json({ limit: '10mb' })(req, res, next);
});

// ── Rate limiter (OTP endpoints) ─────────────────────────
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, max: 5,
  keyGenerator: req => req.body?.phone || req.ip,
  message: { success: false, message: 'Too many OTP requests. Try again in 10 minutes.' }
});
app.use('/api/send-otp',     otpLimiter);
app.use('/api/gms/send-otp', otpLimiter);

// ── Admin dashboard ───────────────────────────────────────
app.get('/whp_admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'gms-dashboard.html'));
});

// ── Health check ─────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', app: 'WHP GMS', time: new Date().toISOString() }));

// ── GMS Routes ───────────────────────────────────────────
require('./routes/admin')(app, cache);
require('./routes/enrolments')(app, cache);
require('./routes/payments')(app);
require('./routes/coupons')(app);
require('./routes/reports')(app);
require('./routes/razorpay')(app, cache);
require('./routes/user-auth')(app, cache);
require('./routes/user-profile')(app, cache);
require('./routes/app-auth')(app, cache);
require('./routes/mobile-shop')(app, cache);

// ── Payment reminders + pay-now routes ──────────────────
require('./routes/payments-reminder')(app, cache);

// ── Legacy WLP routes (keep working) ────────────────────
require('./wlp-routes')(app, cache);

// ── Start ────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`✅ WHP GMS running on port ${PORT}`));

// ── Daily reminder cron (runs at 9am IST = 3:30am UTC) ──
const cron = require('node-cron');
const http = require('http');

function triggerReminders() {
  console.log('[GMS Cron] Running daily reminders...');
  const options = {
    hostname: 'localhost',
    port: PORT,
    path: '/api/gms/send-reminders',
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-cron-secret': process.env.GMS_CRON_SECRET || 'whpcron2026'
    }
  };
  const req = http.request(options, res => {
    let body = '';
    res.on('data', d => body += d);
    res.on('end', () => {
      try { console.log('[GMS Cron] Result:', JSON.parse(body)); }
      catch(e) { console.log('[GMS Cron] Response:', body); }
    });
  const res = await axios.post(
    `https://${SHOPIFY_DOMAIN}/admin/oauth/access_token`,
    params.toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  _token = res.data.access_token;
  _tokenExpiry = Date.now() + (res.data.expires_in || 86399) * 1000;
  return _token;
}

async function shopifyGet(path) {
  const token = await getShopifyToken();
  const res = await axios.get(`https://${SHOPIFY_DOMAIN}/admin/api/2024-04/${path}`, {
    headers: { 'X-Shopify-Access-Token': token }
});
  req.on('error', e => console.error('[GMS Cron] Error:', e.message));
  req.write(JSON.stringify({}));
  req.end();
  return res.data;
}

cron.schedule('30 3 * * *', triggerReminders, { timezone: 'Asia/Kolkata' });


async function sendPendingNudges() {
  try {
    const db = require('./db');
    const { sendSms, SMS } = require('./helpers/sms');
 
    // Only process nudges that are due and not expired
    const [nudges] = await db.query(
      `SELECT * FROM gms_pending_nudges 
       WHERE sent=0 AND send_after <= NOW()
       AND (expires_at IS NULL OR expires_at > NOW())
       LIMIT 50`
    );
 
    for (const nudge of nudges) {
      // Check if autopay already active — stop all nudges
      const [enrolRows] = await db.query(
        'SELECT razorpay_sub_status FROM gms_enrolments WHERE enrolment_id=?',
        [nudge.enrolment_id]
      );
      const enrol = enrolRows[0];
 
      if (enrol?.razorpay_sub_status !== 'active') {
        await sendSms(nudge.phone, SMS.mandateLink(nudge.short_url), 'mandateLink');
        console.log(`[GMS Nudge] Sent nudge #${nudge.nudge_count} to ${nudge.phone} for ${nudge.enrolment_id}`);
 
        // ── Schedule Nudge 2 only if this was Nudge 1
        if ((nudge.nudge_count || 1) === 1) {
          await db.query(
            `INSERT INTO gms_pending_nudges (enrolment_id, phone, short_url, send_after, expires_at, nudge_count)
             VALUES (?, ?, ?, DATE_ADD(NOW(), INTERVAL 48 HOUR), ?, 2)`,
            [nudge.enrolment_id, nudge.phone, nudge.short_url, nudge.expires_at]
          );
          console.log(`[GMS Nudge] Nudge 2 scheduled in 48 hours for ${nudge.enrolment_id}`);
        } else {
          console.log(`[GMS Nudge] Nudge 2 sent — no more nudges for ${nudge.enrolment_id}`);
        }
// ════════════════════════════════════════════════════════
module.exports = (app, cache) => {

  // ── GET /api/app/products ────────────────────────────
  // Query params: limit, page_info, collection_id, vendor, product_type
  app.get('/api/app/products', async (req, res) => {
    try {
      const { limit = 20, page_info, collection_id, vendor, product_type } = req.query;

      let url = `products.json?limit=${limit}&status=active&fields=id,title,handle,variants,images,product_type,vendor,tags`;
      if (page_info)     url += `&page_info=${page_info}`;
      if (vendor)        url += `&vendor=${encodeURIComponent(vendor)}`;
      if (product_type)  url += `&product_type=${encodeURIComponent(product_type)}`;

      let data;
      if (collection_id) {
        // Fetch products from a specific collection
        data = await shopifyGet(`collections/${collection_id}/products.json?limit=${limit}&fields=id,title,handle,variants,images,product_type,vendor,tags`);
} else {
        console.log(`[GMS Nudge] Skipped ${nudge.enrolment_id} — autopay already active`);
        data = await shopifyGet(url);
}
 
      // Mark current nudge as sent
      await db.query('UPDATE gms_pending_nudges SET sent=1 WHERE id=?', [nudge.id]);

      const products = (data.products || []).map(p => ({
        id:       p.id,
        title:    p.title,
        handle:   p.handle,
        type:     p.product_type,
        vendor:   p.vendor,
        tags:     p.tags,
        price:    p.variants?.[0]?.price || '0',
        comparePrice: p.variants?.[0]?.compare_at_price || null,
        image:    p.images?.[0]?.src || null,
        images:   (p.images || []).map(i => i.src),
        inStock:  p.variants?.some(v => v.inventory_quantity > 0 || v.inventory_management === null),
        variantId: p.variants?.[0]?.id,
      }));

      res.json({ success: true, products, count: products.length });
    } catch (err) {
      console.error('[SHOP] products error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch products.' });
}
  } catch(e) {
    console.error('[GMS Nudge] Error:', e.message);
  }
}
 

// ── Run nudge sender every 30 minutes ──
cron.schedule('*/30 * * * *', sendPendingNudges);

app.get('/api/test-nudge', async (req, res) => {
  await sendPendingNudges();
  res.json({ done: true });
});


app.get('/api/check-sub/:enrolmentId', async (req, res) => {
  try {
    const db = require('./db');
    const Razorpay = require('razorpay');
    const rzp = new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
    const [rows] = await db.query('SELECT razorpay_subscription_id, razorpay_sub_status FROM gms_enrolments WHERE enrolment_id=?', [req.params.enrolmentId]);
    if (!rows.length) return res.json({ error: 'Not found' });
    const sub = await rzp.subscriptions.fetch(rows[0].razorpay_subscription_id);
    res.json({ db_status: rows[0].razorpay_sub_status, rzp_status: sub.status, short_url: sub.short_url });
  } catch(e) { res.json({ error: e.message }); }
});
  });


  // ── GET /api/app/collections ─────────────────────────
  app.get('/api/app/collections', async (req, res) => {
    try {
      const data = await shopifyGet('custom_collections.json?limit=20&fields=id,title,handle,image');
      const collections = (data.custom_collections || []).map(c => ({
        id:     c.id,
        title:  c.title,
        handle: c.handle,
        image:  c.image?.src || null,
      }));
      res.json({ success: true, collections });
    } catch (err) {
      console.error('[SHOP] collections error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch collections.' });
    }
  });


  // ── GET /api/app/products/:id ────────────────────────
  app.get('/api/app/products/:id', async (req, res) => {
    try {
      const data = await shopifyGet(`products/${req.params.id}.json`);
      const p = data.product;
      if (!p) return res.status(404).json({ success: false, message: 'Product not found.' });

      res.json({
        success: true,
        product: {
          id:       p.id,
          title:    p.title,
          handle:   p.handle,
          type:     p.product_type,
          vendor:   p.vendor,
          tags:     p.tags,
          body:     p.body_html?.replace(/<[^>]*>/g, '') || '',
          price:    p.variants?.[0]?.price || '0',
          comparePrice: p.variants?.[0]?.compare_at_price || null,
          images:   (p.images || []).map(i => i.src),
          variants: p.variants?.map(v => ({
            id:     v.id,
            title:  v.title,
            price:  v.price,
            inStock: v.inventory_quantity > 0 || v.inventory_management === null,
          })),
        }
      });
    } catch (err) {
      console.error('[SHOP] product detail error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch product.' });
    }
  });

};

  // ── GET /api/app/menu ────────────────────────────────
  // Fetch Shopify navigation menu via GraphQL
  app.get('/api/app/menu', async (req, res) => {
    try {
      const token = await getShopifyToken();
      const handle = req.query.handle || 'main-menu';

      const query = `{
        menu(handle: "${handle}") {
          title
          items {
            id title url
            items {
              id title url
              items {
                id title url
              }
            }
          }
        }
      }`;

      const result = await axios.post(
        `https://${SHOPIFY_DOMAIN}/admin/api/2024-04/graphql.json`,
        { query },
        { headers: { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' } }
      );

      const menu = result.data?.data?.menu;
      if (!menu) return res.json({ success: true, items: [] });

      res.json({ success: true, title: menu.title, items: menu.items || [] });
    } catch (err) {
      console.error('[SHOP] menu error:', err.message);
      res.status(500).json({ success: false, message: 'Failed to fetch menu.' });
    }
  });
