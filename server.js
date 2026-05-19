// server.js — WHP GMS Backend Entry Point
require('dotenv').config();
const express   = require('express');
const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const NodeCache = require('node-cache');

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

// !! IMPORTANT: Razorpay webhook needs raw body for signature verification
// Must be registered BEFORE express.json()
app.use('/api/gms-payment-webhook', (req, res, next) => {
  let rawBody = '';
  req.on('data', chunk => { rawBody += chunk; });
  req.on('end', () => { req.rawBody = rawBody; next(); });
});

app.use(express.json({ limit: '10mb' }));

// ── Rate limiter (OTP endpoints) ─────────────────────────
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, max: 5,
  keyGenerator: req => req.body?.phone || req.ip,
  message: { success: false, message: 'Too many OTP requests. Try again in 10 minutes.' }
});
app.use('/api/send-otp',     otpLimiter);
app.use('/api/gms/send-otp', otpLimiter);

// ── Health check ─────────────────────────────────────────
app.get('/health', (req, res) => res.json({ status: 'ok', app: 'WHP GMS', time: new Date().toISOString() }));

// ── GMS Routes ───────────────────────────────────────────
require('./routes/admin')(app, cache);
require('./routes/enrolments')(app, cache);
require('./routes/payments')(app);
require('./routes/coupons')(app);
require('./routes/reports')(app);
require('./routes/razorpay')(app, cache);   // ← NEW: Razorpay E-Mandate
require('./routes/user-auth')(app, cache);
require('./routes/user-profile')(app, cache);
require('./routes/app-auth')(app, cache);   // ← kept from your existing server.js

// ── Legacy WLP routes (keep working) ────────────────────
require('./wlp-routes')(app, cache);

// ── Start ────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`✅ WHP GMS running on port ${PORT}`));
