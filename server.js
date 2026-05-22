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
  });
  req.on('error', e => console.error('[GMS Cron] Error:', e.message));
  req.write(JSON.stringify({}));
  req.end();
}

cron.schedule('30 3 * * *', triggerReminders, { timezone: 'Asia/Kolkata' });
