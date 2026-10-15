// routes/franchise.js — Franchise form: phone OTP, partial-lead capture, final submit
//
// Endpoints
//   POST /api/franchise/send-otp     { phone, sessionId }
//   POST /api/franchise/verify-otp   { phone, otp, sessionId }        -> { verifyToken }
//   POST /api/franchise/draft        { sessionId, formType, step, fields }   (also accepts sendBeacon text/plain)
//   POST /api/franchise/submit       { sessionId, formType, verifyToken, fields }
//
// Storage
//   MySQL table `franchise_leads` (one row per form session, see SQL at the bottom of this file)
//   Every save is also forwarded to the Google Apps Script so the sheet + emails keep working.
//
// Env
//   FRANCHISE_OTP_SECRET   long random string, signs the verify token (required)
//   FRANCHISE_SHEET_URL    the Apps Script web-app URL (/exec)

const crypto  = require('crypto');
const express = require('express');
const axios   = require('axios');
const db      = require('../db');
const { sendSms, SMS } = require('../helpers/sms');
const { generateOtp, cleanPhone } = require('../helpers/utils');

// Which forms need a verified phone before submit
const OTP_REQUIRED = {
  'franchise-application': true,
  'quick-enquiry':         false   // quick enquiry still posts straight to Apps Script from the page
};
const FORM_TYPES = Object.keys(OTP_REQUIRED);

const TOKEN_TTL_MS      = 60 * 60 * 1000;   // verify token valid for 1 hour
const SHEET_PUSH_GAP_MS = 20 * 1000;        // push a partial to the sheet at most every 20s per session

let SECRET = process.env.FRANCHISE_OTP_SECRET;
if (!SECRET) {
  SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('[Franchise] FRANCHISE_OTP_SECRET not set — using a random secret. Verify tokens will break on restart.');
}

// ── helpers ──────────────────────────────────────────────
function validSession(id) {
  return typeof id === 'string' && /^[a-zA-Z0-9_-]{8,64}$/.test(id);
}

function signToken(phone, sessionId) {
  const exp  = Date.now() + TOKEN_TTL_MS;
  const body = `${phone}.${sessionId}.${exp}`;
  const sig  = crypto.createHmac('sha256', SECRET).update(body).digest('hex');
  return `${body}.${sig}`;
}

function checkToken(token, phone, sessionId) {
  if (typeof token !== 'string') return false;
  const parts = token.split('.');
  if (parts.length !== 4) return false;
  const [tPhone, tSession, tExp, sig] = parts;
  const expected = crypto.createHmac('sha256', SECRET).update(`${tPhone}.${tSession}.${tExp}`).digest('hex');
  if (sig.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return false;
  if (Number(tExp) < Date.now()) return false;
  return tPhone === phone && tSession === sessionId;
}

// Keep only sane keys/values from the browser
function cleanFields(raw) {
  const out = {};
  if (!raw || typeof raw !== 'object') return out;
  let n = 0;
  for (const [k, v] of Object.entries(raw)) {
    if (n >= 40) break;
    if (!/^[a-zA-Z0-9_\- ]{1,60}$/.test(k)) continue;
    if (v === null || v === undefined) continue;
    const val = Array.isArray(v) ? v.join(', ') : String(v);
    out[k] = val.trim().slice(0, 1000);
    n++;
  }
  return out;
}

// Pull common columns out of the field map (handles a few naming styles)
function pick(f, ...keys) {
  for (const k of keys) if (f[k]) return f[k];
  return '';
}
function summary(f) {
  const role = pick(f, 'role', 'preferred_role', 'preferredRole', 'Preferred Role');
  let model = '';
  if (/FOCO/i.test(role)) model = 'foco';
  else if (/SIS/i.test(role)) model = 'sis';
  else if (role) model = 'fofo';
  return {
    name:  pick(f, 'name', 'full_name', 'fullName', 'Name').slice(0, 120),
    phone: cleanPhone(pick(f, 'phone', 'mobile', 'Phone', 'Mobile')),
    email: pick(f, 'email', 'Email').slice(0, 160),
    city:  pick(f, 'city', 'City', 'location').slice(0, 80),
    model
  };
}

// Apps Script reads JSON from a text/plain body (same as the old page script did)
async function pushToSheet(payload) {
  const url = process.env.FRANCHISE_SHEET_URL;
  if (!url) return;
  try {
    await axios.post(url, JSON.stringify(payload), {
      headers: { 'Content-Type': 'text/plain' },
      timeout: 15000,
      maxRedirects: 5
    });
  } catch (e) {
    console.error('[Franchise] Sheet push failed:', e.message);
  }
}

// sendBeacon arrives as text/plain — parse it into req.body
function parseBeacon(req, res, next) {
  if (typeof req.body === 'string') {
    try { req.body = JSON.parse(req.body); } catch (e) { req.body = {}; }
  }
  next();
}

// ═══════════════════════════════════════════════════════════
module.exports = function (app, cache) {

  // ── POST /api/franchise/send-otp ─────────────────────────
  app.post('/api/franchise/send-otp', async (req, res) => {
    try {
      const mobile    = cleanPhone(req.body.phone);
      const sessionId = req.body.sessionId;
      if (mobile.length !== 10 || !/^[6-9]/.test(mobile)) {
        return res.status(400).json({ success: false, message: 'Enter a valid 10-digit mobile number.' });
      }
      if (!validSession(sessionId)) {
        return res.status(400).json({ success: false, message: 'Please refresh the page and try again.' });
      }

      const sentCount = cache.get(`fr_otp_req:${mobile}`) || 0;
      if (sentCount >= 3) {
        return res.status(429).json({ success: false, message: 'Too many OTP requests. Please wait 10 minutes.' });
      }
      cache.set(`fr_otp_req:${mobile}`, sentCount + 1, 600);

      const otp = generateOtp();
      cache.set(`fr_otp:${mobile}`, { otp, sessionId }, 600);
      cache.set(`fr_otp_attempts:${mobile}`, 0, 600);

      await sendSms(mobile, SMS.otp(otp), 'otp');
      return res.json({ success: true, message: `OTP sent to +91 ${mobile}` });
    } catch (err) {
      console.error('[Franchise send-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Could not send OTP. Please try again.' });
    }
  });

  // ── POST /api/franchise/verify-otp ───────────────────────
  app.post('/api/franchise/verify-otp', async (req, res) => {
    try {
      const mobile    = cleanPhone(req.body.phone);
      const sessionId = req.body.sessionId;
      const otp       = String(req.body.otp || '').trim();
      const stored    = cache.get(`fr_otp:${mobile}`);
      const attempts  = cache.get(`fr_otp_attempts:${mobile}`) || 0;

      if (!stored) return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
      if (stored.sessionId !== sessionId) return res.status(400).json({ success: false, message: 'Please request a new OTP.' });
      if (attempts >= 3) {
        cache.del(`fr_otp:${mobile}`);
        return res.status(429).json({ success: false, message: 'Too many wrong attempts. Request a new OTP.' });
      }
      if (String(stored.otp) !== otp) {
        cache.set(`fr_otp_attempts:${mobile}`, attempts + 1, 600);
        const left = 3 - attempts - 1;
        return res.status(400).json({ success: false, message: `Incorrect OTP. ${left} attempt${left === 1 ? '' : 's'} left.` });
      }

      cache.del(`fr_otp:${mobile}`);
      cache.del(`fr_otp_attempts:${mobile}`);

      // Persist verification on the lead row (survives restarts)
      await db.query(
        `INSERT INTO franchise_leads (session_id, phone, phone_verified, status)
         VALUES (?, ?, 1, 'partial')
         ON DUPLICATE KEY UPDATE phone = VALUES(phone), phone_verified = 1`,
        [sessionId, mobile]
      );

      return res.json({ success: true, verified: true, verifyToken: signToken(mobile, sessionId) });
    } catch (err) {
      console.error('[Franchise verify-otp]', err.message);
      return res.status(500).json({ success: false, message: 'Verification failed. Please try again.' });
    }
  });

  // ── POST /api/franchise/draft  (partial lead) ────────────
  app.post('/api/franchise/draft', express.text({ type: 'text/plain', limit: '64kb' }), parseBeacon, async (req, res) => {
    try {
      const { sessionId, formType, step } = req.body || {};
      if (!validSession(sessionId) || !FORM_TYPES.includes(formType)) {
        return res.status(400).json({ success: false });
      }
      const fields = cleanFields(req.body.fields);
      const s      = summary(fields);

      // Nothing worth keeping yet
      if (!s.name && !s.phone && !s.email) return res.json({ success: true, skipped: true });

      const source = String(req.body.source || '').slice(0, 255);
      const last   = String(step || '').slice(0, 60);

      // Never overwrite a lead that has already been submitted
      await db.query(
        `INSERT INTO franchise_leads
           (session_id, form_type, name, phone, email, city, model, data, last_step, source, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'partial')
         ON DUPLICATE KEY UPDATE
           form_type = IF(status = 'submitted', form_type, VALUES(form_type)),
           name      = IF(status = 'submitted', name,      COALESCE(NULLIF(VALUES(name), ''),  name)),
           phone     = IF(status = 'submitted', phone,     COALESCE(NULLIF(VALUES(phone), ''), phone)),
           email     = IF(status = 'submitted', email,     COALESCE(NULLIF(VALUES(email), ''), email)),
           city      = IF(status = 'submitted', city,      COALESCE(NULLIF(VALUES(city), ''),  city)),
           model     = IF(status = 'submitted', model,     COALESCE(NULLIF(VALUES(model), ''), model)),
           data      = IF(status = 'submitted', data,      VALUES(data)),
           last_step = IF(status = 'submitted', last_step, VALUES(last_step)),
           source    = COALESCE(NULLIF(source, ''), VALUES(source))`,
        [sessionId, formType, s.name, s.phone, s.email, s.city, s.model, JSON.stringify(fields), last, source]
      );

      // Throttled copy to the "Partial Leads" sheet tab
      const lastPush = cache.get(`fr_push:${sessionId}`) || 0;
      const leaving  = req.body.leaving === true;
      if (leaving || Date.now() - lastPush > SHEET_PUSH_GAP_MS) {
        cache.set(`fr_push:${sessionId}`, Date.now(), 3600);
        const [rows] = await db.query(
          'SELECT phone_verified, status FROM franchise_leads WHERE session_id = ?', [sessionId]
        );
        if (rows[0] && rows[0].status !== 'submitted') {
          pushToSheet({
            form_type:     'partial-lead',
            original_form: formType,
            sessionId,
            lastStep:      last,
            phoneVerified: rows[0].phone_verified ? 'Yes' : 'No',
            source,
            ...fields
          });
        }
      }

      return res.json({ success: true });
    } catch (err) {
      console.error('[Franchise draft]', err.message);
      return res.status(500).json({ success: false });
    }
  });

  // ── POST /api/franchise/submit ───────────────────────────
  app.post('/api/franchise/submit', async (req, res) => {
    try {
      const { sessionId, formType, verifyToken } = req.body || {};
      if (!validSession(sessionId) || !FORM_TYPES.includes(formType)) {
        return res.status(400).json({ success: false, message: 'Please refresh the page and try again.' });
      }
      const fields = cleanFields(req.body.fields);
      const s      = summary(fields);

      if (!s.name || s.phone.length !== 10) {
        return res.status(400).json({ success: false, message: 'Name and a valid mobile number are required.' });
      }
      if (OTP_REQUIRED[formType] && !checkToken(verifyToken, s.phone, sessionId)) {
        return res.status(401).json({ success: false, message: 'Please verify your mobile number first.', needsOtp: true });
      }

      const source = String(req.body.source || '').slice(0, 255);

      await db.query(
        `INSERT INTO franchise_leads
           (session_id, form_type, name, phone, email, city, model, data, last_step, source,
            phone_verified, status, submitted_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'submitted', ?, ?, 'submitted', NOW())
         ON DUPLICATE KEY UPDATE
           form_type = VALUES(form_type), name = VALUES(name), phone = VALUES(phone),
           email = VALUES(email), city = VALUES(city), model = VALUES(model),
           data = VALUES(data), last_step = 'submitted',
           source = COALESCE(NULLIF(source, ''), VALUES(source)),
           phone_verified = GREATEST(phone_verified, VALUES(phone_verified)),
           status = 'submitted', submitted_at = NOW()`,
        [sessionId, formType, s.name, s.phone, s.email, s.city, s.model, JSON.stringify(fields), source,
         OTP_REQUIRED[formType] ? 1 : 0]
      );

      // Existing Apps Script flow: sheet row + user email + admin email
      await pushToSheet({
        form_type: formType,
        sessionId,
        phoneVerified: OTP_REQUIRED[formType] ? 'Yes' : 'No',
        source,
        ...fields
      });

      return res.json({ success: true, model: s.model || 'fofo' });
    } catch (err) {
      console.error('[Franchise submit]', err.message);
      return res.status(500).json({ success: false, message: 'Something went wrong. Please try again.' });
    }
  });

  console.log('[Franchise] Routes loaded');
};

/* ── Run once in MySQL ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS franchise_leads (
  id              INT AUTO_INCREMENT PRIMARY KEY,
  session_id      VARCHAR(64)  NOT NULL UNIQUE,
  form_type       VARCHAR(40)  DEFAULT NULL,
  name            VARCHAR(120) DEFAULT NULL,
  phone           VARCHAR(15)  DEFAULT NULL,
  email           VARCHAR(160) DEFAULT NULL,
  city            VARCHAR(80)  DEFAULT NULL,
  model           VARCHAR(10)  DEFAULT NULL,
  data            LONGTEXT     DEFAULT NULL,
  last_step       VARCHAR(60)  DEFAULT NULL,
  source          VARCHAR(255) DEFAULT NULL,
  phone_verified  TINYINT(1)   NOT NULL DEFAULT 0,
  status          ENUM('partial','submitted') NOT NULL DEFAULT 'partial',
  created_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP    DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  submitted_at    DATETIME     DEFAULT NULL,
  INDEX idx_status (status),
  INDEX idx_phone  (phone)
);

──────────────────────────────────────────────────────────────── */
