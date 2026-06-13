/**
 * WHP Jewellers – Appointment OTP Routes
 * File: routes/appointments.js
 *
 * Reuses existing OTP cache keys set by user-auth.js
 * so no separate OTP table or SMS helper needed.
 *
 * In app.js:
 *   const appointmentRoutes = require('./routes/appointments');
 *   app.use('/api/appointments', appointmentRoutes);
 *   appointmentRoutes.init(cache);   // pass your existing NodeCache instance
 */

const express        = require('express');
const router         = express.Router();
const { sendSms, SMS } = require('../helpers/sms');
const { generateOtp, cleanPhone } = require('../helpers/utils');

let _cache = null;

// Call this from app.js after require() to inject the shared cache
router.init = function (cache) { _cache = cache; };

// ══════════════════════════════════════════════════════════════════
// POST /api/appointments/send-otp
// Body: { mobile: "9876543210" }
// Reuses gms_otp_req / gms_otp cache keys — same as GMS login
// ══════════════════════════════════════════════════════════════════
router.post('/send-otp', async (req, res) => {
  try {
    const mobile = cleanPhone(req.body.mobile || req.body.phone);
    if (!mobile || mobile.length !== 10) {
      return res.json({ success: false, message: 'Enter a valid 10-digit mobile number.' });
    }

    // Rate-limit: 3 requests per 10 min (same bucket as GMS login)
    const attempts = _cache.get(`gms_otp_req:${mobile}`) || 0;
    if (attempts >= 3) {
      return res.status(429).json({ success: false, message: 'Too many OTP requests. Wait 10 minutes.' });
    }
    _cache.set(`gms_otp_req:${mobile}`, attempts + 1, 600);

    const otp = generateOtp();
    _cache.set(`gms_otp:${mobile}`,          { otp, verified: false }, 600);
    _cache.set(`otp:${mobile}`,              { phone: mobile, verified: false }, 600);
    _cache.set(`gms_otp_attempts:${mobile}`, 0, 600);

    await sendSms(mobile, SMS.otp(otp), 'otp');

    return res.json({ success: true, message: `OTP sent to +91 ${mobile}` });

  } catch (err) {
    console.error('[Appointments send-otp]', err.message);
    return res.status(500).json({ success: false, message: 'Failed to send OTP.' });
  }
});

// ══════════════════════════════════════════════════════════════════
// POST /api/appointments/verify-otp
// Body: { mobile: "9876543210", otp: "123456" }
// ══════════════════════════════════════════════════════════════════
router.post('/verify-otp', (req, res) => {
  try {
    const mobile   = cleanPhone(req.body.mobile || req.body.phone);
    const { otp }  = req.body;
    const stored   = _cache.get(`gms_otp:${mobile}`);
    let   attempts = _cache.get(`gms_otp_attempts:${mobile}`) || 0;

    if (!stored) {
      return res.status(400).json({ success: false, message: 'OTP expired. Please request a new one.' });
    }
    if (attempts >= 3) {
      _cache.del(`gms_otp:${mobile}`);
      return res.status(429).json({ success: false, message: 'Too many wrong attempts. Request a new OTP.' });
    }
    if (String(stored.otp) !== String(otp)) {
      _cache.set(`gms_otp_attempts:${mobile}`, attempts + 1, 600);
      const left = 3 - attempts - 1;
      return res.status(400).json({ success: false, message: `Incorrect OTP. ${left} attempt(s) left.` });
    }

    // Correct — mark verified (keep 30 min so form submit can confirm it later)
    _cache.set(`gms_otp:${mobile}`, { otp, verified: true }, 1800);
    _cache.set(`otp:${mobile}`,     { phone: mobile, verified: true }, 1800);

    return res.json({ success: true, message: 'Mobile verified.' });

  } catch (err) {
    console.error('[Appointments verify-otp]', err.message);
    return res.status(500).json({ success: false, message: 'Verification failed.' });
  }
});

module.exports = router;
