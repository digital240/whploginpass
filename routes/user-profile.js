// routes/user-profile.js — /me, profile, photo, addresses, secondary mobile
const db                              = require('../db');
const { getUserFromToken, createUserSession } = require('../helpers/auth');
const { sendSms }                     = require('../helpers/sms');
const { generateOtp, cleanPhone }     = require('../helpers/utils');

// Auth middleware for customer routes
async function userAuth(req, res, next) {
  const user = await getUserFromToken(req.headers['x-user-token']);
  if (!user) return res.status(401).json({ success: false, message: 'Not logged in.' });
  req.gmsUser = user;
  next();
}

module.exports = function(app, cache) {

  // ── GET /api/gms/me ──────────────────────────────────
  app.get('/api/gms/me', userAuth, async (req, res) => {
    try {
      const cid = req.gmsUser.user_id;
      const [enrolments] = await db.query(
        `SELECT e.*,
          (SELECT COUNT(*) FROM gms_payments p WHERE p.enrolment_id=e.enrolment_id AND p.status='Paid') AS payments_made,
          (SELECT COUNT(*) FROM gms_payments p WHERE p.enrolment_id=e.enrolment_id AND p.status='Pending') AS payments_pending,
          (SELECT SUM(p.amount) FROM gms_payments p WHERE p.enrolment_id=e.enrolment_id AND p.status='Paid') AS total_contribution
         FROM gms_enrolments e
         WHERE e.user_id=? OR e.phone=?
         ORDER BY e.created_at DESC`,
        [cid, req.gmsUser.mobile]
      );
      for (const enrol of enrolments) {
        const [payments] = await db.query(
          'SELECT * FROM gms_payments WHERE enrolment_id=? ORDER BY month_num',
          [enrol.enrolment_id]
        );
        enrol.payments = payments;
      }
      const u = req.gmsUser;
      return res.json({
        success: true,
        user: {
          user_id: u.user_id, first_name: u.first_name, last_name: u.last_name,
          mobile: u.mobile, email: u.email, secondary_mobile: u.secondary_mobile,
          address1: u.address1, address2: u.address2, city: u.city,
          state: u.state, pincode: u.pincode, photo_url: u.photo_url,
          member_since: u.created_at,
          // Nominee details
          nominee_name: u.nominee_name, nominee_address: u.nominee_address,
          nominee_pan: u.nominee_pan, nominee_aadhaar: u.nominee_aadhaar,
          nominee_mobile: u.nominee_mobile, nominee_relation: u.nominee_relation,
          // Bank details
          bank_name: u.bank_name, bank_branch: u.bank_branch,
          bank_account: u.bank_account, bank_ifsc: u.bank_ifsc
        },
        enrolments
      });
    } catch(err) {
      console.error('[GMS /me]', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/update-profile ─────────────────────
  app.post('/api/gms/update-profile', userAuth, async (req, res) => {
    try {
      const { email, first_name, last_name } = req.body;
      const fields = [], vals = [];
      if (first_name !== undefined) { fields.push('first_name=?'); vals.push(first_name.trim()); }
      if (last_name  !== undefined) { fields.push('last_name=?');  vals.push(last_name.trim());  }
      if (email      !== undefined) { fields.push('email=?');      vals.push(email.trim());       }
      if (!fields.length) return res.json({ success: true });
      vals.push(req.gmsUser.user_id);
      await db.query(`UPDATE gms_users SET ${fields.join(',')} WHERE user_id=?`, vals);
      const [rows] = await db.query('SELECT * FROM gms_users WHERE user_id=?', [req.gmsUser.user_id]);
      return res.json({ success: true, user: rows[0] });
    } catch(err) {
      return res.status(500).json({ success: false, message: 'Update failed.' });
    }
  });

  // ── POST /api/gms/upload-photo ───────────────────────
  app.post('/api/gms/upload-photo', userAuth, async (req, res) => {
    try {
      const { photo_base64, mime_type } = req.body;
      if (!photo_base64) return res.status(400).json({ success: false, message: 'No photo provided.' });
      const dataUrl = `data:${mime_type||'image/jpeg'};base64,${photo_base64}`;
      await db.query('UPDATE gms_users SET photo_url=? WHERE user_id=?', [dataUrl, req.gmsUser.user_id]);
      return res.json({ success: true, photo_url: dataUrl });
    } catch(err) {
      return res.status(500).json({ success: false, message: 'Photo upload failed.' });
    }
  });

  // ── GET /api/gms/addresses ───────────────────────────
  app.get('/api/gms/addresses', userAuth, async (req, res) => {
    try {
      const [rows] = await db.query(
        'SELECT * FROM gms_user_addresses WHERE user_id=? ORDER BY is_default DESC, created_at ASC',
        [req.gmsUser.user_id]
      );
      return res.json({ success: true, addresses: rows });
    } catch(err) { return res.status(500).json({ success: false, message: err.message }); }
  });

  // ── GET /api/gms/addresses/default ──────────────────
  app.get('/api/gms/addresses/default', userAuth, async (req, res) => {
    try {
      const uid = req.gmsUser.user_id;
      let [rows] = await db.query('SELECT * FROM gms_user_addresses WHERE user_id=? AND is_default=1 LIMIT 1', [uid]);
      if (!rows.length) [rows] = await db.query('SELECT * FROM gms_user_addresses WHERE user_id=? ORDER BY created_at ASC LIMIT 1', [uid]);
      return res.json({ success: true, address: rows[0] || null });
    } catch(err) { return res.status(500).json({ success: false, message: err.message }); }
  });

  // ── POST /api/gms/addresses ──────────────────────────
  app.post('/api/gms/addresses', userAuth, async (req, res) => {
    try {
      const { label, address1, address2, city, state, pincode, is_default } = req.body;
      if (!address1||!city||!pincode) return res.status(400).json({ success: false, message: 'Address, city and pincode required.' });
      const uid = req.gmsUser.user_id;
      if (is_default) await db.query('UPDATE gms_user_addresses SET is_default=0 WHERE user_id=?', [uid]);
      const [existing] = await db.query('SELECT COUNT(*) as cnt FROM gms_user_addresses WHERE user_id=?', [uid]);
      const makeDefault = is_default || existing[0].cnt === 0;
      const [result] = await db.query(
        'INSERT INTO gms_user_addresses (user_id, label, address1, address2, city, state, pincode, is_default) VALUES (?,?,?,?,?,?,?,?)',
        [uid, label||'Home', address1.trim(), address2||'', city.trim(), state||'', pincode.trim(), makeDefault?1:0]
      );
      const [rows] = await db.query('SELECT * FROM gms_user_addresses WHERE address_id=?', [result.insertId]);
      return res.json({ success: true, address: rows[0] });
    } catch(err) { return res.status(500).json({ success: false, message: err.message }); }
  });

  // ── PUT /api/gms/addresses/:id ───────────────────────
  app.put('/api/gms/addresses/:id', userAuth, async (req, res) => {
    try {
      const uid = req.gmsUser.user_id;
      const addressId = parseInt(req.params.id);
      const { label, address1, address2, city, state, pincode, is_default } = req.body;
      const [check] = await db.query('SELECT * FROM gms_user_addresses WHERE address_id=? AND user_id=?', [addressId, uid]);
      if (!check.length) return res.status(404).json({ success: false, message: 'Address not found.' });
      if (is_default) await db.query('UPDATE gms_user_addresses SET is_default=0 WHERE user_id=?', [uid]);
      await db.query(
        'UPDATE gms_user_addresses SET label=?, address1=?, address2=?, city=?, state=?, pincode=?, is_default=? WHERE address_id=?',
        [label||'Home', address1||'', address2||'', city||'', state||'', pincode||'', is_default?1:0, addressId]
      );
      const [rows] = await db.query('SELECT * FROM gms_user_addresses WHERE address_id=?', [addressId]);
      return res.json({ success: true, address: rows[0] });
    } catch(err) { return res.status(500).json({ success: false, message: err.message }); }
  });

  // ── DELETE /api/gms/addresses/:id ───────────────────
  app.delete('/api/gms/addresses/:id', userAuth, async (req, res) => {
    try {
      const uid = req.gmsUser.user_id;
      const addressId = parseInt(req.params.id);
      const [check] = await db.query('SELECT * FROM gms_user_addresses WHERE address_id=? AND user_id=?', [addressId, uid]);
      if (!check.length) return res.status(404).json({ success: false, message: 'Address not found.' });
      await db.query('DELETE FROM gms_user_addresses WHERE address_id=?', [addressId]);
      if (check[0].is_default) {
        await db.query('UPDATE gms_user_addresses SET is_default=1 WHERE user_id=? ORDER BY created_at ASC LIMIT 1', [uid]);
      }
      return res.json({ success: true });
    } catch(err) { return res.status(500).json({ success: false, message: err.message }); }
  });

  // ── POST /api/gms/addresses/:id/default ─────────────
  app.post('/api/gms/addresses/:id/default', userAuth, async (req, res) => {
    try {
      const uid = req.gmsUser.user_id;
      const addressId = parseInt(req.params.id);
      const [check] = await db.query('SELECT * FROM gms_user_addresses WHERE address_id=? AND user_id=?', [addressId, uid]);
      if (!check.length) return res.status(404).json({ success: false, message: 'Address not found.' });
      await db.query('UPDATE gms_user_addresses SET is_default=0 WHERE user_id=?', [uid]);
      await db.query('UPDATE gms_user_addresses SET is_default=1 WHERE address_id=?', [addressId]);
      return res.json({ success: true });
    } catch(err) { return res.status(500).json({ success: false, message: err.message }); }
  });

  // ── POST /api/gms/send-secondary-otp ────────────────
  app.post('/api/gms/send-secondary-otp', userAuth, async (req, res) => {
    try {
      const secondary = cleanPhone(req.body.phone);
      if (secondary.length !== 10) return res.status(400).json({ success: false, message: 'Enter valid 10-digit number.' });
      if (secondary === req.gmsUser.mobile) return res.status(400).json({ success: false, message: 'Cannot be same as primary number.' });
      const otp = generateOtp();
      cache.set(`gms_sec_otp:${req.gmsUser.user_id}:${secondary}`, { otp }, 600);
      await sendSms(secondary, `Dear user, your WHP Jewellers otp code is ${otp}`);
      return res.json({ success: true });
    } catch(err) { return res.status(500).json({ success: false, message: 'Failed to send OTP.' }); }
  });

  // ── POST /api/gms/verify-secondary-otp ──────────────
  app.post('/api/gms/verify-secondary-otp', userAuth, async (req, res) => {
    try {
      const secondary = cleanPhone(req.body.phone);
      const { otp }   = req.body;
      const stored    = cache.get(`gms_sec_otp:${req.gmsUser.user_id}:${secondary}`);
      if (!stored) return res.status(400).json({ success: false, message: 'OTP expired.' });
      if (String(stored.otp) !== String(otp)) return res.status(400).json({ success: false, message: 'Incorrect OTP.' });
      await db.query('UPDATE gms_users SET secondary_mobile=? WHERE user_id=?', [secondary, req.gmsUser.user_id]);
      cache.del(`gms_sec_otp:${req.gmsUser.user_id}:${secondary}`);
      return res.json({ success: true });
    } catch(err) { return res.status(500).json({ success: false, message: 'Verification failed.' }); }
  });

  // ── POST /api/gms/update-nominee ─────────────────────
  app.post('/api/gms/update-nominee', userAuth, async (req, res) => {
    try {
      const { nominee_name, nominee_address, nominee_pan, nominee_aadhaar, nominee_mobile, nominee_relation } = req.body;
      await db.query(
        `UPDATE gms_users SET 
         nominee_name=?, nominee_address=?, nominee_pan=?,
         nominee_aadhaar=?, nominee_mobile=?, nominee_relation=?
         WHERE user_id=?`,
        [nominee_name||'', nominee_address||'', nominee_pan||'',
         nominee_aadhaar||'', nominee_mobile||'', nominee_relation||'',
         req.gmsUser.user_id]
      );
      const [rows] = await db.query('SELECT * FROM gms_users WHERE user_id=?', [req.gmsUser.user_id]);
      return res.json({ success: true, user: rows[0] });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms/update-bank ─────────────────────────
  app.post('/api/gms/update-bank', userAuth, async (req, res) => {
    try {
      const { bank_name, bank_branch, bank_account, bank_ifsc } = req.body;
      await db.query(
        'UPDATE gms_users SET bank_name=?, bank_branch=?, bank_account=?, bank_ifsc=? WHERE user_id=?',
        [bank_name||'', bank_branch||'', bank_account||'', bank_ifsc||'', req.gmsUser.user_id]
      );
      const [rows] = await db.query('SELECT * FROM gms_users WHERE user_id=?', [req.gmsUser.user_id]);
      return res.json({ success: true, user: rows[0] });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] User profile routes loaded');
};
