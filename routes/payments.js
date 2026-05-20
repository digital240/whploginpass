// routes/payments.js — Mark paid, late fees, discontinue
const db               = require('../db');
const NodeCache        = require('node-cache');
const { staffAuth }    = require('../helpers/auth');
const { sendSms }      = require('../helpers/sms');
const { generateOtp }  = require('../helpers/utils');

const payOtpCache = new NodeCache({ stdTTL: 300 }); // 5 min OTP expiry

module.exports = function(app) {

  // ── POST /api/gms-send-pay-otp ───────────────────────
  // Branch requests OTP before marking month paid
  app.post('/api/gms-send-pay-otp', staffAuth, async (req, res) => {
    try {
      const { enrolmentId, monthNum } = req.body;
      if (!enrolmentId || !monthNum) return res.status(400).json({ success: false, message: 'enrolmentId and monthNum required.' });

      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      // Branch permission check
      if (req.staff.role === 'branch' && enrol.preferred_branch !== req.staff.branch) {
        return res.status(403).json({ success: false, message: `You can only mark payments for ${req.staff.branch} branch.` });
      }

      // Check month is actually pending
      const [payRows] = await db.query(
        "SELECT * FROM gms_payments WHERE enrolment_id=? AND month_num=? AND status='Pending'",
        [enrolmentId, monthNum]
      );
      if (!payRows.length) return res.status(400).json({ success: false, message: `Month ${monthNum} is not pending.` });

      // Generate OTP
      const otp = generateOtp();
      const key = `pay_otp:${enrolmentId}:${monthNum}`;
      payOtpCache.set(key, { otp, branch: req.staff.branch, by: req.staff.username });

      // Send to customer
      await sendSms(enrol.phone,
        `Dear user, your WHP Jewellers otp code is ${otp}`
      );

      console.log(`[GMS] Pay OTP sent for ${enrolmentId} M${monthNum} to ${enrol.phone}`);
      return res.json({ success: true, message: `OTP sent to customer's mobile ending ${enrol.phone.slice(-4)}` });
    } catch(err) {
      console.error('[GMS] send-pay-otp error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-verify-pay-otp ─────────────────────
  // Verify OTP then mark month as paid
  app.post('/api/gms-verify-pay-otp', staffAuth, async (req, res) => {
    try {
      const { enrolmentId, monthNum, otp, lateFee, notes } = req.body;
      if (!enrolmentId || !monthNum || !otp) return res.status(400).json({ success: false, message: 'enrolmentId, monthNum and otp required.' });

      const key    = `pay_otp:${enrolmentId}:${monthNum}`;
      const stored = payOtpCache.get(key);

      if (!stored) return res.status(400).json({ success: false, message: 'OTP expired or not requested. Please resend OTP.' });
      if (String(stored.otp) !== String(otp)) return res.status(400).json({ success: false, message: 'Incorrect OTP. Please try again.' });

      // OTP verified — delete it
      payOtpCache.del(key);

      // Now mark as paid (same logic as mark-paid)
      const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!enrolRows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = enrolRows[0];

      if (req.staff.role === 'branch' && enrol.preferred_branch !== req.staff.branch) {
        return res.status(403).json({ success: false, message: `You can only mark payments for ${req.staff.branch} branch.` });
      }

      await db.query(
        `UPDATE gms_payments SET status='Paid', paid_at=NOW(),
         pay_method='Store', collected_branch=?, collected_by=?, late_fee=?, notes=?
         WHERE enrolment_id=? AND month_num=?`,
        [req.staff.branch||'Admin', req.staff.username, lateFee||0, notes||'', enrolmentId, monthNum]
      );

      const [countRows] = await db.query(
        'SELECT COUNT(*) as paid FROM gms_payments WHERE enrolment_id=? AND status="Paid"',
        [enrolmentId]
      );
      const made    = countRows[0].paid;
      const pending = enrol.pay_months - made;
      const allDone = pending <= 0;
      const status  = allDone ? 'Matured' : 'Active';

      await db.query(
        'UPDATE gms_enrolments SET payments_made=?, payments_pending=?, status=? WHERE enrolment_id=?',
        [made, Math.max(0, pending), status, enrolmentId]
      );

      if (lateFee && parseFloat(lateFee) > 0) {
        await db.query(
          'INSERT INTO gms_late_fees (enrolment_id, month_num, amount, applied_by) VALUES (?,?,?,?)',
          [enrolmentId, monthNum, lateFee, req.staff.username]
        );
        await db.query(
          'UPDATE gms_enrolments SET late_fee_total=late_fee_total+? WHERE enrolment_id=?',
          [lateFee, enrolmentId]
        );
      }

      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, `Month ${monthNum} marked Paid (OTP verified)`, req.staff.username, req.staff.branch||'Admin',
         `OTP verified. Late fee: ${lateFee||0}. Notes: ${notes||''}`]
      );

      const msg = allDone
        ? `Dear Customer, your WHP GMS scheme ${enrolmentId} is now MATURED! WHP team will contact you shortly. - WHP Jewellers`
        : `Dear Customer, month ${monthNum} payment of Rs.${enrol.instalment_amt} recorded for WHP GMS scheme ${enrolmentId}. ${Math.max(0,pending)} payment(s) remaining. - WHP Jewellers`;
      await sendSms(enrol.phone, msg);

      return res.json({
        success: true, made, pending: Math.max(0,pending), allDone, status,
        message: allDone ? 'Scheme matured!' : `Month ${monthNum} marked paid successfully!`
      });
    } catch(err) {
      console.error('[GMS] verify-pay-otp error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-mark-paid ──────────────────────────
  app.post('/api/gms-mark-paid', staffAuth, async (req, res) => {
    try {
      const { enrolmentId, monthNum, lateFee, notes } = req.body;
      if (!enrolmentId || !monthNum) return res.status(400).json({ success: false, message: 'enrolmentId and monthNum required.' });

      const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!enrolRows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = enrolRows[0];

      // Branch managers can only mark their own branch
      if (req.staff.role === 'branch' && enrol.preferred_branch !== req.staff.branch) {
        return res.status(403).json({ success: false, message: `You can only mark payments for ${req.staff.branch} branch.` });
      }

      await db.query(
        `UPDATE gms_payments SET status='Paid', paid_at=NOW(),
         pay_method='Store', collected_branch=?, collected_by=?, late_fee=?, notes=?
         WHERE enrolment_id=? AND month_num=?`,
        [req.staff.branch||'Admin', req.staff.username, lateFee||0, notes||'', enrolmentId, monthNum]
      );

      const [countRows] = await db.query(
        'SELECT COUNT(*) as paid FROM gms_payments WHERE enrolment_id=? AND status="Paid"',
        [enrolmentId]
      );
      const made    = countRows[0].paid;
      const pending = enrol.pay_months - made;
      const allDone = pending <= 0;
      const status  = allDone ? 'Matured' : 'Active';

      await db.query(
        'UPDATE gms_enrolments SET payments_made=?, payments_pending=?, status=? WHERE enrolment_id=?',
        [made, Math.max(0, pending), status, enrolmentId]
      );

      if (lateFee && parseFloat(lateFee) > 0) {
        await db.query(
          'INSERT INTO gms_late_fees (enrolment_id, month_num, amount, applied_by) VALUES (?,?,?,?)',
          [enrolmentId, monthNum, lateFee, req.staff.username]
        );
        await db.query(
          'UPDATE gms_enrolments SET late_fee_total=late_fee_total+? WHERE enrolment_id=?',
          [lateFee, enrolmentId]
        );
      }

      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, `Month ${monthNum} marked Paid`, req.staff.username, req.staff.branch||'Admin', `Late fee: ${lateFee||0}. Notes: ${notes||''}`]
      );

      const msg = allDone
        ? `Dear Customer, your WHP GMS scheme ${enrolmentId} is now MATURED! WHP team will contact you shortly. - WHP Jewellers`
        : `Dear Customer, month ${monthNum} payment recorded for WHP GMS scheme ${enrolmentId}. ${pending} payment(s) remaining. - WHP Jewellers`;
      await sendSms(enrol.phone, msg);

      return res.json({ success: true, made, pending: Math.max(0,pending), allDone, status, message: allDone ? 'Scheme matured!' : `Month ${monthNum} marked paid.` });
    } catch(err) {
      console.error('[GMS] mark-paid error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-apply-late-fee ─────────────────────
  app.post('/api/gms-apply-late-fee', staffAuth, async (req, res) => {
    try {
      const { enrolmentId, monthNum, amount, reason } = req.body;
      await db.query(
        'INSERT INTO gms_late_fees (enrolment_id, month_num, amount, reason, applied_by) VALUES (?,?,?,?,?)',
        [enrolmentId, monthNum, amount, reason||'', req.staff.username]
      );
      await db.query('UPDATE gms_enrolments SET late_fee_total=late_fee_total+? WHERE enrolment_id=?', [amount, enrolmentId]);
      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, 'Late fee applied', req.staff.username, req.staff.branch||'Admin', `Month ${monthNum}: Rs.${amount}. Reason: ${reason}`]
      );
      return res.json({ success: true, message: `Late fee of Rs.${amount} applied.` });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-discontinue ─────────────────────────
  app.post('/api/gms-discontinue', staffAuth, async (req, res) => {
    try {
      if (req.staff.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
      const { enrolmentId, reason } = req.body;
      if (!enrolmentId) return res.status(400).json({ success: false, message: 'enrolmentId required.' });

      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      if (enrol.status === 'Discontinued') return res.status(400).json({ success: false, message: 'Already discontinued.' });
      if (enrol.status === 'Complete')     return res.status(400).json({ success: false, message: 'Cannot discontinue a completed scheme.' });

      await db.query("UPDATE gms_enrolments SET status='Discontinued', completion_date=CURDATE() WHERE enrolment_id=?", [enrolmentId]);
      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, 'Scheme Discontinued', req.staff.username, req.staff.branch||'Admin', `Reason: ${reason||'Not specified'}`]
      );
      await sendSms(enrol.phone,
        `Dear Customer, your WHP GMS scheme ${enrolmentId} has been discontinued. Please contact your nearest WHP branch for details. - WHP Jewellers`
      );

      return res.json({ success: true, message: `Scheme ${enrolmentId} discontinued.` });
    } catch(err) {
      console.error('[GMS] discontinue error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Payment routes loaded');
};
