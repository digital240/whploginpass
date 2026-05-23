// routes/payments.js — Mark paid, late fees, discontinue
const db               = require('../db');
const NodeCache        = require('node-cache');
const { staffAuth }    = require('../helpers/auth');
const { sendSms, SMS } = require('../helpers/sms');
const { generateOtp }  = require('../helpers/utils');

const payOtpCache = new NodeCache({ stdTTL: 300 }); // 5 min OTP expiry

const MONTH_NAMES = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
function getMonthName(enrolDate, monthNum) {
  const start = new Date(enrolDate);
  const d = new Date(start.getFullYear(), start.getMonth() + (monthNum - 1), 1);
  return MONTH_NAMES[d.getMonth()] + ' ' + d.getFullYear();
}

module.exports = function(app) {

  // ── POST /api/gms-send-pay-otp ───────────────────────
  app.post('/api/gms-send-pay-otp', staffAuth, async (req, res) => {
    try {
      const { enrolmentId, monthNum } = req.body;
      if (!enrolmentId || !monthNum) return res.status(400).json({ success: false, message: 'enrolmentId and monthNum required.' });

      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      if (req.staff.role === 'branch' && enrol.preferred_branch !== req.staff.branch) {
        return res.status(403).json({ success: false, message: `You can only mark payments for ${req.staff.branch} branch.` });
      }

      const [payRows] = await db.query(
        "SELECT * FROM gms_payments WHERE enrolment_id=? AND month_num=? AND status='Pending'",
        [enrolmentId, monthNum]
      );
      if (!payRows.length) return res.status(400).json({ success: false, message: `Month ${monthNum} is not pending.` });

      const otp = generateOtp();
      const key = `pay_otp:${enrolmentId}:${monthNum}`;
      payOtpCache.set(key, { otp, branch: req.staff.branch, by: req.staff.username });

      // ── Use 'otp' template — exact DLT approved text
      await sendSms(enrol.phone, SMS.otp(otp), 'otp');

      console.log(`[GMS] Pay OTP sent for ${enrolmentId} M${monthNum} to ${enrol.phone}`);
      return res.json({ success: true, message: `OTP sent to customer's mobile ending ${enrol.phone.slice(-4)}` });
    } catch(err) {
      console.error('[GMS] send-pay-otp error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-verify-pay-otp ─────────────────────
  app.post('/api/gms-verify-pay-otp', staffAuth, async (req, res) => {
    try {
      const { enrolmentId, monthNum, otp, lateFee, notes } = req.body;
      if (!enrolmentId || !monthNum || !otp) return res.status(400).json({ success: false, message: 'enrolmentId, monthNum and otp required.' });

      const key    = `pay_otp:${enrolmentId}:${monthNum}`;
      const stored = payOtpCache.get(key);

      if (!stored) return res.status(400).json({ success: false, message: 'OTP expired or not requested. Please resend OTP.' });
      if (String(stored.otp) !== String(otp)) return res.status(400).json({ success: false, message: 'Incorrect OTP. Please try again.' });

      payOtpCache.del(key);

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

      if (allDone) {
        await sendSms(enrol.phone, SMS.matured(enrolmentId, enrol.total_redeemable), 'matured');
      } else {
        await sendSms(enrol.phone, SMS.autoDebitSuccess(enrol.instalment_amt, enrolmentId, monthNum, Math.max(0, pending)), 'autoDebitSuccess');
      }

      return res.json({
        success: true, made, pending: Math.max(0, pending), allDone, status,
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
        [enrolmentId, `Month ${monthNum} marked Paid`, req.staff.username, req.staff.branch||'Admin',
         `Late fee: ${lateFee||0}. Notes: ${notes||''}`]
      );

      if (allDone) {
        await sendSms(enrol.phone, SMS.matured(enrolmentId, enrol.total_redeemable), 'matured');
      } else {
        await sendSms(enrol.phone, SMS.autoDebitSuccess(enrol.instalment_amt, enrolmentId, monthNum, Math.max(0, pending)), 'autoDebitSuccess');
      }

      return res.json({
        success: true, made, pending: Math.max(0, pending), allDone, status,
        message: allDone ? 'Scheme matured!' : `Month ${monthNum} marked paid.`
      });
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
        [enrolmentId, 'Late fee applied', req.staff.username, req.staff.branch||'Admin',
         `Month ${monthNum}: Rs.${amount}. Reason: ${reason}`]
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
        [enrolmentId, 'Scheme Discontinued', req.staff.username, req.staff.branch||'Admin',
         `Reason: ${reason||'Not specified'}`]
      );

      await sendSms(enrol.phone, SMS.discontinued(enrolmentId), 'discontinued');

      return res.json({ success: true, message: `Scheme ${enrolmentId} discontinued.` });
    } catch(err) {
      console.error('[GMS] discontinue error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-request-discontinue ───────────────
  app.post('/api/gms-request-discontinue', staffAuth, async (req, res) => {
    try {
      const { enrolmentId, reason } = req.body;
      if (!enrolmentId || !reason) return res.status(400).json({ success: false, message: 'enrolmentId and reason required.' });

      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = rows[0];

      if (req.staff.role === 'branch' && enrol.preferred_branch !== req.staff.branch) {
        return res.status(403).json({ success: false, message: 'You can only request discontinue for your branch.' });
      }

      const [existing] = await db.query(
        "SELECT id FROM gms_discontinue_requests WHERE enrolment_id=? AND status='Pending'",
        [enrolmentId]
      );
      if (existing.length) return res.status(400).json({ success: false, message: 'A pending request already exists for this scheme.' });

      const [paidRows] = await db.query(
        "SELECT COUNT(*) as paid FROM gms_payments WHERE enrolment_id=? AND status='Paid'",
        [enrolmentId]
      );
      const paidMonths   = paidRows[0].paid;
      const totalPaid    = paidMonths * parseFloat(enrol.instalment_amt);
      const deduction    = totalPaid * 0.03;
      const refundAmount = Math.round(totalPaid - deduction);

      await db.query(
        `INSERT INTO gms_discontinue_requests 
         (enrolment_id, requested_by, branch, reason, refund_amount, status)
         VALUES (?,?,?,?,?,'Pending')`,
        [enrolmentId, req.staff.username, req.staff.branch||'Admin', reason, refundAmount]
      );

      await db.query(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, 'Discontinue Requested', req.staff.username, req.staff.branch||'Admin',
         `Reason: ${reason}. Refund estimate: Rs.${refundAmount}`]
      );

      // Inform customer request is raised — use discontinued template (closest match)
      await sendSms(enrol.phone, SMS.discontinued(enrolmentId), 'discontinued');

      return res.json({
        success: true,
        refundAmount,
        message: `Discontinue request submitted. Estimated refund: ₹${refundAmount.toLocaleString('en-IN')} (after 3% deduction).`
      });
    } catch(err) {
      console.error('[GMS] request-discontinue error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-discontinue-requests ────────────────
  app.get('/api/gms-discontinue-requests', staffAuth, async (req, res) => {
    try {
      if (req.staff.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
      const [rows] = await db.query(`
        SELECT r.*, e.name, e.phone, e.instalment_amt, e.payments_made, e.pay_months,
               e.total_redeemable, e.preferred_branch, e.status as scheme_status
        FROM gms_discontinue_requests r
        JOIN gms_enrolments e ON r.enrolment_id = e.enrolment_id
        ORDER BY r.created_at DESC
      `);
      return res.json({ success: true, rows });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-review-discontinue ─────────────────
  app.post('/api/gms-review-discontinue', staffAuth, async (req, res) => {
    try {
      if (req.staff.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
      const { requestId, action, adminNotes } = req.body;
      if (!requestId || !action) return res.status(400).json({ success: false, message: 'requestId and action required.' });
      if (!['Approved', 'Rejected'].includes(action)) return res.status(400).json({ success: false, message: 'action must be Approved or Rejected.' });

      const [reqRows] = await db.query('SELECT * FROM gms_discontinue_requests WHERE id=?', [requestId]);
      if (!reqRows.length) return res.status(404).json({ success: false, message: 'Request not found.' });
      const request = reqRows[0];

      if (request.status !== 'Pending') return res.status(400).json({ success: false, message: 'Request already reviewed.' });

      const [enrolRows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [request.enrolment_id]);
      if (!enrolRows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = enrolRows[0];

      await db.query(
        `UPDATE gms_discontinue_requests 
         SET status=?, admin_notes=?, reviewed_by=?, reviewed_at=NOW() WHERE id=?`,
        [action, adminNotes||'', req.staff.username, requestId]
      );

      if (action === 'Approved') {
        await db.query(
          "UPDATE gms_enrolments SET status='Discontinued', completion_date=CURDATE() WHERE enrolment_id=?",
          [request.enrolment_id]
        );
        await db.query(
          'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
          [request.enrolment_id, 'Discontinue Approved', req.staff.username, 'Admin',
           `Request #${requestId} approved. Refund: Rs.${request.refund_amount}. Notes: ${adminNotes||''}`]
        );
        await sendSms(enrol.phone, SMS.discontinued(request.enrolment_id), 'discontinued');
      } else {
        await db.query(
          'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
          [request.enrolment_id, 'Discontinue Rejected', req.staff.username, 'Admin',
           `Request #${requestId} rejected. Notes: ${adminNotes||''}`]
        );
        // No SMS for rejection — no matching DLT template
      }

      return res.json({
        success: true,
        message: action === 'Approved'
          ? `Scheme discontinued. Refund of ₹${request.refund_amount} to be processed.`
          : 'Request rejected.'
      });
    } catch(err) {
      console.error('[GMS] review-discontinue error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-send-reminders ─────────────────────
  app.get('/api/gms-send-reminders', async (req, res) => {
    try {
      const key = req.headers['x-cron-key'] || req.query.key;
      if (key !== process.env.GMS_CRON_KEY) return res.status(401).json({ success: false, message: 'Unauthorized.' });

      const today = new Date();
      const BASE  = 'https://yellowgreen-jay-842557.hostingersite.com';

      const [schemes] = await db.query(`
        SELECT e.*,
          (SELECT month_num FROM gms_payments WHERE enrolment_id=e.enrolment_id AND status='Pending' ORDER BY month_num ASC LIMIT 1) as next_pending_month
        FROM gms_enrolments e
        WHERE e.status='Active'
          AND e.pay_method IN ('Pay at Store', 'UPI One-time')
          AND e.payments_pending > 0
      `);

      let sent = 0;
      for (const scheme of schemes) {
        if (!scheme.next_pending_month) continue;

        const enrollDate = new Date(scheme.enrolment_date || scheme.created_at);
        const dueDay     = enrollDate.getDate();
        const dueDate    = new Date(today.getFullYear(), today.getMonth(), dueDay);
        const diffDays   = Math.round((dueDate - today) / (1000 * 60 * 60 * 24));

        if (diffDays === 5 || diffDays === 0) {
          const payLink    = `${BASE}/api/razorpay/pay-now/${scheme.enrolment_id}`;
          const dueDateStr = dueDate.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });

          await sendSms(
            scheme.phone,
            SMS.reminder(scheme.instalment_amt, scheme.enrolment_id, dueDateStr, payLink),
            'reminder'
          );

          console.log(`[GMS Cron] Reminder sent to ${scheme.phone} for ${scheme.enrolment_id}`);
          sent++;

          await db.query(
            'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
            [scheme.enrolment_id, 'Payment Reminder Sent', 'system', 'Auto',
             `Due on ${dueDateStr}. Month ${scheme.next_pending_month}. SMS sent to ${scheme.phone}`]
          );
        }
      }

      return res.json({ success: true, sent, total: schemes.length });
    } catch(err) {
      console.error('[GMS Cron] reminder error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Payment routes loaded');
};
