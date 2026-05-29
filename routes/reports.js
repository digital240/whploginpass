// routes/reports.js — Stats, audit log, half registrations
const db                        = require('../db');
const { staffAuth, adminOnly }  = require('../helpers/auth');

module.exports = function(app) {

  // ── GET /api/gms-reports ─────────────────────────────
  app.get('/api/gms-reports', staffAuth, async (req, res) => {
    try {
      const [total]        = await db.query("SELECT COUNT(*) as n FROM gms_enrolments WHERE status != 'Draft'");
      const [draft]        = await db.query("SELECT COUNT(*) as n FROM gms_enrolments WHERE status='Draft'");
      const [active]       = await db.query("SELECT COUNT(*) as n FROM gms_enrolments WHERE status='Active'");
      const [matured]      = await db.query("SELECT COUNT(*) as n FROM gms_enrolments WHERE status='Matured'");
      const [complete]     = await db.query("SELECT COUNT(*) as n FROM gms_enrolments WHERE status='Complete'");
      const [discontinued] = await db.query("SELECT COUNT(*) as n FROM gms_enrolments WHERE status='Discontinued'");
      const [upi]          = await db.query("SELECT COUNT(*) as n FROM gms_enrolments WHERE pay_method='UPI Auto-debit'");
      const [store]        = await db.query("SELECT COUNT(*) as n FROM gms_enrolments WHERE pay_method='Pay at Store'");
      const [totalAmt]     = await db.query("SELECT SUM(total_contribution) as n FROM gms_enrolments WHERE status NOT IN ('Discontinued')");
      const [maturingSoon] = await db.query("SELECT COUNT(*) as n FROM gms_enrolments WHERE maturity_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY) AND status='Active'");
      const [halfReg]      = await db.query("SELECT COUNT(*) as n FROM gms_half_registrations WHERE converted=0");
      // Collected = payments paid + late fees
      const [paidAmt]  = await db.query(`
        SELECT (
          COALESCE((SELECT SUM(amount) FROM gms_payments WHERE status='Paid'),0) +
          COALESCE((SELECT SUM(amount) FROM gms_late_fees),0)
        ) as n
      `);
      const [lateFees] = await db.query("SELECT COALESCE(SUM(amount),0) as n FROM gms_late_fees");

      return res.json({
        success: true,
        stats: {
          total: total[0].n, draft: draft[0].n, active: active[0].n, matured: matured[0].n,
          complete: complete[0].n, discontinued: discontinued[0].n,
          upi: upi[0].n, store: store[0].n,
          totalAmount: totalAmt[0].n || 0,
          paidAmount:  paidAmt[0].n  || 0,
          lateFees:    lateFees[0].n || 0,
          maturingSoon: maturingSoon[0].n,
          halfReg: halfReg[0].n
        }
      });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-half-registrations ──────────────────
  app.get('/api/gms-half-registrations', staffAuth, adminOnly, async (req, res) => {
    try {
      const [rows] = await db.query('SELECT * FROM gms_half_registrations WHERE converted=0 ORDER BY created_at DESC');
      return res.json({ success: true, rows });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-audit-log ───────────────────────────
  app.get('/api/gms-audit-log', staffAuth, adminOnly, async (req, res) => {
    try {
      const limit  = parseInt(req.query.limit) || 50;
      const [rows] = await db.query('SELECT * FROM gms_audit_log ORDER BY created_at DESC LIMIT ?', [limit]);
      return res.json({ success: true, rows });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });
// ── GET /api/gms-monthly-trend ────────────────────────
app.get('/api/gms-monthly-trend', staffAuth, async (req, res) => {
  try {
    const [rows] = await db.query(`
      SELECT 
        DATE_FORMAT(p.paid_at, '%Y-%m') as month,
        SUM(p.amount) as total,
        COUNT(*) as count
      FROM gms_payments p
      WHERE p.status = 'Paid' AND p.paid_at IS NOT NULL
      GROUP BY DATE_FORMAT(p.paid_at, '%Y-%m')
      ORDER BY month DESC
      LIMIT 6
    `);
    return res.json({ success: true, months: rows.reverse() });
  } catch(err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});
  console.log('[GMS] Report routes loaded');
};
