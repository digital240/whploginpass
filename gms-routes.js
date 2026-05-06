// gms-routes.js — WHP Golden Moments Scheme API
// Add to server.js: require('./gms-routes')(app, cache);
// npm install mysql2 razorpay googleapis

const crypto = require('crypto');
const axios  = require('axios');
const db     = require('./db');

// ── Helpers ──────────────────────────────────────────────
function genId() {
  return 'WHP-GMS-' + Date.now().toString().slice(-8);
}

function maturityDate(tenure) {
  const d = new Date();
  d.setMonth(d.getMonth() + parseInt(tenure));
  return d.toISOString().split('T')[0];
}

function fmt(n) {
  return new Date(n).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' });
}

// ── Staff accounts ───────────────────────────────────────
function getStaff() {
  const ap = process.env.GMS_ADMIN_PASS  || 'whp_2026_gms';
  const bp = process.env.GMS_BRANCH_PASS || 'whp_2026_gms';
  return {
    whp_admin:  { password: ap, role: 'admin',  branch: null,         name: 'WHP Admin' },
    borivali:   { password: bp, role: 'branch', branch: 'Borivali',   name: 'Borivali Manager' },
    vashi:      { password: bp, role: 'branch', branch: 'Vashi',      name: 'Vashi Manager' },
    nalasopara: { password: bp, role: 'branch', branch: 'Nalasopara', name: 'Nalasopara Manager' },
    vileparle:  { password: bp, role: 'branch', branch: 'Vile Parle', name: 'Vile Parle Manager' },
  };
}

function createStaffToken(username, role, branch, name) {
  const payload = JSON.stringify({ username, role, branch, name, exp: Date.now() + 8*3600*1000 });
  const encoded = Buffer.from(payload).toString('base64url');
  const sig     = crypto.createHmac('sha256', process.env.GMS_ADMIN_PASS || 'whp_2026_gms').update(encoded).digest('hex').slice(0,16);
  return encoded + '.' + sig;
}

function verifyStaffToken(token) {
  try {
    if (!token) return null;
    const [encoded, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', process.env.GMS_ADMIN_PASS || 'whp_2026_gms').update(encoded).digest('hex').slice(0,16);
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch(e) { return null; }
}

function staffAuth(req, res, next) {
  const token = req.headers['x-staff-token'] || req.body?.staffToken;
  const staff = verifyStaffToken(token);
  if (!staff) return res.status(401).json({ success: false, message: 'Session expired. Please login again.' });
  req.staff = staff;
  next();
}

// ── SMS ──────────────────────────────────────────────────
async function sendSms(phone, message) {
  try {
    await axios.post('https://www.smsalert.co.in/api/push.json', null, {
      params: { apikey: process.env.SMSALERT_API_KEY, sender: 'WHPECM', mobileno: phone, text: message },
      timeout: 10000
    });
    console.log(`[SMS] Sent to ${phone}`);
  } catch(e) {
    console.error('[SMS] Failed:', e.message);
  }
}

// ── Generate payment schedule ────────────────────────────
async function createPaymentSchedule(enrolmentId, instalment, payMonths, startDate) {
  const rows = [];
  for (let i = 1; i <= payMonths; i++) {
    const due = new Date(startDate);
    due.setMonth(due.getMonth() + i);
    rows.push([enrolmentId, i, instalment, due.toISOString().split('T')[0]]);
  }
  await db.execute(
    'INSERT INTO gms_payments (enrolment_id, month_num, amount, due_date) VALUES ?',
    [rows]
  );
}

// ═══════════════════════════════════════════════════════
module.exports = function(app, cache) {

  // ── POST /api/gms-login ──────────────────────────────
  app.post('/api/gms-login', (req, res) => {
    const { username, password } = req.body;
    const accounts = getStaff();
    const account  = accounts[username];
    if (!account || account.password !== password) {
      return res.status(401).json({ success: false, message: 'Invalid username or password.' });
    }
    const token = createStaffToken(username, account.role, account.branch, account.name);
    return res.json({ success: true, token, role: account.role, branch: account.branch, name: account.name });
  });

  // ── POST /api/create-gms-enrolment ──────────────────
  app.post('/api/create-gms-enrolment', async (req, res) => {
    try {
      const {
        name, phone, email, address1, address2, city, state, pincode,
        dob, identity, branch, product_title, product_sku, product_url,
        amt, tenure, paymo, pct, type, paid, bonus, redeem, pay, maturity_date
      } = req.body;

      const cleanPhone = String(phone).replace(/\D/g,'').slice(-10);
      const otpData    = cache.get(`otp:${cleanPhone}`);
      if (!otpData || !otpData.verified) {
        return res.status(401).json({ success: false, message: 'Mobile not verified.' });
      }

      const enrolmentId = genId();
      const today       = new Date().toISOString().split('T')[0];
      const mDate       = maturity_date || maturityDate(tenure);

      // Save to MySQL
      await db.execute(`
        INSERT INTO gms_enrolments (
          enrolment_id, name, phone, email, address1, address2, city, state, pincode,
          dob, identity_proof, preferred_branch,
          product_title, product_sku, product_url,
          redeem_type, bonus_pct, instalment_amt, tenure_months, pay_months,
          total_contribution, whp_bonus, total_redeemable,
          maturity_date, enrolment_date, pay_method, payments_pending
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
      `, [
        enrolmentId, name, cleanPhone, email||'', address1||'', address2||'',
        city||'', state||'', pincode||'', dob||null, identity||'', branch||'',
        product_title||'', product_sku||'', product_url||'',
        type, pct, amt, tenure, paymo,
        paid, bonus, redeem,
        mDate, today,
        pay === 'upi' ? 'UPI Auto-debit' : 'Pay at Store',
        paymo
      ]);

      // Create payment schedule
      await createPaymentSchedule(enrolmentId, amt, paymo, today);

      // Save half registration as converted
      await db.execute(
        'UPDATE gms_half_registrations SET converted=1 WHERE phone=? AND converted=0',
        [cleanPhone]
      );

      // Log notification
      await db.execute(
        'INSERT INTO gms_notifications (enrolment_id, phone, type, message, status) VALUES (?,?,?,?,?)',
        [enrolmentId, cleanPhone, 'Enrolment', `Enrolled in GMS. Monthly: Rs.${amt}. Tenure: ${tenure} months. Maturity: ${mDate}`, 'Sent']
      );

      // Send SMS
      await sendSms(cleanPhone,
        `Dear Customer, you have successfully enrolled in WHP Golden Moments Scheme. Enrolment ID: ${enrolmentId}. Monthly: Rs.${amt} x ${paymo} months. Maturity: ${mDate}. - WHP Jewellers`
      );

      // Clear OTP
      cache.del(`otp:${cleanPhone}`);

      // Also save to Google Sheet as backup
      try {
        const { google } = require('googleapis');
        if (process.env.GOOGLE_SERVICE_ACCOUNT_JSON && process.env.GOOGLE_SHEET_ID) {
          const creds = JSON.parse(process.env.GOOGLE_SERVICE_ACCOUNT_JSON);
          const auth  = new google.auth.GoogleAuth({ credentials: creds, scopes: ['https://www.googleapis.com/auth/spreadsheets'] });
          const sheets = google.sheets({ version: 'v4', auth });
          await sheets.spreadsheets.values.append({
            spreadsheetId: process.env.GOOGLE_SHEET_ID,
            range: 'GMS Enrolments!A1',
            valueInputOption: 'RAW',
            insertDataOption: 'INSERT_ROWS',
            requestBody: { values: [[
              enrolmentId, today, name, cleanPhone, email||'', branch||'',
              product_title||'', product_sku||'', type, pct+'%',
              amt, tenure, paymo, paid, bonus, redeem, mDate,
              pay==='upi'?'UPI Auto-debit':'Pay at Store',
              'Active', ''
            ]] }
          });
        }
      } catch(sheetErr) {
        console.error('[GMS] Sheet backup error:', sheetErr.message);
      }

      return res.json({ success: true, enrolmentId, message: 'Enrolment successful!' });

    } catch(err) {
      console.error('[GMS] enrolment error:', err.message);
      return res.status(500).json({ success: false, message: 'Enrolment failed. Please try again.' });
    }
  });

  // ── POST /api/gms-save-half ──────────────────────────
  app.post('/api/gms-save-half', async (req, res) => {
    try {
      const { phone, name, email, product_title, product_sku, redeem_type, instalment, tenure, branch, step } = req.body;
      const cleanPhone = String(phone||'').replace(/\D/g,'').slice(-10);
      if (!cleanPhone) return res.json({ success: false });
      await db.execute(`
        INSERT INTO gms_half_registrations (phone, name, email, product_title, product_sku, redeem_type, instalment, tenure, branch, step_reached)
        VALUES (?,?,?,?,?,?,?,?,?,?)
        ON DUPLICATE KEY UPDATE name=VALUES(name), email=VALUES(email), step_reached=VALUES(step_reached), updated_at=NOW()
      `, [cleanPhone, name||'', email||'', product_title||'', product_sku||'', redeem_type||'', instalment||0, tenure||11, branch||'', step||'form_started']);
      return res.json({ success: true });
    } catch(e) {
      return res.json({ success: false });
    }
  });

  // ── GET /api/gms-enrolments ──────────────────────────
  app.get('/api/gms-enrolments', staffAuth, async (req, res) => {
    try {
      let query  = 'SELECT * FROM gms_enrolments WHERE 1=1';
      const params = [];
      if (req.staff.role === 'branch' && req.staff.branch) {
        query += ' AND preferred_branch = ?';
        params.push(req.staff.branch);
      }
      query += ' ORDER BY created_at DESC';
      const [rows] = await db.execute(query, params);
      return res.json({ success: true, rows, role: req.staff.role, branch: req.staff.branch });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-enrolment/:id ───────────────────────
  app.get('/api/gms-enrolment/:id', staffAuth, async (req, res) => {
    try {
      const [rows] = await db.execute('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [req.params.id]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Not found.' });
      const [payments] = await db.execute('SELECT * FROM gms_payments WHERE enrolment_id=? ORDER BY month_num', [req.params.id]);
      const [fees]     = await db.execute('SELECT * FROM gms_late_fees WHERE enrolment_id=?', [req.params.id]);
      return res.json({ success: true, enrolment: rows[0], payments, fees });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-search ──────────────────────────────
  app.get('/api/gms-search', staffAuth, async (req, res) => {
    try {
      const q = '%' + (req.query.q || '') + '%';
      const [rows] = await db.execute(
        'SELECT * FROM gms_enrolments WHERE (enrolment_id LIKE ? OR phone LIKE ? OR name LIKE ?) ORDER BY created_at DESC LIMIT 50',
        [q, q, q]
      );
      return res.json({ success: true, rows });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-mark-paid ──────────────────────────
  app.post('/api/gms-mark-paid', staffAuth, async (req, res) => {
    try {
      const { enrolmentId, monthNum, lateFee, notes } = req.body;
      if (!enrolmentId || !monthNum) return res.status(400).json({ success: false, message: 'enrolmentId and monthNum required.' });

      const [enrolRows] = await db.execute('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!enrolRows.length) return res.status(404).json({ success: false, message: 'Enrolment not found.' });
      const enrol = enrolRows[0];

      // Mark payment as paid
      await db.execute(`
        UPDATE gms_payments SET status='Paid', paid_at=NOW(),
          pay_method='Store', collected_branch=?, collected_by=?,
          late_fee=?, notes=?
        WHERE enrolment_id=? AND month_num=?
      `, [req.staff.branch||'Admin', req.staff.username, lateFee||0, notes||'', enrolmentId, monthNum]);

      // Update counts
      const [countRows] = await db.execute(
        'SELECT COUNT(*) as paid FROM gms_payments WHERE enrolment_id=? AND status="Paid"',
        [enrolmentId]
      );
      const made    = countRows[0].paid;
      const pending = enrol.pay_months - made;
      const allDone = pending <= 0;
      const status  = allDone ? 'Matured' : 'Active';

      await db.execute(
        'UPDATE gms_enrolments SET payments_made=?, payments_pending=?, status=? WHERE enrolment_id=?',
        [made, Math.max(0, pending), status, enrolmentId]
      );

      // Apply late fee if any
      if (lateFee && parseFloat(lateFee) > 0) {
        await db.execute(
          'INSERT INTO gms_late_fees (enrolment_id, month_num, amount, applied_by) VALUES (?,?,?,?)',
          [enrolmentId, monthNum, lateFee, req.staff.username]
        );
        await db.execute(
          'UPDATE gms_enrolments SET late_fee_total=late_fee_total+? WHERE enrolment_id=?',
          [lateFee, enrolmentId]
        );
      }

      // Audit log
      await db.execute(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, `Month ${monthNum} marked Paid`, req.staff.username, req.staff.branch||'Admin', `Late fee: ${lateFee||0}. Notes: ${notes||''}`]
      );

      // SMS to customer
      const msg = allDone
        ? `Dear Customer, your WHP GMS scheme ${enrolmentId} is now MATURED! WHP team will contact you shortly for redemption. - WHP Jewellers`
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
      await db.execute(
        'INSERT INTO gms_late_fees (enrolment_id, month_num, amount, reason, applied_by) VALUES (?,?,?,?,?)',
        [enrolmentId, monthNum, amount, reason||'', req.staff.username]
      );
      await db.execute(
        'UPDATE gms_enrolments SET late_fee_total=late_fee_total+? WHERE enrolment_id=?',
        [amount, enrolmentId]
      );
      await db.execute(
        'INSERT INTO gms_audit_log (enrolment_id, action, done_by, branch, details) VALUES (?,?,?,?,?)',
        [enrolmentId, `Late fee applied`, req.staff.username, req.staff.branch||'Admin', `Month ${monthNum}: Rs.${amount}. Reason: ${reason}`]
      );
      return res.json({ success: true, message: `Late fee of Rs.${amount} applied.` });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-generate-coupon ────────────────────
  app.post('/api/gms-generate-coupon', staffAuth, async (req, res) => {
    try {
      if (req.staff.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
      const { enrolmentId } = req.body;
      const [rows] = await db.execute('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Not found.' });
      const enrol = rows[0];
      if (enrol.coupon_code) return res.json({ success: true, couponCode: enrol.coupon_code, message: 'Coupon already generated.' });

      // Generate unique coupon code
      const couponCode = 'WHP' + Math.random().toString(36).toUpperCase().slice(2,8);
      const expiryDate = new Date();
      expiryDate.setMonth(expiryDate.getMonth() + 6);

      // Create Shopify discount code
      let shopifyCouponId = '';
      try {
        const shopDomain  = process.env.SHOPIFY_SHOP_DOMAIN;
        const accessToken = process.env.SHOPIFY_ACCESS_TOKEN;
        if (shopDomain && accessToken) {
          const priceRuleRes = await axios.post(
            `https://${shopDomain}/admin/api/2024-01/price_rules.json`,
            { price_rule: {
              title: `GMS-${enrolmentId}`,
              target_type: 'line_item',
              target_selection: 'all',
              allocation_method: 'across',
              value_type: 'fixed_amount',
              value: `-${enrol.total_redeemable}`,
              customer_selection: 'all',
              starts_at: new Date().toISOString(),
              ends_at: expiryDate.toISOString(),
              usage_limit: 1
            }},
            { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
          );
          const priceRuleId = priceRuleRes.data.price_rule.id;
          const couponRes = await axios.post(
            `https://${shopDomain}/admin/api/2024-01/price_rules/${priceRuleId}/discount_codes.json`,
            { discount_code: { code: couponCode } },
            { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
          );
          shopifyCouponId = couponRes.data.discount_code.id;
        }
      } catch(shopErr) {
        console.error('[GMS] Shopify coupon error:', shopErr.message);
      }

      // Save coupon to DB
      await db.execute(
        'INSERT INTO gms_coupons (enrolment_id, coupon_code, discount_amount, generated_by, shopify_coupon_id, expires_at) VALUES (?,?,?,?,?,?)',
        [enrolmentId, couponCode, enrol.total_redeemable, req.staff.username, shopifyCouponId, expiryDate.toISOString().split('T')[0]]
      );
      await db.execute(
        'UPDATE gms_enrolments SET coupon_code=?, status="Complete" WHERE enrolment_id=?',
        [couponCode, enrolmentId]
      );

      // Send SMS to customer
      await sendSms(enrol.phone,
        `Dear Customer, your WHP GMS scheme is complete! Your coupon code is ${couponCode} worth Rs.${enrol.total_redeemable}. Use at whpjewellers.com. Valid till ${expiryDate.toLocaleDateString('en-IN')}. - WHP Jewellers`
      );

      // Log notification
      await db.execute(
        'INSERT INTO gms_notifications (enrolment_id, phone, type, message) VALUES (?,?,?,?)',
        [enrolmentId, enrol.phone, 'Coupon', `Coupon ${couponCode} generated and sent.`]
      );

      return res.json({ success: true, couponCode, amount: enrol.total_redeemable, message: 'Coupon generated and SMS sent to customer.' });

    } catch(err) {
      console.error('[GMS] coupon error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-reports ─────────────────────────────
  app.get('/api/gms-reports', staffAuth, async (req, res) => {
    try {
      const [total]        = await db.execute('SELECT COUNT(*) as n FROM gms_enrolments');
      const [active]       = await db.execute("SELECT COUNT(*) as n FROM gms_enrolments WHERE status='Active'");
      const [matured]      = await db.execute("SELECT COUNT(*) as n FROM gms_enrolments WHERE status='Matured'");
      const [complete]     = await db.execute("SELECT COUNT(*) as n FROM gms_enrolments WHERE status='Complete'");
      const [discontinued] = await db.execute("SELECT COUNT(*) as n FROM gms_enrolments WHERE status='Discontinued'");
      const [upi]          = await db.execute("SELECT COUNT(*) as n FROM gms_enrolments WHERE pay_method='UPI Auto-debit'");
      const [store]        = await db.execute("SELECT COUNT(*) as n FROM gms_enrolments WHERE pay_method='Pay at Store'");
      const [totalAmt]     = await db.execute("SELECT SUM(total_contribution) as n FROM gms_enrolments WHERE status NOT IN ('Discontinued')");
      const [paidAmt]      = await db.execute("SELECT SUM(amount) as n FROM gms_payments WHERE status='Paid'");
      const [maturingSoon] = await db.execute("SELECT COUNT(*) as n FROM gms_enrolments WHERE maturity_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY) AND status='Active'");
      const [halfReg]      = await db.execute("SELECT COUNT(*) as n FROM gms_half_registrations WHERE converted=0");

      return res.json({
        success: true,
        stats: {
          total:        total[0].n,
          active:       active[0].n,
          matured:      matured[0].n,
          complete:     complete[0].n,
          discontinued: discontinued[0].n,
          upi:          upi[0].n,
          store:        store[0].n,
          totalAmount:  totalAmt[0].n || 0,
          paidAmount:   paidAmt[0].n  || 0,
          maturingSoon: maturingSoon[0].n,
          halfReg:      halfReg[0].n
        }
      });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /api/gms-half-registrations ──────────────────
  app.get('/api/gms-half-registrations', staffAuth, async (req, res) => {
    try {
      if (req.staff.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
      const [rows] = await db.execute('SELECT * FROM gms_half_registrations WHERE converted=0 ORDER BY created_at DESC');
      return res.json({ success: true, rows });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-customer-lookup ────────────────────
  app.post('/api/gms-customer-lookup', async (req, res) => {
    try {
      const { phone } = req.body;
      const cleanPhone = String(phone||'').replace(/\D/g,'').slice(-10);
      const otpData    = cache.get(`otp:${cleanPhone}`);
      if (!otpData || !otpData.verified) {
        return res.status(401).json({ success: false, message: 'OTP not verified.' });
      }
      const [enrolments] = await db.execute(
        'SELECT * FROM gms_enrolments WHERE phone=? ORDER BY created_at DESC',
        [cleanPhone]
      );
      const result = [];
      for (const e of enrolments) {
        const [payments] = await db.execute(
          'SELECT * FROM gms_payments WHERE enrolment_id=? ORDER BY month_num',
          [e.enrolment_id]
        );
        result.push({ ...e, payments });
      }
      return res.json({ success: true, enrolments: result });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /whp_admin — serve admin dashboard ───────────
  app.get('/whp_admin', (req, res) => {
    res.sendFile(__dirname + '/gms-dashboard.html');
  });
  app.get('/whp_admin/*', (req, res) => {
    res.sendFile(__dirname + '/gms-dashboard.html');
  });

  // ── GET /api/gms-menu-debug — raw response ────────────
  app.get('/api/gms-menu-debug', async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    try {
      const shopDomain  = process.env.SHOPIFY_SHOP_DOMAIN;
      const accessToken = process.env.SHOPIFY_ACCESS_TOKEN;
      const gqlRes = await require('axios').post(
        'https://' + shopDomain + '/admin/api/2024-01/graphql.json',
        { query: '{ menus(first: 10) { nodes { handle title items { title url } } } }' },
        { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
      );
      return res.json({ shop: shopDomain, raw: gqlRes.data });
    } catch(e) {
      return res.json({ error: e.message });
    }
  });

  // ── GET /api/gms-menu — Shopify nav (cached 10 min) ──
  let _menuCache = null;
  let _menuCacheTime = 0;

  app.get('/api/gms-menu', async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    try {
      if (_menuCache && Date.now() - _menuCacheTime < 600000) {
        return res.json({ success: true, items: _menuCache });
      }
      const shopDomain  = process.env.SHOPIFY_SHOP_DOMAIN;
      const accessToken = process.env.SHOPIFY_ACCESS_TOKEN;
      if (!shopDomain || !accessToken) {
        return res.json({ success: false, items: [] });
      }
      const gqlRes = await require('axios').post(
        'https://' + shopDomain + '/admin/api/2024-01/graphql.json',
        { query: `{
  menus(first: 5) {
    nodes {
      handle
      title
      items {
        title
        url
        items { title url }
      }
    }
  }
}` },
        { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
      );
      console.log('[GMS Menu] raw:', JSON.stringify(gqlRes.data).slice(0, 400));
      const errors = gqlRes.data?.errors;
      // Find main-menu from list
      const allMenus = gqlRes.data?.data?.menus?.nodes || [];
      console.log('[GMS Menu] found menus:', allMenus.map(m => m.handle));
      const menu = allMenus.find(m => m.handle === 'main-menu') || allMenus[0];
      const errors2 = errors;

            if (!menu) {
        console.error('[GMS Menu] Not found. Last error:', lastError);
        return res.json({ success: false, items: [], debug: lastError });
      }
      const BASE = 'https://www.whpjewellers.com';
      const clean = (u) => {
        if (!u) return BASE;
        if (u.startsWith('http')) return u.replace('https://' + shopDomain, BASE);
        return BASE + u; // relative URL like /collections/ring
      };
      const items = (menu.items || []).map(i => ({
        title: i.title, url: clean(i.url),
        children: (i.items || []).map(s => ({ title: s.title, url: clean(s.url) }))
      }));
      _menuCache = items; _menuCacheTime = Date.now();
      return res.json({ success: true, items });
    } catch(e) {
      return res.json({ success: false, items: [] });
    }
  });

  console.log('[GMS] All routes loaded successfully');
};

