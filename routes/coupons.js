// routes/coupons.js — Generate redemption coupon + Shopify discount
const axios          = require('axios');
const db             = require('../db');
const { staffAuth }  = require('../helpers/auth');
const { sendSms }    = require('../helpers/sms');

module.exports = function(app) {

  // ── POST /api/gms-generate-coupon ────────────────────
  app.post('/api/gms-generate-coupon', staffAuth, async (req, res) => {
    try {
      if (req.staff.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });

      const { enrolmentId } = req.body;
      const [rows] = await db.query('SELECT * FROM gms_enrolments WHERE enrolment_id=?', [enrolmentId]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'Not found.' });
      const enrol = rows[0];

      if (enrol.coupon_code) return res.json({ success: true, couponCode: enrol.coupon_code, message: 'Coupon already generated.' });

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
              title: `GMS-${enrolmentId}`, target_type: 'line_item',
              target_selection: 'all', allocation_method: 'across',
              value_type: 'fixed_amount', value: `-${enrol.total_redeemable}`,
              customer_selection: 'all', starts_at: new Date().toISOString(),
              ends_at: expiryDate.toISOString(), usage_limit: 1
            }},
            { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
          );
          const priceRuleId = priceRuleRes.data.price_rule.id;
          const couponRes   = await axios.post(
            `https://${shopDomain}/admin/api/2024-01/price_rules/${priceRuleId}/discount_codes.json`,
            { discount_code: { code: couponCode } },
            { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
          );
          shopifyCouponId = couponRes.data.discount_code.id;
        }
      } catch(shopErr) {
        console.error('[GMS] Shopify coupon error:', shopErr.message);
      }

      await db.query(
        'INSERT INTO gms_coupons (enrolment_id, coupon_code, discount_amount, generated_by, shopify_coupon_id, expires_at) VALUES (?,?,?,?,?,?)',
        [enrolmentId, couponCode, enrol.total_redeemable, req.staff.username, shopifyCouponId, expiryDate.toISOString().split('T')[0]]
      );
      await db.query("UPDATE gms_enrolments SET coupon_code=?, status='Complete' WHERE enrolment_id=?", [couponCode, enrolmentId]);

      await sendSms(enrol.phone,
        `Dear Customer, your WHP GMS scheme is complete! Coupon: ${couponCode} worth Rs.${enrol.total_redeemable}. Use at whpjewellers.com. Valid till ${expiryDate.toLocaleDateString('en-IN')}. - WHP Jewellers`
      );

      await db.query(
        'INSERT INTO gms_notifications (enrolment_id, phone, type, message) VALUES (?,?,?,?)',
        [enrolmentId, enrol.phone, 'Coupon', `Coupon ${couponCode} generated and sent.`]
      );

      return res.json({ success: true, couponCode, amount: enrol.total_redeemable, message: 'Coupon generated and SMS sent.' });
    } catch(err) {
      console.error('[GMS] coupon error:', err.message);
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  console.log('[GMS] Coupon routes loaded');
};
