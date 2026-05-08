// routes/admin.js — Staff login, user management, menu, branches
const axios  = require('axios');
const path   = require('path');
const { createStaffToken, staffAuth, adminOnly, getStaff } = require('../helpers/auth');

const DASHBOARD_PATH = path.resolve(__dirname, '../gms-dashboard.html');

const BRANCHES = ['Borivali', 'Vashi', 'Nalasopara', 'Vile Parle'];
let _menuCache = null, _menuCacheTime = 0;

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

  // ── GET /api/gms-branches ────────────────────────────
  app.get('/api/gms-branches', (req, res) => {
    res.json({ success: true, branches: BRANCHES });
  });

  // ── GET /api/gms-menu ────────────────────────────────
  app.get('/api/gms-menu-reset', (req, res) => {
    _menuCache = null; _menuCacheTime = 0;
    res.json({ success: true, message: 'Menu cache cleared' });
  });

  app.get('/api/gms-menu', async (req, res) => {
    try {
      if (_menuCache && Date.now() - _menuCacheTime < 600000) {
        return res.json({ success: true, items: _menuCache });
      }
      const shopDomain  = process.env.SHOPIFY_SHOP_DOMAIN;
      const accessToken = process.env.SHOPIFY_ACCESS_TOKEN;
      if (!shopDomain || !accessToken) return res.json({ success: false, items: [] });

      const gqlRes = await axios.post(
        `https://${shopDomain}/admin/api/2024-01/graphql.json`,
        { query: `{ menus(first:5){ nodes{ handle title items{ title url items{ title url items{ title url } } } } } }` },
        { headers: { 'X-Shopify-Access-Token': accessToken, 'Content-Type': 'application/json' } }
      );
      const allMenus = gqlRes.data?.data?.menus?.nodes || [];
      const menu     = allMenus.find(m => m.handle === 'main-menu') || allMenus[0];
      if (!menu) return res.json({ success: false, items: [] });

      const BASE     = 'https://www.whpjewellers.com';
      const clean    = u => u?.startsWith('http') ? u.replace(`https://${shopDomain}`, BASE) : BASE + (u||'');
      const mapItems = arr => (arr||[]).map(i => ({ title: i.title, url: clean(i.url), children: mapItems(i.items) }));

      _menuCache = mapItems(menu.items); _menuCacheTime = Date.now();
      return res.json({ success: true, items: _menuCache });
    } catch(e) {
      return res.json({ success: false, items: [] });
    }
  });

  // ── GET /api/gms-menu-debug ──────────────────────────
  app.get('/api/gms-menu-debug', async (req, res) => {
    try {
      const gqlRes = await axios.post(
        `https://${process.env.SHOPIFY_SHOP_DOMAIN}/admin/api/2024-01/graphql.json`,
        { query: '{ menus(first:10){ nodes{ handle title items{ title url } } } }' },
        { headers: { 'X-Shopify-Access-Token': process.env.SHOPIFY_ACCESS_TOKEN, 'Content-Type': 'application/json' } }
      );
      return res.json({ raw: gqlRes.data });
    } catch(e) { return res.json({ error: e.message }); }
  });

  // ── GET /whp_admin ───────────────────────────────────
  app.get('/whp_admin',   (req, res) => res.sendFile(DASHBOARD_PATH));
  app.get('/whp_admin/*', (req, res) => res.sendFile(DASHBOARD_PATH));

  console.log('[GMS] Admin routes loaded');
};
