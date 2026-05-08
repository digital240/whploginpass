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

  // ── GET /api/gms-users ───────────────────────────────
  app.get('/api/gms-users', staffAuth, adminOnly, (req, res) => {
    const accounts = getStaff();
    const users = Object.entries(accounts).map(([username, acc]) => ({
      username,
      role:   acc.role,
      branch: acc.branch || 'All',
      name:   acc.name
    }));
    return res.json({ success: true, users });
  });

  // ── POST /api/gms-create-user ────────────────────────
  // Note: Since accounts are in env/code, this saves to a
  // simple JSON file so new users persist across restarts
  app.post('/api/gms-create-user', staffAuth, adminOnly, async (req, res) => {
    try {
      const { username, name, password, role, branch } = req.body;
      if (!username || !name || !password || !role) {
        return res.status(400).json({ success: false, message: 'All fields required.' });
      }
      const accounts = getStaff();
      if (accounts[username]) {
        return res.status(400).json({ success: false, message: 'Username already exists.' });
      }
      // Save to a local JSON file for persistence
      const fs   = require('fs');
      const FILE = __dirname + '/../custom-users.json';
      let custom = {};
      try { custom = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch(e) {}
      custom[username] = { password, role, branch: branch||null, name };
      fs.writeFileSync(FILE, JSON.stringify(custom, null, 2));
      return res.json({ success: true, message: `User "${username}" created.` });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── POST /api/gms-change-password ────────────────────
  app.post('/api/gms-change-password', staffAuth, adminOnly, async (req, res) => {
    try {
      const { username, newPassword } = req.body;
      if (!username || !newPassword) return res.status(400).json({ success: false, message: 'Username and password required.' });
      const fs   = require('fs');
      const FILE = __dirname + '/../custom-users.json';
      let custom = {};
      try { custom = JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch(e) {}
      if (!custom[username]) {
        // Can't change hardcoded accounts via API — use .env instead
        return res.status(400).json({ success: false, message: 'Cannot change password for built-in accounts. Update GMS_ADMIN_PASS or GMS_BRANCH_PASS in .env instead.' });
      }
      custom[username].password = newPassword;
      fs.writeFileSync(FILE, JSON.stringify(custom, null, 2));
      return res.json({ success: true, message: 'Password changed.' });
    } catch(err) {
      return res.status(500).json({ success: false, message: err.message });
    }
  });

  // ── GET /whp_admin ───────────────────────────────────
  app.get('/whp_admin',   (req, res) => res.sendFile(DASHBOARD_PATH));
  app.get('/whp_admin/*', (req, res) => res.sendFile(DASHBOARD_PATH));

  console.log('[GMS] Admin routes loaded');
};
