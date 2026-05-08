// helpers/auth.js — Staff + Customer auth helpers
const crypto = require('crypto');
const db     = require('../db');

// ── Staff token ───────────────────────────────────────────
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

function adminOnly(req, res, next) {
  if (req.staff?.role !== 'admin') return res.status(403).json({ success: false, message: 'Admin only.' });
  next();
}

// ── Customer session ──────────────────────────────────────
async function getUserFromToken(token) {
  if (!token) return null;
  try {
    const now = new Date().toISOString().slice(0,19).replace('T',' ');
    const [rows] = await db.query(
      `SELECT u.* FROM gms_users u
       JOIN gms_user_sessions s ON u.user_id = s.user_id
       WHERE s.token = ? AND s.expires_at > ?`,
      [token, now]
    );
    return rows[0] || null;
  } catch(e) { return null; }
}

async function createUserSession(userId) {
  const token  = crypto.randomBytes(48).toString('hex');
  const expiry = new Date(Date.now() + 30*24*3600*1000).toISOString().slice(0,19).replace('T',' ');
  await db.query('INSERT INTO gms_user_sessions (token, user_id, expires_at) VALUES (?,?,?)', [token, userId, expiry]);
  return token;
}

// ── Staff accounts ────────────────────────────────────────
function getStaff() {
  const ap = process.env.GMS_ADMIN_PASS  || 'whp_2026_gms';
  const bp = process.env.GMS_BRANCH_PASS || 'whp_2026_gms';
  return {
    whp_admin:  { password: ap, role: 'admin',  branch: null,          name: 'WHP Admin' },
    borivali:   { password: bp, role: 'branch', branch: 'Borivali',    name: 'Borivali Manager' },
    vashi:      { password: bp, role: 'branch', branch: 'Vashi',       name: 'Vashi Manager' },
    nalasopara: { password: bp, role: 'branch', branch: 'Nalasopara',  name: 'Nalasopara Manager' },
    vileparle:  { password: bp, role: 'branch', branch: 'Vile Parle',  name: 'Vile Parle Manager' },
  };
}

module.exports = { createStaffToken, verifyStaffToken, staffAuth, adminOnly, getUserFromToken, createUserSession, getStaff };
