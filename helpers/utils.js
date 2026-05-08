// helpers/utils.js — Shared utility functions
const db = require('../db');

function genId() {
  return 'WHP-GMS-' + Date.now().toString().slice(-8);
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function cleanPhone(phone) {
  return String(phone || '').replace(/\D/g, '').slice(-10);
}

// Convert any date format to YYYY-MM-DD for MySQL DATE column
// Frontend sends "07 Nov 2027" — MySQL needs "2027-11-07"
function toMysqlDate(dateStr, tenure) {
  if (dateStr && /^\d{4}-\d{2}-\d{2}$/.test(String(dateStr))) return dateStr;
  if (dateStr && typeof dateStr === 'string' && dateStr.trim()) {
    const months = { Jan:1,Feb:2,Mar:3,Apr:4,May:5,Jun:6,Jul:7,Aug:8,Sep:9,Oct:10,Nov:11,Dec:12 };
    const parts  = dateStr.trim().split(' ');
    if (parts.length === 3) {
      const day   = parseInt(parts[0], 10);
      const month = months[parts[1]];
      const year  = parseInt(parts[2], 10);
      if (day && month && year) return `${year}-${String(month).padStart(2,'0')}-${String(day).padStart(2,'0')}`;
    }
  }
  // Calculate from tenure as fallback
  const now    = new Date();
  const t      = parseInt(tenure) || 17;
  const totalM = now.getMonth() + t;
  const year   = now.getFullYear() + Math.floor(totalM / 12);
  const month  = totalM % 12;
  return new Date(year, month, now.getDate()).toISOString().split('T')[0];
}

function maturityDate(tenure) {
  const now    = new Date();
  const totalM = now.getMonth() + parseInt(tenure);
  const year   = now.getFullYear() + Math.floor(totalM / 12);
  const month  = totalM % 12;
  return new Date(year, month, now.getDate()).toISOString().split('T')[0];
}

async function createPaymentSchedule(enrolmentId, instalment, payMonths, startDate) {
  const rows = [];
  for (let i = 1; i <= payMonths; i++) {
    const due = new Date(startDate);
    due.setMonth(due.getMonth() + i);
    rows.push([enrolmentId, i, instalment, due.toISOString().split('T')[0]]);
  }
  await db.query('INSERT INTO gms_payments (enrolment_id, month_num, amount, due_date) VALUES ?', [rows]);
}

module.exports = { genId, generateOtp, cleanPhone, toMysqlDate, maturityDate, createPaymentSchedule };
