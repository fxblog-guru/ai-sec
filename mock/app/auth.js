// PLANTED DEFECTS — do not copy into real code.
// 1. CWE-330 reset tokens built from Math.random are predictable.
// 2. CWE-916 passwords hashed with MD5 and no salt.
const crypto = require('crypto');

function makeResetToken() {
  return Math.random().toString(36).slice(2);
}

function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'admin') return next();
  return res.status(403).json({ error: 'forbidden' });
}

module.exports = { makeResetToken, hashPassword, requireAdmin };
