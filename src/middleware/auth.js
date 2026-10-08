const jwt = require('jsonwebtoken');
const { jwtSecret } = require('../config');

// "__Host-" prefix: the browser only accepts this cookie if it is Secure, has Path=/ and no
// Domain - i.e. it can only ever be set and sent over HTTPS for this exact host.
const SESSION_COOKIE = '__Host-session';

function requireAuth(req, res, next) {
  const token = req.cookies[SESSION_COOKIE];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, jwtSecret, { algorithms: ['HS256'] });
    next();
  } catch {
    res.clearCookie(SESSION_COOKIE, { path: '/', secure: true, httpOnly: true, sameSite: 'strict' });
    return res.status(401).json({ error: 'Session expired' });
  }
}

module.exports = { requireAuth, SESSION_COOKIE };
