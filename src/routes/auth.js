const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const validator = require('validator');
const rateLimit = require('express-rate-limit');

const User = require('../models/User');
const { encrypt, decrypt, blindIndex, normalizeEmail } = require('../utils/crypto');
const { requireAuth, SESSION_COOKIE } = require('../middleware/auth');
const config = require('../config');

const router = express.Router();

// Slow down credential stuffing / brute force against the auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts, please try again later.' },
});

// Used so a login for an unknown email costs the same time as one for a real user
// (prevents discovering registered emails by response timing).
const DUMMY_HASH = bcrypt.hashSync('timing-equaliser-not-a-real-password', config.bcryptRounds);

function validateEmail(email) {
  if (typeof email !== 'string' || email.length > 254) return false;
  return validator.isEmail(email.trim(), { allow_utf8_local_part: false, require_tld: true });
}

function passwordProblems(password) {
  if (typeof password !== 'string') return ['Password is required.'];
  const problems = [];
  if (password.length < 8) problems.push('at least 8 characters');
  // bcrypt only uses the first 72 bytes of input
  if (Buffer.byteLength(password, 'utf8') > 72) problems.push('at most 72 bytes');
  if (!/[a-z]/.test(password)) problems.push('a lowercase letter');
  if (!/[A-Z]/.test(password)) problems.push('an uppercase letter');
  if (!/[0-9]/.test(password)) problems.push('a number');
  if (!/[^A-Za-z0-9]/.test(password)) problems.push('a symbol');
  return problems.length ? [`Password must contain ${problems.join(', ')}.`] : [];
}

const cookieOptions = {
  httpOnly: true,     // not readable from JavaScript (mitigates token theft via XSS)
  secure: true,       // only ever sent over HTTPS
  sameSite: 'strict', // not sent on cross-site requests (CSRF mitigation)
  path: '/',
  maxAge: 60 * 60 * 1000,
};

router.post('/signup', authLimiter, async (req, res, next) => {
  try {
    const { email, password, confirmPassword } = req.body || {};

    if (!validateEmail(email)) {
      return res.status(400).json({ error: 'Please enter a valid email address.' });
    }
    const problems = passwordProblems(password);
    if (problems.length) return res.status(400).json({ error: problems[0] });
    if (password !== confirmPassword) {
      return res.status(400).json({ error: 'Passwords do not match.' });
    }

    const emailIndex = blindIndex(email);
    if (await User.exists({ emailIndex })) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }

    const user = await User.create({
      emailIndex,
      email: encrypt(normalizeEmail(email)),
      passwordHash: await bcrypt.hash(password, config.bcryptRounds),
    });

    res.status(201).json({ message: 'Account created. You can now log in.', id: user._id });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'An account with this email already exists.' });
    }
    next(err);
  }
});

router.post('/login', authLimiter, async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const invalid = () => res.status(401).json({ error: 'Invalid email or password.' });

    if (!validateEmail(email) || typeof password !== 'string' || !password) return invalid();

    const user = await User.findOne({ emailIndex: blindIndex(email) });
    const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
    if (!user || !ok) return invalid();

    user.lastLoginAt = new Date();
    await user.save();

    const token = jwt.sign({ sub: user._id.toString() }, config.jwtSecret, {
      algorithm: 'HS256',
      expiresIn: config.jwtExpiresIn,
    });
    res.cookie(SESSION_COOKIE, token, cookieOptions);
    res.json({ message: 'Login successful.' });
  } catch (err) {
    next(err);
  }
});

router.post('/logout', (req, res) => {
  const { maxAge, ...clearOptions } = cookieOptions;
  res.clearCookie(SESSION_COOKIE, clearOptions);
  res.json({ message: 'Logged out.' });
});

router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({
      id: user._id,
      email: decrypt(user.email), // decrypted only in memory, for the authenticated owner
      storedEmail: user.email,    // what is actually persisted in MongoDB
      passwordStorage: 'bcrypt hash (plaintext never stored)',
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
