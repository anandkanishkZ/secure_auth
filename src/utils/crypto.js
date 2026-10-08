// Data-at-rest protection for the email address.
//
// AES-256-GCM is an authenticated cipher: it gives confidentiality AND integrity, so a
// tampered ciphertext fails to decrypt instead of silently producing garbage.
// A fresh random 96-bit IV is used for every encryption, so the same email encrypts to a
// different ciphertext each time. Because of that we cannot search by ciphertext, so we
// also store a keyed HMAC-SHA256 "blind index" of the normalised email for lookups and the
// unique constraint. Without EMAIL_HMAC_KEY the index cannot be brute-forced offline.
const crypto = require('crypto');
const { aesKey, emailHmacKey } = require('../config');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

function encrypt(plaintext) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function decrypt({ iv, tag, ciphertext }) {
  const decipher = crypto.createDecipheriv(ALGORITHM, aesKey, Buffer.from(iv, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

function normalizeEmail(email) {
  return String(email).trim().toLowerCase();
}

function blindIndex(email) {
  return crypto.createHmac('sha256', emailHmacKey).update(normalizeEmail(email)).digest('hex');
}

module.exports = { encrypt, decrypt, blindIndex, normalizeEmail, ALGORITHM };
