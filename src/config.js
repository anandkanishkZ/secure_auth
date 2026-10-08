const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '.env') });

const root = path.join(__dirname, '..');

function required(name) {
  const value = process.env[name];
  if (!value || !value.trim()) {
    throw new Error(`Missing required environment variable ${name}. Run "npm run setup" first.`);
  }
  return value.trim();
}

function hexKey(name) {
  const key = Buffer.from(required(name), 'hex');
  if (key.length !== 32) {
    throw new Error(`${name} must be 32 bytes (64 hex characters) for AES-256 / HMAC-SHA256.`);
  }
  return key;
}

module.exports = {
  host: process.env.HOST || 'localhost',
  httpsPort: Number(process.env.HTTPS_PORT) || 8443,
  httpPort: Number(process.env.HTTP_PORT) || 8080,

  tls: {
    keyPath: path.resolve(root, process.env.TLS_KEY_PATH || 'certs/server.key'),
    certPath: path.resolve(root, process.env.TLS_CERT_PATH || 'certs/server.crt'),
    // Set TLS_CA_PATH= (empty) when TLS_CERT_PATH already contains the full chain (e.g. Let's Encrypt fullchain.pem)
    caPath: process.env.TLS_CA_PATH === '' ? null : path.resolve(root, process.env.TLS_CA_PATH || 'certs/ca.crt'),
    keylogFile: process.env.TLS_KEYLOG_FILE ? path.resolve(root, process.env.TLS_KEYLOG_FILE) : null,
  },

  mongoUri: process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/secure_auth',

  aesKey: hexKey('AES_KEY'),
  emailHmacKey: hexKey('EMAIL_HMAC_KEY'),

  bcryptRounds: Number(process.env.BCRYPT_ROUNDS) || 12,

  jwtSecret: required('JWT_SECRET'),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '1h',
};
