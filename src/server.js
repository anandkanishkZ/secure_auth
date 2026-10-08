const fs = require('fs');
const path = require('path');
const http = require('http');
const https = require('https');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');

const config = require('./config');
const authRoutes = require('./routes/auth');

const app = express();
app.disable('x-powered-by');

// ---------- Security headers ----------
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        'default-src': ["'self'"],
        'script-src': ["'self'"],
        'style-src': ["'self'"],
        'img-src': ["'self'", 'data:'],
        'connect-src': ["'self'"], // the frontend may only call this same HTTPS origin
        'form-action': ["'self'"],
        'frame-ancestors': ["'none'"],
        'upgrade-insecure-requests': [],
      },
    },
    // HSTS: browser must use HTTPS for this host for the next year, even if the user types http://
    strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
    referrerPolicy: { policy: 'no-referrer' },
    frameguard: { action: 'deny' }, // clickjacking protection for older browsers
  })
);
app.use((req, res, next) => {
  // Never cache authentication responses
  if (req.path.startsWith('/api/')) res.set('Cache-Control', 'no-store');
  next();
});

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// ---------- API ----------
app.use('/api/auth', authRoutes);

// Reports the negotiated TLS parameters of the current connection (used in the UI as a PoC)
app.get('/api/tls-info', (req, res) => {
  const socket = req.socket;
  res.json({
    encrypted: Boolean(socket.encrypted),
    protocol: socket.getProtocol?.(),
    cipher: socket.getCipher?.(),
    alpn: socket.alpnProtocol || null,
  });
});

// ---------- Frontend (served by the same HTTPS server) ----------
app.use(express.static(path.join(__dirname, '..', 'public'), { extensions: ['html'] }));
app.get('/', (req, res) => res.redirect('/login'));

app.use((req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, _next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON' });
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------- TLS configuration ----------
const tlsOptions = {
  key: fs.readFileSync(config.tls.keyPath),
  cert: fs.readFileSync(config.tls.certPath),
  // Send the CA with the leaf so clients can build the full chain
  ca: config.tls.caPath && fs.existsSync(config.tls.caPath) ? fs.readFileSync(config.tls.caPath) : undefined,
  minVersion: 'TLSv1.2', // SSLv3, TLS 1.0 and TLS 1.1 are refused
  maxVersion: 'TLSv1.3',
  // TLS 1.2 suites: forward-secret ECDHE key exchange + AEAD ciphers only
  // (no RSA key exchange, no CBC, no RC4/3DES, no SHA-1 MACs).
  ciphers: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-RSA-CHACHA20-POLY1305',
    'ECDHE-RSA-AES128-GCM-SHA256',
  ].join(':'),
  honorCipherOrder: true,
  ecdhCurve: 'X25519:P-256:P-384',
};

const httpsServer = https.createServer(tlsOptions, app);

if (config.tls.keylogFile) {
  // DEMO ONLY: export per-session TLS secrets (NSS key log format) so Wireshark can
  // decrypt our own capture for the report. Never enable this in production.
  console.warn(`[!] TLS key logging enabled -> ${config.tls.keylogFile} (demo only)`);
  httpsServer.on('keylog', (line) => fs.appendFileSync(config.tls.keylogFile, line));
}

// Plain HTTP listener: serves nothing except a permanent redirect to HTTPS
const httpServer = http.createServer((req, res) => {
  const host = (req.headers.host || config.host).replace(/:\d+$/, '');
  res.writeHead(301, { Location: `https://${host}:${config.httpsPort}${req.url}` });
  res.end();
});

async function start() {
  await mongoose.connect(config.mongoUri);
  console.log(`MongoDB connected: ${mongoose.connection.host}/${mongoose.connection.name}`);

  httpsServer.listen(config.httpsPort, () =>
    console.log(`HTTPS server:  https://${config.host}:${config.httpsPort}`)
  );
  httpServer.listen(config.httpPort, () =>
    console.log(`HTTP redirect: http://${config.host}:${config.httpPort} -> HTTPS`)
  );
}

start().catch((err) => {
  console.error('Failed to start:', err.message);
  process.exit(1);
});
