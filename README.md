# secure_auth

Express + MongoDB authentication demo that protects user data **in motion** and **at rest**:

- **HTTPS only**: TLS 1.2/1.3 with forward-secret AEAD cipher suites, a certificate signed by a local root CA, HSTS, and plain HTTP limited to a 301 redirect.
- **AES-256-GCM** encryption of the email address, plus an HMAC-SHA256 blind index for lookups.
- **bcrypt** (cost 12) password hashing. Plaintext passwords are never stored.
- Signup with email validation, login, and a `__Host-` session cookie (`Secure`, `HttpOnly`, `SameSite=Strict`).
- Helmet security headers (strict CSP), rate limiting, generic login errors and timing equalisation.
- Wireshark/tshark proof of concept showing that credentials are not visible in the captured traffic.

## Requirements
- Node.js 18+
- MongoDB on `mongodb://127.0.0.1:27017`
- Chrome or Edge (for the screenshot/report scripts)
- Wireshark with Npcap loopback support (for the capture script)

## Setup
```bash
npm install
npm run setup                               # creates .env with random keys + certs/ (local CA and server cert)
certutil -user -addstore Root certs\ca.crt  # Windows: trust the local CA
npm start
```
- App: https://localhost:8443
- `http://localhost:8080` only redirects to HTTPS.

## Scripts
| Command | Purpose |
|---|---|
| `npm start` | Start the HTTPS server (+ HTTP→HTTPS redirect) |
| `npm run setup` | Generate `.env` secrets and TLS certificates |
| `npm run certs -- --force` | Regenerate certificates |
| `npm run show-db [-- --email x --decrypt]` | Show the raw stored documents |
| `npm run screenshots -- <email> <password>` | Screenshot the signup/login flow |
| `npm run capture -- <email> <password>` | Loopback capture of signup + login, with tshark analysis |
| `npm run api-tests -- <email> <password>` | Run the authentication security test cases |
| `npm run report` | Build `report/Security_Report.pdf` |

## Project structure
```
src/          server.js (HTTPS/TLS, headers), routes/auth.js, models/User.js, utils/crypto.js (AES-GCM, HMAC)
public/       signup, login and dashboard pages
scripts/      key/cert generation, DB viewer, screenshots, packet capture, API tests, report builder
report/       report template, evidence, screenshots, capture, PDF
```

`.env`, private keys and TLS key logs are git-ignored and never committed.
