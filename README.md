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

## SSL/TLS (HTTPS) setup guide

### 1. How it works
```
Browser ──HTTPS (TLS 1.3, AES-256-GCM, X25519)──▶ Express :8443 ──▶ MongoDB
Browser ──HTTP :8080──▶ 301 redirect to https://localhost:8443 (no content is served over HTTP)
```
The browser only trusts a certificate signed by a Certificate Authority (CA) it knows. For local development this project creates its **own root CA**, uses it to sign a **server certificate** for `localhost`, and you add that CA to your trust store. The browser then shows a normal padlock with no warning, exactly as it would with a public CA.

| File | What it is | Keep secret? |
|---|---|---|
| `certs/ca.crt` | Root CA certificate (RSA-4096, 5 years). Import into the trust store | No |
| `certs/ca.key` | Root CA private key. Used only to sign the server certificate | **Yes** |
| `certs/server.crt` | Server certificate (RSA-2048, SHA-256, 397 days), SAN = `localhost`, `127.0.0.1`, `::1` | No |
| `certs/server.key` | Server private key. Loaded by the HTTPS server | **Yes** |

All of these are git-ignored.

### 2. Generate the certificates
```bash
npm run certs              # first time (also done by `npm run setup`)
npm run certs -- --force   # regenerate (then re-import ca.crt and restart the server)
```
To change the name shown in the browser's certificate viewer (Organization / Organizational Unit), edit the `OWNER` block at the top of `scripts/generate-certs.js`.

<details>
<summary>Alternative: the same certificates with OpenSSL</summary>

```bash
mkdir -p certs && cd certs

# Root CA
openssl req -x509 -newkey rsa:4096 -sha256 -days 1825 -nodes \
  -keyout ca.key -out ca.crt \
  -subj "/CN=Anand Sharma Local Root CA/OU=Softwarica - Security Task 1/O=Anand Sharma/C=NP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Server key + certificate signing request
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=localhost/OU=Softwarica - Security Task 1/O=Anand Sharma/C=NP"

# Extensions for the server certificate
cat > server.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1
EOF

# Sign the server certificate with the CA (max 398 days for browsers)
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days 397 -sha256 -extfile server.ext -out server.crt

openssl verify -CAfile ca.crt server.crt   # -> server.crt: OK
```
</details>

### 3. Trust the local CA

**Windows** (Chrome, Edge and other apps that use the Windows store; no admin needed):
```powershell
certutil -user -addstore Root certs\ca.crt
# remove an old CA later:
certutil -user -delstore Root "Anand Sharma Local Root CA"
```
**macOS**:
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.crt
```
**Linux (Debian/Ubuntu)**:
```bash
sudo cp certs/ca.crt /usr/local/share/ca-certificates/secure-auth-ca.crt
sudo update-ca-certificates
# Chrome/Chromium on Linux uses its own NSS store:
certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "Secure Auth Local CA" -i certs/ca.crt
```
**Firefox** (any OS, own store): Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import → `certs/ca.crt` → tick *Trust this CA to identify websites*.

Then **fully close and reopen the browser** and open https://localhost:8443.

### 4. Server TLS configuration
Paths and ports come from `.env`:
```ini
HTTPS_PORT=8443
HTTP_PORT=8080                # plain HTTP, only redirects to HTTPS
TLS_KEY_PATH=certs/server.key
TLS_CERT_PATH=certs/server.crt
TLS_CA_PATH=certs/ca.crt      # sent with the leaf; leave empty if TLS_CERT_PATH is a full chain
TLS_KEYLOG_FILE=              # demo only: export TLS secrets for Wireshark decryption
```
The hardening lives in `src/server.js`:

| Setting | Value | Why |
|---|---|---|
| `minVersion` / `maxVersion` | `TLSv1.2` / `TLSv1.3` | SSLv3, TLS 1.0 and TLS 1.1 are refused |
| `ciphers` | TLS 1.3 suites + `ECDHE-RSA-AES256-GCM-SHA384`, `ECDHE-RSA-CHACHA20-POLY1305`, `ECDHE-RSA-AES128-GCM-SHA256` | Forward secrecy (ECDHE) + authenticated encryption (AEAD) only. No CBC, RC4, 3DES, SHA-1 or static RSA |
| `honorCipherOrder` | `true` | Server picks the strongest suite |
| `ecdhCurve` | `X25519:P-256:P-384` | Modern key-exchange groups |
| HSTS (Helmet) | `max-age=31536000; includeSubDomains` | Browser refuses plain HTTP for this host for a year |
| CSP | `default-src 'self'; connect-src 'self'; upgrade-insecure-requests` | Frontend can only call this HTTPS origin |
| Session cookie | `__Host-session; Secure; HttpOnly; SameSite=Strict` | Token is only ever sent over TLS |
| HTTP listener | `301 → https://…:8443` | No page or form is ever served over HTTP |

### 5. Verify HTTPS/TLS
```bash
# Negotiated protocol, cipher and certificate check (expect TLSv1.3, TLS_AES_256_GCM_SHA384, Verification: OK)
openssl s_client -connect localhost:8443 -servername localhost -CAfile certs/ca.crt -brief

# Old protocols / weak ciphers must FAIL (alert 70 protocol_version / alert 40 handshake_failure)
openssl s_client -connect localhost:8443 -tls1_1
openssl s_client -connect localhost:8443 -tls1_2 -cipher AES128-SHA

# Certificate details
openssl s_client -connect localhost:8443 -CAfile certs/ca.crt </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# Security headers (HSTS, CSP) and the HTTP -> HTTPS redirect
curl -sI --cacert certs/ca.crt https://localhost:8443/login     # Windows curl: add --ssl-no-revoke
curl -sI http://localhost:8080/login                             # -> 301 Location: https://localhost:8443/login
```
In the browser: click the padlock → *Connection is secure* → *Certificate is valid*, or press F12 → **Security** tab. Every page footer also shows the TLS version and cipher of its own connection (from `/api/tls-info`).

### 6. Prove it with Wireshark
1. Install Wireshark with **Npcap**, ticking *Support loopback traffic capture*.
2. Capture on **Adapter for loopback traffic capture**. Capture filter: `tcp port 8443 or tcp port 8080`. This box takes a capture filter, not a URL.
3. Sign up and log in, then stop the capture. Or run it automatically: `npm run capture -- <email> <password>`.
4. Display filters:

| Filter | Expected |
|---|---|
| `tls.handshake` | Client Hello / Server Hello, TLS 1.3 |
| `tls.app_data` | Only "Encrypted Application Data" |
| `http && tcp.port == 8443` | 0 packets |
| `frame contains "<your password>"` | 0 packets |
| `frame contains "<your email>"` | 0 packets |

Optional control experiment: Wireshark can decrypt the traffic **only** when given the session key log (*Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename*). That shows the data is protected by TLS alone.

### 7. Production: use a public CA (Let's Encrypt)
The server code stays the same; only the certificate files change.
```bash
sudo certbot certonly --standalone -d yourdomain.com
```
```ini
HTTPS_PORT=443
HTTP_PORT=80
TLS_KEY_PATH=/etc/letsencrypt/live/yourdomain.com/privkey.pem
TLS_CERT_PATH=/etc/letsencrypt/live/yourdomain.com/fullchain.pem
TLS_CA_PATH=
```
- Ports 443 and 80 need elevated privileges, or put Nginx/Caddy in front as a TLS-terminating reverse proxy.
- Certbot renews automatically. Restart the app after each renewal (e.g. a `--deploy-hook`).
- Never deploy `ca.key` or the local CA, and keep `TLS_KEYLOG_FILE` empty.

### 8. Optional: TLS between the app and MongoDB
Not needed while MongoDB runs on the same machine. When it's on another host, enable TLS in `mongod.cfg`:
```yaml
net:
  tls:
    mode: requireTLS
    certificateKeyFile: C:\mongodb\certs\mongodb.pem   # server cert + key in one PEM
    CAFile: C:\mongodb\certs\ca.crt
```
Then use `MONGODB_URI=mongodb://user:pass@dbhost:27017/secure_auth?tls=true&tlsCAFile=certs/ca.crt` in `.env`.

### 9. Troubleshooting
| Problem | Fix |
|---|---|
| `NET::ERR_CERT_AUTHORITY_INVALID` | `ca.crt` isn't trusted yet. Import it (step 3) and fully restart the browser |
| `NET::ERR_CERT_COMMON_NAME_INVALID` | Use `https://localhost:8443` (or 127.0.0.1). Other host names aren't in the SAN |
| Browser still shows the old certificate | Restart the server after regenerating, and close **all** browser windows |
| `curl: (60) schannel … REVOCATION_STATUS_UNKNOWN` (Windows) | A local CA has no revocation list. Add `--ssl-no-revoke` (the chain is still verified) |
| Other `http://localhost` projects now force HTTPS | HSTS. Open `chrome://net-internals/#hsts` → *Delete domain security policies* → `localhost` |
| `EADDRINUSE :8443` | Another server instance is running. Stop it or change `HTTPS_PORT` |
| Wireshark filter box turns red | That box takes a capture filter like `tcp port 8443`, not a URL |

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
