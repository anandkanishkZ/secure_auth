// Runs the authentication security test cases against the running HTTPS server and writes
// the transcript to report/evidence/api-tests.txt.
// The account must already exist (sign up first, or run `npm run capture`).
//
// Usage: npm run api-tests -- <email> <password>
const fs = require('fs');
const path = require('path');
const https = require('https');

const root = path.join(__dirname, '..');
const [EMAIL, PASSWORD] = process.argv.slice(2);
if (!EMAIL || !PASSWORD) {
  console.error('Usage: npm run api-tests -- <email> <password>');
  process.exit(1);
}

const ca = fs.readFileSync(path.join(root, 'certs', 'ca.crt'));
const BASE = 'https://localhost:8443';

function request(method, urlPath, body, cookie) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request(
      `${BASE}${urlPath}`,
      {
        method,
        ca, // verify the server certificate against our CA (no verification bypass)
        headers: {
          ...(data && { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) }),
          ...(cookie && { Cookie: cookie }),
        },
      },
      (res) => {
        let text = '';
        res.on('data', (c) => (text += c));
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

const redactJwt = (s) => s.replace(/(eyJ[\w-]+)\.[\w-]+\.[\w-]+/, '$1.<payload>.<signature>');

(async () => {
  const out = [];
  const log = (s = '') => out.push(s);

  async function test(title, method, urlPath, body, cookie) {
    const res = await request(method, urlPath, body, cookie);
    log(`### ${title}`);
    log(`> ${method} ${urlPath}${body ? '  ' + JSON.stringify(body) : ''}${cookie ? '  (with session cookie)' : ''}`);
    if (res.headers['set-cookie']) log(`Set-Cookie: ${redactJwt(res.headers['set-cookie'][0])}`);
    log(`< HTTP ${res.status}  ${res.text}`);
    log();
    return res;
  }

  const dup = EMAIL.replace(/^./, (c) => c.toUpperCase()).replace(/@(.)/, (_, c) => '@' + c.toUpperCase());

  await test('1. Signup rejected - invalid email', 'POST', '/api/auth/signup',
    { email: 'john.doe@invalid', password: 'Demo@Pass123', confirmPassword: 'Demo@Pass123' });
  await test('2. Signup rejected - weak password', 'POST', '/api/auth/signup',
    { email: 'john@example.com', password: 'password', confirmPassword: 'password' });
  await test('3. Signup rejected - passwords do not match', 'POST', '/api/auth/signup',
    { email: 'john@example.com', password: 'Demo@Pass123', confirmPassword: 'Demo@Pass124' });
  await test('4. Signup rejected - duplicate email in different letter case (HMAC blind index)', 'POST', '/api/auth/signup',
    { email: dup, password: PASSWORD, confirmPassword: PASSWORD });
  await test('5. Login rejected - wrong password', 'POST', '/api/auth/login',
    { email: EMAIL, password: 'Wrong@Pass999' });
  await test('6. Login rejected - unknown email (same generic message: no user enumeration)', 'POST', '/api/auth/login',
    { email: 'nobody@example.com', password: 'Wrong@Pass999' });
  const login = await test('7. Login succeeds - Secure / HttpOnly / SameSite=Strict session cookie issued', 'POST', '/api/auth/login',
    { email: EMAIL, password: PASSWORD });
  const cookie = (login.headers['set-cookie'] || [''])[0].split(';')[0];
  await test('8. Protected route with the session cookie', 'GET', '/api/auth/me', null, cookie);
  await test('9. Protected route without a session cookie', 'GET', '/api/auth/me');

  const file = path.join(root, 'report', 'evidence', 'api-tests.txt');
  fs.writeFileSync(file, out.join('\n').trimEnd() + '\n');
  console.log(out.join('\n'));
  console.log(`Wrote ${path.relative(root, file)}`);
})().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
