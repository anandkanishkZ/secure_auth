// Drives the locally installed Chrome/Edge through the full signup -> login -> dashboard flow
// and saves page screenshots into report/screenshots/ for the report.
//
// Usage (server must be running):  npm run screenshots -- [email] [password]
//
// The browser is told to trust only the public key of OUR server certificate
// (--ignore-certificate-errors-spki-list), so the screenshots work before the local CA has
// been imported. For the address-bar padlock screenshot, import certs/ca.crt and use a
// normal browser window instead.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const puppeteer = require('puppeteer-core');

const BASE = process.env.APP_URL || 'https://localhost:8443';
const EMAIL = process.argv[2] || 'report.demo@example.com';
const PASSWORD = process.argv[3] || 'Demo@Pass123';
const OUT = path.join(__dirname, '..', 'report', 'screenshots');

const BROWSERS = [
  process.env.CHROME_PATH,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

function serverSpkiHash() {
  const cert = new crypto.X509Certificate(fs.readFileSync(path.join(__dirname, '..', 'certs', 'server.crt')));
  const spki = cert.publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(spki).digest('base64');
}

(async () => {
  const executablePath = BROWSERS.find((p) => fs.existsSync(p));
  if (!executablePath) throw new Error('No Chrome/Edge found. Set CHROME_PATH.');
  fs.mkdirSync(OUT, { recursive: true });

  const browser = await puppeteer.launch({
    executablePath,
    headless: true,
    args: [`--ignore-certificate-errors-spki-list=${serverSpkiHash()}`],
    defaultViewport: { width: 900, height: 760, deviceScaleFactor: 1.5 },
  });
  const page = await browser.newPage();
  const shot = async (name) => {
    await new Promise((r) => setTimeout(r, 400)); // let the TLS-info footer render
    await page.screenshot({ path: path.join(OUT, name) });
    console.log(`  report/screenshots/${name}`);
  };
  const fill = async (selector, value) => {
    await page.$eval(selector, (el) => { el.value = ''; });
    await page.type(selector, value);
  };

  console.log(`Using ${executablePath}\nSaving:`);

  // 1. Signup with an invalid email -> rejected
  await page.goto(`${BASE}/signup`, { waitUntil: 'networkidle0' });
  await fill('#email', 'not-an-email');
  await fill('#password', PASSWORD);
  await fill('#confirmPassword', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForSelector('.message.error');
  await shot('app-signup-invalid-email.png');

  // 2. Valid signup
  await fill('#email', EMAIL);
  await shot('app-signup-filled.png');
  await page.click('button[type=submit]');
  await page.waitForSelector('.message.ok, .message.error');
  await shot('app-signup-success.png');

  // 3. Login with the wrong password -> generic error
  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await fill('#email', EMAIL);
  await fill('#password', 'Wrong@Pass999');
  await page.click('button[type=submit]');
  await page.waitForSelector('.message.error');
  await shot('app-login-failed.png');

  // 4. Correct login -> dashboard
  await fill('#password', PASSWORD);
  await shot('app-login-filled.png');
  await page.click('button[type=submit]');
  await page.waitForFunction(
    () => location.pathname === '/dashboard' && document.getElementById('email')?.textContent.includes('@'),
    { polling: 200, timeout: 15000 }
  );
  await shot('app-dashboard.png');

  await browser.close();
})().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
