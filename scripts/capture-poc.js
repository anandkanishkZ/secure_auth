// Wireshark/tshark Proof of Concept.
//
// 1. Starts a capture on the loopback adapter (ports 8443 and 8080).
// 2. Sends one plain-HTTP request to port 8080 (to show it only redirects).
// 3. Drives Chrome through a real signup + login over HTTPS with a fresh test account.
// 4. Analyses the capture with tshark and writes the results to report/evidence/wireshark-*.txt.
//
// Output: report/capture/signup-login.pcapng  -> open it in Wireshark for screenshots.
//         report/capture/chrome-sslkeys.log   -> the BROWSER's TLS session keys, used only for the
//                                                control experiment (decryption is possible only
//                                                when you hold these keys).
//
// Usage (server must be running):  npm run capture -- [email] [password]
const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');
const puppeteer = require('puppeteer-core');

const root = path.join(__dirname, '..');
const capDir = path.join(root, 'report', 'capture');
const evDir = path.join(root, 'report', 'evidence');
const PCAP = path.join(capDir, 'signup-login.pcapng');
const KEYLOG = path.join(capDir, 'chrome-sslkeys.log');

const WIRESHARK_DIR = process.env.WIRESHARK_DIR || 'C:/Program Files/Wireshark';
const TSHARK = path.join(WIRESHARK_DIR, process.platform === 'win32' ? 'tshark.exe' : 'tshark');
const IFACE = process.env.CAPTURE_IFACE || (process.platform === 'win32' ? '\\Device\\NPF_Loopback' : 'lo');
const BASE = 'https://localhost:8443';

const stamp = new Date().toISOString().slice(11, 19).replace(/:/g, '');
const EMAIL = process.argv[2] || `anand.poc${stamp}@example.com`;
const PASSWORD = process.argv[3] || 'Anand@Secure2026';

const BROWSERS = [
  process.env.CHROME_PATH,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
].filter(Boolean);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function tshark(args, { keylog = false } = {}) {
  const base = ['-r', PCAP, '-n'];
  if (keylog) base.push('-o', `tls.keylog_file:${KEYLOG}`);
  return execFileSync(TSHARK, [...base, ...args], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trimEnd();
}

function startCapture() {
  return new Promise((resolve, reject) => {
    const proc = spawn(TSHARK, ['-i', IFACE, '-f', 'tcp port 8443 or tcp port 8080', '-w', PCAP, '-q']);
    let ready = false;
    proc.stderr.on('data', (d) => {
      if (!ready && /Capturing on/i.test(d.toString())) {
        ready = true;
        resolve(proc);
      }
    });
    proc.on('error', reject);
    proc.on('exit', (code) => !ready && reject(new Error(`tshark exited with code ${code}`)));
  });
}

function stopCapture(proc) {
  return new Promise((resolve) => {
    proc.on('exit', resolve);
    // tshark flushes and closes the pcapng cleanly when its stdin closes / on termination
    proc.kill();
    setTimeout(resolve, 3000);
  });
}

function plainHttpRequest() {
  return new Promise((resolve) => {
    http.get('http://localhost:8080/login', (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    }).on('error', () => resolve(null));
  });
}

function serverSpkiHash() {
  const cert = new crypto.X509Certificate(fs.readFileSync(path.join(root, 'certs', 'server.crt')));
  return crypto.createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
}

async function browserFlow() {
  const browser = await puppeteer.launch({
    executablePath: BROWSERS.find((p) => fs.existsSync(p)),
    headless: true,
    args: [`--ignore-certificate-errors-spki-list=${serverSpkiHash()}`, `--ssl-key-log-file=${KEYLOG}`],
  });
  const page = await browser.newPage();
  const fill = async (sel, v) => {
    await page.$eval(sel, (el) => { el.value = ''; });
    await page.type(sel, v);
  };

  await page.goto(`${BASE}/signup`, { waitUntil: 'networkidle0' });
  await fill('#email', EMAIL);
  await fill('#password', PASSWORD);
  await fill('#confirmPassword', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForSelector('.message.ok, .message.error');
  const signupMsg = await page.$eval('#message', (el) => el.textContent);

  await page.goto(`${BASE}/login`, { waitUntil: 'networkidle0' });
  await fill('#email', EMAIL);
  await fill('#password', PASSWORD);
  await page.click('button[type=submit]');
  await page.waitForFunction(
    () => location.pathname === '/dashboard' && document.getElementById('email')?.textContent.includes('@'),
    { polling: 200, timeout: 15000 }
  );
  await sleep(500);
  await browser.close();
  return signupMsg;
}

function countMatches(filter) {
  const out = tshark(['-Y', filter]);
  return out ? out.split('\n').length : 0;
}

(async () => {
  if (!fs.existsSync(TSHARK)) throw new Error(`tshark not found at ${TSHARK} (set WIRESHARK_DIR)`);
  fs.mkdirSync(capDir, { recursive: true });
  fs.mkdirSync(evDir, { recursive: true });
  for (const f of [PCAP, KEYLOG]) fs.rmSync(f, { force: true });

  console.log(`Capturing on ${IFACE} -> ${path.relative(root, PCAP)}`);
  const cap = await startCapture();
  await sleep(1000);

  const redirectStatus = await plainHttpRequest();
  console.log(`  plain HTTP request to :8080 -> ${redirectStatus}`);
  const signupMsg = await browserFlow();
  console.log(`  signup: ${signupMsg}`);
  console.log(`  login:  dashboard reached for ${EMAIL}`);

  await sleep(1500);
  await stopCapture(cap);
  await sleep(500);

  // ---------------- Analysis ----------------
  const total = tshark(['-q', '-z', 'io,stat,0']).match(/\|\s*Frames\s*\|[\s\S]*?\|\s*(\d+)\s*\|/);
  const sections = [];
  const add = (title, cmd, body) => sections.push(`### ${title}\n$ ${cmd}\n${body || '(no packets)'}\n`);

  add('Capture', `tshark -i "${IFACE}" -f "tcp port 8443 or tcp port 8080" -w ${path.relative(root, PCAP).replace(/\\/g, '/')}`,
    `Interface: ${IFACE}\nCapture filter: tcp port 8443 or tcp port 8080\nTest account: ${EMAIL} / ${PASSWORD}\nFrames captured: ${total ? total[1] : 'n/a'}`);

  add('TLS handshake messages',
    'tshark -r signup-login.pcapng -Y "tls.handshake.type == 1 || tls.handshake.type == 2"',
    tshark(['-Y', 'tls.handshake.type == 1 || tls.handshake.type == 2']).split('\n').slice(0, 8).join('\n'));

  const sh = tshark(['-Y', 'tls.handshake.type == 2', '-V', '-O', 'tls'])
    .split(/\n(?=Frame \d+:)/)[0] // first Server Hello only
    .split('\n')
    .filter((l) => /Handshake Type|Cipher Suite:|Supported Version:|Group:|Version: TLS|Content Type/.test(l))
    .map((l) => l.trim())
    .filter((l, i, a) => a.indexOf(l) === i)
    .join('\n');
  add('Server Hello details (negotiated parameters)', 'tshark -r signup-login.pcapng -Y "tls.handshake.type == 2" -V -O tls', sh);

  fs.writeFileSync(path.join(evDir, 'wireshark-handshake.txt'), sections.splice(0).join('\n'));

  // Encrypted application data
  // tls.app_data matches both TLS 1.2 (content_type 23) and TLS 1.3 (opaque_type 23) records
  const appData = tshark(['-Y', 'tls.app_data && tcp.dstport == 8443 && tcp.len > 300']).split('\n');
  add('Encrypted Application Data sent by the browser (signup/login requests among them)',
    'tshark -r signup-login.pcapng -Y "tls.app_data && tcp.dstport == 8443 && tcp.len > 300"',
    appData.slice(0, 12).join('\n'));
  const records = countMatches('tls.app_data');
  add('Total TLS Application Data packets', 'tshark ... -Y "tls.app_data" | count', String(records));

  // Hex dump of the signup POST packet (identify it with the key log, display it WITHOUT it)
  const signupFrame = tshark(['-Y', 'http.request.uri == "/api/auth/signup"', '-T', 'fields', '-e', 'frame.number'], { keylog: true }).split('\n')[0];
  if (signupFrame) {
    const hex = tshark(['-Y', `frame.number == ${signupFrame}`, '-x']).split('\n').slice(0, 40).join('\n');
    add(`Raw bytes of frame ${signupFrame} (the signup request) as an eavesdropper sees it`,
      `tshark -r signup-login.pcapng -Y "frame.number == ${signupFrame}" -x`, hex);
  }
  fs.writeFileSync(path.join(evDir, 'wireshark-appdata.txt'), sections.splice(0).join('\n'));

  // Plaintext searches
  const searches = [
    ['http && tcp.port == 8443', 'any readable HTTP on the HTTPS port'],
    [`frame contains "${PASSWORD}"`, 'the password'],
    [`frame contains "${EMAIL}"`, 'the full email address'],
    [`frame contains "${EMAIL.split('@')[0]}"`, 'the email local part'],
    ['frame contains "password"', 'the JSON field name "password"'],
    ['frame contains "/api/auth/"', 'the API path'],
    ['frame contains "__Host-session"', 'the session cookie name'],
    ['frame contains "POST"', 'the HTTP method'],
  ];
  const rows = searches.map(([f, what]) => {
    const n = countMatches(`(${f}) && tcp.port == 8443`);
    return `${String(n).padStart(3)} packets  <-  ${f.padEnd(44)} (${what})`;
  });
  add('Searching the HTTPS traffic for sensitive plaintext (display filter, port 8443)',
    'tshark -r signup-login.pcapng -Y \'<filter> && tcp.port == 8443\' | count', rows.join('\n'));
  fs.writeFileSync(path.join(evDir, 'wireshark-search.txt'), sections.splice(0).join('\n'));

  // Plain HTTP port
  add('Plain-HTTP port 8080: only a redirect, no credentials',
    'tshark -r signup-login.pcapng -Y "http && tcp.port == 8080"',
    tshark(['-Y', 'http && tcp.port == 8080']));
  fs.writeFileSync(path.join(evDir, 'wireshark-http-redirect.txt'), sections.splice(0).join('\n'));

  // Control experiment: with the browser's session keys the same capture decrypts
  const decrypted = tshark(
    ['-Y', 'http.request.method == "POST"', '-T', 'fields', '-e', 'frame.number', '-e', 'http.request.uri', '-e', 'http.file_data'],
    { keylog: true }
  )
    .split('\n')
    .filter(Boolean)
    .map((line) => {
      const [frame, uri, hex] = line.split('\t');
      return `frame ${frame}  POST ${uri}\n    body: ${Buffer.from(hex || '', 'hex').toString('utf8')}`;
    })
    .join('\n');
  add('CONTROL: same capture decrypted with the TLS session key log (keys an eavesdropper never has)',
    'tshark -r signup-login.pcapng -o tls.keylog_file:chrome-sslkeys.log -Y "http.request.method == POST" -T fields -e frame.number -e http.request.uri -e http.file_data',
    decrypted);
  fs.writeFileSync(path.join(evDir, 'wireshark-decrypted-control.txt'), sections.splice(0).join('\n'));

  console.log('\nEvidence written:');
  for (const f of fs.readdirSync(evDir).filter((f) => f.startsWith('wireshark-'))) console.log(`  report/evidence/${f}`);
  console.log(`\nOpen ${path.relative(root, PCAP)} in Wireshark to take the GUI screenshots.`);
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
