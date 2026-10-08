// Builds report/Security_Report.pdf from report/report.template.html.
//
// Template directives (HTML comments, replaced at build time):
//   <!--evidence:file.txt-->                 contents of report/evidence/file.txt
//   <!--code:path/to/file.js:START-END-->    source excerpt (line range optional)
//   <!--shot:file.png|Caption|How to capture-->
//        report/screenshots/file.png if it exists, otherwise a placeholder box that
//        explains how to capture it. Drop the PNG in and re-run `npm run report`.
//   {{key}}                                  value from report/report-info.json
//
// Usage: npm run report
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const puppeteer = require('puppeteer-core');

const root = path.join(__dirname, '..');
const reportDir = path.join(root, 'report');
const shotsDir = path.join(reportDir, 'screenshots');
const evidenceDir = path.join(reportDir, 'evidence');

const BROWSERS = [
  process.env.CHROME_PATH,
  'C:/Program Files/Google/Chrome/Application/chrome.exe',
  'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
  '/usr/bin/google-chrome',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
].filter(Boolean);

const escapeHtml = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const info = JSON.parse(fs.readFileSync(path.join(reportDir, 'report-info.json'), 'utf8'));
let html = fs.readFileSync(path.join(reportDir, 'report.template.html'), 'utf8');

let figure = 0;
const missing = [];

html = html
  .replace(/\{\{(\w+)\}\}/g, (_, key) => escapeHtml(String(info[key] ?? `{{${key}}}`)))
  .replace(/<!--evidence:([\w.-]+)-->/g, (_, file) => {
    const p = path.join(evidenceDir, file);
    const text = fs.existsSync(p) ? fs.readFileSync(p, 'utf8').trimEnd() : `(missing evidence file ${file})`;
    return `<pre class="evidence">${escapeHtml(text)}</pre>`;
  })
  .replace(/<!--code:([\w./-]+)(?::(\d+)-(\d+))?-->/g, (_, file, start, end) => {
    const lines = fs.readFileSync(path.join(root, file), 'utf8').split(/\r?\n/);
    const from = start ? Number(start) : 1;
    const to = end ? Number(end) : lines.length;
    const body = lines
      .slice(from - 1, to)
      .map((l, i) => `<span class="ln">${String(from + i).padStart(3)}</span>${escapeHtml(l)}`)
      .join('\n');
    const label = start ? `${file} (lines ${from}–${to})` : file;
    return `<div class="code"><div class="code-title">${escapeHtml(label)}</div><pre>${body}</pre></div>`;
  })
  .replace(/<!--shot:([\w.-]+)\|([^|]*)\|([\s\S]*?)-->/g, (_, file, caption, howTo) => {
    figure += 1;
    const cap = `<figcaption><b>Figure ${figure}.</b> ${caption}</figcaption>`;
    if (fs.existsSync(path.join(shotsDir, file))) {
      return `<figure><img src="screenshots/${file}" alt="${escapeHtml(caption)}">${cap}</figure>`;
    }
    missing.push(file);
    return `<figure class="pending"><div class="placeholder"><b>Screenshot to add:</b> report/screenshots/${file}<br><span>${howTo.trim()}</span></div>${cap}</figure>`;
  });

const outHtml = path.join(reportDir, 'report.html');
fs.writeFileSync(outHtml, html);

(async () => {
  const executablePath = BROWSERS.find((p) => fs.existsSync(p));
  if (!executablePath) throw new Error('No Chrome/Edge found. Set CHROME_PATH.');
  const browser = await puppeteer.launch({ executablePath, headless: true });
  const page = await browser.newPage();
  await page.goto(pathToFileURL(outHtml).href, { waitUntil: 'networkidle0' });
  const outPdf = path.join(reportDir, 'Security_Report.pdf');
  await page.pdf({
    path: outPdf,
    format: 'A4',
    printBackground: true,
    margin: { top: '18mm', bottom: '18mm', left: '16mm', right: '16mm' },
    displayHeaderFooter: true,
    headerTemplate: '<span></span>',
    footerTemplate: `<div style="font-size:8px;width:100%;padding:0 16mm;color:#666;display:flex;justify-content:space-between">
      <span>${escapeHtml(info.title)}</span><span><span class="pageNumber"></span> / <span class="totalPages"></span></span></div>`,
  });
  await browser.close();

  console.log(`Wrote ${path.relative(root, outPdf)} (${figure} figures)`);
  if (missing.length) {
    console.log(`\n${missing.length} screenshot(s) still to capture (placeholders shown in the PDF):`);
    missing.forEach((f) => console.log(`  report/screenshots/${f}`));
  }
})().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
