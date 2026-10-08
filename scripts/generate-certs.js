// Generates a private local Certificate Authority and a server certificate signed by it.
//
//   certs/ca.crt      - root CA certificate (import into the OS/browser trust store)
//   certs/ca.key      - root CA private key (keep private; only used to sign)
//   certs/server.crt  - server certificate for localhost / 127.0.0.1 / ::1
//   certs/server.key  - server private key used by the HTTPS server
//
// Equivalent OpenSSL commands are listed in README.md.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
require('reflect-metadata'); // required by @peculiar/x509
const x509 = require('@peculiar/x509');

const { webcrypto } = crypto;
x509.cryptoProvider.set(webcrypto);

const certDir = path.join(__dirname, '..', 'certs');
const DAY = 24 * 3600 * 1000;

// Certificate owner details (shown in the browser's Certificate Viewer)
const OWNER = {
  organization: 'Anand Sharma',
  unit: 'Softwarica - Security Task 1',
  country: 'NP',
};
const dn = (cn) => `CN=${cn}, OU=${OWNER.unit}, O=${OWNER.organization}, C=${OWNER.country}`;

const rsa = (modulusLength) => ({
  name: 'RSASSA-PKCS1-v1_5',
  hash: 'SHA-256',
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength,
});

const serial = () => '01' + crypto.randomBytes(15).toString('hex'); // positive 128-bit
const keyToPem = (key) => crypto.KeyObject.from(key).export({ type: 'pkcs8', format: 'pem' });

async function main() {
  fs.mkdirSync(certDir, { recursive: true });
  if (!process.argv.includes('--force') && fs.existsSync(path.join(certDir, 'server.crt'))) {
    console.log('certs/server.crt already exists. Use `node scripts/generate-certs.js --force` to regenerate.');
    return;
  }

  // ---- Root CA (RSA 4096, 5 years) ----
  const caAlg = rsa(4096);
  const caKeys = await webcrypto.subtle.generateKey(caAlg, true, ['sign', 'verify']);
  const caCert = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: serial(),
    name: dn(`${OWNER.organization} Local Root CA`),
    notBefore: new Date(Date.now() - 60 * 1000),
    notAfter: new Date(Date.now() + 5 * 365 * DAY),
    signingAlgorithm: caAlg,
    keys: caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
      await x509.SubjectKeyIdentifierExtension.create(caKeys.publicKey),
    ],
  });

  // ---- Server certificate (RSA 2048, 397 days - browsers reject leaf certs valid > 398 days) ----
  const srvKeys = await webcrypto.subtle.generateKey(rsa(2048), true, ['sign', 'verify']);
  const srvCert = await x509.X509CertificateGenerator.create({
    serialNumber: serial(),
    subject: dn('localhost'),
    issuer: caCert.subject,
    notBefore: new Date(Date.now() - 60 * 1000),
    notAfter: new Date(Date.now() + 397 * DAY),
    signingAlgorithm: caAlg,
    publicKey: srvKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.digitalSignature | x509.KeyUsageFlags.keyEncipherment,
        true
      ),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.SubjectAlternativeNameExtension([
        { type: 'dns', value: 'localhost' },
        { type: 'ip', value: '127.0.0.1' },
        { type: 'ip', value: '::1' },
      ]),
      await x509.SubjectKeyIdentifierExtension.create(srvKeys.publicKey),
      await x509.AuthorityKeyIdentifierExtension.create(caKeys.publicKey),
    ],
  });

  const write = (name, data, mode = 0o644) => {
    fs.writeFileSync(path.join(certDir, name), data, { mode });
    console.log(`  certs/${name}`);
  };

  console.log('Generated:');
  write('ca.key', keyToPem(caKeys.privateKey), 0o600);
  write('ca.crt', caCert.toString('pem') + '\n');
  write('server.key', keyToPem(srvKeys.privateKey), 0o600);
  write('server.crt', srvCert.toString('pem') + '\n');

  console.log(`
Next: trust the local CA so the browser shows a valid padlock (no warning).
  Windows (current user, no admin needed):
    certutil -user -addstore Root certs\\ca.crt
  Firefox uses its own store: Settings > Privacy & Security > Certificates > View Certificates
    > Authorities > Import > certs/ca.crt (tick "Trust this CA to identify websites").`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
