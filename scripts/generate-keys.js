// Creates .env from .env.example and fills the secret values with fresh random keys.
// Existing non-empty values are kept, so re-running never rotates a key that is in use
// (rotating AES_KEY would make already-stored emails undecryptable).
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = path.join(__dirname, '..');
const envPath = path.join(root, '.env');
const examplePath = path.join(root, '.env.example');

const source = fs.existsSync(envPath) ? envPath : examplePath;
let content = fs.readFileSync(source, 'utf8');

const secrets = {
  AES_KEY: () => crypto.randomBytes(32).toString('hex'),
  EMAIL_HMAC_KEY: () => crypto.randomBytes(32).toString('hex'),
  JWT_SECRET: () => crypto.randomBytes(48).toString('base64url'),
};

for (const [name, generate] of Object.entries(secrets)) {
  const re = new RegExp(`^${name}=(.*)$`, 'm');
  const match = content.match(re);
  if (match && match[1].trim()) {
    console.log(`= ${name} already set, keeping it`);
    continue;
  }
  const line = `${name}=${generate()}`;
  content = match ? content.replace(re, line) : `${content.trimEnd()}\n${line}\n`;
  console.log(`+ ${name} generated`);
}

fs.writeFileSync(envPath, content, { mode: 0o600 });
console.log(`Wrote ${path.relative(root, envPath)}`);
