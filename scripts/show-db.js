// Prints the raw user documents exactly as stored in MongoDB, to show that the email is
// AES-encrypted and the password exists only as a bcrypt hash.
// Usage: npm run show-db                        (all raw documents)
//        npm run show-db -- --email a@b.com     (only that user, found via the HMAC blind index)
//        npm run show-db -- --decrypt           (also decrypt the email with the server key)
const mongoose = require('mongoose');
const config = require('../src/config');
const { decrypt, blindIndex } = require('../src/utils/crypto');

const emailArg = process.argv.indexOf('--email');
const email = emailArg !== -1 ? process.argv[emailArg + 1] : null;

(async () => {
  await mongoose.connect(config.mongoUri);
  const query = email ? { emailIndex: blindIndex(email) } : {};
  const users = await mongoose.connection.db.collection('users').find(query).toArray();
  const shown = email ? `db.users.find({ emailIndex: HMAC-SHA256("${email}") })` : 'db.users.find()';
  console.log(`${shown}  ->  ${users.length} document(s) in ${mongoose.connection.name}.users\n`);
  for (const u of users) {
    console.log(JSON.stringify(u, null, 2));
    if (process.argv.includes('--decrypt')) {
      console.log(`  -> decrypted with AES_KEY: ${decrypt(u.email)}`);
    }
    console.log();
  }
  await mongoose.disconnect();
})().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
