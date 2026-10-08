const mongoose = require('mongoose');

// Only protected values are stored: no plaintext email, no plaintext password.
const encryptedFieldSchema = new mongoose.Schema(
  {
    iv: { type: String, required: true },
    tag: { type: String, required: true },
    ciphertext: { type: String, required: true },
  },
  { _id: false }
);

const userSchema = new mongoose.Schema(
  {
    // HMAC-SHA256(normalised email) - lets us find a user and enforce uniqueness
    emailIndex: { type: String, required: true, unique: true },
    // AES-256-GCM encrypted email
    email: { type: encryptedFieldSchema, required: true },
    // bcrypt hash (algorithm, cost and salt are embedded in the string)
    passwordHash: { type: String, required: true },
    lastLoginAt: { type: Date },
  },
  { timestamps: true }
);

userSchema.set('toJSON', {
  transform(_doc, ret) {
    delete ret.passwordHash;
    return ret;
  },
});

module.exports = mongoose.model('User', userSchema);
