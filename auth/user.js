const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, unique: true, required: true },
  password: String,
  email: { type: String, unique: true, required: true },
  isVerified: { type: Boolean, default: false },
  verificationToken: String,
  verificationTokenExpires: Date,
  resetPasswordToken: String,
  resetPasswordExpires: Date,
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('User', userSchema);