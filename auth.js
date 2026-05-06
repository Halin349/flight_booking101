const express = require('express');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const User = require('./user');
const sendEmail = require('./mailer');

const router = express.Router();

// ================= REGISTER =================
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ msg: 'All fields required' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ msg: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const token = crypto.randomBytes(32).toString('hex');

    const user = new User({
      name,
      email,
      password: hashedPassword,
      verificationToken: token,
      verificationTokenExpires: Date.now() + 86400000
    });

    await user.save();

    const verifyLink = `${process.env.BASE_URL}/verify-email/${token}`;

    await sendEmail(
      user.email,
      'Verify your email',
      `<a href="${verifyLink}">${verifyLink}</a>`
    );

    res.status(201).json({ msg: 'User registered successfully' });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= VERIFY EMAIL =================
router.get('/verify-email/:token', async (req, res) => {
  try {
    const user = await User.findOne({
      verificationToken: req.params.token,
      verificationTokenExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).send('Invalid or expired token');
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    user.verificationTokenExpires = undefined;

    await user.save();

    res.send('Email verified successfully');

  } catch (err) {
    res.status(500).send(err.message);
  }
});

// ================= LOGIN =================
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    if (!user.isVerified) {
      return res.status(400).json({ msg: 'Please verify your email first' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Invalid credentials' });
    }

    res.json({ msg: 'Login successful', userId: user._id });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= CHANGE PASSWORD =================
router.post('/change-password', async (req, res) => {
  try {
    const { email, oldPassword, newPassword } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ msg: 'User not found' });
    }

    const isMatch = await bcrypt.compare(oldPassword, user.password);
    if (!isMatch) {
      return res.status(400).json({ msg: 'Incorrect old password' });
    }

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(newPassword, salt);

    await user.save();

    res.json({ msg: 'Password updated successfully' });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= FORGOT PASSWORD =================
router.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ msg: 'User not found' });

    const token = crypto.randomBytes(32).toString('hex');

    user.resetPasswordToken = token;
    user.resetPasswordExpires = Date.now() + 3600000;

    await user.save();

    const resetLink = `${process.env.BASE_URL}/reset-password/${token}`;

    await sendEmail(
      email,
      'Reset Password',
      `<a href="${resetLink}">${resetLink}</a>`
    );

    res.json({ msg: 'Password reset email sent' });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ================= RESET PASSWORD =================
router.post('/reset-password/:token', async (req, res) => {
  try {
    const { newPassword } = req.body;

    const user = await User.findOne({
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ msg: 'Invalid or expired token' });
    }

    const salt = await bcrypt.genSalt(10);

    user.password = await bcrypt.hash(newPassword, salt);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;

    await user.save();

    res.json({ msg: 'Password reset successful' });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;