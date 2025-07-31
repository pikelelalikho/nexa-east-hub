// routes/auth.js
import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import nodemailer from 'nodemailer';
import { readUsers, saveUsers } from '../utils/users.js';
import { saveLog } from '../utils/logs.js';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'pikelelalikho@gmail.com',
    pass: process.env.EMAIL_PASS
  }
});

// ----- Login -----
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    saveLog({ timestamp: Date.now(), eventType: 'login_failed', details: 'Missing email or password', user: email || 'unknown' });
    return res.status(400).json({ success: false, error: 'Email and password are required' });
  }

  const users = readUsers();
  const user = users.find(u => u.email === email);
  if (!user) {
    saveLog({ timestamp: Date.now(), eventType: 'login_failed', details: 'User not found', user: email });
    return res.status(401).json({ success: false, error: 'Invalid email or password' });
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    saveLog({ timestamp: Date.now(), eventType: 'login_failed', details: 'Invalid password', user: email });
    return res.status(401).json({ success: false, error: 'Invalid email or password' });
  }

  const token = jwt.sign({ email: user.email, role: user.role || 'user' }, JWT_SECRET, { expiresIn: '2h' });
  saveLog({ timestamp: Date.now(), eventType: 'login_success', details: 'User logged in', user: email });

  try {
    await transporter.sendMail({
      from: 'Nexa East Hub <pikelelalikho@gmail.com>',
      to: email,
      subject: 'Thank you for signing in',
      text: `Hello ${user.name},\n\nYou signed in on ${new Date().toLocaleString()}.\n\n- Nexa Team`
    });
  } catch (err) {
    console.error('Login email failed:', err);
  }

  res.json({ success: true, message: 'Login successful', name: user.name, role: user.role || 'user', token });
});

export default router;