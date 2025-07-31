// ---------- Dependencies ----------
import express from 'express';
import fs from 'fs';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Server } from 'socket.io';
import http from 'http';
import nodemailer from 'nodemailer';
import path from 'path';
import { fileURLToPath } from 'url';

// ES Module dirname fix
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();

const PORT = process.env.PORT || 3000;
const app = express();

// ---------- JWT Secret ----------
const JWT_SECRET = process.env.JWT_SECRET || 'your_fallback_secret';

// ---------- Email Transporter ----------
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// ---------- Global Error Handlers ----------
process.on('uncaughtException', (err) => {
  console.error('Uncaught Exception:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// ---------- Rate Limiters ----------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { success: false, error: 'Too many login attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { success: false, error: 'Too many signup attempts, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3,
  message: { success: false, error: 'Too many contact form submissions, please try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const forgotPasswordLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 6,
  message: { success: false, error: 'Too many password reset attempts, please try again later.' }
});

// ---------- Middleware Setup (Applied Once) ----------
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? (process.env.ALLOWED_ORIGINS?.split(',') || ['https://nexa-east-hub.onrender.com']) 
    : ['http://localhost:5500', 'http://localhost:3000', 'http://127.0.0.1:5500'],
  credentials: true
}));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  }
}));

// ---------- Create HTTP Server and Socket.IO ----------
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? (process.env.ALLOWED_ORIGINS?.split(',') || ['https://nexa-east-hub.onrender.com']) 
      : ['http://localhost:5500', 'http://localhost:3000', 'http://127.0.0.1:5500'],
    credentials: true
  }
});

// ---------- Serve Static Files ----------
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Utility Functions ----------
function readUsers() {
  const filePath = path.join(__dirname, 'users.json');
  if (!fs.existsSync(filePath)) return [];
  try {
    const data = fs.readFileSync(filePath, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading users.json:', error);
    return [];
  }
}

function saveUsers(users) {
  const filePath = path.join(__dirname, 'users.json');
  try {
    fs.writeFileSync(filePath, JSON.stringify(users, null, 2));
    return true;
  } catch (error) {
    console.error('Error saving users:', error);
    return false;
  }
}

function saveLog(entry) {
  const filePath = path.join(__dirname, 'logs.json');
  let logs = [];

  if (fs.existsSync(filePath)) {
    try {
      const data = fs.readFileSync(filePath, 'utf-8');
      logs = JSON.parse(data);
    } catch (error) {
      console.error('Error reading logs.json:', error);
    }
  }

  const logEntry = {
    ...entry,
    timestamp: entry.timestamp || Date.now(),
    id: Date.now() + Math.random()
  };

  logs.push(logEntry);

  try {
    fs.writeFileSync(filePath, JSON.stringify(logs, null, 2));
    io.emit('new_log', logEntry);
  } catch (error) {
    console.error('Error writing logs.json:', error);
  }
}

// ---------- Authentication Middleware ----------
function authenticateUser(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ success: false, error: 'No authorization header' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, error: 'Token missing' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }
}

function authenticateAdminRoute(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({ success: false, error: 'No authorization header' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ success: false, error: 'Token missing' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (decoded.role !== 'admin') {
      return res.status(403).json({ success: false, error: 'Admin access required' });
    }
    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ success: false, error: 'Invalid token' });
  }
}

// ---------- ADMIN RESET FUNCTION ----------
async function createOrUpdateAdmin() {
  const adminEmail = process.env.ADMIN_EMAIL || 'pikelelalikho@gmail.com';
  const adminPassword = process.env.ADMIN_PASSWORD || '@01Nexaadmin';
  const adminName = process.env.ADMIN_NAME || 'Nexa Admin';

  try {
    console.log('🔄 Creating/Updating admin user...');

    let users = readUsers();
    const hashedPassword = await bcrypt.hash(adminPassword, 12);

    const adminIndex = users.findIndex(u => u.email === adminEmail || u.role === 'admin');

    if (adminIndex !== -1) {
      users[adminIndex] = {
        ...users[adminIndex],
        password: hashedPassword,
        role: 'admin',
        email: adminEmail,
        name: adminName,
        updatedAt: new Date().toISOString()
      };
      console.log('✅ Admin user updated successfully');
    } else {
      const newAdmin = {
        id: Date.now(),
        name: adminName,
        email: adminEmail,
        password: hashedPassword,
        role: 'admin',
        createdAt: new Date().toISOString(),
        isActive: true
      };
      users.push(newAdmin);
      console.log('✅ New admin user created successfully');
    }

    if (saveUsers(users)) {
      saveLog({
        eventType: 'admin_reset',
        details: 'Admin password reset on server startup',
        user: 'system'
      });

      console.log('==========================================');
      console.log('🔐 ADMIN LOGIN CREDENTIALS:');
      console.log(`📧 Email: ${adminEmail}`);
      console.log(`🔑 Password: ${adminPassword}`);
      console.log('==========================================');
    }

  } catch (error) {
    console.error('❌ Error creating/updating admin:', error);
  }
}

// ---------- SIGNUP ROUTE ----------
app.post('/signup', signupLimiter, async (req, res) => {
  const { name, email, password } = req.body;

  // Validation
  if (!name || !email || !password) {
    return res.status(400).json({ success: false, error: 'All fields are required' });
  }

  if (name.trim().length < 2) {
    return res.status(400).json({ success: false, error: 'Name must be at least 2 characters' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, error: 'Invalid email format' });
  }

  if (password.length < 6) {
    return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
  }

  try {
    const users = readUsers();
    
    // Check if user already exists
    if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
      saveLog({ eventType: 'signup_failed', details: `Email already exists: ${email}`, user: email });
      return res.status(409).json({ success: false, error: 'Email already exists' });
    }

    // Hash password and create user
    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = {
      id: Date.now(),
      name: name.trim(),
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'user',
      createdAt: new Date().toISOString(),
      isActive: true
    };

    users.push(newUser);
    
    if (saveUsers(users)) {
      saveLog({ eventType: 'signup_success', details: `New user registered: ${email}`, user: email });
      
      // Send welcome email
      try {
        const mailOptions = {
          from: `"Nexa East Hub" <${process.env.EMAIL_USER}>`,
          to: email,
          subject: 'Welcome to Nexa East Hub!',
          html: `
            <h2>Welcome to Nexa East Hub!</h2>
            <p>Hello ${name},</p>
            <p>Thank you for joining Nexa East Hub. Your account has been created successfully.</p>
            <p>You can now log in and start exploring our services.</p>
            <br>
            <p>Best regards,<br>Nexa Team</p>
          `
        };
        await transporter.sendMail(mailOptions);
      } catch (emailError) {
        console.error('Failed to send welcome email:', emailError);
      }

      res.json({ success: true, message: 'Account created successfully' });
    } else {
      throw new Error('Failed to save user data');
    }
  } catch (error) {
    console.error('Signup error:', error);
    saveLog({ eventType: 'signup_error', details: error.message, user: email });
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// ---------- LOGIN ROUTE ----------
app.post('/login', loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, error: 'Email and password are required' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, error: 'Invalid email format' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

  if (!user) {
    saveLog({ eventType: 'login_failed', details: `Login attempt with non-existent email: ${email}`, user: email });
    return res.status(401).json({ success: false, error: 'Invalid email or password' });
  }

  if (!user.isActive) {
    saveLog({ eventType: 'login_failed', details: `Login attempt with deactivated account: ${email}`, user: email });
    return res.status(401).json({ success: false, error: 'Account has been deactivated' });
  }

  try {
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      saveLog({ eventType: 'login_failed', details: `Invalid password for ${email}`, user: email });
      return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { email: user.email, role: user.role || 'user', id: user.id },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    saveLog({ eventType: 'login_success', details: 'User logged in successfully', user: email });

    // Send login notification email
    try {
      const mailOptions = {
        from: `"Nexa East Hub" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Login Notification - Nexa East Hub',
        html: `
          <h3>Login Notification</h3>
          <p>Hello ${user.name},</p>
          <p>You successfully signed in to Nexa East Hub on ${new Date().toLocaleString()}.</p>
          <p>If this wasn't you, please contact our support immediately.</p>
          <br>
          <p>Best regards,<br>Nexa Team</p>
        `
      };
      await transporter.sendMail(mailOptions);
    } catch (emailError) {
      console.error('Failed to send login email:', emailError);
    }

    res.json({
      success: true,
      message: 'Login successful',
      name: user.name,
      role: user.role || 'user',
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    saveLog({ eventType: 'login_error', details: error.message, user: email });
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// ---------- FORGOT PASSWORD ROUTE ----------
app.post('/api/forgot-password', forgotPasswordLimiter, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ success: false, error: 'Email is required' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, error: 'Please enter a valid email address' });
  }

  const users = readUsers();
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

  saveLog({ eventType: 'forgot_password_request', details: `Password reset requested for ${email}`, user: email });

  if (user && user.isActive) {
    try {
      const resetToken = jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: '1h' });
      const resetLink = `${req.protocol}://${req.get('host')}/reset-password.html?token=${resetToken}`;

      const mailOptions = {
        from: `"Nexa East Hub" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Password Reset Request - Nexa East Hub',
        html: `
          <h2>Password Reset Request</h2>
          <p>Hello ${user.name},</p>
          <p>You requested a password reset. Click the button below to reset your password:</p>
          <p style="text-align: center; margin: 30px 0;">
            <a href="${resetLink}" 
               style="background:#0066cc;color:white;padding:12px 24px;text-decoration:none;border-radius:6px;display:inline-block;">
               Reset Your Password
            </a>
          </p>
          <p>If the button doesn't work, copy and paste this link into your browser:</p>
          <p><a href="${resetLink}">${resetLink}</a></p>
          <p><strong>This link will expire in 1 hour.</strong></p>
          <p>If you didn't request this password reset, please ignore this email.</p>
          <br>
          <p>Best regards,<br>Nexa Team</p>
        `
      };

      await transporter.sendMail(mailOptions);
    } catch (emailError) {
      console.error('Failed to send reset email:', emailError);
    }
  }

  // Always return success for security
  res.json({ success: true, message: 'If the email exists in our system, a reset link has been sent' });
});

// ---------- RESET PASSWORD ROUTE ----------
app.post('/api/reset-password', forgotPasswordLimiter, async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res.status(400).json({ success: false, error: 'Token and password are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ success: false, error: 'Password must be at least 6 characters long' });
  }

  try {
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (error) {
      if (error.name === 'TokenExpiredError') {
        saveLog({ eventType: 'password_reset_failed', details: 'Expired reset token', user: 'unknown' });
        return res.status(400).json({ success: false, error: 'Reset link expired. Please request a new one.' });
      }
      if (error.name === 'JsonWebTokenError') {
        saveLog({ eventType: 'password_reset_failed', details: 'Invalid reset token', user: 'unknown' });
        return res.status(400).json({ success: false, error: 'Invalid reset token' });
      }
      saveLog({ eventType: 'password_reset_failed', details: 'Unknown token error', user: 'unknown' });
      return res.status(400).json({ success: false, error: 'Token verification failed' });
    }

    const users = readUsers();
    const userIndex = users.findIndex(u => u.email.toLowerCase() === decoded.email.toLowerCase());

    if (userIndex === -1) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    users[userIndex].password = hashedPassword;
    users[userIndex].updatedAt = new Date().toISOString();

    if (!saveUsers(users)) {
      throw new Error('Failed to save password update');
    }

    saveLog({ eventType: 'password_reset_success', details: `Password reset completed for ${decoded.email}`, user: decoded.email });

    try {
      const mailOptions = {
        from: `"Nexa East Hub" <${process.env.EMAIL_USER}>`,
        to: decoded.email,
        subject: 'Password Reset Successful - Nexa East Hub',
        html: `
          <h2>Password Reset Successful</h2>
          <p>Hello ${users[userIndex].name},</p>
          <p>Your password has been successfully reset.</p>
          <p>You can now log in with your new password.</p>
          <p>If you didn't perform this action, please contact our support immediately.</p>
          <br>
          <p>Best regards,<br>Nexa Team</p>
        `
      };
      await transporter.sendMail(mailOptions);
    } catch (emailError) {
      console.error('Failed to send confirmation email:', emailError);
    }

    return res.json({ success: true, message: 'Password reset successfully' });
  } catch (err) {
    console.error('Unexpected error in reset:', err);
    saveLog({ eventType: 'password_reset_error', details: err.message, user: 'unknown' });
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// ---------- CONTACT FORM ROUTE ----------
app.post('/contact', contactLimiter, async (req, res) => {
  const { name, email, phone, service, message } = req.body;

  if (!name || !email || !service || !message) {
    saveLog({ eventType: 'contact_form_failed', details: 'Missing required fields', user: email || 'unknown' });
    return res.status(400).json({ success: false, error: 'All required fields must be filled' });
  }

  if (name.trim().length < 2) {
    return res.status(400).json({ success: false, error: 'Name must be at least 2 characters' });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, error: 'Please enter a valid email address' });
  }

  if (message.trim().length < 10) {
    return res.status(400).json({ success: false, error: 'Message must be at least 10 characters' });
  }

  try {
    const contactEntry = {
      id: Date.now(),
      name: name.trim(),
      email: email.toLowerCase(),
      phone: phone?.trim() || null,
      service,
      message: message.trim(),
      timestamp: new Date().toISOString(),
      status: 'new'
    };

    const contactsPath = path.join(__dirname, 'contacts.json');
    let contacts = [];

    if (fs.existsSync(contactsPath)) {
      try {
        const data = fs.readFileSync(contactsPath, 'utf-8');
        contacts = JSON.parse(data);
      } catch (error) {
        console.error('Error reading contacts.json:', error);
      }
    }

    contacts.push(contactEntry);
    fs.writeFileSync(contactsPath, JSON.stringify(contacts, null, 2));

    saveLog({ eventType: 'contact_message', details: `Contact form submission from ${name} (${email}) for ${service}`, user: email });

    const userMailOptions = {
      from: `"Nexa East Hub" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: 'Thank you for contacting Nexa East Hub',
      html: `
        <h2>Thank you for contacting us!</h2>
        <p>Hello ${name},</p>
        <p>Thank you for contacting us regarding <strong>${service}</strong>.</p>
        <p>We have received your message and will get back to you within 24-48 hours.</p>
        <div style="background:#f5f5f5;padding:15px;margin:20px 0;border-left:4px solid #0066cc;">
          <h4>Your message:</h4>
          <p>${message}</p>
        </div>
        <p>Best regards,<br>Nexa Team</p>
      `
    };

    const adminMailOptions = {
      from: `"Nexa East Hub" <${process.env.EMAIL_USER}>`,
      to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
      subject: `New Contact Form Submission - ${service}`,
      html: `
        <h2>New Contact Form Submission</h2>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Phone:</strong> ${phone || 'Not provided'}</p>
        <p><strong>Service:</strong> ${service}</p>
        <div style="background:#f5f5f5;padding:15px;margin:20px 0;">
          <h4>Message:</h4>
          <p>${message}</p>
        </div>
        <p><strong>Timestamp:</strong> ${new Date().toLocaleString()}</p>
      `
    };

    await Promise.all([transporter.sendMail(userMailOptions), transporter.sendMail(adminMailOptions)]);

    res.json({ success: true, message: 'Thank you for your message. We will get back to you soon!' });
  } catch (error) {
    console.error('Contact form error:', error);
    saveLog({ eventType: 'contact_form_error', details: error.message, user: email });
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// ---------- API LOGGING ROUTE ----------
app.post('/api/log', (req, res) => {
  const { eventType, details, user } = req.body;

  if (!eventType) {
    return res.status(400).json({ success: false, error: 'eventType is required' });
  }

  saveLog({ timestamp: Date.now(), eventType, details: details || '', user: user || 'anonymous' });
  res.json({ success: true, message: 'Log saved' });
});

// ---------- ADMIN ROUTES ----------
app.get('/admin/logs', authenticateAdminRoute, (req, res) => {
  const logsPath = path.join(__dirname, 'logs.json');

  try {
    if (fs.existsSync(logsPath)) {
      const data = fs.readFileSync(logsPath, 'utf-8');
      const logs = JSON.parse(data);
      res.json(logs.sort((a, b) => b.timestamp - a.timestamp));
    } else {
      res.json([]);
    }
  } catch (error) {
    console.error('Error reading logs:', error);
    res.status(500).json({ success: false, error: 'Error reading logs' });
  }
});

app.get('/admin/contacts', authenticateAdminRoute, (req, res) => {
  const contactsPath = path.join(__dirname, 'contacts.json');

  try {
    if (fs.existsSync(contactsPath)) {
      const data = fs.readFileSync(contactsPath, 'utf-8');
      const contacts = JSON.parse(data);
      res.json(contacts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp)));
    } else {
      res.json([]);
    }
  } catch (error) {
    console.error('Error reading contacts:', error);
    res.status(500).json({ success: false, error: 'Error reading contacts' });
  }
});

app.get('/admin/users', authenticateAdminRoute, (req, res) => {
  try {
    const users = readUsers();
    const sanitizedUsers = users.map(user => ({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
      isActive: user.isActive !== false
    }));
    res.json(sanitizedUsers);
  } catch (error) {
    console.error('Error reading users:', error);
    res.status(500).json({ success: false, error: 'Error reading users' });
  }
});

app.delete('/admin/logs', authenticateAdminRoute, (req, res) => {
  const logsPath = path.join(__dirname, 'logs.json');

  try {
    fs.writeFileSync(logsPath, '[]', 'utf-8');
    saveLog({ eventType: 'logs_cleared', details: 'Admin cleared all logs', user: req.admin.email });
    res.json({ success: true, message: 'Logs cleared successfully' });
  } catch (error) {
    console.error('Error clearing logs:', error);
    res.status(500).json({ success: false, error: 'Error clearing logs' });
  }
});

// ---------- USER PROFILE ROUTES ----------
app.get('/api/user/profile', authenticateUser, (req, res) => {
  try {
    const users = readUsers();
    const user = users.find(u => u.email === req.user.email);

    if (!user) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    const profile = {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };

    res.json({ success: true, profile });
  } catch (error) {
    console.error('Error fetching user profile:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

app.put('/api/user/profile', authenticateUser, async (req, res) => {
  const { name, currentPassword, newPassword } = req.body;

  if (!name || name.trim().length < 2) {
    return res.status(400).json({ success: false, error: 'Name must be at least 2 characters' });
  }

  try {
    const users = readUsers();
    const userIndex = users.findIndex(u => u.email === req.user.email);

    if (userIndex === -1) {
      return res.status(404).json({ success: false, error: 'User not found' });
    }

    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ success: false, error: 'Current password is required to change password' });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({ success: false, error: 'New password must be at least 6 characters' });
      }

      const validCurrentPassword = await bcrypt.compare(currentPassword, users[userIndex].password);
      if (!validCurrentPassword) {
        return res.status(400).json({ success: false, error: 'Current password is incorrect' });
      }

      users[userIndex].password = await bcrypt.hash(newPassword, 12);
    }

    users[userIndex].name = name.trim();
    users[userIndex].updatedAt = new Date().toISOString();

    if (saveUsers(users)) {
      saveLog({
        eventType: 'profile_updated',
        details: `Profile updated for ${req.user.email}${newPassword ? ' (password changed)' : ''}`,
        user: req.user.email
      });

      res.json({ success: true, message: 'Profile updated successfully' });
    } else {
      throw new Error('Failed to save user data');
    }
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ success: false, error: 'Internal server error' });
  }
});

// ---------- Socket.IO Connection ----------
io.on('connection', (socket) => {
  console.log('Socket connected:', socket.id);
  
  socket.on('join_admin', (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      if (decoded.role === 'admin') {
        socket.join('admin');
        console.log('Admin joined socket room:', decoded.email);
      }
    } catch (error) {
      console.error('Invalid admin token for socket:', error);
    }
  });
  
  socket.on('disconnect', () => {
    console.log('Socket disconnected:', socket.id);
  });
});

// ---------- Health Check Endpoints ----------
app.get('/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    version: process.env.npm_package_version || '1.0.0'
  });
});

app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    services: {
      database: 'OK',
      email: transporter ? 'OK' : 'Error',
      socket: 'OK'
    }
  });
});

// ---------- Static File Routes ----------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});

app.get('/dashboard', authenticateUser, (req, res) => {
  if (req.user.role === 'admin') {
    res.redirect('/admin');
  } else {
    res.sendFile(path.join(__dirname, 'public', 'user-dashboard.html'));
  }
});

// ---------- Error Handling Middleware ----------
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  
  saveLog({
    eventType: 'server_error',
    details: `${err.message} - ${req.method} ${req.path}`,
    user: req.user?.email || 'anonymous'
  });

  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ success: false, error: 'Invalid JSON in request body' });
  }

  if (err.type === 'entity.too.large') {
    return res.status(413).json({ success: false, error: 'Request entity too large' });
  }

  res.status(500).json({ 
    success: false, 
    error: process.env.NODE_ENV === 'production' ? 'Internal server error' : err.message 
  });
});

// ---------- 404 Handler ----------
app.use('*', (req, res) => {
  saveLog({
    eventType: '404_error',
    details: `404 - ${req.method} ${req.originalUrl}`,
    user: req.user?.email || 'anonymous'
  });

  if (req.originalUrl.startsWith('/api/')) {
    res.status(404).json({ success: false, error: 'API endpoint not found' });
  } else {
    res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
  }
});

// ---------- Graceful Shutdown ----------
function gracefulShutdown(signal) {
  console.log(`\n${signal} received. Starting graceful shutdown...`);
  
  server.close(() => {
    console.log('HTTP server closed.');
    
    // Close Socket.IO server
    io.close(() => {
      console.log('Socket.IO server closed.');
      
      saveLog({
        eventType: 'server_shutdown',
        details: `Server shutdown via ${signal}`,
        user: 'system'
      });
      
      console.log('Graceful shutdown completed.');
      process.exit(0);
    });
  });

  // Force close after 10 seconds
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ---------- Start Server ----------
server.listen(PORT, async () => {
  console.log(`✅ Server running on http://localhost:${PORT}`);
  console.log(`📧 Email service: ${process.env.EMAIL_USER ? 'Configured' : 'Not configured'}`);
  console.log(`🔒 JWT Secret: ${JWT_SECRET !== 'your_fallback_secret' ? 'Custom' : 'Default (Change in production!)'}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  
  // Create/Update admin user on server start
  await createOrUpdateAdmin();
  
  // Log server startup
  saveLog({
    eventType: 'server_startup',
    details: `Server started on port ${PORT}`,
    user: 'system'
  });
  
  console.log('🚀 Server initialization completed!');
});
