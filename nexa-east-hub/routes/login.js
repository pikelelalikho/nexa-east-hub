import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import fs from 'fs';
import path from 'path';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

// ES Module dirname fix
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'your_fallback_secret_key_change_in_production';

// Email transporter configuration
const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER || 'pikelelalikho@gmail.com',
        pass: process.env.EMAIL_PASS
    }
});

// ---------- Utility Functions ----------
function readUsers() {
    const filePath = path.join(process.cwd(), 'users.json');
    if (!fs.existsSync(filePath)) return [];
    try {
        const data = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
    } catch (err) {
        console.error('Failed to read users.json:', err);
        return [];
    }
}

function saveUsers(users) {
    const filePath = path.join(process.cwd(), 'users.json');
    try {
        fs.writeFileSync(filePath, JSON.stringify(users, null, 2));
        return true;
    } catch (err) {
        console.error('Failed to save users.json:', err);
        return false;
    }
}

function saveLog(entry) {
    const filePath = path.join(process.cwd(), 'logs.json');
    let logs = [];
    
    if (fs.existsSync(filePath)) {
        try {
            const data = fs.readFileSync(filePath, 'utf-8');
            logs = JSON.parse(data);
        } catch (err) {
            console.error('Error reading logs:', err);
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
    } catch (err) {
        console.error('Error saving log:', err);
    }
}

// ---------- Authentication Middleware ----------
function authenticateAdmin(req, res, next) {
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
    } catch (err) {
        console.error('Admin auth token invalid:', err.message);
        return res.status(401).json({ success: false, error: 'Invalid token' });
    }
}

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
    } catch (err) {
        console.error('User auth token invalid:', err.message);
        return res.status(401).json({ success: false, error: 'Invalid token' });
    }
}

// ---------- ROUTES ----------

// Login route (Alternative endpoint)
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({ success: false, error: 'Email and password required' });
        }

        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
            return res.status(400).json({ success: false, error: 'Invalid email format' });
        }

        const users = readUsers();
        const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

        if (!user) {
            saveLog({
                timestamp: Date.now(),
                eventType: 'login_failed',
                user: email,
                details: 'User not found'
            });
            return res.status(401).json({ success: false, error: 'Invalid email or password' });
        }

        if (!user.isActive) {
            saveLog({
                timestamp: Date.now(),
                eventType: 'login_failed',
                user: email,
                details: 'Account deactivated'
            });
            return res.status(401).json({ success: false, error: 'Account has been deactivated' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            saveLog({
                timestamp: Date.now(),
                eventType: 'login_failed',
                user: email,
                details: 'Invalid password'
            });
            return res.status(401).json({ success: false, error: 'Invalid email or password' });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email, 
                role: user.role || 'user',
                name: user.name
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        saveLog({
            timestamp: Date.now(),
            eventType: 'login_success',
            user: email,
            details: 'User logged in successfully via route'
        });

        // Send login notification email (optional)
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
            console.error('Failed to send login notification:', emailError);
        }

        res.json({ 
            success: true, 
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role || 'user'
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        saveLog({
            timestamp: Date.now(),
            eventType: 'login_error',
            user: req.body.email || 'unknown',
            details: error.message,
        });
        res.status(500).json({ success: false, error: 'An error occurred during login.' });
    }
});

// Reset password route
router.post('/reset-password', async (req, res) => {
    const { password, token } = req.body;

    if (!password || !token) {
        return res.status(400).json({ success: false, error: 'Password and token are required.' });
    }

    if (password.length < 6) {
        return res.status(400).json({ success: false, error: 'Password must be at least 6 characters.' });
    }

    let decoded;
    try {
        decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
        saveLog({
            timestamp: Date.now(),
            eventType: 'password_reset_failed',
            user: 'unknown',
            details: `Token verification failed: ${err.message}`,
        });
        
        if (err.name === 'TokenExpiredError') {
            return res.status(400).json({ success: false, error: 'Reset link has expired. Please request a new one.' });
        }
        return res.status(400).json({ success: false, error: 'Invalid or expired token.' });
    }

    const users = readUsers();
    const userIndex = users.findIndex(u => u.email.toLowerCase() === decoded.email.toLowerCase());
    
    if (userIndex === -1) {
        return res.status(404).json({ success: false, error: 'User not found.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 12);
        users[userIndex].password = hashedPassword;
        users[userIndex].updatedAt = new Date().toISOString();
        
        if (!saveUsers(users)) {
            throw new Error('Failed to save user data');
        }

        saveLog({ 
            timestamp: Date.now(), 
            eventType: 'password_reset_success', 
            user: decoded.email,
            details: 'Password reset completed via route'
        });

        // Send confirmation email
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
            console.error('Failed to send password reset confirmation:', emailError);
        }

        res.json({ success: true, message: 'Password updated successfully.' });
    } catch (err) {
        console.error('Error updating password:', err);
        saveLog({
            timestamp: Date.now(),
            eventType: 'password_reset_error',
            user: decoded.email,
            details: err.message
        });
        res.status(500).json({ success: false, error: 'Server error updating password.' });
    }
});

// Forgot password route
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, error: 'Email is required' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ success: false, error: 'Please enter a valid email address' });
    }

    const users = readUsers();
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());

    saveLog({ 
        timestamp: Date.now(),
        eventType: 'forgot_password_request', 
        user: email,
        details: 'Password reset requested via route'
    });

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

// Admin logs retrieval route
router.get('/admin/logs', authenticateAdmin, (req, res) => {
    try {
        const filePath = path.join(process.cwd(), 'logs.json');
        const logs = fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf-8')) : [];
        
        // Sort logs by timestamp (newest first)
        const sortedLogs = logs.sort((a, b) => b.timestamp - a.timestamp);
        
        res.json(sortedLogs);
    } catch (error) {
        console.error('Error reading logs:', error);
        res.status(500).json({ success: false, error: 'Error reading logs' });
    }
});

// Admin users retrieval route
router.get('/admin/users', authenticateAdmin, (req, res) => {
    try {
        const users = readUsers();
        const sanitizedUsers = users.map(user => ({
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role || 'user',
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

// Admin contacts retrieval route
router.get('/admin/contacts', authenticateAdmin, (req, res) => {
    try {
        const filePath = path.join(process.cwd(), 'contacts.json');
        const contacts = fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf-8')) : [];
        
        // Sort contacts by timestamp (newest first)
        const sortedContacts = contacts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        
        res.json(sortedContacts);
    } catch (error) {
        console.error('Error reading contacts:', error);
        res.status(500).json({ success: false, error: 'Error reading contacts' });
    }
});

// User profile route
router.get('/profile', authenticateUser, (req, res) => {
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
            role: user.role || 'user',
            createdAt: user.createdAt,
            updatedAt: user.updatedAt
        };

        res.json({ success: true, profile });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// Update user profile route
router.put('/profile', authenticateUser, async (req, res) => {
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

        // Handle password change
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

        // Update user data
        users[userIndex].name = name.trim();
        users[userIndex].updatedAt = new Date().toISOString();

        if (saveUsers(users)) {
            saveLog({
                timestamp: Date.now(),
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

// Verify token route
router.post('/verify-token', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ success: false, error: 'Token is required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ success: true, user: decoded });
    } catch (error) {
        res.status(401).json({ success: false, error: 'Invalid or expired token' });
    }
});

// Health check route
router.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        service: 'login-routes'
    });
});

export default router;
