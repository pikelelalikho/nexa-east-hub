import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import fs from 'fs';
import path from 'path';
import nodemailer from 'nodemailer';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';

// ES Module dirname fix
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'your_fallback_secret';

// Email transporter configuration
const transporter = nodemailer.createTransporter({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
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

const forgotPasswordLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 6,
    message: { success: false, error: 'Too many password reset attempts, please try again later.' }
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
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

function authenticateAdmin(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ success: false, error: 'Access token required' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, error: 'Invalid or expired token' });
        }
        
        if (user.role !== 'admin') {
            return res.status(403).json({ success: false, error: 'Admin access required' });
        }
        
        req.admin = user;
        next();
    });
}

// ---------- AUTH ROUTES ----------

// Signup Route
router.post('/signup', signupLimiter, async (req, res) => {
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
            saveLog({ 
                eventType: 'signup_failed', 
                details: `Email already exists: ${email}`, 
                user: email 
            });
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
            saveLog({ 
                eventType: 'signup_success', 
                details: `New user registered: ${email}`, 
                user: email 
            });
            
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
        saveLog({ 
            eventType: 'signup_error', 
            details: error.message, 
            user: email 
        });
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// Login Route
router.post('/login', loginLimiter, async (req, res) => {
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
        saveLog({ 
            eventType: 'login_failed', 
            details: `Login attempt with non-existent email: ${email}`, 
            user: email 
        });
        return res.status(401).json({ success: false, error: 'Invalid email or password' });
    }

    if (!user.isActive) {
        saveLog({ 
            eventType: 'login_failed', 
            details: `Login attempt with deactivated account: ${email}`, 
            user: email 
        });
        return res.status(401).json({ success: false, error: 'Account has been deactivated' });
    }

    try {
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            saveLog({ 
                eventType: 'login_failed', 
                details: `Invalid password for ${email}`, 
                user: email 
            });
            return res.status(401).json({ success: false, error: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { 
                email: user.email, 
                role: user.role || 'user', 
                id: user.id,
                name: user.name
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        saveLog({ 
            eventType: 'login_success', 
            details: 'User logged in successfully', 
            user: email 
        });

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
            eventType: 'login_error', 
            details: error.message, 
            user: email 
        });
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// Forgot Password Route
router.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
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
        eventType: 'forgot_password_request', 
        details: `Password reset requested for ${email}`, 
        user: email 
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
    res.json({ 
        success: true, 
        message: 'If the email exists in our system, a reset link has been sent' 
    });
});

// Reset Password Route
router.post('/reset-password', forgotPasswordLimiter, async (req, res) => {
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
                saveLog({ 
                    eventType: 'password_reset_failed', 
                    details: 'Expired reset token', 
                    user: 'unknown' 
                });
                return res.status(400).json({ success: false, error: 'Reset link expired. Please request a new one.' });
            }
            if (error.name === 'JsonWebTokenError') {
                saveLog({ 
                    eventType: 'password_reset_failed', 
                    details: 'Invalid reset token', 
                    user: 'unknown' 
                });
                return res.status(400).json({ success: false, error: 'Invalid reset token' });
            }
            saveLog({ 
                eventType: 'password_reset_failed', 
                details: 'Unknown token error', 
                user: 'unknown' 
            });
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

        saveLog({ 
            eventType: 'password_reset_success', 
            details: `Password reset completed for ${decoded.email}`, 
            user: decoded.email 
        });

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
        saveLog({ 
            eventType: 'password_reset_error', 
            details: err.message, 
            user: 'unknown' 
        });
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// Verify Token Route
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

// Logout Route (client-side token removal, but log the event)
router.post('/logout', authenticateToken, (req, res) => {
    saveLog({ 
        eventType: 'logout', 
        details: 'User logged out', 
        user: req.user.email 
    });
    
    res.json({ 
        success: true, 
        message: 'Logged out successfully' 
    });
});

// Refresh Token Route
router.post('/refresh-token', authenticateToken, (req, res) => {
    try {
        const users = readUsers();
        const user = users.find(u => u.email === req.user.email && u.isActive);

        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found or inactive' });
        }

        const newToken = jwt.sign(
            { 
                email: user.email, 
                role: user.role || 'user', 
                id: user.id,
                name: user.name
            },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        saveLog({ 
            eventType: 'token_refreshed', 
            details: 'User token refreshed', 
            user: user.email 
        });

        res.json({
            success: true,
            token: newToken,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role || 'user'
            }
        });
    } catch (error) {
        console.error('Token refresh error:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// Health Check Route
router.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        service: 'auth-routes',
        email_configured: !!process.env.EMAIL_USER
    });
});

// Export middleware functions and router
export { authenticateToken, authenticateAdmin };
export default router;
