// ---------- Dependencies ----------
import 'dotenv/config';
import express from 'express';
import fs from 'fs';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Server } from 'socket.io';
import http from 'http';
import nodemailer from 'nodemailer';
import path from 'path';
import { fileURLToPath } from 'url';

// Import routes
import apiRoutes from './routes/login.js';
import authRoutes from './routes/auth.js';
import adminRoutes from './routes/admin.js';
import { authenticateToken } from './middleware/authMiddleware.js';
import { dbEnabled, dbAvailable, User, Contact, syncDatabase, markDatabaseUnavailable } from './utils/db.js';

// ES Module dirname fix
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const isProduction = process.env.NODE_ENV === 'production';
const PORT = Number(process.env.PORT) || 3000;
const allowedOrigins = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim()).filter(Boolean)
    : [];
const emailEnabled = Boolean(process.env.EMAIL_USER && process.env.EMAIL_PASS);
const emailFrom = `"${process.env.EMAIL_FROM_NAME}" <${process.env.EMAIL_FROM_EMAIL}>`;

function validateEnvironment() {
    const errors = [];
    const warnings = [];

    if (isProduction) {
        if (!process.env.JWT_SECRET) {
            errors.push('JWT_SECRET is required in production.');
        } else if (process.env.JWT_SECRET.length < 32) {
            errors.push('JWT_SECRET must be at least 32 characters in production.');
        }

        if (allowedOrigins.length === 0) {
            errors.push('ALLOWED_ORIGINS must include your production origin, for example https://nexaeasthub.co.za.');
        }

        if (!allowedOrigins.includes('https://nexaeasthub.co.za')) {
            warnings.push('ALLOWED_ORIGINS should include https://nexaeasthub.co.za in production.');
        }
    }

    if (!dbEnabled) {
        warnings.push('PostgreSQL is not configured. User and contact storage will fall back to JSON files.');
    }

    if (!emailEnabled) {
        warnings.push('EMAIL_USER and EMAIL_PASS are not both set. Email delivery will be skipped.');
    }

    if (emailEnabled && (!process.env.EMAIL_FROM_NAME || !process.env.EMAIL_FROM_EMAIL)) {
        warnings.push('EMAIL_FROM_NAME and EMAIL_FROM_EMAIL should be set so Brevo sends from the public NEXA East Hub address.');
    }

    if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
        warnings.push('ADMIN_EMAIL and ADMIN_PASSWORD are not both set. Startup admin reset will be skipped.');
    }

    warnings.forEach(message => console.warn(`Config warning: ${message}`));

    if (errors.length > 0) {
        console.error('Invalid production configuration:');
        errors.forEach(message => console.error(`- ${message}`));
        process.exit(1);
    }
}

validateEnvironment();

const app = express();

app.set('trust proxy', isProduction ? 1 : false);

const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: isProduction ? allowedOrigins : ["http://localhost:3000", "http://127.0.0.1:3000"],
        methods: ["GET", "POST"]
    }
});

// ---------- JWT Secret ----------
const JWT_SECRET = process.env.JWT_SECRET || 'development-only-jwt-secret-change-me';

// ---------- Email Transporter ----------
function getEmailTransportConfig() {
    const auth = {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    };

    if (process.env.EMAIL_HOST) {
        const port = Number(process.env.EMAIL_PORT) || 587;
        return {
            host: process.env.EMAIL_HOST,
            port,
            secure: process.env.EMAIL_SECURE === 'true' || port === 465,
            auth
        };
    }

    return {
        service: process.env.EMAIL_SERVICE || 'gmail',
        auth
    };
}

const transporter = emailEnabled
    ? nodemailer.createTransport(getEmailTransportConfig())
    : null;

async function sendEmail(mailOptions) {
    if (!transporter) {
        console.warn(`Email skipped because SMTP is not configured: ${mailOptions.subject}`);
        return false;
    }

    await transporter.sendMail({
        ...mailOptions,
        from: emailFrom
    });
    return true;
}

// ---------- Global Error Handlers ----------
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

// ---------- Rate Limiters (Define before middleware) ----------
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

// ---------- Middleware ----------
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cors({
    origin: isProduction ? allowedOrigins : true,
    credentials: true
}));
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
            fontSrc: ["'self'", "data:", "https://cdnjs.cloudflare.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://cdn.socket.io", "https://static.cloudflareinsights.com"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "ws:", "wss:", "https://static.cloudflareinsights.com", "https://cloudflareinsights.com"]
        }
    }
}));

// Serve static files without default index handling so root can use web.html
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// Apply rate limiting to specific routes
app.use('/api/auth/login', loginLimiter);
app.use('/login', loginLimiter);
app.use('/api/auth/signup', signupLimiter);
app.use('/signup', signupLimiter);
app.use('/contact', contactLimiter);
app.use('/api/forgot-password', forgotPasswordLimiter);
app.use('/api/reset-password', forgotPasswordLimiter);

// ---------- Utility Functions ----------
async function readUsers() {
    if (dbAvailable) {
        try {
            const dbUsers = await User.findAll({ raw: true });
            return dbUsers.map(user => ({ ...user, email: user.email.toLowerCase() }));
        } catch (error) {
            markDatabaseUnavailable(error);
        }
    }

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

async function findUserByEmail(email) {
    const normalizedEmail = email.toLowerCase();
    if (dbAvailable) {
        try {
            return await User.findOne({ where: { email: normalizedEmail } });
        } catch (error) {
            markDatabaseUnavailable(error);
        }
    }
    const users = await readUsers();
    return users.find(user => user.email.toLowerCase() === normalizedEmail);
}

async function createUser(userData) {
    if (dbAvailable) {
        try {
            return await User.create({ ...userData, email: userData.email.toLowerCase() });
        } catch (error) {
            markDatabaseUnavailable(error);
        }
    }
    const users = await readUsers();
    users.push(userData);
    saveUsers(users);
    return userData;
}

async function updateUser(email, updates) {
    const normalizedEmail = email.toLowerCase();
    if (dbAvailable) {
        try {
            const user = await User.findOne({ where: { email: normalizedEmail } });
            if (!user) return null;
            return await user.update(updates);
        } catch (error) {
            markDatabaseUnavailable(error);
        }
    }
    const users = await readUsers();
    const index = users.findIndex(u => u.email.toLowerCase() === normalizedEmail);
    if (index === -1) return null;
    users[index] = { ...users[index], ...updates, updatedAt: new Date().toISOString() };
    saveUsers(users);
    return users[index];
}

async function listUsers() {
    if (dbAvailable) {
        try {
            return await User.findAll({ raw: true });
        } catch (error) {
            markDatabaseUnavailable(error);
        }
    }
    return await readUsers();
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

function readJsonFile(filename, fallback = []) {
    const filePath = path.join(__dirname, filename);
    if (!fs.existsSync(filePath)) return fallback;

    try {
        const content = fs.readFileSync(filePath, 'utf-8').trim();
        if (!content) return fallback;
        return JSON.parse(content);
    } catch (error) {
        console.error(`Error reading ${filename}:`, error);
        return fallback;
    }
}

function writeJsonFile(filename, data) {
    const filePath = path.join(__dirname, filename);
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function sanitizeUser(user) {
    if (!user) return null;
    return {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role || 'user',
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        isActive: user.isActive !== false
    };
}

function getUserKey(user) {
    return String(user.id || user.email).toLowerCase();
}

function itemBelongsToUser(item, user) {
    const userKey = getUserKey(user);
    return [item.userId, item.userEmail, item.email]
        .filter(Boolean)
        .map(value => String(value).toLowerCase())
        .includes(userKey) || String(item.userEmail || '').toLowerCase() === String(user.email || '').toLowerCase();
}

function countByStatus(items, status) {
    return items.filter(item => String(item.status || '').toLowerCase() === status).length;
}

const ORDER_STATUSES = ['pending', 'in-progress', 'ready', 'ready-for-download', 'delivered', 'completed', 'cancelled'];

function isActiveOrder(order) {
    return ['pending', 'in-progress', 'ready', 'ready-for-download', 'awaiting-payment'].includes(String(order.status || 'pending').toLowerCase());
}

async function findUserByIdentifier(identifier) {
    const users = await listUsers();
    return users.find(item => String(item.id) === String(identifier) || String(item.email).toLowerCase() === String(identifier).toLowerCase());
}

function getLastActivityForUser(logs, user) {
    const email = String(user.email || '').toLowerCase();
    const userLogs = logs.filter(log => String(log.user || '').toLowerCase() === email);
    if (!userLogs.length) return user.updatedAt || user.createdAt || null;
    return new Date(Math.max(...userLogs.map(log => Number(log.timestamp || 0)))).toISOString();
}

async function buildOperationsSnapshot(user = null) {
    const users = await listUsers();
    const contacts = readJsonFile('contacts.json');
    const orders = readJsonFile('orders.json');
    const uploads = readJsonFile('uploads.json');
    const deliveries = readJsonFile('deliveries.json');
    const messages = readJsonFile('messages.json');
    const feedback = readJsonFile('feedback.json');
    const notes = readJsonFile('admin-notes.json');
    const logs = readJsonFile('logs.json');

    const scope = items => user ? items.filter(item => itemBelongsToUser(item, user)) : items;
    const scopedOrders = scope(orders);
    const scopedContacts = scope(contacts);
    const scopedUploads = scope(uploads);
    const scopedDeliveries = scope(deliveries);
    const scopedMessages = scope(messages);
    const scopedFeedback = scope(feedback);
    const scopedNotes = scope(notes);

    const oneWeekAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const weeklyActivity = logs.filter(log => Number(log.timestamp || new Date(log.createdAt || log.submittedAt || 0).getTime()) >= oneWeekAgo).length;

    return {
        metrics: {
            totalUsers: users.length,
            activeOrders: orders.filter(isActiveOrder).length,
            pendingOrders: countByStatus(orders, 'pending') + countByStatus(orders, 'in-progress') + countByStatus(orders, 'ready') + countByStatus(orders, 'ready-for-download'),
            completedOrders: countByStatus(orders, 'completed'),
            pendingDeliveries: deliveries.filter(item => String(item.status || 'available').toLowerCase() !== 'delivered').length,
            completedDeliveries: countByStatus(deliveries, 'delivered') + countByStatus(deliveries, 'completed'),
            serviceRequests: contacts.length,
            uploads: uploads.length,
            feedbackCount: feedback.length,
            failedLogins: logs.filter(log => log.eventType === 'login_failed').length,
            successfulLogins: logs.filter(log => log.eventType === 'login_success').length,
            weeklyActivity,
            userPendingOrders: scopedOrders.filter(isActiveOrder).length,
            userCompletedOrders: countByStatus(scopedOrders, 'completed')
        },
        users: users.map(item => ({
            ...sanitizeUser(item),
            ordersCount: orders.filter(order => itemBelongsToUser(order, item)).length,
            lastActivity: getLastActivityForUser(logs, item)
        })),
        requests: scopedContacts,
        orders: scopedOrders,
        uploads: scopedUploads,
        downloads: scopedDeliveries,
        deliveries: scopedDeliveries,
        messages: scopedMessages,
        feedback: scopedFeedback,
        notes: scopedNotes,
        logs
    };
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
    const adminEmail = process.env.ADMIN_EMAIL;
    const adminPassword = process.env.ADMIN_PASSWORD;
    const adminName = process.env.ADMIN_NAME || 'Nexa Admin';

    if (!adminEmail || !adminPassword) {
        console.warn('Admin reset skipped: ADMIN_EMAIL and ADMIN_PASSWORD are required to create or update the admin user.');
        return;
    }

    try {
        console.log('🔄 Creating/Updating admin user...');
        const hashedPassword = await bcrypt.hash(adminPassword, 12);

        if (dbAvailable) {
            const [admin, created] = await User.findOrCreate({
                where: { email: adminEmail.toLowerCase() },
                defaults: {
                    name: adminName,
                    password: hashedPassword,
                    role: 'admin',
                    isActive: true
                }
            });

            if (!created) {
                await admin.update({
                    name: adminName,
                    password: hashedPassword,
                    role: 'admin',
                    isActive: true
                });
                console.log('✅ Admin user updated successfully');
            } else {
                console.log('✅ New admin user created successfully');
            }
        } else {
            let users = await readUsers();
            const adminIndex = users.findIndex(u => u.email === adminEmail.toLowerCase() || u.role === 'admin');

            if (adminIndex !== -1) {
                users[adminIndex] = {
                    ...users[adminIndex],
                    password: hashedPassword,
                    role: 'admin',
                    email: adminEmail.toLowerCase(),
                    name: adminName,
                    updatedAt: new Date().toISOString(),
                    isActive: true
                };
                console.log('✅ Admin user updated successfully');
            } else {
                const newAdmin = {
                    id: Date.now(),
                    name: adminName,
                    email: adminEmail.toLowerCase(),
                    password: hashedPassword,
                    role: 'admin',
                    createdAt: new Date().toISOString(),
                    isActive: true
                };
                users.push(newAdmin);
                console.log('✅ New admin user created successfully');
            }

            saveUsers(users);
        }

        saveLog({
            eventType: 'admin_reset',
            details: 'Admin password reset on server startup',
            user: 'system'
        });

        console.log(`🔐 Admin user ready: ${adminEmail}`);
    } catch (error) {
        console.error('❌ Error creating/updating admin:', error);
    }
}

// ---------- Routes ----------
app.use('/api', apiRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/admin', authenticateAdminRoute, adminRoutes);

// ---------- Signup Route ----------
app.post('/signup', signupLimiter, async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
        saveLog({
            eventType: 'signup_failed',
            details: 'Missing required fields',
            user: email || 'unknown'
        });
        return res.status(400).json({ success: false, error: 'All fields are required' });
    }

    if (name.trim().length < 2) {
        saveLog({
            eventType: 'signup_failed',
            details: 'Name too short',
            user: email
        });
        return res.status(400).json({ success: false, error: 'Name must be at least 2 characters' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        saveLog({
            eventType: 'signup_failed',
            details: 'Invalid email format',
            user: email
        });
        return res.status(400).json({ success: false, error: 'Please enter a valid email address' });
    }

    if (password.length < 6) {
        saveLog({
            eventType: 'signup_failed',
            details: 'Password too short',
            user: email
        });
        return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }

    const existingUser = await findUserByEmail(email);

    if (existingUser) {
        saveLog({
            eventType: 'signup_failed',
            details: 'Email already exists',
            user: email
        });
        return res.status(409).json({ success: false, error: 'Email already registered' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 12);
        const newUser = {
            name: name.trim(),
            email: email.toLowerCase(),
            password: hashedPassword,
            role: 'user',
            isActive: true
        };

        await createUser({
            ...newUser,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        });

        saveLog({
            eventType: 'signup_success',
            details: `New user registered: ${name}`,
            user: email
        });

        try {
            const mailOptions = {
                from: emailFrom,
                to: email,
                subject: 'Welcome to Nexa East Hub!',
                html: `
                    <h2>Welcome to Nexa East Hub!</h2>
                    <p>Hello ${name},</p>
                    <p>Your account has been created successfully.</p>
                    <p>You can now log in and explore our services.</p>
                    <br>
                    <p>Best regards,<br>Nexa Team</p>
                `
            };

            await sendEmail(mailOptions);
        } catch (emailError) {
            console.error('Failed to send welcome email:', emailError);
        }

        res.json({ success: true, message: 'User registered successfully' });
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

// ---------- Login Route ----------
app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ success: false, error: 'Email and password are required' });
    }

    const user = await findUserByEmail(email);

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
                id: user.id
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
                from: emailFrom,
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

            await sendEmail(mailOptions);

            res.json({
                success: true,
                message: 'Login successful',
                name: user.name,
                role: user.role || 'user',
                token
            });
        } catch (emailError) {
            console.error('Failed to send login email:', emailError);
            // Still return success even if email fails
            res.json({
                success: true,
                message: 'Login successful, but email notification failed',
                name: user.name,
                role: user.role || 'user',
                token
            });
        }
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

// ---------- Forgot Password Route ----------
app.post('/api/forgot-password', forgotPasswordLimiter, async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, error: 'Email is required' });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({ success: false, error: 'Please enter a valid email address' });
    }

    const user = await findUserByEmail(email);

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
                from: emailFrom,
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

            await sendEmail(mailOptions);
        } catch (emailError) {
            console.error('Failed to send reset email:', emailError);
        }
    }

    // Always return success for security (don't reveal if email exists)
    res.json({
        success: true,
        message: 'If the email exists in our system, a reset link has been sent'
    });
});

// ---------- Reset Password Route ----------
app.post('/api/reset-password', forgotPasswordLimiter, async (req, res) => {
    const { token, password } = req.body;

    if (!token || !password) {
        return res.status(400).json({ success: false, error: 'Token and password are required' });
    }

    if (password.length < 6) {
        return res.status(400).json({ success: false, error: 'Password must be at least 6 characters long' });
    }

    try {
        // 🔍 Safe token verification
        let decoded;
        try {
            decoded = jwt.verify(token, JWT_SECRET);
        } catch (error) {
            console.error('❌ Token verification failed:', error.name, error.message);

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

        const user = await findUserByEmail(decoded.email);

        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const hashedPassword = await bcrypt.hash(password, 12);
        await updateUser(decoded.email, {
            password: hashedPassword,
            updatedAt: new Date().toISOString()
        });

        saveLog({
            eventType: 'password_reset_success',
            details: `Password reset completed for ${decoded.email}`,
            user: decoded.email
        });

        // ✅ Optional email notification
        try {
            const mailOptions = {
                from: emailFrom,
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
            await sendEmail(mailOptions);
        } catch (emailError) {
            console.error('Failed to send confirmation email:', emailError);
        }

        return res.json({ success: true, message: 'Password reset successfully' });

    } catch (err) {
        console.error('🚨 Unexpected error in reset:', err);
        saveLog({ eventType: 'password_reset_error', details: err.message, user: 'unknown' });
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});


// ---------- Contact Form Route ----------
app.post('/contact', contactLimiter, async (req, res) => {
    const { name, email, phone, service, message } = req.body;

    // Validation
    if (!name || !email || !service || !message) {
        saveLog({
            eventType: 'contact_form_failed',
            details: 'Missing required fields',
            user: email || 'unknown'
        });
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
        // Save contact message to file
        const contactEntry = {
            name: name.trim(),
            email: email.toLowerCase(),
            phone: phone?.trim() || null,
            service,
            message: message.trim(),
            status: 'new'
        };

        if (dbAvailable) {
            try {
                await Contact.create(contactEntry);
            } catch (error) {
                markDatabaseUnavailable(error);
            }
        }

        if (!dbAvailable) {
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

            contacts.push({
                id: Date.now(),
                ...contactEntry,
                timestamp: new Date().toISOString()
            });
            fs.writeFileSync(contactsPath, JSON.stringify(contacts, null, 2));
        }

        saveLog({
            eventType: 'contact_message',
            details: `Contact form submission from ${name} (${email}) for ${service}`,
            user: email
        });

        // Send confirmation email to user
        const userMailOptions = {
            from: emailFrom,
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

        // Send notification email to admin
        const adminMailOptions = {
            from: emailFrom,
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

        // Send both emails
        await Promise.all([
            sendEmail(userMailOptions),
            sendEmail(adminMailOptions)
        ]);

        res.json({
            success: true,
            message: 'Thank you for your message. We will get back to you soon!'
        });
    } catch (error) {
        console.error('Contact form error:', error);
        saveLog({
            eventType: 'contact_form_error',
            details: error.message,
            user: email
        });
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// ---------- API Routes ----------
app.post('/api/log', (req, res) => {
    const { eventType, details, user } = req.body;

    if (!eventType) {
        return res.status(400).json({ success: false, error: 'eventType is required' });
    }

    const log = {
        timestamp: Date.now(),
        eventType,
        details: details || '',
        user: user || 'anonymous'
    };

    saveLog(log);
    res.json({ success: true, message: 'Log saved' });
});

// ---------- Admin Routes ----------
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

app.get('/admin/users', authenticateAdminRoute, async (req, res) => {
    try {
        const users = await listUsers();
        const sanitizedUsers = users.map(sanitizeUser);
        res.json(sanitizedUsers);
    } catch (error) {
        console.error('Error reading users:', error);
        res.status(500).json({ success: false, error: 'Error reading users' });
    }
});

app.get('/admin/operations-metrics', authenticateAdminRoute, async (req, res) => {
    try {
        const snapshot = await buildOperationsSnapshot();
        res.json({ success: true, ...snapshot });
    } catch (error) {
        console.error('Error loading operations metrics:', error);
        res.status(500).json({ success: false, error: 'Error loading operations metrics' });
    }
});

app.get('/admin/users/:id', authenticateAdminRoute, async (req, res) => {
    try {
        const users = await listUsers();
        const user = users.find(item => String(item.id) === String(req.params.id) || String(item.email).toLowerCase() === String(req.params.id).toLowerCase());

        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const snapshot = await buildOperationsSnapshot(user);
        res.json({ success: true, user: sanitizeUser(user), ...snapshot });
    } catch (error) {
        console.error('Error loading admin user view:', error);
        res.status(500).json({ success: false, error: 'Error loading user details' });
    }
});

app.put('/admin/orders/:id/status', authenticateAdminRoute, (req, res) => {
    const { status, paymentStatus } = req.body;
    const allowedStatuses = ORDER_STATUSES;

    if (status && !allowedStatuses.includes(status)) {
        return res.status(400).json({ success: false, error: 'Invalid order status' });
    }

    const orders = readJsonFile('orders.json');
    const orderIndex = orders.findIndex(order => String(order.id) === String(req.params.id));

    if (orderIndex === -1) {
        return res.status(404).json({ success: false, error: 'Order not found' });
    }

    orders[orderIndex] = {
        ...orders[orderIndex],
        status: status || orders[orderIndex].status,
        paymentStatus: paymentStatus || orders[orderIndex].paymentStatus || 'pending',
        updatedAt: new Date().toISOString(),
        updatedBy: req.admin.email
    };
    writeJsonFile('orders.json', orders);

    const messages = readJsonFile('messages.json');
    messages.push({
        id: Date.now(),
        userEmail: orders[orderIndex].userEmail || orders[orderIndex].email,
        orderId: orders[orderIndex].id,
        message: `Your order status is now ${orders[orderIndex].status}.`,
        type: 'status-update',
        createdAt: new Date().toISOString(),
        createdBy: req.admin.email,
        read: false
    });
    writeJsonFile('messages.json', messages);

    saveLog({
        eventType: 'order_status_updated',
        details: `Order ${req.params.id} updated to ${orders[orderIndex].status}`,
        user: req.admin.email
    });

    res.json({ success: true, order: orders[orderIndex] });
});

app.post('/admin/users/:id/messages', authenticateAdminRoute, async (req, res) => {
    const { message, orderId } = req.body;
    if (!message || message.trim().length < 3) {
        return res.status(400).json({ success: false, error: 'Message is required' });
    }

    const users = await listUsers();
    const user = users.find(item => String(item.id) === String(req.params.id) || String(item.email).toLowerCase() === String(req.params.id).toLowerCase());
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const messages = readJsonFile('messages.json');
    const entry = {
        id: Date.now(),
        userId: user.id,
        userEmail: user.email,
        orderId: orderId || null,
        message: message.trim(),
        type: 'admin-message',
        createdAt: new Date().toISOString(),
        createdBy: req.admin.email,
        read: false
    };
    messages.push(entry);
    writeJsonFile('messages.json', messages);

    res.json({ success: true, message: entry });
});

app.post('/admin/users/:id/notes', authenticateAdminRoute, async (req, res) => {
    const { note, orderId } = req.body;
    if (!note || note.trim().length < 3) {
        return res.status(400).json({ success: false, error: 'Note is required' });
    }

    const users = await listUsers();
    const user = users.find(item => String(item.id) === String(req.params.id) || String(item.email).toLowerCase() === String(req.params.id).toLowerCase());
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const notes = readJsonFile('admin-notes.json');
    const entry = {
        id: Date.now(),
        userId: user.id,
        userEmail: user.email,
        orderId: orderId || null,
        note: note.trim(),
        createdAt: new Date().toISOString(),
        createdBy: req.admin.email
    };
    notes.push(entry);
    writeJsonFile('admin-notes.json', notes);

    res.json({ success: true, note: entry });
});

app.post('/admin/users/:id/deliveries', authenticateAdminRoute, async (req, res) => {
    const { fileName, fileUrl, orderId, type, status } = req.body;
    if (!fileName || !fileUrl) {
        return res.status(400).json({ success: false, error: 'fileName and fileUrl are required' });
    }

    const user = await findUserByIdentifier(req.params.id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const deliveries = readJsonFile('deliveries.json');
    const entry = {
        id: Date.now(),
        userId: user.id,
        userEmail: user.email,
        orderId: orderId || null,
        fileName,
        fileUrl,
        type: type || 'other',
        status: status || 'available',
        createdAt: new Date().toISOString(),
        createdBy: req.admin.email
    };
    deliveries.push(entry);
    writeJsonFile('deliveries.json', deliveries);

    res.json({ success: true, delivery: entry });
});

app.get('/api/admin/users', authenticateAdminRoute, async (req, res) => {
    try {
        const snapshot = await buildOperationsSnapshot();
        res.json({ success: true, users: snapshot.users });
    } catch (error) {
        console.error('Error loading admin users:', error);
        res.status(500).json({ success: false, error: 'Error loading users' });
    }
});

app.get('/api/admin/users/:id', authenticateAdminRoute, async (req, res) => {
    try {
        const user = await findUserByIdentifier(req.params.id);
        if (!user) return res.status(404).json({ success: false, error: 'User not found' });
        res.json({ success: true, user: sanitizeUser(user) });
    } catch (error) {
        console.error('Error loading admin user:', error);
        res.status(500).json({ success: false, error: 'Error loading user' });
    }
});

app.get('/api/admin/users/:id/workspace', authenticateAdminRoute, async (req, res) => {
    try {
        const user = await findUserByIdentifier(req.params.id);
        if (!user) return res.status(404).json({ success: false, error: 'User not found' });
        const snapshot = await buildOperationsSnapshot(user);
        res.json({ success: true, user: sanitizeUser(user), ...snapshot });
    } catch (error) {
        console.error('Error loading admin user workspace:', error);
        res.status(500).json({ success: false, error: 'Error loading user workspace' });
    }
});

app.get('/api/admin/operations', authenticateAdminRoute, async (req, res) => {
    try {
        const snapshot = await buildOperationsSnapshot();
        res.json({ success: true, ...snapshot });
    } catch (error) {
        console.error('Error loading admin operations:', error);
        res.status(500).json({ success: false, error: 'Error loading admin operations' });
    }
});

app.post('/api/admin/users/:id/orders', authenticateAdminRoute, async (req, res) => {
    const { title, service, description, status, paymentStatus } = req.body;
    if (!title || title.trim().length < 3) {
        return res.status(400).json({ success: false, error: 'Order title is required' });
    }

    const normalizedStatus = status || 'pending';
    if (!ORDER_STATUSES.includes(normalizedStatus)) {
        return res.status(400).json({ success: false, error: 'Invalid order status' });
    }

    const user = await findUserByIdentifier(req.params.id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const orders = readJsonFile('orders.json');
    const entry = {
        id: Date.now(),
        userId: user.id,
        userEmail: user.email,
        title: title.trim(),
        service: service || 'General Service',
        description: description?.trim() || '',
        status: normalizedStatus,
        paymentStatus: paymentStatus || 'pending',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        createdBy: req.admin.email
    };
    orders.push(entry);
    writeJsonFile('orders.json', orders);

    const messages = readJsonFile('messages.json');
    messages.push({
        id: Date.now() + 1,
        userId: user.id,
        userEmail: user.email,
        orderId: entry.id,
        message: `A new order has been created: ${entry.title}.`,
        type: 'order-created',
        createdAt: new Date().toISOString(),
        createdBy: req.admin.email,
        read: false
    });
    writeJsonFile('messages.json', messages);

    saveLog({
        eventType: 'admin_order_created',
        details: `Order ${entry.id} created for ${user.email}`,
        user: req.admin.email
    });

    res.json({ success: true, order: entry });
});

app.patch('/api/admin/orders/:orderId/status', authenticateAdminRoute, (req, res) => {
    const { status, paymentStatus } = req.body;
    if (status && !ORDER_STATUSES.includes(status)) {
        return res.status(400).json({ success: false, error: 'Invalid order status' });
    }

    const orders = readJsonFile('orders.json');
    const orderIndex = orders.findIndex(order => String(order.id) === String(req.params.orderId));
    if (orderIndex === -1) return res.status(404).json({ success: false, error: 'Order not found' });

    orders[orderIndex] = {
        ...orders[orderIndex],
        status: status || orders[orderIndex].status,
        paymentStatus: paymentStatus || orders[orderIndex].paymentStatus || 'pending',
        updatedAt: new Date().toISOString(),
        updatedBy: req.admin.email
    };
    writeJsonFile('orders.json', orders);

    const messages = readJsonFile('messages.json');
    messages.push({
        id: Date.now(),
        userId: orders[orderIndex].userId,
        userEmail: orders[orderIndex].userEmail || orders[orderIndex].email,
        orderId: orders[orderIndex].id,
        message: `Your order "${orders[orderIndex].title || orders[orderIndex].service || orders[orderIndex].id}" is now ${orders[orderIndex].status}.`,
        type: 'status-update',
        createdAt: new Date().toISOString(),
        createdBy: req.admin.email,
        read: false
    });
    writeJsonFile('messages.json', messages);

    res.json({ success: true, order: orders[orderIndex] });
});

app.post('/api/admin/users/:id/deliveries', authenticateAdminRoute, async (req, res) => {
    const { fileName, fileUrl, orderId, type, status } = req.body;
    if (!fileName || !fileUrl) {
        return res.status(400).json({ success: false, error: 'fileName and fileUrl are required' });
    }

    const user = await findUserByIdentifier(req.params.id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const deliveries = readJsonFile('deliveries.json');
    const entry = {
        id: Date.now(),
        userId: user.id,
        userEmail: user.email,
        orderId: orderId || null,
        fileName,
        fileUrl,
        type: type || 'other',
        status: status || 'available',
        createdAt: new Date().toISOString(),
        createdBy: req.admin.email
    };
    deliveries.push(entry);
    writeJsonFile('deliveries.json', deliveries);

    res.json({ success: true, delivery: entry });
});

app.post('/api/admin/users/:id/messages', authenticateAdminRoute, async (req, res) => {
    const { message, orderId } = req.body;
    if (!message || message.trim().length < 3) {
        return res.status(400).json({ success: false, error: 'Message is required' });
    }

    const user = await findUserByIdentifier(req.params.id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const messages = readJsonFile('messages.json');
    const entry = {
        id: Date.now(),
        userId: user.id,
        userEmail: user.email,
        orderId: orderId || null,
        message: message.trim(),
        type: 'admin-message',
        createdAt: new Date().toISOString(),
        createdBy: req.admin.email,
        read: false
    };
    messages.push(entry);
    writeJsonFile('messages.json', messages);

    res.json({ success: true, message: entry });
});

app.post('/api/admin/users/:id/notes', authenticateAdminRoute, async (req, res) => {
    const { note, orderId } = req.body;
    if (!note || note.trim().length < 3) {
        return res.status(400).json({ success: false, error: 'Note is required' });
    }

    const user = await findUserByIdentifier(req.params.id);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const notes = readJsonFile('admin-notes.json');
    const entry = {
        id: Date.now(),
        userId: user.id,
        userEmail: user.email,
        orderId: orderId || null,
        note: note.trim(),
        createdAt: new Date().toISOString(),
        createdBy: req.admin.email
    };
    notes.push(entry);
    writeJsonFile('admin-notes.json', notes);

    res.json({ success: true, note: entry });
});

app.delete('/admin/logs', authenticateAdminRoute, (req, res) => {
    const logsPath = path.join(__dirname, 'logs.json');

    try {
        fs.writeFileSync(logsPath, '[]', 'utf-8');
        saveLog({
            eventType: 'logs_cleared',
            details: 'Admin cleared all logs',
            user: req.admin.email
        });
        res.json({ success: true, message: 'Logs cleared successfully' });
    } catch (error) {
        console.error('Error clearing logs:', error);
        res.status(500).json({ success: false, error: 'Error clearing logs' });
    }
});

// ---------- User Profile Routes ----------
app.get('/api/user/profile', authenticateUser, async (req, res) => {
    try {
        const user = await findUserByEmail(req.user.email);

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
        const user = await findUserByEmail(req.user.email);

        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        if (newPassword) {
            if (!currentPassword) {
                return res.status(400).json({ success: false, error: 'Current password is required to change password' });
            }

            if (newPassword.length < 6) {
                return res.status(400).json({ success: false, error: 'New password must be at least 6 characters' });
            }

            const validCurrentPassword = await bcrypt.compare(currentPassword, user.password);
            if (!validCurrentPassword) {
                return res.status(400).json({ success: false, error: 'Current password is incorrect' });
            }

            await updateUser(req.user.email, {
                password: await bcrypt.hash(newPassword, 12)
            });
        }

        await updateUser(req.user.email, {
            name: name.trim(),
            updatedAt: new Date().toISOString()
        });

        saveLog({
            eventType: 'profile_updated',
            details: `Profile updated for ${req.user.email}${newPassword ? ' (password changed)' : ''}`,
            user: req.user.email
        });

        res.json({ success: true, message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.get('/api/user/workspace', authenticateUser, async (req, res) => {
    try {
        const user = await findUserByEmail(req.user.email);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found' });
        }

        const snapshot = await buildOperationsSnapshot(user);
        res.json({ success: true, user: sanitizeUser(user), ...snapshot });
    } catch (error) {
        console.error('Error loading user workspace:', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

app.post('/api/user/service-request', authenticateUser, async (req, res) => {
    const { service, message } = req.body;

    if (!service || !message || message.trim().length < 10) {
        return res.status(400).json({ success: false, error: 'Service and a clear message are required.' });
    }

    const user = await findUserByEmail(req.user.email);
    if (!user) return res.status(404).json({ success: false, error: 'User not found' });

    const requests = readJsonFile('contacts.json');
    const entry = {
        id: Date.now(),
        userId: user.id,
        userEmail: user.email,
        name: user.name,
        email: user.email,
        service,
        message: message.trim(),
        status: 'new',
        timestamp: new Date().toISOString()
    };
    requests.push(entry);
    writeJsonFile('contacts.json', requests);

    saveLog({
        eventType: 'dashboard_service_request',
        details: `Dashboard request for ${service}`,
        user: user.email
    });

    res.json({ success: true, request: entry });
});

app.post('/api/user/feedback', authenticateUser, (req, res) => {
    const { feedback } = req.body;

    if (!feedback || feedback.trim().length < 10) {
        return res.status(400).json({ success: false, error: 'Feedback must be at least 10 characters.' });
    }

    const feedbackPath = path.join(__dirname, 'feedback.json');
    let feedbackItems = [];

    if (fs.existsSync(feedbackPath)) {
        try {
            feedbackItems = JSON.parse(fs.readFileSync(feedbackPath, 'utf-8'));
        } catch (error) {
            console.error('Error reading feedback.json:', error);
        }
    }

    const entry = {
        id: Date.now(),
        name: req.user.name || req.user.email,
        email: req.user.email,
        feedback: feedback.trim(),
        status: 'pending-review',
        submittedAt: new Date().toISOString()
    };

    feedbackItems.push(entry);
    fs.writeFileSync(feedbackPath, JSON.stringify(feedbackItems, null, 2));

    saveLog({
        eventType: 'dashboard_feedback_submitted',
        details: 'Client submitted dashboard feedback',
        user: req.user.email
    });

    res.json({ success: true, message: 'Feedback submitted for review.' });
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

// ---------- Health Check Endpoint ----------
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
            database: dbAvailable ? 'OK' : 'Not available',
            email: transporter ? 'OK' : 'Not configured',
            socket: 'OK'
        }
    });
});

// ---------- Static File Routes ----------
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'web.html'));
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
server.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`Port ${PORT} is already in use. Stop the duplicate PM2/process instance or set a different PORT.`);
    } else {
        console.error('Server startup error:', error);
    }
    process.exit(1);
});

server.listen(PORT, '0.0.0.0', async () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`📧 Email service: ${emailEnabled ? 'Configured' : 'Not configured'}`);
    console.log(`🔒 JWT Secret: ${process.env.JWT_SECRET ? 'Configured' : 'Development fallback'}`);
    console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️  Database config: ${dbEnabled ? 'PostgreSQL' : 'JSON fallback'}`);

    if (dbEnabled) {
        const dbInitialized = await syncDatabase();
        if (!dbInitialized) {
            markDatabaseUnavailable();
        }
    }

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
