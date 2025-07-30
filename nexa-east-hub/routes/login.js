import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import fs from 'fs';
import path from 'path';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';

dotenv.config();
const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'your_fallback_secret_key_change_in_production';

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'pikelelalikho@gmail.com',
        pass: process.env.EMAIL_PASS
    }
});

function readUsers() {
    if (!fs.existsSync('users.json')) return [];
    try {
        return JSON.parse(fs.readFileSync('users.json', 'utf8'));
    } catch (err) {
        console.error('Failed to read users.json:', err);
        return [];
    }
}

function saveUsers(users) {
    try {
        fs.writeFileSync('users.json', JSON.stringify(users, null, 2));
        return true;
    } catch (err) {
        console.error('Failed to save users.json:', err);
        return false;
    }
}

function saveLog(entry) {
    let logs = [];
    if (fs.existsSync('logs.json')) {
        try {
            logs = JSON.parse(fs.readFileSync('logs.json', 'utf-8'));
        } catch (err) {
            console.error('Error reading logs:', err);
        }
    }
    logs.push(entry);
    try {
        fs.writeFileSync('logs.json', JSON.stringify(logs, null, 2));
    } catch (err) {
        console.error('Error saving log:', err);
    }
}

function authenticateAdmin(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ success: false, error: 'No authorization header' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, error: 'Token missing' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.role !== 'admin') {
            return res.status(403).json({ success: false, error: 'Admins only' });
        }
        req.admin = decoded;
        next();
    } catch (err) {
        console.error('Admin auth token invalid:', err.message);
        return res.status(401).json({ success: false, error: 'Invalid token' });
    }
}

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
            details: err.message,
        });
        return res.status(400).json({ success: false, error: 'Invalid or expired token.' });
    }

    const users = readUsers();
    const userIndex = users.findIndex(u => u.email.toLowerCase() === decoded.email.toLowerCase());
    if (userIndex === -1) {
        return res.status(404).json({ success: false, error: 'User not found.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        users[userIndex].password = hashedPassword;
        saveUsers(users);

        saveLog({ timestamp: Date.now(), eventType: 'password_reset', user: decoded.email });

        res.json({ success: true, message: 'Password updated successfully.' });
    } catch (err) {
        console.error('Error updating password:', err);
        res.status(500).json({ success: false, error: 'Server error updating password.' });
    }
});

// 404 handler for unmatched routes in this router
router.use((req, res) => {
    res.status(404).sendFile(path.resolve('public/404.html'));
});

router.get('/admin/logs', authenticateAdmin, (req, res) => {
    const logs = fs.existsSync('logs.json') ? JSON.parse(fs.readFileSync('logs.json', 'utf-8')) : [];
    res.json(logs);
});

export default router;
