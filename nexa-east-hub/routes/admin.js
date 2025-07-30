import express from 'express';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const router = express.Router();

// ES Module dirname fix
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Utility function to read logs
function readLogs() {
  const logPath = path.join(__dirname, '..', 'logs.json');
  if (!fs.existsSync(logPath)) return [];
  
  try {
    const data = fs.readFileSync(logPath, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Error reading logs.json:', error);
    return [];
  }
}

// GET /api/admin/logs
router.get('/logs', (req, res) => {
  const logs = readLogs();
  res.json(logs);
});

export default router;
