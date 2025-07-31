// utils/logs.js
import fs from 'fs';
import path from 'path';

// Create logs directory if it doesn't exist
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Helper function to format timestamp
const getTimestamp = () => {
  return new Date().toISOString();
};

// Helper function to format log entry
const formatLogEntry = (level, message, metadata = {}) => {
  const logEntry = {
    timestamp: getTimestamp(),
    level: level.toUpperCase(),
    message,
    ...metadata
  };
  return JSON.stringify(logEntry) + '\n';
};

// Write to log file
const writeToFile = (filename, content) => {
  const filePath = path.join(logsDir, filename);
  fs.appendFileSync(filePath, content);
};

// Main logging functions
export const logInfo = (message, metadata = {}) => {
  const logEntry = formatLogEntry('info', message, metadata);
  writeToFile('app.log', logEntry);
  console.log(`[INFO] ${message}`, metadata);
};

export const logError = (message, error = null, metadata = {}) => {
  const errorMetadata = {
    ...metadata,
    ...(error && {
      error: {
        message: error.message,
        stack: error.stack,
        name: error.name
      }
    })
  };
  
  const logEntry = formatLogEntry('error', message, errorMetadata);
  writeToFile('error.log', logEntry);
  writeToFile('app.log', logEntry);
  console.error(`[ERROR] ${message}`, errorMetadata);
};

export const logWarning = (message, metadata = {}) => {
  const logEntry = formatLogEntry('warning', message, metadata);
  writeToFile('app.log', logEntry);
  console.warn(`[WARNING] ${message}`, metadata);
};

export const logDebug = (message, metadata = {}) => {
  if (process.env.NODE_ENV === 'development') {
    const logEntry = formatLogEntry('debug', message, metadata);
    writeToFile('debug.log', logEntry);
    console.debug(`[DEBUG] ${message}`, metadata);
  }
};

// Authentication specific logging functions
export const logAuth = (event, userId = null, metadata = {}) => {
  const authMetadata = {
    userId,
    event,
    ip: metadata.ip || 'unknown',
    userAgent: metadata.userAgent || 'unknown',
    ...metadata
  };
  
  const logEntry = formatLogEntry('auth', `Auth event: ${event}`, authMetadata);
  writeToFile('auth.log', logEntry);
  writeToFile('app.log', logEntry);
  console.log(`[AUTH] ${event}`, authMetadata);
};

// Security event logging
export const logSecurity = (event, severity = 'medium', metadata = {}) => {
  const securityMetadata = {
    event,
    severity,
    timestamp: getTimestamp(),
    ...metadata
  };
  
  const logEntry = formatLogEntry('security', `Security event: ${event}`, securityMetadata);
  writeToFile('security.log', logEntry);
  writeToFile('app.log', logEntry);
  
  if (severity === 'high' || severity === 'critical') {
    console.error(`[SECURITY] ${event}`, securityMetadata);
  } else {
    console.warn(`[SECURITY] ${event}`, securityMetadata);
  }
};

// Database operation logging
export const logDatabase = (operation, table = null, metadata = {}) => {
  const dbMetadata = {
    operation,
    table,
    timestamp: getTimestamp(),
    ...metadata
  };
  
  const logEntry = formatLogEntry('database', `DB operation: ${operation}`, dbMetadata);
  if (process.env.NODE_ENV === 'development') {
    writeToFile('database.log', logEntry);
  }
  writeToFile('app.log', logEntry);
  
  if (process.env.NODE_ENV === 'development') {
    console.log(`[DB] ${operation}`, dbMetadata);
  }
};

// API request logging
export const logRequest = (method, path, statusCode, responseTime, metadata = {}) => {
  const requestMetadata = {
    method,
    path,
    statusCode,
    responseTime: `${responseTime}ms`,
    timestamp: getTimestamp(),
    ...metadata
  };
  
  const logEntry = formatLogEntry('request', `${method} ${path} - ${statusCode}`, requestMetadata);
  writeToFile('requests.log', logEntry);
  
  if (statusCode >= 400) {
    writeToFile('error.log', logEntry);
  }
  
  console.log(`[REQUEST] ${method} ${path} - ${statusCode} (${responseTime}ms)`);
};

// Function to save log entries (matching your existing code)
export const saveLog = (logData) => {
  const { timestamp, eventType, details, user, ...metadata } = logData;
  
  const formattedLog = {
    timestamp: timestamp ? new Date(timestamp).toISOString() : getTimestamp(),
    eventType: eventType || 'general',
    details: details || 'No details provided',
    user: user || 'unknown',
    ...metadata
  };
  
  const logEntry = JSON.stringify(formattedLog) + '\n';
  
  // Write to appropriate log files based on event type
  if (eventType && eventType.includes('login')) {
    writeToFile('auth.log', logEntry);
  } else if (eventType && eventType.includes('error')) {
    writeToFile('error.log', logEntry);
  } else if (eventType && eventType.includes('security')) {
    writeToFile('security.log', logEntry);
  }
  
  // Always write to main app log
  writeToFile('app.log', logEntry);
  
  // Console output for development
  if (process.env.NODE_ENV === 'development') {
    console.log(`[${eventType?.toUpperCase() || 'LOG'}] ${details}`, { user, ...metadata });
  }
};

// Export default logger object
export default {
  info: logInfo,
  error: logError,
  warning: logWarning,
  debug: logDebug,
  auth: logAuth,
  security: logSecurity,
  database: logDatabase,
  request: logRequest,
  saveLog
};