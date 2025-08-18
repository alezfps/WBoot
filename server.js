#!/usr/bin/env node

const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const redis = require('redis');
const mime = require('mime-types');

const config = {
    port: process.env.PORT || 3000,
    authToken: process.env.AUTH_TOKEN || 'your-secure-auth-token-here',
    pluginDir: process.env.PLUGIN_DIR || '/var/www/plugins',
    maxDownloadSize: parseInt(process.env.MAX_DOWNLOAD_SIZE) || 50 * 1024 * 1024, // 50MB
    redisUrl: process.env.REDIS_URL || 'redis://localhost:6379',
    logFile: path.join(process.env.PLUGIN_DIR || '/var/www/plugins', 'access.log'),
    environment: process.env.NODE_ENV || 'production'
};

const app = express();

// Redis client setup
let redisClient = null;
if (config.environment === 'production') {
    try {
        redisClient = redis.createClient({ url: config.redisUrl });
        redisClient.on('error', (err) => console.log('Redis Client Error', err));
        redisClient.connect();
    } catch (error) {
        console.warn('Redis not available, falling back to memory store');
    }
}

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true
    }
}));

// Rate limiting
const createRateLimit = (windowMs, max, message) => rateLimit({
    windowMs,
    max,
    message: { error: message },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => getClientIP(req)
});

app.use(createRateLimit(15 * 60 * 1000, 100, 'Too many requests')); 

const versionRateLimit = createRateLimit(60 * 1000, 10, 'Too many version checks');
const downloadRateLimit = createRateLimit(60 * 1000, 5, 'Too many downloads');

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] ||
           req.headers['x-client-ip'] ||
           req.connection?.remoteAddress ||
           req.socket?.remoteAddress ||
           req.ip;
}

async function logAccess(action, ip, success = true, details = '') {
    const timestamp = new Date().toISOString();
    const status = success ? 'SUCCESS' : 'FAILED';
    const logEntry = `${timestamp} | ${ip} | ${action} | ${status} | ${details}\n`;
    
    try {
        await fs.appendFile(config.logFile, logEntry);
    } catch (error) {
        console.error('Failed to write log:', error);
    }
}

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const expectedToken = `Bearer ${config.authToken}`;
    
    if (!authHeader || authHeader !== expectedToken) {
        logAccess('AUTH_FAILED', getClientIP(req), false, `Invalid token: ${authHeader?.substring(0, 20)}...`);
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    next();
}

async function verifyJarFile(filePath) {
    try {
        const stats = await fs.stat(filePath);
        
        if (stats.size > config.maxDownloadSize) {
            return { valid: false, error: 'File too large' };
        }
        
        const mimeType = mime.lookup(filePath);
        if (!['application/java-archive', 'application/zip'].includes(mimeType)) {
            return { valid: false, error: 'Invalid file type' };
        }
        
        const buffer = Buffer.alloc(4);
        const fd = await fs.open(filePath, 'r');
        await fd.read(buffer, 0, 4, 0);
        await fd.close();
        
        if (!buffer.equals(Buffer.from([0x50, 0x4B, 0x03, 0x04]))) {
            return { valid: false, error: 'Not a valid ZIP/JAR file' };
        }
        
        return { valid: true, error: null };
    } catch (error) {
        return { valid: false, error: `Verification error: ${error.message}` };
    }
}

async function customRateLimitCheck(ip) {
    if (!redisClient) return true;
    
    const currentTime = Math.floor(Date.now() / 1000);
    const window = 300;
    const maxRequests = 20;
    const key = `rate_limit:${ip}`;
    
    try {
        await redisClient.zRemRangeByScore(key, 0, currentTime - window);
        const requestCount = await redisClient.zCard(key);
        
        if (requestCount >= maxRequests) {
            await logAccess('RATE_LIMITED', ip, false, `Requests: ${requestCount}`);
            return false;
        }
        
        await redisClient.zAdd(key, { score: currentTime, value: currentTime.toString() });
        await redisClient.expire(key, window);
        
        return true;
    } catch (error) {
        console.error('Rate limit check error:', error);
        return true; 
    }
}

app.use(async (req, res, next) => {
    const clientIP = getClientIP(req);
    const allowed = await customRateLimitCheck(clientIP);
    
    if (!allowed) {
        return res.status(429).json({ error: 'Rate limit exceeded' });
    }
    
    next();
});

// Routes
app.get('/version.txt', authenticateToken, versionRateLimit, async (req, res) => {
    const clientIP = getClientIP(req);
    const versionFile = path.join(config.pluginDir, 'version.txt');
    
    try {
        const version = await fs.readFile(versionFile, 'utf8');
        await logAccess('VERSION_CHECK', clientIP, true, `Version: ${version.trim()}`);
        
        res.set({
            'Content-Type': 'text/plain',
            'Cache-Control': 'no-cache, must-revalidate'
        });
        
        res.send(version.trim());
    } catch (error) {
        if (error.code === 'ENOENT') {
            await logAccess('VERSION_NOT_FOUND', clientIP, false);
            return res.status(404).json({ error: 'Version file not found' });
        }
        
        await logAccess('VERSION_ERROR', clientIP, false, error.message);
        console.error('Version check error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/download.jar', authenticateToken, downloadRateLimit, async (req, res) => {
    const clientIP = getClientIP(req);
    const pluginFile = path.join(config.pluginDir, 'plugin.jar');
    
    try {
        await fs.access(pluginFile);
        const verification = await verifyJarFile(pluginFile);
        if (!verification.valid) {
            await logAccess('INVALID_FILE', clientIP, false, verification.error);
            return res.status(403).json({ error: verification.error });
        }
        
        const stats = await fs.stat(pluginFile);
        await logAccess('DOWNLOAD_SUCCESS', clientIP, true, `Size: ${stats.size} bytes`);
        
        res.set({
            'Content-Type': 'application/java-archive',
            'Content-Disposition': 'attachment; filename="plugin.jar"',
            'Content-Length': stats.size,
            'Cache-Control': 'no-cache, must-revalidate'
        });
        
        const readStream = fsSync.createReadStream(pluginFile);
        readStream.pipe(res);
        
        readStream.on('error', async (error) => {
            await logAccess('DOWNLOAD_ERROR', clientIP, false, error.message);
            if (!res.headersSent) {
                res.status(500).json({ error: 'Download error' });
            }
        });
        
    } catch (error) {
        if (error.code === 'ENOENT') {
            await logAccess('DOWNLOAD_NOT_FOUND', clientIP, false);
            return res.status(404).json({ error: 'Plugin file not found' });
        }
        
        await logAccess('DOWNLOAD_ERROR', clientIP, false, error.message);
        console.error('Download error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/health', createRateLimit(60 * 1000, 30, 'Too many health checks'), (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        uptime: process.uptime()
    });
});

app.get('/stats', authenticateToken, createRateLimit(60 * 1000, 5, 'Too many stats requests'), async (req, res) => {
    const clientIP = getClientIP(req);
    
    try {
        const pluginFile = path.join(config.pluginDir, 'plugin.jar');
        const versionFile = path.join(config.pluginDir, 'version.txt');
        
        const stats = {
            pluginExists: false,
            pluginSize: 0,
            currentVersion: '',
            lastModified: null,
            serverTime: new Date().toISOString()
        };
        
        try {
            const pluginStats = await fs.stat(pluginFile);
            stats.pluginExists = true;
            stats.pluginSize = pluginStats.size;
            stats.lastModified = pluginStats.mtime.toISOString();
        } catch (error) {
            // Plugin file doesn't exist
        }
        
        try {
            const version = await fs.readFile(versionFile, 'utf8');
            stats.currentVersion = version.trim();
        } catch (error) {
            // Version file doesn't exist
        }
        
        await logAccess('STATS_CHECK', clientIP, true);
        res.json(stats);
        
    } catch (error) {
        await logAccess('STATS_ERROR', clientIP, false, error.message);
        console.error('Stats error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.use((req, res) => {
    const clientIP = getClientIP(req);
    logAccess('INVALID_ENDPOINT', clientIP, false, `${req.method} ${req.path}`);
    res.status(404).json({ error: 'Not found' });
});

app.use((error, req, res, next) => {
    const clientIP = getClientIP(req);
    logAccess('SERVER_ERROR', clientIP, false, error.message);
    console.error('Server error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

async function initApp() {
    try {
        await fs.mkdir(config.pluginDir, { recursive: true });
        
        const versionFile = path.join(config.pluginDir, 'version.txt');
        try {
            await fs.access(versionFile);
        } catch (error) {
            await fs.writeFile(versionFile, '1.0.0');
        }
        
        const logsDir = path.join(config.pluginDir, 'logs');
        await fs.mkdir(logsDir, { recursive: true });
        
        console.log('Plugin distribution server initialized');
        console.log(`Plugin directory: ${config.pluginDir}`);
        console.log(`Environment: ${config.environment}`);
        
    } catch (error) {
        console.error('Failed to initialize application:', error);
        process.exit(1);
    }
}

process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully');
    
    if (redisClient) {
        await redisClient.quit();
    }
    
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully');
    
    if (redisClient) {
        await redisClient.quit();
    }
    
    process.exit(0);
});

if (require.main === module) {
    initApp().then(() => {
        app.listen(config.port, '127.0.0.1', () => {
            console.log(`Plugin distribution server running on port ${config.port}`);
            console.log(`Auth token: ${config.authToken.substring(0, 8)}...`);
        });
    });
}

module.exports = app;