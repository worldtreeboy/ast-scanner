/**
 * Express.js configuration - INTENTIONALLY VULNERABLE for testing
 * These settings should NEVER be used in production
 */

const express = require('express');
const session = require('express-session');
const app = express();

// CRITICAL: Hardcoded secret key
const SECRET_KEY = 'super-secret-hardcoded-key-123';

// HIGH: Debug mode / verbose errors
app.set('env', 'development');

// HIGH: Disable security headers (helmet not used)
// Should use: const helmet = require('helmet'); app.use(helmet());

// CRITICAL: Session with weak configuration
app.use(session({
    secret: 'keyboard cat',  // Weak hardcoded secret
    resave: true,
    saveUninitialized: true,
    cookie: {
        secure: false,       // HIGH: Not HTTPS only
        httpOnly: false,     // HIGH: Accessible via JavaScript
        maxAge: 31536000000  // MEDIUM: 1 year expiry
    }
}));

// CRITICAL: CORS allow all origins
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Credentials', 'true');
    next();
});

// HIGH: Body parser with large limit (DoS risk)
app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// CRITICAL: Serve hidden files
app.use(express.static('public', {
    dotfiles: 'allow'  // Serves .env, .git, etc.
}));

// HIGH: Verbose error handling exposes stack traces
app.use((err, req, res, next) => {
    res.status(500).json({
        error: err.message,
        stack: err.stack,      // CRITICAL: Stack trace exposed
        path: req.path,
        query: req.query
    });
});

// CRITICAL: Hardcoded database credentials
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: 'admin123',  // Hardcoded password
    database: 'myapp'
};

// CRITICAL: JWT with weak/no verification
const jwt = require('jsonwebtoken');
const token = jwt.sign({ user: 'admin' }, 'weak-secret', {
    algorithm: 'none'  // CRITICAL: No signature verification
});

// HIGH: Rate limiting disabled
// Should use: const rateLimit = require('express-rate-limit');

module.exports = { app, dbConfig, SECRET_KEY };
