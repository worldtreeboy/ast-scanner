/**
 * NoSQL Injection and SSRF Test Cases
 * =====================================
 * Tests for NoSQL injection (MongoDB) and SSRF vulnerabilities
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected
 */

const express = require('express');
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb');
const axios = require('axios');
const fetch = require('node-fetch');
const http = require('http');
const https = require('https');
const app = express();
app.use(express.json());

// ============================================================================
// SECTION 1: NOSQL INJECTION - MongoDB
// ============================================================================

// Mock User model
const User = mongoose.model('User', new mongoose.Schema({ name: String, password: String }));

// [TP-NOSQL-001] Direct query object from body
app.post('/nosql/login', async (req, res) => {
    const user = await User.findOne(req.body);  // VULNERABLE: { username: "admin", password: { $ne: "" } }
    res.json(user);
});

// [TP-NOSQL-002] Query with user-controlled field
app.get('/nosql/user', async (req, res) => {
    const query = { username: req.query.user };
    const user = await User.findOne(query);  // VULNERABLE if user = { $regex: ".*" }
    res.json(user);
});

// [TP-NOSQL-003] $where with user input
app.get('/nosql/where', async (req, res) => {
    const user = await User.findOne({ $where: `this.name === '${req.query.name}'` });  // VULNERABLE
    res.json(user);
});

// [TP-NOSQL-004] Aggregation pipeline with user data
app.post('/nosql/aggregate', async (req, res) => {
    const pipeline = req.body.pipeline;  // User controls entire pipeline
    const result = await User.aggregate(pipeline);  // VULNERABLE
    res.json(result);
});

// [TP-NOSQL-005] Update with user query
app.patch('/nosql/update', async (req, res) => {
    const { filter, update } = req.body;
    await User.updateOne(filter, update);  // VULNERABLE: user controls both
    res.send('Updated');
});

// [TP-NOSQL-006] Delete with user filter
app.delete('/nosql/delete', async (req, res) => {
    await User.deleteMany(req.body);  // VULNERABLE
    res.send('Deleted');
});

// [TP-NOSQL-007] Native MongoDB driver
app.get('/nosql/native', async (req, res) => {
    const client = new MongoClient('mongodb://localhost');
    const db = client.db('test');
    const result = await db.collection('users').findOne({ name: req.query.name });  // VULNERABLE
    res.json(result);
});

// [TP-NOSQL-008] Operator injection via query param
app.get('/nosql/operator', async (req, res) => {
    const { field, value, op } = req.query;
    const query = { [field]: { [op]: value } };  // VULNERABLE: user controls operator
    const users = await User.find(query);
    res.json(users);
});

// [TP-NOSQL-009] $regex from user
app.get('/nosql/regex', async (req, res) => {
    const user = await User.findOne({
        name: { $regex: req.query.pattern }  // VULNERABLE: ReDoS + injection
    });
    res.json(user);
});

// [TP-NOSQL-010] $expr with user data
app.get('/nosql/expr', async (req, res) => {
    const result = await User.find({
        $expr: { $eq: ['$name', req.query.name] }  // VULNERABLE
    });
    res.json(result);
});

// ============================================================================
// SECTION 2: SSRF - Server-Side Request Forgery
// ============================================================================

// [TP-SSRF-001] fetch with user URL
app.get('/ssrf/fetch', async (req, res) => {
    const response = await fetch(req.query.url);  // VULNERABLE
    const data = await response.text();
    res.send(data);
});

// [TP-SSRF-002] axios GET
app.get('/ssrf/axios', async (req, res) => {
    const { data } = await axios.get(req.query.url);  // VULNERABLE
    res.json(data);
});

// [TP-SSRF-003] axios with config
app.post('/ssrf/axios-config', async (req, res) => {
    const { data } = await axios(req.body);  // VULNERABLE: user controls entire config
    res.json(data);
});

// [TP-SSRF-004] http.get
app.get('/ssrf/http', (req, res) => {
    http.get(req.query.url, (response) => {  // VULNERABLE
        response.pipe(res);
    });
});

// [TP-SSRF-005] https.request
app.get('/ssrf/https', (req, res) => {
    const url = new URL(req.query.url);
    const options = { hostname: url.hostname, path: url.pathname };  // VULNERABLE
    https.request(options, (response) => {
        response.pipe(res);
    }).end();
});

// [TP-SSRF-006] URL concatenation
app.get('/ssrf/concat', async (req, res) => {
    const apiUrl = 'https://api.example.com/' + req.query.path;  // VULNERABLE
    const response = await fetch(apiUrl);
    res.json(await response.json());
});

// [TP-SSRF-007] Template literal URL
app.get('/ssrf/template', async (req, res) => {
    const url = `https://api.service.com/v1/${req.query.endpoint}`;  // VULNERABLE
    const { data } = await axios.get(url);
    res.json(data);
});

// [TP-SSRF-008] URL object with user input
app.get('/ssrf/url-obj', async (req, res) => {
    const url = new URL(req.query.path, 'https://internal.corp/');  // VULNERABLE: path can escape base
    const response = await fetch(url);
    res.send(await response.text());
});

// [TP-SSRF-009] Redirect following
app.get('/ssrf/redirect', async (req, res) => {
    const response = await fetch(req.query.url, { redirect: 'follow' });  // VULNERABLE
    res.send(await response.text());
});

// [TP-SSRF-010] Image/file proxy
app.get('/ssrf/proxy', async (req, res) => {
    const imageUrl = req.query.src;
    const response = await fetch(imageUrl);  // VULNERABLE
    res.set('Content-Type', response.headers.get('content-type'));
    response.body.pipe(res);
});

// [TP-SSRF-011] Webhook URL
app.post('/ssrf/webhook', async (req, res) => {
    const webhookUrl = req.body.callback;
    await axios.post(webhookUrl, { status: 'complete' });  // VULNERABLE
    res.send('Notified');
});

// [TP-SSRF-012] PDF/Screenshot generator URL
app.get('/ssrf/screenshot', async (req, res) => {
    const targetUrl = req.query.url;
    // Puppeteer or similar
    // await page.goto(targetUrl);  // VULNERABLE
    res.send('Screenshot taken of: ' + targetUrl);
});

// ============================================================================
// SECTION 3: HEADER INJECTION
// ============================================================================

// [TP-HEADER-001] Set-Cookie with user data
app.get('/header/cookie', (req, res) => {
    res.setHeader('Set-Cookie', `session=${req.query.token}`);  // VULNERABLE
    res.send('Cookie set');
});

// [TP-HEADER-002] Location header (open redirect)
app.get('/header/redirect', (req, res) => {
    res.setHeader('Location', req.query.url);  // VULNERABLE
    res.status(302).end();
});

// [TP-HEADER-003] Custom header with user value
app.get('/header/custom', (req, res) => {
    res.setHeader('X-Custom', req.query.value);  // VULNERABLE: CRLF injection
    res.send('OK');
});

// [TP-HEADER-004] res.set with user data
app.get('/header/set', (req, res) => {
    res.set('X-User-Data', req.query.data);  // VULNERABLE
    res.send('OK');
});

// ============================================================================
// SECTION 4: FALSE POSITIVES
// ============================================================================

// [FP-NOSQL-001] Hardcoded query
app.get('/safe/nosql', async (req, res) => {
    const user = await User.findOne({ role: 'admin' });  // SAFE: no user input
    res.json(user);
});

// [FP-NOSQL-002] Sanitized input
app.get('/safe/nosql-sanitized', async (req, res) => {
    const name = String(req.query.name).replace(/[${}]/g, '');  // Sanitized
    const user = await User.findOne({ name });
    res.json(user);
});

// [FP-SSRF-001] Whitelist URL check
app.get('/safe/ssrf', async (req, res) => {
    const allowed = ['https://api.trusted.com', 'https://cdn.trusted.com'];
    const url = req.query.url;
    if (!allowed.some(a => url.startsWith(a))) {
        return res.status(403).send('Forbidden');
    }
    const response = await fetch(url);  // SAFER: whitelist check
    res.send(await response.text());
});

// [FP-SSRF-002] Internal URL only
app.get('/safe/internal', async (req, res) => {
    const path = req.query.path.replace(/[^a-zA-Z0-9/]/g, '');  // Sanitized
    const url = `https://internal.api/v1/${path}`;
    const { data } = await axios.get(url);
    res.json(data);
});

// [FP-HEADER-001] Encoded header value
app.get('/safe/header', (req, res) => {
    const safe = encodeURIComponent(req.query.value);
    res.setHeader('X-Safe', safe);  // SAFER: encoded
    res.send('OK');
});

app.listen(3000);
