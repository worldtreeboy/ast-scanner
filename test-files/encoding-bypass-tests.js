/**
 * Encoding and Data Transformation Test Cases
 * ============================================
 * Tests for XSS/PP through various encoding and transformation methods
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected
 */

const express = require('express');
const app = express();

// ============================================================================
// toString() TRANSFORMATIONS - XSS
// ============================================================================

// [TP-TOSTRING-001] Basic toString on tainted data
app.get('/tostring-basic', (req, res) => {
    const input = req.query.data;
    const str = input.toString();
    res.send(`<p>${str}</p>`);  // VULNERABLE: toString doesn't sanitize
});

// [TP-TOSTRING-002] toString with radix (number conversion)
app.get('/tostring-radix', (req, res) => {
    const num = parseInt(req.query.num);
    const hex = num.toString(16);  // Still tainted if num was tainted
    res.send(`<code>0x${hex}</code>`);  // VULNERABLE
});

// [TP-TOSTRING-003] Object toString
app.post('/tostring-obj', (req, res) => {
    const obj = req.body;
    const str = JSON.stringify(obj);  // Serialization doesn't sanitize for HTML
    res.send(`<pre>${str}</pre>`);  // VULNERABLE
});

// [TP-TOSTRING-004] Array toString
app.get('/tostring-arr', (req, res) => {
    const items = req.query.items.split(',');
    const output = items.toString();  // Joins with comma, still tainted
    res.send(`<div>${output}</div>`);  // VULNERABLE
});

// [TP-TOSTRING-005] valueOf transformation
app.get('/valueof', (req, res) => {
    const input = req.query.data;
    const val = input.valueOf();
    res.send(`<span>${val}</span>`);  // VULNERABLE
});

// ============================================================================
// BASE64 ENCODING - XSS
// ============================================================================

// [TP-BASE64-001] btoa encoding (doesn't sanitize)
app.get('/btoa', (req, res) => {
    const input = req.query.data;
    const encoded = btoa(input);  // Base64 encode
    // If decoded on client-side and rendered, still XSS
    res.send(`<script>document.write(atob('${encoded}'))</script>`);  // VULNERABLE
});

// [TP-BASE64-002] atob decoding of user input
app.get('/atob', (req, res) => {
    const encoded = req.query.b64;
    const decoded = atob(encoded);  // User controls decoded content
    res.send(`<div>${decoded}</div>`);  // VULNERABLE
});

// [TP-BASE64-003] Buffer.from base64
app.get('/buffer-b64', (req, res) => {
    const encoded = req.query.data;
    const decoded = Buffer.from(encoded, 'base64').toString();
    res.send(`<p>${decoded}</p>`);  // VULNERABLE
});

// [TP-BASE64-004] Buffer.from utf8
app.get('/buffer-utf8', (req, res) => {
    const input = req.query.data;
    const buf = Buffer.from(input, 'utf8');
    const str = buf.toString('utf8');
    res.send(`<div>${str}</div>`);  // VULNERABLE
});

// ============================================================================
// URL ENCODING - XSS
// ============================================================================

// [TP-URL-001] decodeURIComponent (decoding user input)
app.get('/decode-uri', (req, res) => {
    const encoded = req.query.data;
    const decoded = decodeURIComponent(encoded);  // User controls decoded content
    res.send(`<p>${decoded}</p>`);  // VULNERABLE
});

// [TP-URL-002] decodeURI
app.get('/decode-uri-full', (req, res) => {
    const encoded = req.query.url;
    const decoded = decodeURI(encoded);
    res.send(`<a href="${decoded}">Link</a>`);  // VULNERABLE
});

// [TP-URL-003] unescape (deprecated but still used)
app.get('/unescape', (req, res) => {
    const encoded = req.query.data;
    const decoded = unescape(encoded);
    res.send(`<div>${decoded}</div>`);  // VULNERABLE
});

// [TP-URL-004] URLSearchParams iteration
app.get('/urlparams', (req, res) => {
    const params = new URLSearchParams(req.query);
    let html = '<ul>';
    for (const [key, value] of params) {
        html += `<li>${key}: ${value}</li>`;  // VULNERABLE: both key and value tainted
    }
    html += '</ul>';
    res.send(html);
});

// ============================================================================
// JSON TRANSFORMATIONS - XSS & PP
// ============================================================================

// [TP-JSON-001] JSON.stringify in HTML context
app.post('/json-stringify', (req, res) => {
    const data = req.body;
    const json = JSON.stringify(data);
    res.send(`<script>var config = ${json};</script>`);  // VULNERABLE: script injection
});

// [TP-JSON-002] JSON.parse then render
app.get('/json-parse', (req, res) => {
    const jsonStr = req.query.json;
    const obj = JSON.parse(jsonStr);
    res.send(`<div>${obj.name}</div>`);  // VULNERABLE
});

// [TP-JSON-003] JSON.parse for prototype pollution
app.post('/json-parse-pp', (req, res) => {
    const jsonStr = req.body.data;
    const parsed = JSON.parse(jsonStr);
    const result = { ...parsed };  // VULNERABLE: spread of parsed JSON
    res.json(result);
});

// [TP-JSON-004] Double JSON parse
app.post('/double-parse', (req, res) => {
    const outer = req.body.nested;
    const inner = JSON.parse(outer);
    const final = JSON.parse(inner.data);
    res.send(`<p>${final.value}</p>`);  // VULNERABLE
});

// ============================================================================
// STRING METHODS THAT DON'T SANITIZE - XSS
// ============================================================================

// [TP-STR-001] String.fromCharCode (can reconstruct XSS)
app.get('/fromcharcode', (req, res) => {
    const codes = req.query.codes.split(',').map(Number);
    const str = String.fromCharCode(...codes);  // User controls char codes
    res.send(`<div>${str}</div>`);  // VULNERABLE
});

// [TP-STR-002] String.raw template
app.get('/string-raw', (req, res) => {
    const input = req.query.data;
    const raw = String.raw`${input}`;  // Doesn't escape, raw string
    res.send(`<p>${raw}</p>`);  // VULNERABLE
});

// [TP-STR-003] normalize doesn't sanitize
app.get('/normalize', (req, res) => {
    const input = req.query.data;
    const normalized = input.normalize('NFC');
    res.send(`<span>${normalized}</span>`);  // VULNERABLE
});

// [TP-STR-004] repeat can amplify attack
app.get('/repeat', (req, res) => {
    const input = req.query.char;
    const repeated = input.repeat(100);
    res.send(`<pre>${repeated}</pre>`);  // VULNERABLE
});

// [TP-STR-005] padStart/padEnd
app.get('/pad', (req, res) => {
    const input = req.query.data;
    const padded = input.padStart(50, ' ');
    res.send(`<code>${padded}</code>`);  // VULNERABLE
});

// [TP-STR-006] split then join
app.get('/split-join', (req, res) => {
    const input = req.query.data;
    const parts = input.split('');
    const rejoined = parts.join('');  // Same as original, still tainted
    res.send(`<div>${rejoined}</div>`);  // VULNERABLE
});

// [TP-STR-007] slice/substring
app.get('/slice', (req, res) => {
    const input = req.query.data;
    const sliced = input.slice(0, 100);  // Still tainted
    res.send(`<p>${sliced}</p>`);  // VULNERABLE
});

// [TP-STR-008] charAt iteration
app.get('/charat', (req, res) => {
    const input = req.query.data;
    let result = '';
    for (let i = 0; i < input.length; i++) {
        result += input.charAt(i);  // Rebuilding the string
    }
    res.send(`<div>${result}</div>`);  // VULNERABLE
});

// ============================================================================
// ARRAY TRANSFORMATIONS - XSS
// ============================================================================

// [TP-ARR-001] Array.from
app.get('/array-from', (req, res) => {
    const input = req.query.data;
    const arr = Array.from(input);  // String to array of chars
    const str = arr.join('');
    res.send(`<p>${str}</p>`);  // VULNERABLE
});

// [TP-ARR-002] Array spread
app.get('/array-spread', (req, res) => {
    const input = req.query.data;
    const arr = [...input];  // Spread string to chars
    const str = arr.join('');
    res.send(`<div>${str}</div>`);  // VULNERABLE
});

// [TP-ARR-003] reverse doesn't sanitize
app.get('/reverse', (req, res) => {
    const input = req.query.data;
    const reversed = input.split('').reverse().join('');
    res.send(`<span>${reversed}</span>`);  // VULNERABLE
});

// [TP-ARR-004] sort doesn't sanitize
app.get('/sort', (req, res) => {
    const items = req.query.items.split(',');
    const sorted = items.sort();
    res.send(`<ul>${sorted.map(i => `<li>${i}</li>`).join('')}</ul>`);  // VULNERABLE
});

// [TP-ARR-005] flat/flatMap
app.post('/flat', (req, res) => {
    const nested = req.body.data;  // [[a, b], [c, d]]
    const flat = nested.flat();
    res.send(`<p>${flat.join(', ')}</p>`);  // VULNERABLE
});

// ============================================================================
// REGEX TRANSFORMATIONS - XSS
// ============================================================================

// [TP-REGEX-001] replace with non-sanitizing pattern
app.get('/regex-replace', (req, res) => {
    const input = req.query.data;
    const cleaned = input.replace(/\s+/g, ' ');  // Only removes extra spaces
    res.send(`<p>${cleaned}</p>`);  // VULNERABLE
});

// [TP-REGEX-002] match extracts tainted data
app.get('/regex-match', (req, res) => {
    const input = req.query.data;
    const matches = input.match(/\w+/g);  // Extracts words, still tainted
    if (matches) {
        res.send(`<div>${matches.join(' ')}</div>`);  // VULNERABLE
    }
});

// [TP-REGEX-003] split on regex
app.get('/regex-split', (req, res) => {
    const input = req.query.data;
    const parts = input.split(/[,;]/);  // Split on delimiters
    res.send(`<ul>${parts.map(p => `<li>${p}</li>`).join('')}</ul>`);  // VULNERABLE
});

// ============================================================================
// OBJECT TRANSFORMATIONS - PP
// ============================================================================

// [TP-OBJ-001] Object.entries iteration
app.post('/obj-entries', (req, res) => {
    const data = req.body;
    const target = {};
    for (const [key, value] of Object.entries(data)) {
        target[key] = value;  // VULNERABLE: still copies __proto__ if present
    }
    res.json(target);
});

// [TP-OBJ-002] Object.fromEntries
app.post('/obj-fromentries', (req, res) => {
    const entries = req.body.entries;  // [[key, val], ...]
    const obj = Object.fromEntries(entries);  // VULNERABLE if entries has __proto__
    res.json(obj);
});

// [TP-OBJ-003] Object.setPrototypeOf
app.post('/setprototype', (req, res) => {
    const proto = req.body.proto;
    const obj = {};
    Object.setPrototypeOf(obj, proto);  // VULNERABLE: user controls prototype
    res.json(obj);
});

// [TP-OBJ-004] Reflect.set
app.post('/reflect-set', (req, res) => {
    const { target, key, value } = req.body;
    const obj = {};
    Reflect.set(obj, key, value);  // VULNERABLE: user controls key
    res.json(obj);
});

// [TP-OBJ-005] Object.create with properties
app.post('/obj-create', (req, res) => {
    const props = req.body.props;
    const obj = Object.create({}, props);  // User controls property descriptors
    res.json(obj);
});

// ============================================================================
// TEMPLATE TRANSFORMATIONS - XSS
// ============================================================================

// [TP-TPL-001] Template literal without sanitization
app.get('/template-basic', (req, res) => {
    const name = req.query.name;
    const html = `<h1>Welcome, ${name}!</h1>`;
    res.send(html);  // VULNERABLE
});

// [TP-TPL-002] Nested template literals
app.get('/template-nested', (req, res) => {
    const user = req.query.user;
    const role = req.query.role;
    const html = `<div>${`<span>${user}</span> - <em>${role}</em>`}</div>`;
    res.send(html);  // VULNERABLE
});

// [TP-TPL-003] Template with expression
app.get('/template-expr', (req, res) => {
    const items = req.query.items.split(',');
    const html = `<ul>${items.map(i => `<li>${i}</li>`).join('')}</ul>`;
    res.send(html);  // VULNERABLE
});

// ============================================================================
// FALSE POSITIVES - SAFE TRANSFORMATIONS
// ============================================================================

// [FP-SAFE-001] encodeURIComponent output (safe for URL context)
app.get('/safe-encode', (req, res) => {
    const input = req.query.data;
    const encoded = encodeURIComponent(input);
    res.send(`<a href="?q=${encoded}">Link</a>`);  // SAFER: encoded for URL
});

// [FP-SAFE-002] HTML entity encoding
app.get('/safe-entities', (req, res) => {
    const input = req.query.data;
    const safe = input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    res.send(`<p>${safe}</p>`);  // SAFE: properly escaped
});

// [FP-SAFE-003] parseInt for numeric only
app.get('/safe-parseint', (req, res) => {
    const input = req.query.num;
    const num = parseInt(input, 10);
    if (!isNaN(num)) {
        res.send(`<p>Number: ${num}</p>`);  // SAFER: converted to number
    }
});

// [FP-SAFE-004] JSON response (not HTML context)
app.get('/safe-json', (req, res) => {
    const data = req.query.data;
    res.json({ value: data });  // SAFE: JSON encoding
});

// [FP-SAFE-005] Text content type
app.get('/safe-text', (req, res) => {
    res.type('text/plain');
    res.send(req.query.data);  // SAFER: plain text, no HTML parsing
});

app.listen(3000);
