/**
 * JSHunter Comprehensive Test Cases
 * ==================================
 * Patterns to test JavaScript vulnerability detection
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected
 */

const express = require('express');
const fs = require('fs');
const { exec, spawn, execSync } = require('child_process');
const path = require('path');
const app = express();
app.use(express.json());

// ============================================================================
// SECTION 1: DIRECT XSS PATTERNS (Basic - Should all be detected)
// ============================================================================

// [TP-XSS-001] Direct query param to res.send
app.get('/xss/direct', (req, res) => {
    res.send(req.query.input);  // VULNERABLE
});

// [TP-XSS-002] Template literal XSS
app.get('/xss/template', (req, res) => {
    const name = req.query.name;
    res.send(`<h1>Hello ${name}</h1>`);  // VULNERABLE
});

// [TP-XSS-003] String concatenation XSS
app.get('/xss/concat', (req, res) => {
    res.send('<div>' + req.query.msg + '</div>');  // VULNERABLE
});

// [TP-XSS-004] Body param XSS
app.post('/xss/body', (req, res) => {
    res.send(`<p>${req.body.content}</p>`);  // VULNERABLE
});

// [TP-XSS-005] Route param XSS
app.get('/xss/user/:id', (req, res) => {
    res.send(`<span>User: ${req.params.id}</span>`);  // VULNERABLE
});

// [TP-XSS-006] Header injection to response
app.get('/xss/header', (req, res) => {
    const userAgent = req.headers['user-agent'];
    res.send(`<p>Your browser: ${userAgent}</p>`);  // VULNERABLE
});

// [TP-XSS-007] Cookie value XSS
app.get('/xss/cookie', (req, res) => {
    res.send(`<div>${req.cookies.session}</div>`);  // VULNERABLE
});

// ============================================================================
// SECTION 2: INTER-PROCEDURAL XSS (Function calls with tainted data)
// ============================================================================

// [TP-XSS-010] Helper function returning HTML
function createCard(title) {
    return `<div class="card"><h2>${title}</h2></div>`;
}

app.get('/xss/helper', (req, res) => {
    const html = createCard(req.query.title);
    res.send(html);  // VULNERABLE: taint flows through createCard
});

// [TP-XSS-011] Multiple wrapper functions
function wrap(content) {
    return `<section>${content}</section>`;
}

function render(data) {
    return wrap(data);
}

app.get('/xss/multi-wrap', (req, res) => {
    const output = render(req.query.data);
    res.send(output);  // VULNERABLE: taint through render -> wrap
});

// [TP-XSS-012] Arrow function helper
const formatMessage = (msg) => `<p class="message">${msg}</p>`;

app.get('/xss/arrow', (req, res) => {
    res.send(formatMessage(req.query.msg));  // VULNERABLE
});

// [TP-XSS-013] Method on object
const htmlHelper = {
    paragraph: (text) => `<p>${text}</p>`,
    heading: (text) => `<h1>${text}</h1>`
};

app.get('/xss/method', (req, res) => {
    res.send(htmlHelper.heading(req.query.title));  // VULNERABLE
});

// [TP-XSS-014] Class method
class TemplateEngine {
    static render(template, data) {
        return `<div>${data}</div>`;
    }
}

app.get('/xss/class', (req, res) => {
    res.send(TemplateEngine.render('user', req.query.user));  // VULNERABLE
});

// [TP-XSS-015] Callback pattern
function processAndRespond(input, callback) {
    const processed = `<result>${input}</result>`;
    callback(processed);
}

app.get('/xss/callback', (req, res) => {
    processAndRespond(req.query.data, (html) => {
        res.send(html);  // VULNERABLE
    });
});

// ============================================================================
// SECTION 3: SINK ALIASING (res.send assigned to variable)
// ============================================================================

// [TP-XSS-020] Basic sink aliasing
app.get('/xss/alias', (req, res) => {
    const output = res.send.bind(res);
    output(req.query.data);  // VULNERABLE
});

// [TP-XSS-021] Destructured sink
app.get('/xss/destruct-sink', (req, res) => {
    const { send } = res;
    send.call(res, req.query.data);  // VULNERABLE
});

// [TP-XSS-022] Sink in wrapper object
app.get('/xss/wrapped-sink', (req, res) => {
    const responder = { emit: res.send.bind(res) };
    responder.emit(`<div>${req.query.msg}</div>`);  // VULNERABLE
});

// ============================================================================
// SECTION 4: PROTOTYPE POLLUTION PATTERNS
// ============================================================================

// [TP-PP-001] Direct bracket notation with user key
app.post('/pp/direct', (req, res) => {
    const config = {};
    const { key, value } = req.body;
    config[key] = value;  // VULNERABLE: user controls key
    res.json(config);
});

// [TP-PP-002] For-in loop copying
app.post('/pp/forin', (req, res) => {
    const target = {};
    for (const k in req.body) {
        target[k] = req.body[k];  // VULNERABLE
    }
    res.json(target);
});

// [TP-PP-003] Object.assign with user data
app.post('/pp/assign', (req, res) => {
    const defaults = { admin: false };
    const merged = Object.assign(defaults, req.body);  // VULNERABLE
    res.json(merged);
});

// [TP-PP-004] Spread operator pollution
app.post('/pp/spread', (req, res) => {
    const user = { role: 'guest', ...req.body };  // VULNERABLE
    res.json(user);
});

// [TP-PP-005] Nested property setting
app.post('/pp/nested', (req, res) => {
    const obj = {};
    const { path, val } = req.body;
    const parts = path.split('.');
    let current = obj;
    for (let i = 0; i < parts.length - 1; i++) {
        current[parts[i]] = current[parts[i]] || {};
        current = current[parts[i]];
    }
    current[parts[parts.length - 1]] = val;  // VULNERABLE: deep pollution
    res.json(obj);
});

// [TP-PP-006] Function parameter pollution (like applyPatch in ghost.js)
function merge(target, source) {
    for (const key in source) {
        target[key] = source[key];  // VULNERABLE
    }
    return target;
}

app.post('/pp/func-merge', (req, res) => {
    const settings = { debug: false };
    merge(settings, req.body);  // Calls vulnerable function with req.body
    res.json(settings);
});

// [TP-PP-007] Recursive deep merge
function deepMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            deepMerge(target[key], source[key]);  // VULNERABLE: recursive
        } else {
            target[key] = source[key];  // VULNERABLE
        }
    }
    return target;
}

app.post('/pp/deep', (req, res) => {
    const config = { settings: {} };
    deepMerge(config, req.body);
    res.json(config);
});

// [TP-PP-008] Array reduce building object
app.post('/pp/reduce', (req, res) => {
    const entries = req.body.entries;  // [[key, val], ...]
    const obj = entries.reduce((acc, [k, v]) => {
        acc[k] = v;  // VULNERABLE
        return acc;
    }, {});
    res.json(obj);
});

// [TP-PP-009] Object.defineProperty with user key
app.post('/pp/defineprop', (req, res) => {
    const obj = {};
    const { prop, val } = req.body;
    Object.defineProperty(obj, prop, { value: val, writable: true });  // VULNERABLE
    res.json(obj);
});

// [TP-PP-010] Object.setPrototypeOf
app.post('/pp/setproto', (req, res) => {
    const obj = {};
    Object.setPrototypeOf(obj, req.body.proto);  // VULNERABLE
    res.json(obj);
});

// ============================================================================
// SECTION 5: PATH TRAVERSAL (LFI/LFW)
// ============================================================================

// [TP-LFI-001] Direct readFile with user input
app.get('/lfi/read', (req, res) => {
    fs.readFile(req.query.file, 'utf8', (err, data) => {
        if (err) return res.status(500).send('Error');
        res.send(data);  // VULNERABLE
    });
});

// [TP-LFI-002] readFileSync
app.get('/lfi/sync', (req, res) => {
    const content = fs.readFileSync(req.query.path, 'utf8');  // VULNERABLE
    res.send(content);
});

// [TP-LFI-003] createReadStream
app.get('/lfi/stream', (req, res) => {
    const stream = fs.createReadStream(req.query.file);  // VULNERABLE
    stream.pipe(res);
});

// [TP-LFI-004] Path concatenation (partial)
app.get('/lfi/concat', (req, res) => {
    const filepath = './uploads/' + req.query.name;  // VULNERABLE: path traversal
    fs.readFile(filepath, (err, data) => {
        res.send(data);
    });
});

// [TP-LFI-005] Template literal path
app.get('/lfi/template', (req, res) => {
    fs.readFile(`./data/${req.query.id}.json`, 'utf8', (err, data) => {  // VULNERABLE
        res.json(JSON.parse(data));
    });
});

// [TP-LFW-006] writeFile with user path
app.post('/lfw/write', (req, res) => {
    fs.writeFile(req.body.path, req.body.content, (err) => {  // VULNERABLE
        res.send(err ? 'Error' : 'Written');
    });
});

// [TP-LFI-007] readdir listing
app.get('/lfi/dir', (req, res) => {
    fs.readdir(req.query.dir, (err, files) => {  // VULNERABLE
        res.json(files);
    });
});

// [TP-LFI-008] stat/lstat
app.get('/lfi/stat', (req, res) => {
    fs.stat(req.query.path, (err, stats) => {  // VULNERABLE
        res.json(stats);
    });
});

// ============================================================================
// SECTION 6: COMMAND INJECTION
// ============================================================================

// [TP-CMD-001] exec with user input
app.get('/cmd/exec', (req, res) => {
    exec(`ls ${req.query.dir}`, (err, stdout) => {  // VULNERABLE
        res.send(stdout);
    });
});

// [TP-CMD-002] execSync
app.get('/cmd/sync', (req, res) => {
    const output = execSync(`cat ${req.query.file}`);  // VULNERABLE
    res.send(output);
});

// [TP-CMD-003] spawn with user args
app.get('/cmd/spawn', (req, res) => {
    const proc = spawn('grep', [req.query.pattern, '/var/log/app.log']);  // VULNERABLE
    proc.stdout.pipe(res);
});

// [TP-CMD-004] spawn with shell option
app.get('/cmd/shell', (req, res) => {
    spawn(req.query.cmd, { shell: true });  // VULNERABLE
    res.send('Executed');
});

// [TP-CMD-005] Template in exec
app.post('/cmd/template', (req, res) => {
    exec(`echo "${req.body.message}"`, (err, out) => {  // VULNERABLE
        res.send(out);
    });
});

// ============================================================================
// SECTION 7: EVAL AND CODE INJECTION
// ============================================================================

// [TP-EVAL-001] Direct eval
app.get('/eval/direct', (req, res) => {
    const result = eval(req.query.code);  // VULNERABLE
    res.send(String(result));
});

// [TP-EVAL-002] new Function
app.get('/eval/function', (req, res) => {
    const fn = new Function('x', req.query.body);  // VULNERABLE
    res.send(String(fn(5)));
});

// [TP-EVAL-003] setTimeout with string
app.get('/eval/timeout', (req, res) => {
    setTimeout(req.query.code, 1000);  // VULNERABLE
    res.send('Scheduled');
});

// [TP-EVAL-004] setInterval with string
app.get('/eval/interval', (req, res) => {
    setInterval(req.query.code, 1000);  // VULNERABLE
    res.send('Running');
});

// [TP-EVAL-005] vm.runInContext (if using vm module)
// const vm = require('vm');
// app.get('/eval/vm', (req, res) => {
//     vm.runInNewContext(req.query.code);  // VULNERABLE
// });

// ============================================================================
// SECTION 8: SSRF PATTERNS
// ============================================================================

// [TP-SSRF-001] fetch with user URL
app.get('/ssrf/fetch', async (req, res) => {
    const response = await fetch(req.query.url);  // VULNERABLE
    const data = await response.text();
    res.send(data);
});

// [TP-SSRF-002] axios with user URL
// const axios = require('axios');
// app.get('/ssrf/axios', async (req, res) => {
//     const { data } = await axios.get(req.query.url);  // VULNERABLE
//     res.json(data);
// });

// ============================================================================
// SECTION 9: COMPLEX TAINT FLOWS
// ============================================================================

// [TP-FLOW-001] Through array operations
app.get('/flow/array', (req, res) => {
    const items = req.query.items.split(',');
    const mapped = items.map(i => `<li>${i}</li>`);
    const html = `<ul>${mapped.join('')}</ul>`;
    res.send(html);  // VULNERABLE: taint through split->map->join
});

// [TP-FLOW-002] Through object property
app.get('/flow/object', (req, res) => {
    const data = { message: req.query.msg };
    res.send(`<p>${data.message}</p>`);  // VULNERABLE
});

// [TP-FLOW-003] Through destructuring
app.get('/flow/destruct', (req, res) => {
    const { name, email } = req.query;
    res.send(`<div>${name} - ${email}</div>`);  // VULNERABLE
});

// [TP-FLOW-004] Through ternary
app.get('/flow/ternary', (req, res) => {
    const value = req.query.x ? req.query.x : req.query.y;
    res.send(`<span>${value}</span>`);  // VULNERABLE: both branches tainted
});

// [TP-FLOW-005] Through logical OR
app.get('/flow/or', (req, res) => {
    const msg = req.query.msg || 'default';
    res.send(`<p>${msg}</p>`);  // VULNERABLE if msg exists
});

// [TP-FLOW-006] Through async/await
app.get('/flow/async', async (req, res) => {
    const process = async (x) => x.toUpperCase();
    const result = await process(req.query.data);
    res.send(`<div>${result}</div>`);  // VULNERABLE
});

// [TP-FLOW-007] Through Promise.then
app.get('/flow/promise', (req, res) => {
    Promise.resolve(req.query.data)
        .then(d => d.trim())
        .then(d => res.send(`<p>${d}</p>`));  // VULNERABLE
});

// [TP-FLOW-008] Through try-catch
app.get('/flow/trycatch', (req, res) => {
    try {
        const data = req.query.input;
        res.send(`<div>${data}</div>`);  // VULNERABLE
    } catch (e) {
        res.send('Error');
    }
});

// ============================================================================
// SECTION 10: FALSE POSITIVES (Should NOT be detected)
// ============================================================================

// [FP-001] Properly escaped output
app.get('/safe/escaped', (req, res) => {
    const input = req.query.data;
    const safe = input
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
    res.send(`<p>${safe}</p>`);  // SAFE: properly escaped
});

// [FP-002] JSON response (not HTML context)
app.get('/safe/json', (req, res) => {
    res.json({ data: req.query.data });  // SAFE: JSON encoding
});

// [FP-003] Number-only after parseInt
app.get('/safe/number', (req, res) => {
    const num = parseInt(req.query.id, 10);
    if (!isNaN(num)) {
        res.send(`<p>ID: ${num}</p>`);  // SAFER: converted to number
    }
});

// [FP-004] Whitelist validation
app.get('/safe/whitelist', (req, res) => {
    const allowed = ['home', 'about', 'contact'];
    const page = req.query.page;
    if (allowed.includes(page)) {
        res.send(`<h1>${page}</h1>`);  // SAFE: whitelisted
    }
});

// [FP-005] Regex validation
app.get('/safe/regex', (req, res) => {
    const id = req.query.id;
    if (/^[a-zA-Z0-9]+$/.test(id)) {
        res.send(`<p>${id}</p>`);  // SAFER: alphanumeric only
    }
});

// [FP-006] Path with basename
app.get('/safe/path', (req, res) => {
    const filename = path.basename(req.query.file);  // Strips directory traversal
    fs.readFile(`./uploads/${filename}`, (err, data) => {
        res.send(data);  // SAFER: basename used
    });
});

// [FP-007] Constant only
app.get('/safe/constant', (req, res) => {
    res.send('<h1>Welcome</h1>');  // SAFE: no user input
});

// [FP-008] Prototype pollution blocked keys
app.post('/safe/pp', (req, res) => {
    const BLOCKED = ['__proto__', 'constructor', 'prototype'];
    const result = {};
    for (const key in req.body) {
        if (!BLOCKED.includes(key) && Object.hasOwn(req.body, key)) {
            result[key] = req.body[key];  // SAFER: blocked keys filtered
        }
    }
    res.json(result);
});

// [FP-009] encodeURIComponent for URL
app.get('/safe/url', (req, res) => {
    const query = encodeURIComponent(req.query.search);
    res.send(`<a href="/search?q=${query}">Search</a>`);  // SAFER: URL encoded
});

// [FP-010] Text content type
app.get('/safe/text', (req, res) => {
    res.type('text/plain');
    res.send(req.query.data);  // SAFER: plain text, no HTML parsing
});

app.listen(3000);
