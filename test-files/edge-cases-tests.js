/**
 * Edge Cases and Tricky Patterns - XSS and Prototype Pollution
 * =============================================================
 * These patterns are designed to test scanner accuracy on complex flows
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected
 */

const express = require('express');
const app = express();

// ============================================================================
// INDIRECT TAINT FLOW - Multiple hops
// ============================================================================

// [TP-INDIRECT-001] Three-hop taint flow
app.get('/hop3', (req, res) => {
    const a = req.query.x;      // Hop 1: source
    const b = a;                // Hop 2: propagation
    const c = b;                // Hop 3: propagation
    res.send(`<p>${c}</p>`);    // VULNERABLE: 3-hop flow
});

// [TP-INDIRECT-002] Taint through function call
app.get('/func-flow', (req, res) => {
    const wrap = (s) => s;      // Identity function
    const input = req.query.data;
    const wrapped = wrap(input);
    res.send(`<div>${wrapped}</div>`);  // VULNERABLE
});

// [TP-INDIRECT-003] Taint through ternary
app.get('/ternary', (req, res) => {
    const flag = true;
    const data = flag ? req.query.a : req.query.b;
    res.send(`<span>${data}</span>`);  // VULNERABLE: both branches tainted
});

// [TP-INDIRECT-004] Taint through logical OR
app.get('/or-flow', (req, res) => {
    const val = req.query.val || 'default';  // Still tainted if val exists
    res.send(`<p>${val}</p>`);  // VULNERABLE
});

// [TP-INDIRECT-005] Taint through logical AND
app.get('/and-flow', (req, res) => {
    const val = req.query.val && req.query.val.trim();
    if (val) {
        res.send(`<p>${val}</p>`);  // VULNERABLE
    }
});

// ============================================================================
// OBJECT PROPERTY FLOW
// ============================================================================

// [TP-OBJ-001] Taint in object property
app.get('/obj-prop', (req, res) => {
    const data = { value: req.query.x };
    res.send(`<p>${data.value}</p>`);  // VULNERABLE
});

// [TP-OBJ-002] Computed property retrieval
app.get('/obj-computed', (req, res) => {
    const { key, val } = req.query;
    const obj = { [key]: val };
    res.send(`<p>${obj[key]}</p>`);  // VULNERABLE: both key and val tainted
});

// [TP-OBJ-003] Object method returning tainted data
app.get('/obj-method', (req, res) => {
    const wrapper = {
        data: req.query.input,
        get() { return this.data; }
    };
    res.send(`<div>${wrapper.get()}</div>`);  // VULNERABLE
});

// ============================================================================
// ARRAY COMPLEX FLOWS
// ============================================================================

// [TP-ARR-001] Spread in array
app.post('/arr-spread', (req, res) => {
    const items = [...req.body.items];
    const html = items.map(i => `<li>${i}</li>`).join('');
    res.send(`<ul>${html}</ul>`);  // VULNERABLE
});

// [TP-ARR-002] Array destructuring
app.get('/arr-destruct', (req, res) => {
    const parts = req.query.data.split(',');
    const [first, second] = parts;
    res.send(`<p>${first} - ${second}</p>`);  // VULNERABLE
});

// [TP-ARR-003] Array find then use
app.post('/arr-find', (req, res) => {
    const items = req.body.items;
    const found = items.find(x => x.id === 1);
    if (found) {
        res.send(`<div>${found.name}</div>`);  // VULNERABLE
    }
});

// [TP-ARR-004] Array at() method
app.get('/arr-at', (req, res) => {
    const parts = req.query.data.split('|');
    const last = parts.at(-1);
    res.send(`<span>${last}</span>`);  // VULNERABLE
});

// ============================================================================
// ASYNC PATTERNS
// ============================================================================

// [TP-ASYNC-001] Async/await flow
app.get('/async-flow', async (req, res) => {
    const processInput = async (x) => x;
    const input = req.query.data;
    const result = await processInput(input);
    res.send(`<p>${result}</p>`);  // VULNERABLE
});

// [TP-ASYNC-002] Promise chain
app.get('/promise-chain', (req, res) => {
    const input = req.query.data;
    Promise.resolve(input)
        .then(x => x.trim())
        .then(x => res.send(`<div>${x}</div>`));  // VULNERABLE
});

// ============================================================================
// CLOSURE PATTERNS
// ============================================================================

// [TP-CLOSURE-001] Tainted closure variable
app.get('/closure', (req, res) => {
    const tainted = req.query.data;
    const render = () => `<p>${tainted}</p>`;
    res.send(render());  // VULNERABLE
});

// [TP-CLOSURE-002] Factory with tainted input
app.get('/factory', (req, res) => {
    const createHtml = (content) => () => `<div>${content}</div>`;
    const htmlFn = createHtml(req.query.content);
    res.send(htmlFn());  // VULNERABLE
});

// ============================================================================
// PROTOTYPE POLLUTION - EDGE CASES
// ============================================================================

// [TP-PP-001] Constructor access
app.post('/constructor', (req, res) => {
    const obj = {};
    const { prop, val } = req.body;
    // obj['constructor']['prototype']['polluted'] = true
    obj[prop] = val;  // VULNERABLE: prop could be 'constructor'
    res.json(obj);
});

// [TP-PP-002] Multiple level nesting
app.post('/multi-nest', (req, res) => {
    const data = {};
    const { a, b, c, val } = req.body;
    data[a] = data[a] || {};
    data[a][b] = data[a][b] || {};
    data[a][b][c] = val;  // VULNERABLE: deep pollution path
    res.json(data);
});

// [TP-PP-003] Recursive merge
function deepMerge(target, source) {
    for (const key in source) {
        if (typeof source[key] === 'object') {
            target[key] = target[key] || {};
            deepMerge(target[key], source[key]);  // VULNERABLE: recursive
        } else {
            target[key] = source[key];  // VULNERABLE
        }
    }
    return target;
}

app.post('/recursive-merge', (req, res) => {
    const config = { safe: true };
    deepMerge(config, req.body);  // VULNERABLE
    res.json(config);
});

// [TP-PP-004] Spread then modify
app.post('/spread-modify', (req, res) => {
    const initial = { ...req.body };  // VULNERABLE: spread pollution
    initial.processed = true;
    res.json(initial);
});

// [TP-PP-005] Array method with pollution potential
app.post('/arr-reduce-pp', (req, res) => {
    const updates = req.body.updates;
    const merged = updates.reduce((acc, u) => {
        acc[u.key] = u.value;  // VULNERABLE: user controls keys
        return acc;
    }, {});
    res.json(merged);
});

// ============================================================================
// TRICKY FALSE NEGATIVES (Scanner might miss these)
// ============================================================================

// [TP-TRICKY-001] Taint through WeakMap
app.get('/weakmap', (req, res) => {
    const store = new WeakMap();
    const key = {};
    store.set(key, req.query.data);
    const val = store.get(key);
    res.send(`<p>${val}</p>`);  // VULNERABLE: taint through WeakMap
});

// [TP-TRICKY-002] Taint through Symbol
app.get('/symbol', (req, res) => {
    const sym = Symbol('data');
    const obj = { [sym]: req.query.data };
    res.send(`<p>${obj[sym]}</p>`);  // VULNERABLE
});

// [TP-TRICKY-003] Eval-like patterns
app.get('/indirect-eval', (req, res) => {
    const code = req.query.code;
    const fn = new Function('return ' + code);  // VULNERABLE: code injection
    res.send(`Result: ${fn()}`);
});

// [TP-TRICKY-004] setTimeout with string
app.get('/timeout-string', (req, res) => {
    const action = req.query.action;
    setTimeout(action, 0);  // VULNERABLE: string execution
    res.send('Scheduled');
});

// [TP-TRICKY-005] Assignment expression return
app.get('/assign-return', (req, res) => {
    let html;
    res.send(html = `<p>${req.query.x}</p>`);  // VULNERABLE
});

// ============================================================================
// COMPLEX SANITIZATION BYPASS ATTEMPTS (Should still detect)
// ============================================================================

// [TP-BYPASS-001] Partial replace (not sanitizing)
app.get('/partial-replace', (req, res) => {
    const input = req.query.data;
    const partial = input.replace('<script>', '');  // Not complete sanitization
    res.send(`<div>${partial}</div>`);  // VULNERABLE: still allows other vectors
});

// [TP-BYPASS-002] Only checking for one pattern
app.get('/single-check', (req, res) => {
    let input = req.query.data;
    if (!input.includes('<script>')) {
        res.send(`<div>${input}</div>`);  // VULNERABLE: other XSS vectors work
    }
});

// [TP-BYPASS-003] RegExp that doesn't match all
app.get('/regex-partial', (req, res) => {
    const input = req.query.data;
    const safe = input.replace(/<script>/g, '');  // Only removes <script>
    res.send(`<div>${safe}</div>`);  // VULNERABLE
});

// ============================================================================
// FALSE POSITIVES - Scanner should NOT flag these
// ============================================================================

// [FP-SAFE-001] Constant string only
app.get('/constant-only', (req, res) => {
    res.send('<h1>Hello World</h1>');  // SAFE: no user input
});

// [FP-SAFE-002] User input not in HTML context
app.get('/no-html', (req, res) => {
    const count = parseInt(req.query.count);
    res.json({ count });  // SAFE: JSON encoding
});

// [FP-SAFE-003] User input after validation
app.get('/validated', (req, res) => {
    const id = req.query.id;
    if (/^[0-9]+$/.test(id)) {
        res.send(`<p>ID: ${id}</p>`);  // SAFER: validated to digits only
    }
});

// [FP-SAFE-004] User input in safe context
app.get('/attr-safe', (req, res) => {
    const id = req.query.id;
    res.send(`<div data-id="${encodeURIComponent(id)}">Item</div>`);  // SAFE: encoded
});

// [FP-SAFE-005] Spread on validated object
app.post('/validated-spread', (req, res) => {
    const allowed = ['name', 'email'];
    const filtered = {};
    for (const key of allowed) {
        if (req.body[key]) {
            filtered[key] = req.body[key];
        }
    }
    const user = { ...filtered };  // SAFER: only allowed keys
    res.json(user);
});

// [FP-SAFE-006] For-in with explicit filter
app.post('/filtered-forin', (req, res) => {
    const BLOCKED = ['__proto__', 'constructor', 'prototype'];
    const result = {};
    for (const key in req.body) {
        if (!BLOCKED.includes(key) && req.body.hasOwnProperty(key)) {
            result[key] = req.body[key];  // SAFE: filtered and hasOwnProperty
        }
    }
    res.json(result);
});

app.listen(3001);
