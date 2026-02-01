/**
 * Advanced Node.js/Express.js XSS and Prototype Pollution Test Cases
 * =====================================================================
 * ES6+ syntax patterns for scanner validation
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected (safe code)
 */

const express = require('express');
const app = express();
app.use(express.json());

// ============================================================================
// ES6 DESTRUCTURING - XSS
// ============================================================================

// [TP-DESTRUCT-001] Destructured query XSS
app.get('/destruct1', (req, res) => {
    const { name } = req.query;
    res.send(`<h1>Hello ${name}</h1>`);  // VULNERABLE: destructured query in template literal
});

// [TP-DESTRUCT-002] Nested destructuring XSS
app.post('/destruct2', (req, res) => {
    const { user: { name, bio } } = req.body;
    res.send(`<div>${bio}</div>`);  // VULNERABLE: nested destructured body
});

// [TP-DESTRUCT-003] Destructured params XSS
app.get('/user/:id', (req, res) => {
    const { id } = req.params;
    res.send(`<a href="/profile/${id}">Profile ${id}</a>`);  // VULNERABLE
});

// [TP-DESTRUCT-004] Destructured with default XSS
app.get('/greet', (req, res) => {
    const { name = 'Guest' } = req.query;
    res.send(`<p>Welcome ${name}</p>`);  // VULNERABLE: default doesn't sanitize
});

// [TP-DESTRUCT-005] Destructured rename XSS
app.get('/alias', (req, res) => {
    const { q: searchTerm } = req.query;
    res.send(`<div>Searching: ${searchTerm}</div>`);  // VULNERABLE
});

// ============================================================================
// ES6 DESTRUCTURING - PROTOTYPE POLLUTION
// ============================================================================

// [TP-DESTRUCT-PP-001] Spread with destructured object
app.post('/spread-destruct', (req, res) => {
    const { settings } = req.body;
    const merged = { ...settings };  // VULNERABLE: spreading nested req.body property
    res.json(merged);
});

// [TP-DESTRUCT-PP-002] Object.assign with destructured
app.post('/assign-destruct', (req, res) => {
    const { config } = req.body;
    const serverConfig = { debug: false };
    Object.assign(serverConfig, config);  // VULNERABLE
    res.json(serverConfig);
});

// ============================================================================
// ARRAY METHOD TAINT FLOW - XSS
// ============================================================================

// [TP-ARRAY-001] Array join XSS
app.get('/array-join', (req, res) => {
    const items = [req.query.a, req.query.b, req.query.c];
    const output = items.join(' - ');  // Taint propagates through join
    res.send(`<ul>${output}</ul>`);  // VULNERABLE
});

// [TP-ARRAY-002] Array map XSS
app.get('/array-map', (req, res) => {
    const tags = req.query.tags.split(',');
    const html = tags.map(t => `<span>${t}</span>`).join('');  // VULNERABLE
    res.send(html);
});

// [TP-ARRAY-003] Array reduce XSS
app.get('/array-reduce', (req, res) => {
    const parts = ['<div>', req.query.content, '</div>'];
    const html = parts.reduce((acc, part) => acc + part, '');  // VULNERABLE
    res.send(html);
});

// [TP-ARRAY-004] Array filter then output XSS
app.post('/array-filter', (req, res) => {
    const items = req.body.items;
    const filtered = items.filter(x => x.active);
    const output = filtered.map(x => x.name).join(', ');  // VULNERABLE
    res.send(`<p>Active: ${output}</p>`);
});

// [TP-ARRAY-005] Array concat XSS
app.get('/array-concat', (req, res) => {
    const prefix = ['Search: '];
    const userInput = [req.query.q];
    const combined = prefix.concat(userInput).join('');  // VULNERABLE
    res.send(combined);
});

// ============================================================================
// STRING METHOD TAINT FLOW - XSS
// ============================================================================

// [TP-STRING-001] String replace (non-sanitizing) XSS
app.get('/str-replace', (req, res) => {
    const input = req.query.text;
    const processed = input.replace('foo', 'bar');  // Still tainted
    res.send(`<p>${processed}</p>`);  // VULNERABLE
});

// [TP-STRING-002] String trim XSS
app.get('/str-trim', (req, res) => {
    const input = req.query.text.trim();  // trim doesn't sanitize
    res.send(`<div>${input}</div>`);  // VULNERABLE
});

// [TP-STRING-003] String toLowerCase XSS
app.get('/str-lower', (req, res) => {
    const input = req.query.name.toLowerCase();
    res.send(`<span>${input}</span>`);  // VULNERABLE
});

// [TP-STRING-004] String split then join XSS
app.get('/str-split-join', (req, res) => {
    const input = req.query.data;
    const parts = input.split(',');
    const joined = parts.join(' | ');  // Taint preserved through split/join
    res.send(`<pre>${joined}</pre>`);  // VULNERABLE
});

// [TP-STRING-005] String substring XSS
app.get('/str-substr', (req, res) => {
    const full = req.query.text;
    const partial = full.substring(0, 50);  // Still tainted
    res.send(`<code>${partial}</code>`);  // VULNERABLE
});

// [TP-STRING-006] Template literal with expression XSS
app.get('/template-expr', (req, res) => {
    const { x, y } = req.query;
    const result = `${x} + ${y} = ${parseInt(x) + parseInt(y)}`;  // VULNERABLE
    res.send(`<p>${result}</p>`);
});

// ============================================================================
// DYNAMIC PROPERTY ACCESS - PROTOTYPE POLLUTION / RCE
// ============================================================================

// [TP-DYNAMIC-001] Dynamic property access for function call
app.get('/dynamic-call', (req, res) => {
    const actions = {
        greet: () => 'Hello',
        bye: () => 'Goodbye'
    };
    const action = req.query.action;
    const result = actions[action]();  // VULNERABLE: can access constructor
    res.send(result);
});

// [TP-DYNAMIC-002] Dynamic property access with params
app.get('/dynamic-method/:method', (req, res) => {
    const methods = {
        upper: s => s.toUpperCase(),
        lower: s => s.toLowerCase()
    };
    const method = req.params.method;
    const data = req.query.data;
    const result = methods[method](data);  // VULNERABLE
    res.send(result);
});

// [TP-DYNAMIC-003] Dynamic property assignment
app.post('/dynamic-set', (req, res) => {
    const obj = {};
    const key = req.body.key;
    const value = req.body.value;
    obj[key] = value;  // VULNERABLE: prototype pollution
    res.json(obj);
});

// [TP-DYNAMIC-004] Dynamic nested property access
app.post('/dynamic-nested', (req, res) => {
    const config = { db: {}, cache: {} };
    const section = req.body.section;
    const key = req.body.key;
    const val = req.body.val;
    config[section][key] = val;  // VULNERABLE: nested pollution
    res.json(config);
});

// ============================================================================
// SPREAD OPERATOR - PROTOTYPE POLLUTION
// ============================================================================

// [TP-SPREAD-001] Direct spread of req.body
app.post('/spread-body', (req, res) => {
    const data = { ...req.body };  // VULNERABLE
    res.json(data);
});

// [TP-SPREAD-002] Spread in function return
app.post('/spread-func', (req, res) => {
    const createUser = (input) => ({ id: 1, ...input });  // VULNERABLE
    const user = createUser(req.body);
    res.json(user);
});

// [TP-SPREAD-003] Spread with additional props
app.post('/spread-extra', (req, res) => {
    const merged = {
        timestamp: Date.now(),
        ...req.body,  // VULNERABLE
        processed: true
    };
    res.json(merged);
});

// [TP-SPREAD-004] Nested spread
app.post('/spread-nested', (req, res) => {
    const { data } = req.body;
    const inner = { ...data };  // VULNERABLE: nested property spread
    const outer = { inner };
    res.json(outer);
});

// [TP-SPREAD-005] Spread in array context
app.post('/spread-array', (req, res) => {
    const items = req.body.items;
    const allItems = [...items];  // Could contain objects with __proto__
    res.json(allItems);
});

// ============================================================================
// FOR-IN LOOP - PROTOTYPE POLLUTION
// ============================================================================

// [TP-FORIN-001] Classic for-in pollution
app.post('/forin-classic', (req, res) => {
    const result = {};
    for (const key in req.body) {
        result[key] = req.body[key];  // VULNERABLE
    }
    res.json(result);
});

// [TP-FORIN-002] For-in with destructured source
app.post('/forin-destruct', (req, res) => {
    const { updates } = req.body;
    const config = { debug: false };
    for (const prop in updates) {
        config[prop] = updates[prop];  // VULNERABLE
    }
    res.json(config);
});

// [TP-FORIN-003] For-in nested assignment
app.post('/forin-nested', (req, res) => {
    const settings = { ui: {}, api: {} };
    const { section, values } = req.body;
    for (const k in values) {
        settings[section][k] = values[k];  // VULNERABLE
    }
    res.json(settings);
});

// [FP-FORIN-001] For-in with hasOwnProperty check
app.post('/forin-safe-hop', (req, res) => {
    const result = {};
    for (const key in req.body) {
        if (req.body.hasOwnProperty(key)) {
            result[key] = req.body[key];  // SAFER: hasOwnProperty check
        }
    }
    res.json(result);
});

// [FP-FORIN-002] For-in with Object.hasOwn check
app.post('/forin-safe-hasown', (req, res) => {
    const result = {};
    for (const key in req.body) {
        if (Object.hasOwn(req.body, key)) {
            result[key] = req.body[key];  // SAFE: Object.hasOwn check
        }
    }
    res.json(result);
});

// [FP-FORIN-003] Using Object.keys instead
app.post('/forin-safe-keys', (req, res) => {
    const result = {};
    Object.keys(req.body).forEach(key => {
        result[key] = req.body[key];  // SAFE: Object.keys doesn't include prototype
    });
    res.json(result);
});

// ============================================================================
// LODASH/UNDERSCORE - PROTOTYPE POLLUTION
// ============================================================================

// [TP-LODASH-001] _.merge with req.body
app.post('/lodash-merge', (req, res) => {
    const defaults = { admin: false };
    const config = _.merge(defaults, req.body);  // VULNERABLE
    res.json(config);
});

// [TP-LODASH-002] _.defaultsDeep with destructured
app.post('/lodash-defaults', (req, res) => {
    const { settings } = req.body;
    const base = { theme: 'light' };
    _.defaultsDeep(base, settings);  // VULNERABLE
    res.json(base);
});

// [TP-LODASH-003] _.set with user path
app.post('/lodash-set', (req, res) => {
    const obj = {};
    const { path, value } = req.body;
    _.set(obj, path, value);  // VULNERABLE: path can be "__proto__.polluted"
    res.json(obj);
});

// ============================================================================
// WEBSOCKET - XSS (broadcast patterns)
// ============================================================================

// [TP-WS-001] Socket.io broadcast user message
io.on('connection', (socket) => {
    socket.on('chat', (message) => {
        io.emit('message', message);  // VULNERABLE: broadcasts user input
    });
});

// [TP-WS-002] Socket.io with destructuring
io.on('connection', (socket) => {
    socket.on('post', ({ title, content }) => {
        io.emit('newPost', { title, content });  // VULNERABLE: user content broadcast
    });
});

// [TP-WS-003] Socket.io user-controlled event name
io.on('connection', (socket) => {
    socket.on('trigger', (data) => {
        socket.emit(data.event, data.payload);  // VULNERABLE: event name injection
    });
});

// ============================================================================
// RESPONSE METHODS - XSS
// ============================================================================

// [TP-RES-001] res.write with user input
app.get('/res-write', (req, res) => {
    const { chunk } = req.query;
    res.write(`<p>${chunk}</p>`);  // VULNERABLE
    res.end();
});

// [TP-RES-002] res.end with content
app.get('/res-end', (req, res) => {
    const { msg } = req.query;
    res.end(`<div>${msg}</div>`);  // VULNERABLE
});

// [TP-RES-003] Multiple res.write calls
app.get('/res-multi', (req, res) => {
    res.write('<html><body>');
    res.write(`<h1>${req.query.title}</h1>`);  // VULNERABLE
    res.write(`<p>${req.query.content}</p>`);  // VULNERABLE
    res.write('</body></html>');
    res.end();
});

// ============================================================================
// TEMPLATE ENGINE - XSS
// ============================================================================

// [TP-TPL-001] EJS render with user input
app.get('/ejs-render', (req, res) => {
    const { name, bio } = req.query;
    res.render('profile', { name, bio });  // VULNERABLE if template uses <%- %>
});

// [TP-TPL-002] Pug render with user input
app.get('/pug-render', (req, res) => {
    const content = req.body.content;
    res.render('page.pug', { content });  // VULNERABLE if template uses != operator
});

// ============================================================================
// FALSE POSITIVES - SAFE PATTERNS
// ============================================================================

// [FP-SAFE-001] JSON response (auto-escaped)
app.get('/safe-json', (req, res) => {
    res.json({ data: req.query.data });  // SAFE: JSON encoding
});

// [FP-SAFE-002] Text response
app.get('/safe-text', (req, res) => {
    res.type('text/plain');
    res.send(req.query.data);  // SAFER: plain text content type
});

// [FP-SAFE-003] Sanitized HTML output
app.get('/safe-sanitized', (req, res) => {
    const input = req.query.data;
    const safe = sanitizeHtml(input);  // Sanitized
    res.send(`<div>${safe}</div>`);  // SAFE: sanitized
});

// [FP-SAFE-004] Escaped output
app.get('/safe-escaped', (req, res) => {
    const input = escapeHtml(req.query.data);
    res.send(`<p>${input}</p>`);  // SAFE: escaped
});

// [FP-SAFE-005] DOMPurify sanitized
app.get('/safe-purify', (req, res) => {
    const input = req.body.html;
    const clean = DOMPurify.sanitize(input);
    res.send(clean);  // SAFE: DOMPurify sanitized
});

// [FP-SAFE-006] Spread on Object.create(null)
app.post('/safe-spread-null', (req, res) => {
    const base = Object.create(null);
    Object.assign(base, req.body);  // SAFER: null prototype target
    res.json(base);
});

app.listen(3000);
