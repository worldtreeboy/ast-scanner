/**
 * Inter-procedural Taint Flow Test Cases
 * ========================================
 * Tests for tracking taint through function calls, returns, and callbacks
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected
 */

const express = require('express');
const fs = require('fs');
const app = express();
app.use(express.json());

// ============================================================================
// SECTION 1: FUNCTION PARAMETER POLLUTION (Like ghost.js applyPatch)
// ============================================================================

// [TP-PARAM-001] For-in loop in function with tainted second param
function applyPatch(target, patch) {
    for (const key in patch) {
        target[key] = patch[key];  // VULNERABLE
    }
}

app.patch('/param/patch', (req, res) => {
    const settings = { theme: 'light' };
    applyPatch(settings, req.body);  // Taint flows to patch parameter
    res.json(settings);
});

// [TP-PARAM-002] Object.assign wrapper
function mergeConfig(base, updates) {
    return Object.assign(base, updates);  // VULNERABLE
}

app.post('/param/merge', (req, res) => {
    const config = mergeConfig({}, req.body);
    res.json(config);
});

// [TP-PARAM-003] Spread in function
function extendUser(user, extras) {
    return { ...user, ...extras };  // VULNERABLE
}

app.post('/param/spread', (req, res) => {
    const user = extendUser({ id: 1 }, req.body);
    res.json(user);
});

// [TP-PARAM-004] Recursive merge function
function deepSet(obj, path, value) {
    const keys = path.split('.');
    let current = obj;
    for (let i = 0; i < keys.length - 1; i++) {
        current[keys[i]] = current[keys[i]] || {};  // VULNERABLE
        current = current[keys[i]];
    }
    current[keys[keys.length - 1]] = value;  // VULNERABLE
}

app.post('/param/deepset', (req, res) => {
    const obj = {};
    deepSet(obj, req.body.path, req.body.value);
    res.json(obj);
});

// [TP-PARAM-005] Array method in function
function processItems(items, processor) {
    return items.map(processor);
}

app.post('/param/process', (req, res) => {
    const result = processItems(req.body.items, x => x);  // Taint flows through
    res.json(result);
});

// ============================================================================
// SECTION 2: RETURN VALUE XSS (Like ghost.js renderNotification)
// ============================================================================

// [TP-RETURN-001] HTML template helper
function renderCard(title) {
    return `<div class="card"><h2>${title}</h2></div>`;
}

app.get('/return/card', (req, res) => {
    const html = renderCard(req.query.title);  // Taint flows through return
    res.send(html);  // VULNERABLE
});

// [TP-RETURN-002] Nested function returns
function wrapInSection(content) {
    return `<section>${content}</section>`;
}

function wrapInDiv(content) {
    return wrapInSection(`<div>${content}</div>`);
}

app.get('/return/nested', (req, res) => {
    const html = wrapInDiv(req.query.content);
    res.send(html);  // VULNERABLE
});

// [TP-RETURN-003] Arrow function return
const formatMessage = msg => `<p class="msg">${msg}</p>`;

app.get('/return/arrow', (req, res) => {
    res.send(formatMessage(req.query.msg));  // VULNERABLE
});

// [TP-RETURN-004] Object method return
const helpers = {
    bold: text => `<b>${text}</b>`,
    italic: text => `<i>${text}</i>`,
    link: (text, url) => `<a href="${url}">${text}</a>`
};

app.get('/return/method', (req, res) => {
    res.send(helpers.bold(req.query.text));  // VULNERABLE
});

// [TP-RETURN-005] Class method return
class HtmlBuilder {
    static paragraph(text) {
        return `<p>${text}</p>`;
    }

    static heading(level, text) {
        return `<h${level}>${text}</h${level}>`;
    }
}

app.get('/return/class', (req, res) => {
    res.send(HtmlBuilder.heading(1, req.query.title));  // VULNERABLE
});

// [TP-RETURN-006] Chained returns
function step1(x) { return x; }
function step2(x) { return step1(x); }
function step3(x) { return step2(x); }

app.get('/return/chain', (req, res) => {
    const result = step3(req.query.data);
    res.send(`<div>${result}</div>`);  // VULNERABLE
});

// [TP-RETURN-007] Conditional return
function maybeWrap(content, shouldWrap) {
    if (shouldWrap) {
        return `<div>${content}</div>`;
    }
    return content;
}

app.get('/return/conditional', (req, res) => {
    const html = maybeWrap(req.query.content, true);
    res.send(html);  // VULNERABLE: both branches return tainted
});

// ============================================================================
// SECTION 3: SINK ALIASING (Like ghost.js res.send.bind)
// ============================================================================

// [TP-ALIAS-001] bind() on sink
app.get('/alias/bind', (req, res) => {
    const output = res.send.bind(res);
    output(req.query.data);  // VULNERABLE
});

// [TP-ALIAS-002] Destructure and call
app.get('/alias/destruct', (req, res) => {
    const { send } = res;
    send.call(res, `<p>${req.query.msg}</p>`);  // VULNERABLE
});

// [TP-ALIAS-003] Assign to variable
app.get('/alias/assign', (req, res) => {
    const respond = res.send;
    respond.call(res, req.query.data);  // VULNERABLE
});

// [TP-ALIAS-004] Wrapper object
app.get('/alias/wrapper', (req, res) => {
    const responder = {
        emit: res.send.bind(res),
        json: res.json.bind(res)
    };
    responder.emit(`<div>${req.query.content}</div>`);  // VULNERABLE
});

// [TP-ALIAS-005] Function returning sink
function getSink(res) {
    return res.send.bind(res);
}

app.get('/alias/factory', (req, res) => {
    const output = getSink(res);
    output(req.query.data);  // VULNERABLE
});

// [TP-ALIAS-006] Aliased fs function
app.get('/alias/fs', (req, res) => {
    const read = fs.readFileSync;
    const content = read(req.query.file, 'utf8');  // VULNERABLE: LFI
    res.send(content);
});

// ============================================================================
// SECTION 4: CALLBACK PATTERNS
// ============================================================================

// [TP-CB-001] Callback receives tainted data
function fetchAndProcess(data, callback) {
    const processed = `<result>${data}</result>`;
    callback(processed);
}

app.get('/callback/basic', (req, res) => {
    fetchAndProcess(req.query.data, html => {
        res.send(html);  // VULNERABLE
    });
});

// [TP-CB-002] Async callback
function asyncProcess(input, callback) {
    setTimeout(() => {
        callback(`<div>${input}</div>`);
    }, 10);
}

app.get('/callback/async', (req, res) => {
    asyncProcess(req.query.input, result => {
        res.send(result);  // VULNERABLE
    });
});

// [TP-CB-003] Error-first callback
function loadData(source, callback) {
    if (!source) {
        callback(new Error('No source'));
    } else {
        callback(null, `<data>${source}</data>`);
    }
}

app.get('/callback/errfirst', (req, res) => {
    loadData(req.query.src, (err, data) => {
        if (err) return res.status(500).send('Error');
        res.send(data);  // VULNERABLE
    });
});

// [TP-CB-004] Multiple callbacks
function processWithHooks(input, { onStart, onComplete }) {
    onStart();
    const result = `<p>${input}</p>`;
    onComplete(result);
}

app.get('/callback/hooks', (req, res) => {
    processWithHooks(req.query.data, {
        onStart: () => console.log('Starting'),
        onComplete: html => res.send(html)  // VULNERABLE
    });
});

// ============================================================================
// SECTION 5: PROMISE PATTERNS
// ============================================================================

// [TP-PROMISE-001] Promise.resolve flow
app.get('/promise/resolve', (req, res) => {
    Promise.resolve(req.query.data)
        .then(d => `<p>${d}</p>`)
        .then(html => res.send(html));  // VULNERABLE
});

// [TP-PROMISE-002] Custom promise function
function asyncWrap(content) {
    return new Promise(resolve => {
        resolve(`<div>${content}</div>`);
    });
}

app.get('/promise/custom', async (req, res) => {
    const html = await asyncWrap(req.query.content);
    res.send(html);  // VULNERABLE
});

// [TP-PROMISE-003] Promise chain transformation
app.get('/promise/chain', (req, res) => {
    Promise.resolve(req.query.input)
        .then(x => x.trim())
        .then(x => x.toUpperCase())
        .then(x => `<h1>${x}</h1>`)
        .then(html => res.send(html));  // VULNERABLE
});

// [TP-PROMISE-004] Promise.all
app.get('/promise/all', async (req, res) => {
    const [a, b] = await Promise.all([
        Promise.resolve(req.query.a),
        Promise.resolve(req.query.b)
    ]);
    res.send(`<p>${a} - ${b}</p>`);  // VULNERABLE
});

// ============================================================================
// SECTION 6: ASYNC/AWAIT PATTERNS
// ============================================================================

// [TP-ASYNC-001] Async function return
async function fetchHtml(content) {
    return `<div>${content}</div>`;
}

app.get('/async/return', async (req, res) => {
    const html = await fetchHtml(req.query.content);
    res.send(html);  // VULNERABLE
});

// [TP-ASYNC-002] Async transform chain
async function transform(input) {
    const step1 = await Promise.resolve(input.trim());
    const step2 = await Promise.resolve(`<p>${step1}</p>`);
    return step2;
}

app.get('/async/chain', async (req, res) => {
    const result = await transform(req.query.data);
    res.send(result);  // VULNERABLE
});

// [TP-ASYNC-003] Async IIFE
app.get('/async/iife', (req, res) => {
    (async () => {
        const data = req.query.data;
        const html = `<div>${data}</div>`;
        res.send(html);  // VULNERABLE
    })();
});

// ============================================================================
// SECTION 7: CLOSURE PATTERNS
// ============================================================================

// [TP-CLOSURE-001] Closure capturing tainted variable
app.get('/closure/capture', (req, res) => {
    const tainted = req.query.data;
    const render = () => `<p>${tainted}</p>`;
    res.send(render());  // VULNERABLE
});

// [TP-CLOSURE-002] Factory returning closure
function createRenderer(content) {
    return () => `<div>${content}</div>`;
}

app.get('/closure/factory', (req, res) => {
    const render = createRenderer(req.query.content);
    res.send(render());  // VULNERABLE
});

// [TP-CLOSURE-003] Memoized function
function memoize(fn) {
    const cache = {};
    return (arg) => {
        if (!cache[arg]) cache[arg] = fn(arg);
        return cache[arg];
    };
}

const cachedRender = memoize(x => `<span>${x}</span>`);

app.get('/closure/memo', (req, res) => {
    res.send(cachedRender(req.query.input));  // VULNERABLE
});

// ============================================================================
// SECTION 8: FALSE POSITIVES
// ============================================================================

// [FP-INTER-001] Function that escapes
function safeRender(text) {
    const escaped = text.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return `<p>${escaped}</p>`;
}

app.get('/safe/escape-fn', (req, res) => {
    res.send(safeRender(req.query.text));  // SAFE: escaped in function
});

// [FP-INTER-002] Function returning JSON
function createResponse(data) {
    return { status: 'ok', data };
}

app.get('/safe/json-fn', (req, res) => {
    res.json(createResponse(req.query.data));  // SAFE: JSON encoding
});

// [FP-INTER-003] Validation function
function validateAndRender(input) {
    if (!/^[a-zA-Z0-9]+$/.test(input)) {
        return '<p>Invalid</p>';
    }
    return `<p>${input}</p>`;
}

app.get('/safe/validate-fn', (req, res) => {
    res.send(validateAndRender(req.query.input));  // SAFER: validated
});

// [FP-INTER-004] Constant callback
function withConstant(callback) {
    callback('<h1>Hello</h1>');  // Constant, not tainted
}

app.get('/safe/const-cb', (req, res) => {
    withConstant(html => res.send(html));  // SAFE: constant
});

app.listen(3000);
