/**
 * Template Injection and Deserialization Test Cases
 * ===================================================
 * Tests for SSTI and unsafe deserialization in Node.js
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected
 */

const express = require('express');
const ejs = require('ejs');
const pug = require('pug');
const handlebars = require('handlebars');
const nunjucks = require('nunjucks');
const serialize = require('node-serialize');
const yaml = require('js-yaml');
const vm = require('vm');
const app = express();
app.use(express.json());

// ============================================================================
// SECTION 1: SERVER-SIDE TEMPLATE INJECTION (SSTI)
// ============================================================================

// [TP-SSTI-001] EJS render with user template
app.get('/ssti/ejs', (req, res) => {
    const template = req.query.template;
    const html = ejs.render(template, { name: 'Guest' });  // VULNERABLE
    res.send(html);
});

// [TP-SSTI-002] EJS compile with user template
app.post('/ssti/ejs-compile', (req, res) => {
    const fn = ejs.compile(req.body.template);  // VULNERABLE
    res.send(fn({ user: 'test' }));
});

// [TP-SSTI-003] Pug compile from user
app.get('/ssti/pug', (req, res) => {
    const fn = pug.compile(req.query.template);  // VULNERABLE
    res.send(fn({ title: 'Page' }));
});

// [TP-SSTI-004] Pug render with user template
app.post('/ssti/pug-render', (req, res) => {
    const html = pug.render(req.body.template);  // VULNERABLE
    res.send(html);
});

// [TP-SSTI-005] Handlebars compile
app.get('/ssti/handlebars', (req, res) => {
    const template = handlebars.compile(req.query.template);  // VULNERABLE
    res.send(template({ name: 'User' }));
});

// [TP-SSTI-006] Nunjucks renderString
app.get('/ssti/nunjucks', (req, res) => {
    const html = nunjucks.renderString(req.query.template, { x: 1 });  // VULNERABLE
    res.send(html);
});

// [TP-SSTI-007] Template concatenation
app.get('/ssti/concat', (req, res) => {
    const header = req.query.header;
    const template = `<h1>${header}</h1><p>Welcome</p>`;
    const html = ejs.render(template);  // VULNERABLE: user controls template content
    res.send(html);
});

// [TP-SSTI-008] Dynamic include/partial
app.get('/ssti/include', (req, res) => {
    const partial = req.query.partial;
    const template = `<%- include('${partial}') %>`;  // VULNERABLE: path injection
    const html = ejs.render(template, {}, { filename: 'main.ejs' });
    res.send(html);
});

// ============================================================================
// SECTION 2: UNSAFE DESERIALIZATION
// ============================================================================

// [TP-DESER-001] node-serialize unserialize
app.post('/deser/serialize', (req, res) => {
    const obj = serialize.unserialize(req.body.data);  // VULNERABLE: RCE
    res.json(obj);
});

// [TP-DESER-002] JSON.parse with reviver function from user
app.post('/deser/reviver', (req, res) => {
    const reviver = new Function('key', 'value', req.body.reviver);  // VULNERABLE
    const obj = JSON.parse(req.body.json, reviver);
    res.json(obj);
});

// [TP-DESER-003] YAML load (unsafe by default in some versions)
app.post('/deser/yaml', (req, res) => {
    const obj = yaml.load(req.body.yaml);  // VULNERABLE in older js-yaml
    res.json(obj);
});

// [TP-DESER-004] vm.runInContext with user code
app.post('/deser/vm', (req, res) => {
    const context = vm.createContext({ result: null });
    vm.runInContext(req.body.code, context);  // VULNERABLE: sandbox escape
    res.json({ result: context.result });
});

// [TP-DESER-005] vm.runInNewContext
app.get('/deser/vm-new', (req, res) => {
    const result = vm.runInNewContext(req.query.expr);  // VULNERABLE
    res.send(String(result));
});

// [TP-DESER-006] vm.Script with user code
app.post('/deser/script', (req, res) => {
    const script = new vm.Script(req.body.code);  // VULNERABLE
    const result = script.runInNewContext({});
    res.json({ result });
});

// ============================================================================
// SECTION 3: REGEX DOS (ReDoS)
// ============================================================================

// [TP-REDOS-001] User-controlled regex pattern
app.get('/redos/pattern', (req, res) => {
    const pattern = req.query.regex;
    const regex = new RegExp(pattern);  // VULNERABLE: ReDoS
    const match = regex.test('test string');
    res.json({ match });
});

// [TP-REDOS-002] User input in regex constructor
app.post('/redos/match', (req, res) => {
    const { pattern, flags, input } = req.body;
    const regex = new RegExp(pattern, flags);  // VULNERABLE
    const matches = input.match(regex);
    res.json({ matches });
});

// [TP-REDOS-003] Dynamic regex in loop
app.get('/redos/loop', (req, res) => {
    const items = req.query.items.split(',');
    const pattern = req.query.pattern;
    const results = items.filter(i => new RegExp(pattern).test(i));  // VULNERABLE
    res.json(results);
});

// ============================================================================
// SECTION 4: CODE INJECTION VARIATIONS
// ============================================================================

// [TP-CODE-001] Function constructor
app.get('/code/function', (req, res) => {
    const fn = new Function('x', 'y', req.query.body);  // VULNERABLE
    res.send(String(fn(1, 2)));
});

// [TP-CODE-002] Indirect eval
app.get('/code/indirect', (req, res) => {
    const evil = eval;
    const result = evil(req.query.code);  // VULNERABLE
    res.send(String(result));
});

// [TP-CODE-003] eval via window/global
app.get('/code/global', (req, res) => {
    const result = global.eval(req.query.expr);  // VULNERABLE
    res.send(String(result));
});

// [TP-CODE-004] setTimeout with string (code)
app.get('/code/timeout', (req, res) => {
    setTimeout(req.query.code, 100);  // VULNERABLE
    res.send('Scheduled');
});

// [TP-CODE-005] setInterval with string
app.get('/code/interval', (req, res) => {
    const id = setInterval(req.query.code, 1000);  // VULNERABLE
    setTimeout(() => clearInterval(id), 5000);
    res.send('Running');
});

// [TP-CODE-006] setImmediate (if it accepts strings - typically doesn't)
// app.get('/code/immediate', (req, res) => {
//     setImmediate(req.query.code);  // Check if vulnerable
//     res.send('Immediate');
// });

// ============================================================================
// SECTION 5: DYNAMIC REQUIRE/IMPORT
// ============================================================================

// [TP-REQUIRE-001] Dynamic require
app.get('/require/dynamic', (req, res) => {
    const module = require(req.query.module);  // VULNERABLE: arbitrary module load
    res.json({ loaded: true });
});

// [TP-REQUIRE-002] require with path concatenation
app.get('/require/path', (req, res) => {
    const mod = require('./modules/' + req.query.name);  // VULNERABLE
    res.json(mod.info);
});

// [TP-REQUIRE-003] Dynamic import
app.get('/import/dynamic', async (req, res) => {
    const module = await import(req.query.module);  // VULNERABLE
    res.json({ loaded: true });
});

// ============================================================================
// SECTION 6: FALSE POSITIVES
// ============================================================================

// [FP-SSTI-001] Safe template rendering
app.get('/safe/ejs', (req, res) => {
    const name = req.query.name;
    // Template is not user-controlled
    const html = ejs.render('<h1>Hello <%= name %></h1>', { name });  // SAFE: escaped output
    res.send(html);
});

// [FP-SSTI-002] Render from file (controlled template)
app.get('/safe/render', (req, res) => {
    res.render('page', { title: req.query.title });  // SAFER: template from file
});

// [FP-DESER-001] JSON.parse without custom reviver
app.post('/safe/json', (req, res) => {
    const obj = JSON.parse(req.body.data);  // SAFE: no code execution
    res.json(obj);
});

// [FP-DESER-002] YAML safeLoad
app.post('/safe/yaml', (req, res) => {
    const obj = yaml.safeLoad(req.body.yaml);  // SAFE: restricted types
    res.json(obj);
});

// [FP-REDOS-001] Constant regex
app.get('/safe/regex', (req, res) => {
    const regex = /^[a-zA-Z0-9]+$/;  // SAFE: constant pattern
    const valid = regex.test(req.query.input);
    res.json({ valid });
});

// [FP-CODE-001] Literal function body
app.get('/safe/function', (req, res) => {
    const fn = new Function('x', 'return x * 2');  // SAFE: no user input
    res.send(String(fn(5)));
});

app.listen(3000);
