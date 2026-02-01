/**
 * XSSHunter Test Cases - JavaScript
 * ==================================
 * This file contains test cases for DOM XSS and Prototype Pollution detection.
 *
 * Naming Convention:
 * - [TP] = True Positive - SHOULD be detected as vulnerable
 * - [FP] = False Positive - Should NOT be detected (safe code)
 * - [FN] = False Negative - Edge cases that might be missed
 */

// ============================================================================
// DOM XSS - innerHTML/outerHTML Sinks
// ============================================================================

// [TP-001] Direct innerHTML with location.hash
function vulnerableHashXSS() {
    document.getElementById('output').innerHTML = location.hash.slice(1);
}

// [TP-002] innerHTML with document.URL
function vulnerableURLXSS() {
    var url = document.URL;
    document.body.innerHTML = url;
}

// [TP-003] innerHTML with location.search
function vulnerableSearchXSS() {
    const params = location.search;
    document.querySelector('.content').innerHTML = params;
}

// [TP-004] outerHTML with user input
function vulnerableOuterHTML() {
    var userInput = location.hash;
    document.getElementById('container').outerHTML = userInput;
}

// [FP-001] innerHTML with static string - SAFE
function safeStaticInnerHTML() {
    document.getElementById('output').innerHTML = '<p>Hello World</p>';
}

// [FP-002] innerHTML with textContent as source - SAFE (textContent is safe)
function safeTextContentSource() {
    var text = document.getElementById('source').textContent;
    document.getElementById('output').innerHTML = text; // Still risky but textContent is safer
}

// [FP-003] Using textContent instead of innerHTML - SAFE
function safeTextContent() {
    var userInput = location.hash;
    document.getElementById('output').textContent = userInput;
}

// [FP-004] innerHTML with DOMPurify sanitization - SAFE
function safeSanitizedInnerHTML() {
    var userInput = location.hash;
    document.getElementById('output').innerHTML = DOMPurify.sanitize(userInput);
}

// ============================================================================
// DOM XSS - document.write Sinks
// ============================================================================

// [TP-005] document.write with location.search
function vulnerableDocumentWrite() {
    document.write(location.search);
}

// [TP-006] document.writeln with URL params
function vulnerableDocumentWriteln() {
    var param = new URLSearchParams(location.search).get('name');
    document.writeln('<p>' + param + '</p>');
}

// [FP-005] document.write with static content - SAFE
function safeDocumentWrite() {
    document.write('<p>Static content</p>');
}

// ============================================================================
// DOM XSS - eval and Function Sinks
// ============================================================================

// [TP-007] eval with location.hash
function vulnerableEval() {
    var code = location.hash.substring(1);
    eval(code);
}

// [TP-008] Function constructor with user input
function vulnerableFunctionConstructor() {
    var userCode = document.getElementById('codeInput').value;
    var fn = new Function(userCode);
    fn();
}

// [TP-009] setTimeout with string (from user input)
function vulnerableSetTimeout() {
    var callback = location.hash.slice(1);
    setTimeout(callback, 1000);
}

// [TP-010] setInterval with string argument
function vulnerableSetInterval() {
    var code = new URLSearchParams(location.search).get('interval');
    setInterval(code, 2000);
}

// [FP-006] setTimeout with function reference - SAFE
function safeSetTimeout() {
    var userInput = location.hash;
    setTimeout(function() {
        console.log(userInput);
    }, 1000);
}

// [FP-007] eval with JSON.parse wrapper - arguably SAFE for JSON
function safeJSONParse() {
    var data = localStorage.getItem('data');
    var parsed = JSON.parse(data); // JSON.parse is safe from code execution
}

// ============================================================================
// DOM XSS - URL/Navigation Sinks
// ============================================================================

// [TP-011] location.href assignment with user input
function vulnerableLocationHref() {
    var redirect = new URLSearchParams(location.search).get('redirect');
    location.href = redirect;
}

// [TP-012] location.assign with user input
function vulnerableLocationAssign() {
    var url = document.referrer;
    location.assign(url);
}

// [TP-013] window.open with user input
function vulnerableWindowOpen() {
    var popup = location.hash.substring(1);
    window.open(popup);
}

// [FP-008] location.href with validated URL - SAFE (conceptually)
function safeLocationHref() {
    var url = new URLSearchParams(location.search).get('redirect');
    if (url && url.startsWith('/')) {
        location.href = url; // Relative URLs only - still flagged but safer
    }
}

// ============================================================================
// DOM XSS - jQuery Sinks
// ============================================================================

// [TP-014] jQuery .html() with user input
function vulnerablejQueryHtml() {
    var userInput = location.hash;
    $('#output').html(userInput);
}

// [TP-015] jQuery .append() with user input
function vulnerablejQueryAppend() {
    var content = new URLSearchParams(location.search).get('content');
    $('.container').append(content);
}

// [TP-016] jQuery selector with HTML from user input
function vulnerablejQuerySelector() {
    var tag = location.hash.slice(1);
    $('<div>' + tag + '</div>').appendTo('body');
}

// [TP-017] jQuery .replaceWith() with user input
function vulnerablejQueryReplace() {
    var html = localStorage.getItem('template');
    $('#placeholder').replaceWith(html);
}

// [FP-009] jQuery .text() - SAFE
function safejQueryText() {
    var userInput = location.hash;
    $('#output').text(userInput);
}

// [FP-010] jQuery .html() with static content - SAFE
function safejQueryStaticHtml() {
    $('#output').html('<span>Static</span>');
}

// ============================================================================
// DOM XSS - React Patterns
// ============================================================================

// [TP-018] React dangerouslySetInnerHTML with user input (JS equivalent)
function VulnerableReactComponent() {
    const userContent = window.location.hash.slice(1);
    // React createElement equivalent - still dangerous
    const element = document.createElement('div');
    element.innerHTML = userContent;  // Same vulnerability
    return element;
}

// [FP-011] React dangerouslySetInnerHTML with sanitized content - SAFE
function SafeReactComponent() {
    const userContent = window.location.hash.slice(1);
    const sanitized = DOMPurify.sanitize(userContent);
    const element = document.createElement('div');
    element.innerHTML = sanitized;  // Sanitized - safer
    return element;
}

// ============================================================================
// DOM XSS - insertAdjacentHTML
// ============================================================================

// [TP-019] insertAdjacentHTML with user input
function vulnerableInsertAdjacentHTML() {
    var userHtml = location.hash.substring(1);
    document.getElementById('container').insertAdjacentHTML('beforeend', userHtml);
}

// ============================================================================
// DOM XSS - PostMessage Handler
// ============================================================================

// [TP-020] PostMessage event handler without origin check
window.addEventListener('message', function(event) {
    // No origin validation!
    document.getElementById('output').innerHTML = event.data;
});

// [TP-021] PostMessage with e.data directly used
window.addEventListener('message', function(e) {
    eval(e.data.code);
});

// [FP-012] PostMessage with origin check - SAFER
window.addEventListener('message', function(event) {
    if (event.origin !== 'https://trusted.com') return;
    document.getElementById('output').textContent = event.data;
});

// ============================================================================
// DOM XSS - Event Handler Injection
// ============================================================================

// [TP-022] Dynamic onclick assignment
function vulnerableEventHandler() {
    var handler = location.hash.slice(1);
    document.getElementById('btn').onclick = handler;
}

// [TP-023] setAttribute with event handler
function vulnerableSetAttribute() {
    var action = new URLSearchParams(location.search).get('action');
    document.getElementById('btn').setAttribute('onclick', action);
}

// ============================================================================
// DOM XSS - Script src manipulation
// ============================================================================

// [TP-024] Script src from user input
function vulnerableScriptSrc() {
    var scriptUrl = location.hash.substring(1);
    var script = document.createElement('script');
    script.src = scriptUrl;
    document.body.appendChild(script);
}

// [TP-025] iframe src from user input
function vulnerableIframeSrc() {
    var frameSrc = new URLSearchParams(location.search).get('frame');
    document.getElementById('frame').src = frameSrc;
}

// ============================================================================
// Prototype Pollution Vulnerabilities
// ============================================================================

// [TP-026] Direct __proto__ access
function vulnerableProtoAccess(obj, key, value) {
    obj[key] = value; // If key is '__proto__', pollution occurs
}

// [TP-027] Explicit __proto__ manipulation
function vulnerableExplicitProto(userInput) {
    var obj = {};
    obj['__proto__']['polluted'] = userInput;
}

// [TP-028] constructor.prototype access
function vulnerableConstructorPrototype(obj) {
    obj['constructor']['prototype']['isAdmin'] = true;
}

// [TP-029] Lodash merge (vulnerable versions)
function vulnerableLodashMerge(userInput) {
    _.merge({}, userInput);
}

// [TP-030] jQuery deep extend
function vulnerablejQueryExtend(userInput) {
    $.extend(true, {}, userInput);
}

// [TP-031] Custom deep merge without protection
function vulnerableDeepMerge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            target[key] = target[key] || {};
            deepMerge(target[key], source[key]); // Recursive without hasOwnProperty
        } else {
            target[key] = source[key];
        }
    }
}

// [TP-032] Object.assign with spread from user input
function vulnerableObjectAssign(userInput) {
    const config = Object.assign({}, userInput);
}

// [TP-033] JSON.parse to object property access
function vulnerableJSONParse(jsonString) {
    const data = JSON.parse(jsonString);
    config[data.key] = data.value; // If key is __proto__
}

// [FP-013] Safe merge with hasOwnProperty check
function safeMerge(target, source) {
    for (let key in source) {
        if (source.hasOwnProperty(key) && key !== '__proto__' && key !== 'constructor') {
            target[key] = source[key];
        }
    }
}

// [FP-014] Using Map instead of Object - SAFE
function safeMapUsage(userKey, userValue) {
    const map = new Map();
    map.set(userKey, userValue); // Maps are not vulnerable to prototype pollution
}

// [FP-015] Object.create(null) - SAFE
function safeNullPrototype(userInput) {
    const obj = Object.create(null);
    obj[userInput.key] = userInput.value; // No prototype chain
}

// ============================================================================
// Taint Flow Tracking Tests
// ============================================================================

// [TP-034] Multi-step taint flow
function multiStepTaint() {
    var source = location.search;        // Tainted
    var step1 = source.substring(1);     // Still tainted
    var step2 = step1.split('&')[0];     // Still tainted
    var step3 = decodeURIComponent(step2); // Still tainted
    document.body.innerHTML = step3;      // Sink with tainted data
}

// [TP-035] Taint through function parameter
function taintThroughParam(userInput) {
    document.getElementById('output').innerHTML = userInput;
}
// Called with: taintThroughParam(location.hash);

// [FP-016] Taint cleared by encoding
function taintClearedByEncode() {
    var source = location.search;
    var encoded = encodeURIComponent(source);
    document.body.innerHTML = encoded; // Encoded - safer but still flagged
}

// ============================================================================
// Edge Cases / False Negative Tests
// ============================================================================

// [FN-001] Indirect property access (harder to detect)
function indirectPropertyAccess(obj, prop) {
    const sinkName = 'innerHTML';
    obj[sinkName] = location.hash; // Dynamic sink name
}

// [FN-002] Promise chain taint flow
function promiseTaintFlow() {
    fetch('/api?q=' + location.search)
        .then(function(response) { return response.json(); })
        .then(function(data) {
            document.body.innerHTML = data.html; // 2nd order XSS
        });
}

// [FN-003] Callback taint flow
function callbackTaint() {
    fetchData(location.search, function(result) {
        document.body.innerHTML = result;
    });
}

console.log("XSS Test cases loaded");
