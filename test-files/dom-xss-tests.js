/**
 * DOM XSS Test Cases (Client-Side JavaScript)
 * ============================================
 * Tests for DOM-based XSS in browser JavaScript
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected
 */

// ============================================================================
// SECTION 1: URL SOURCES
// ============================================================================

// [TP-DOM-001] location.hash to innerHTML
document.getElementById('content').innerHTML = location.hash.slice(1);  // VULNERABLE

// [TP-DOM-002] location.search to innerHTML
const params = new URLSearchParams(location.search);
document.body.innerHTML = params.get('msg');  // VULNERABLE

// [TP-DOM-003] location.href in innerHTML
document.querySelector('.url').innerHTML = location.href;  // VULNERABLE

// [TP-DOM-004] document.referrer
document.getElementById('ref').innerHTML = document.referrer;  // VULNERABLE

// [TP-DOM-005] document.URL
document.write(document.URL);  // VULNERABLE

// [TP-DOM-006] location.pathname
document.body.innerHTML = `Path: ${location.pathname}`;  // VULNERABLE

// ============================================================================
// SECTION 2: DANGEROUS SINKS
// ============================================================================

// [TP-SINK-001] innerHTML
const userInput = location.hash.substr(1);
document.getElementById('output').innerHTML = userInput;  // VULNERABLE

// [TP-SINK-002] outerHTML
document.querySelector('.target').outerHTML = location.hash;  // VULNERABLE

// [TP-SINK-003] document.write
document.write('<div>' + decodeURIComponent(location.search) + '</div>');  // VULNERABLE

// [TP-SINK-004] document.writeln
document.writeln(location.hash);  // VULNERABLE

// [TP-SINK-005] insertAdjacentHTML
document.body.insertAdjacentHTML('beforeend', location.hash);  // VULNERABLE

// [TP-SINK-006] eval
eval(location.hash.slice(1));  // VULNERABLE

// [TP-SINK-007] setTimeout with string
setTimeout(location.hash.substr(1), 1000);  // VULNERABLE

// [TP-SINK-008] setInterval with string
setInterval(location.hash.substr(1), 1000);  // VULNERABLE

// [TP-SINK-009] new Function
const fn = new Function(location.hash.slice(1));  // VULNERABLE

// [TP-SINK-010] src attribute
const img = document.createElement('img');
img.src = location.hash.slice(1);  // VULNERABLE

// [TP-SINK-011] href attribute
const link = document.createElement('a');
link.href = location.hash;  // VULNERABLE (javascript: URLs)

// [TP-SINK-012] action attribute
document.forms[0].action = location.search;  // VULNERABLE

// ============================================================================
// SECTION 3: JQUERY SINKS
// ============================================================================

// [TP-JQ-001] .html()
$('#content').html(location.hash);  // VULNERABLE

// [TP-JQ-002] .append()
$('body').append(location.hash);  // VULNERABLE

// [TP-JQ-003] .prepend()
$('.container').prepend(location.search);  // VULNERABLE

// [TP-JQ-004] .after()
$('#elem').after(location.hash);  // VULNERABLE

// [TP-JQ-005] .before()
$('#elem').before(location.hash);  // VULNERABLE

// [TP-JQ-006] .replaceWith()
$('.old').replaceWith(location.hash);  // VULNERABLE

// [TP-JQ-007] .wrap()
$('.item').wrap(location.hash);  // VULNERABLE

// [TP-JQ-008] .wrapAll()
$('.items').wrapAll(location.hash);  // VULNERABLE

// [TP-JQ-009] $() constructor with HTML
$(location.hash);  // VULNERABLE if hash contains HTML

// [TP-JQ-010] $.parseHTML with untrusted
$.parseHTML(location.hash, document, true);  // VULNERABLE

// ============================================================================
// SECTION 4: STORAGE SOURCES
// ============================================================================

// [TP-STOR-001] localStorage
document.body.innerHTML = localStorage.getItem('userContent');  // VULNERABLE

// [TP-STOR-002] sessionStorage
document.write(sessionStorage.getItem('data'));  // VULNERABLE

// [TP-STOR-003] IndexedDB (if tracked)
// IndexedDB requires async handling

// ============================================================================
// SECTION 5: POSTMESSAGE
// ============================================================================

// [TP-MSG-001] postMessage event.data
window.addEventListener('message', (event) => {
    document.body.innerHTML = event.data;  // VULNERABLE
});

// [TP-MSG-002] postMessage without origin check
window.onmessage = function(e) {
    eval(e.data);  // VULNERABLE
};

// ============================================================================
// SECTION 6: COMPLEX FLOWS
// ============================================================================

// [TP-FLOW-001] Through variable assignment
const hash = location.hash;
const decoded = decodeURIComponent(hash);
const sliced = decoded.slice(1);
document.body.innerHTML = sliced;  // VULNERABLE: multi-hop

// [TP-FLOW-002] Through function
function getHash() {
    return location.hash.slice(1);
}
document.body.innerHTML = getHash();  // VULNERABLE

// [TP-FLOW-003] Through array
const parts = location.hash.split('/');
document.body.innerHTML = parts.join('<br>');  // VULNERABLE

// [TP-FLOW-004] Through object
const data = { content: location.hash };
document.body.innerHTML = data.content;  // VULNERABLE

// [TP-FLOW-005] Through ternary
const val = location.hash ? location.hash : location.search;
document.body.innerHTML = val;  // VULNERABLE

// [TP-FLOW-006] Through template literal
const template = `<div class="user-content">${location.hash}</div>`;
document.body.innerHTML = template;  // VULNERABLE

// [TP-FLOW-007] Through string methods
const processed = location.hash.toLowerCase().trim();
document.body.innerHTML = processed;  // VULNERABLE

// ============================================================================
// SECTION 7: FALSE POSITIVES
// ============================================================================

// [FP-SAFE-001] textContent (safe sink)
document.getElementById('out').textContent = location.hash;  // SAFE

// [FP-SAFE-002] innerText (safer sink)
document.body.innerText = location.hash;  // SAFER

// [FP-SAFE-003] value property (form input)
document.getElementById('input').value = location.hash;  // SAFE

// [FP-SAFE-004] setAttribute with safe attribute
document.body.setAttribute('data-hash', location.hash);  // SAFER

// [FP-SAFE-005] Proper escaping
function escapeHtml(str) {
    return str.replace(/&/g, '&amp;')
              .replace(/</g, '&lt;')
              .replace(/>/g, '&gt;')
              .replace(/"/g, '&quot;');
}
document.body.innerHTML = escapeHtml(location.hash);  // SAFE

// [FP-SAFE-006] DOMPurify sanitization
// document.body.innerHTML = DOMPurify.sanitize(location.hash);  // SAFE

// [FP-SAFE-007] createTextNode (safe)
const textNode = document.createTextNode(location.hash);
document.body.appendChild(textNode);  // SAFE

// [FP-SAFE-008] Constant only
document.body.innerHTML = '<h1>Hello World</h1>';  // SAFE

// [FP-SAFE-009] Number after parseInt
const num = parseInt(location.hash.slice(1), 10);
if (!isNaN(num)) {
    document.body.innerHTML = `<p>Page ${num}</p>`;  // SAFER
}
