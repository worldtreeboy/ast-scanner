/**
 * XSS Test File - INTENTIONALLY VULNERABLE
 * Tests DOM-based XSS, Reflected XSS, and framework-specific patterns
 */

// ==================== DOM-BASED XSS ====================

// DOM sources flowing to DOM sinks
function domBasedXSS() {
    // innerHTML with location.hash (DOM-based XSS)
    document.getElementById('content').innerHTML = location.hash.substring(1);

    // innerHTML with URL parameter
    const params = new URLSearchParams(location.search);
    document.getElementById('result').innerHTML = params.get('query');

    // document.write with referrer
    document.write('<div>' + document.referrer + '</div>');

    // outerHTML with user input
    const userInput = document.getElementById('input').value;
    element.outerHTML = '<span>' + userInput + '</span>';

    // insertAdjacentHTML
    div.insertAdjacentHTML('beforeend', location.hash);
}

// ==================== JQUERY XSS ====================

function jqueryXSS() {
    // jQuery .html() with user data
    $('#output').html(userInput);

    // jQuery selector with HTML
    $('<div>' + userData + '</div>').appendTo('body');

    // jQuery .append() with HTML
    $('#container').append('<script>' + payload + '</script>');
}

// ==================== REACT XSS ====================

function ReactComponent() {
    // dangerouslySetInnerHTML
    return <div dangerouslySetInnerHTML={{ __html: userContent }} />;
}

// ==================== ANGULAR XSS ====================

// Angular innerHTML binding
// <div [innerHTML]="userContent"></div>

// Angular security bypass
// this.sanitizer.bypassSecurityTrustHtml(userInput);

// ==================== VUE XSS ====================

// Vue v-html directive
// <div v-html="userContent"></div>

// ==================== REFLECTED XSS (Express.js) ====================

const express = require('express');
const app = express();

app.get('/search', (req, res) => {
    const query = req.query.q;

    // Reflected XSS - template literal
    res.send(`<h1>Search results for: ${query}</h1>`);
});

app.get('/greet', (req, res) => {
    const name = req.query.name;

    // Reflected XSS - concatenation
    res.send('<h1>Hello, ' + name + '!</h1>');
});

// ==================== URL-BASED XSS ====================

function urlXSS() {
    // javascript: protocol
    element.href = 'javascript:' + userCode;

    // javascript: in location
    location = 'javascript:alert(1)';

    // javascript: in window.open
    window.open('javascript:' + payload);
}
