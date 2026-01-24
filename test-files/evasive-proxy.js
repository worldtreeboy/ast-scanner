/**
 * Test file for JavaScript Proxy trap evasion detection
 * These patterns should be detected as XSS/code injection via Proxy traps
 */

// Pattern 1: Proxy with eval in getter
// Any property access triggers eval
const evasiveProxy1 = new Proxy({}, {
    get: function(target, prop) {
        // DETECT: Proxy get trap with eval
        return eval(sessionStorage.getItem(prop));
    }
});

// Access like evasiveProxy1.anything triggers eval
const result1 = evasiveProxy1.maliciousCode;

// Pattern 2: Proxy with innerHTML in setter
const targetElement = document.getElementById('output');
const evasiveProxy2 = new Proxy({}, {
    set: (target, prop, value) => {
        // DETECT: Proxy set trap with innerHTML
        targetElement.innerHTML = value;
        return true;
    }
});

// Assignment triggers innerHTML
evasiveProxy2.content = location.hash.slice(1);

// Pattern 3: Proxy with Function constructor in getter
const evasiveProxy3 = new Proxy({}, {
    get: (t, p) => {
        const code = localStorage.getItem('code');
        // DETECT: Proxy get trap with Function constructor
        return Function(code)();
    }
});

// Pattern 4: Proxy with document.write in apply trap
const funcProxy = new Proxy(function() {}, {
    apply: function(target, thisArg, args) {
        // DETECT: Proxy apply trap with document.write
        document.write(args[0]);
    }
});

funcProxy(location.search);

// Pattern 5: Nested Proxy with eval
const handler = {
    get: (target, name) => {
        if (name === 'exec') {
            // DETECT: Proxy get trap with eval
            return (code) => eval(code);
        }
        return target[name];
    }
};
const nestedProxy = new Proxy({}, handler);
nestedProxy.exec(userInput);

// Pattern 6: Proxy with .html() (jQuery-style sink)
const jQueryProxy = new Proxy({}, {
    set: function(obj, prop, value) {
        // DETECT: Proxy set trap with .html()
        $('#' + prop).html(value);
        return true;
    }
});

jQueryProxy.output = new URLSearchParams(location.search).get('data');

// Safe Proxy (should NOT be flagged)
const loggingProxy = new Proxy({}, {
    get: function(target, prop) {
        console.log('Property accessed:', prop);
        return target[prop];
    },
    set: function(target, prop, value) {
        console.log('Property set:', prop, value);
        target[prop] = value;
        return true;
    }
});
