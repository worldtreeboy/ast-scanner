/**
 * Prototype Pollution Comprehensive Test Cases
 * =============================================
 * Tests for false negatives (FN) and false positives (FP)
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected (safe code)
 * [FN] = Known False Negative - May be missed (edge cases)
 */

// ============================================================================
// FOR-IN LOOP PROTOTYPE POLLUTION (Critical pattern from user report)
// ============================================================================

// [TP-FORIN-001] Classic for-in loop pollution - MUST DETECT
function vulnerableForInMerge(userConfig) {
    const config = { theme: 'light', notifications: true };
    for (let key in userConfig) {
        config[key] = userConfig[key];  // VULNERABLE: no hasOwnProperty check
    }
    return config;
}

// [TP-FORIN-002] For-in with JSON.parse from location.hash - MUST DETECT
function vulnerableJSONParsePollution() {
    const maliciousInput = JSON.parse(window.location.hash.slice(1));
    const settings = {};
    for (var prop in maliciousInput) {
        settings[prop] = maliciousInput[prop];  // VULNERABLE
    }
}

// [TP-FORIN-003] For-in with URL parameter - MUST DETECT
function vulnerableURLParamPollution() {
    const params = new URLSearchParams(location.search);
    const userObj = JSON.parse(params.get('data'));
    const target = {};
    for (let k in userObj) {
        target[k] = userObj[k];  // VULNERABLE
    }
}

// [TP-FORIN-004] Nested for-in (recursive merge) - MUST DETECT
function vulnerableDeepMerge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            target[key] = target[key] || {};
            vulnerableDeepMerge(target[key], source[key]);  // Recursive
        } else {
            target[key] = source[key];  // VULNERABLE
        }
    }
    return target;
}

// [TP-FORIN-005] For-in inside if statement - MUST DETECT
function vulnerableConditionalMerge(condition, userInput) {
    const obj = {};
    if (condition) {
        for (let key in userInput) {
            obj[key] = userInput[key];  // VULNERABLE
        }
    }
    return obj;
}

// [FP-FORIN-001] For-in with hasOwnProperty check - SAFE
function safeForInWithHasOwn(userConfig) {
    const config = {};
    for (let key in userConfig) {
        if (userConfig.hasOwnProperty(key)) {
            config[key] = userConfig[key];  // SAFE: hasOwnProperty check
        }
    }
    return config;
}

// [FP-FORIN-002] For-in with Object.hasOwn check - SAFE
function safeForInWithObjectHasOwn(userConfig) {
    const config = {};
    for (let key in userConfig) {
        if (Object.hasOwn(userConfig, key)) {
            config[key] = userConfig[key];  // SAFE
        }
    }
    return config;
}

// [FP-FORIN-003] For-in with explicit __proto__ filter - SAFE
function safeForInWithProtoFilter(userConfig) {
    const config = {};
    for (let key in userConfig) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // SAFE: explicit filter
        }
        config[key] = userConfig[key];
    }
    return config;
}

// [FP-FORIN-004] Using Object.keys instead of for-in - SAFE
function safeObjectKeysIteration(userConfig) {
    const config = {};
    Object.keys(userConfig).forEach(function(key) {
        config[key] = userConfig[key];  // SAFE: Object.keys doesn't include prototype
    });
    return config;
}

// [FP-FORIN-005] For-in over hardcoded object - SAFE
function safeHardcodedIteration() {
    const defaults = { a: 1, b: 2, c: 3 };
    const config = {};
    for (let key in defaults) {
        config[key] = defaults[key];  // SAFE: iterating over known object
    }
    return config;
}

// ============================================================================
// DIRECT __PROTO__ ACCESS
// ============================================================================

// [TP-PROTO-001] Direct __proto__ property access
function vulnerableDirectProto(obj, value) {
    obj['__proto__']['polluted'] = value;  // VULNERABLE
}

// [TP-PROTO-002] Direct __proto__ with dot notation
function vulnerableDotProto(obj) {
    obj.__proto__.isAdmin = true;  // VULNERABLE
}

// [TP-PROTO-003] constructor.prototype access
function vulnerableConstructorProto(obj) {
    obj['constructor']['prototype']['pwned'] = true;  // VULNERABLE
}

// [TP-PROTO-004] Nested __proto__ access
function vulnerableNestedProto() {
    var x = {};
    x['__proto__']['__proto__']['deep'] = 'pollution';  // VULNERABLE
}

// [TP-PROTO-005] Dynamic key that could be __proto__
function vulnerableDynamicKey(obj, key, value) {
    obj[key] = value;  // VULNERABLE if key comes from user input
}

// [FP-PROTO-001] Checking for __proto__ before access - SAFE
function safeProtoCheck(obj, key, value) {
    if (key === '__proto__' || key === 'constructor') {
        throw new Error('Invalid key');
    }
    obj[key] = value;  // SAFE: validated
}

// ============================================================================
// MERGE/EXTEND FUNCTIONS
// ============================================================================

// [TP-MERGE-001] Lodash _.merge with user input
function vulnerableLodashMerge(userInput) {
    const defaults = { safe: true };
    return _.merge(defaults, userInput);  // VULNERABLE
}

// [TP-MERGE-002] Lodash _.defaultsDeep with user input
function vulnerableDefaultsDeep(userInput) {
    return _.defaultsDeep({}, userInput);  // VULNERABLE
}

// [TP-MERGE-003] jQuery $.extend deep with user input
function vulnerablejQueryDeepExtend(userInput) {
    return $.extend(true, {}, userInput);  // VULNERABLE: deep extend
}

// [TP-MERGE-004] Custom deepMerge function
function customDeepMerge(target, source) {
    return deepMerge(target, source);  // VULNERABLE if deepMerge is unsafe
}

// [TP-MERGE-005] Object.assign with spread
function vulnerableObjectAssign(userInput) {
    const config = Object.assign({}, userInput);  // POTENTIALLY VULNERABLE
    return config;
}

// [FP-MERGE-001] Lodash _.merge with sanitized input - SAFE
function safeLodashMerge(userInput) {
    const sanitized = sanitizeObject(userInput);
    return _.merge({}, sanitized);  // SAFE: sanitized
}

// [FP-MERGE-002] jQuery shallow extend - SAFE
function safejQueryShallowExtend(userInput) {
    return $.extend({}, userInput);  // SAFER: shallow extend (no 'true' first arg)
}

// [FP-MERGE-003] Object.assign to null prototype object - SAFE
function safeNullProtoAssign(userInput) {
    const target = Object.create(null);
    return Object.assign(target, userInput);  // SAFE: no prototype chain
}

// ============================================================================
// JSON.PARSE PATTERNS
// ============================================================================

// [TP-JSON-001] JSON.parse from URL hash directly used
function vulnerableJSONFromHash() {
    const data = JSON.parse(location.hash.substring(1));
    globalConfig = data;  // Data may contain __proto__
}

// [TP-JSON-002] JSON.parse from localStorage
function vulnerableJSONFromStorage() {
    const saved = localStorage.getItem('userPrefs');
    const prefs = JSON.parse(saved);
    for (let key in prefs) {
        appConfig[key] = prefs[key];  // VULNERABLE
    }
}

// [TP-JSON-003] JSON.parse from postMessage
window.addEventListener('message', function(event) {
    const data = JSON.parse(event.data);
    for (let prop in data) {
        settings[prop] = data[prop];  // VULNERABLE
    }
});

// [FP-JSON-001] JSON.parse with schema validation - SAFE
function safeJSONWithValidation(jsonStr) {
    const data = JSON.parse(jsonStr);
    if (!validateSchema(data)) {
        throw new Error('Invalid data');
    }
    return data;  // SAFE: validated
}

// ============================================================================
// OBJECT PROPERTY ASSIGNMENT PATTERNS
// ============================================================================

// [TP-ASSIGN-001] Bracket notation with user key
function vulnerableBracketAssign(obj, userKey, userValue) {
    obj[userKey] = userValue;  // VULNERABLE
}

// [TP-ASSIGN-002] Nested bracket assignment
function vulnerableNestedBracket(obj, path, value) {
    obj[path[0]][path[1]] = value;  // VULNERABLE
}

// [TP-ASSIGN-003] Set property via variable
function vulnerableSetViaVar(obj, prop) {
    const key = prop;
    obj[key] = true;  // VULNERABLE if prop is user-controlled
}

// [FP-ASSIGN-001] Known/hardcoded property - SAFE
function safeKnownProperty(obj) {
    obj['knownKey'] = 'value';  // SAFE: hardcoded key
}

// [FP-ASSIGN-002] Property from whitelist - SAFE
function safeWhitelistedProperty(obj, key, value) {
    const whitelist = ['name', 'email', 'age'];
    if (whitelist.includes(key)) {
        obj[key] = value;  // SAFE: whitelisted
    }
}

// [FP-ASSIGN-003] Using Map instead of Object - SAFE
function safeMapUsage(userKey, userValue) {
    const map = new Map();
    map.set(userKey, userValue);  // SAFE: Map doesn't have prototype issues
    return map;
}

// ============================================================================
// EDGE CASES / COMPLEX PATTERNS
// ============================================================================

// [FN-001] Indirect assignment via function call
function indirectAssignment(obj, key, value) {
    setProperty(obj, key, value);  // Hard to track: depends on setProperty impl
}

// [FN-002] Assignment via eval
function evalAssignment(obj, key, value) {
    eval('obj["' + key + '"] = value');  // Hard to analyze statically
}

// [FN-003] Assignment via Reflect.set
function reflectAssignment(obj, key, value) {
    Reflect.set(obj, key, value);  // May be missed
}

// [FN-004] Proxy-based assignment
function proxyAssignment(target, key, value) {
    const proxy = new Proxy(target, {});
    proxy[key] = value;  // Hard to track through Proxy
}

// [FN-005] Assignment in callback
function callbackAssignment(userInput) {
    processData(userInput, function(key, value) {
        globalObj[key] = value;  // Context lost in callback
    });
}

// ============================================================================
// REAL-WORLD VULNERABLE PATTERNS
// ============================================================================

// [TP-REAL-001] Express.js body parser pollution
function vulnerableExpressHandler(req, res) {
    const settings = {};
    for (let key in req.body) {
        settings[key] = req.body[key];  // VULNERABLE: req.body is user-controlled
    }
    res.json(settings);
}

// [TP-REAL-002] Config merge from query params
function vulnerableConfigMerge() {
    const params = new URLSearchParams(location.search);
    const userConfig = {};
    params.forEach(function(value, key) {
        userConfig[key] = value;
    });
    for (let k in userConfig) {
        appConfig[k] = userConfig[k];  // VULNERABLE
    }
}

// [TP-REAL-003] WebSocket message handler
socket.on('updateSettings', function(data) {
    for (let key in data) {
        userSettings[key] = data[key];  // VULNERABLE
    }
});

// [TP-REAL-004] Template/View data merge
function vulnerableViewMerge(userData) {
    const viewData = { title: 'Page' };
    for (let prop in userData) {
        viewData[prop] = userData[prop];  // VULNERABLE
    }
    return renderTemplate(viewData);
}

// [TP-REAL-005] Redux/State management pollution
function vulnerableReducer(state, action) {
    if (action.type === 'UPDATE_ALL') {
        for (let key in action.payload) {
            state[key] = action.payload[key];  // VULNERABLE
        }
    }
    return state;
}

console.log('Prototype Pollution test cases loaded');
