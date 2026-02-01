/**
 * Advanced Prototype Pollution Test Cases
 * =======================================
 * Complex patterns and edge cases for prototype pollution detection
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected (safe code)
 * [FN] = False Negative - Edge cases that might be missed
 */

// ============================================================================
// DEEP MERGE PATTERNS
// ============================================================================

// [TP-DEEP-001] Custom recursive deep merge
function vulnerableDeepMerge(target, source) {
    for (var key in source) {
        if (source[key] && typeof source[key] === 'object') {
            if (!target[key]) {
                target[key] = {};
            }
            vulnerableDeepMerge(target[key], source[key]);  // VULNERABLE: recursive
        } else {
            target[key] = source[key];  // VULNERABLE
        }
    }
    return target;
}

// [TP-DEEP-002] Deep clone with pollution
function vulnerableDeepClone(obj) {
    var clone = {};
    for (var key in obj) {
        if (typeof obj[key] === 'object' && obj[key] !== null) {
            clone[key] = vulnerableDeepClone(obj[key]);
        } else {
            clone[key] = obj[key];  // VULNERABLE
        }
    }
    return clone;
}

// [TP-DEEP-003] Object.assign in loop
function vulnerableAssignLoop(target, sources) {
    for (var i = 0; i < sources.length; i++) {
        var source = sources[i];
        for (var key in source) {
            target[key] = source[key];  // VULNERABLE
        }
    }
    return target;
}

// [TP-DEEP-004] Nested property setter
function vulnerableNestedSet(obj, path, value) {
    var parts = path.split('.');
    var current = obj;
    for (var i = 0; i < parts.length - 1; i++) {
        var part = parts[i];
        if (!current[part]) {
            current[part] = {};
        }
        current = current[part];
    }
    current[parts[parts.length - 1]] = value;  // VULNERABLE if path contains __proto__
    return obj;
}

// [TP-DEEP-005] Lodash _.set equivalent
function vulnerableSet(obj, path, value) {
    var keys = path.replace(/\[(\d+)\]/g, '.$1').split('.');
    var target = obj;
    for (var i = 0; i < keys.length - 1; i++) {
        var key = keys[i];
        if (!(key in target)) {
            target[key] = {};
        }
        target = target[key];
    }
    target[keys[keys.length - 1]] = value;  // VULNERABLE
    return obj;
}

// [FP-DEEP-001] Safe deep merge with filter
function safeDeepMerge(target, source) {
    var dangerous = ['__proto__', 'constructor', 'prototype'];
    for (var key in source) {
        if (dangerous.indexOf(key) !== -1) continue;  // SAFE: filtered
        if (source[key] && typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            safeDeepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// [FP-DEEP-002] Deep merge with Object.hasOwn
function safeDeepMergeHasOwn(target, source) {
    for (var key in source) {
        if (!Object.hasOwn(source, key)) continue;  // SAFE
        if (source[key] && typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            safeDeepMergeHasOwn(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// ============================================================================
// CONSTRUCTOR/PROTOTYPE ACCESS PATTERNS
// ============================================================================

// [TP-PROTO-001] Direct constructor access
function vulnerableConstructorAccess(obj, value) {
    obj['constructor']['prototype']['polluted'] = value;  // VULNERABLE
}

// [TP-PROTO-002] Chained prototype access
function vulnerableChainedProto(obj) {
    obj['__proto__']['__proto__']['deep'] = true;  // VULNERABLE
}

// [TP-PROTO-003] Constructor via variable
function vulnerableConstructorVar(obj, prop, value) {
    var ctor = 'constructor';
    obj[ctor]['prototype'][prop] = value;  // VULNERABLE
}

// [TP-PROTO-004] Prototype via computed property
function vulnerableComputedProto(obj, key) {
    var proto = '__proto__';
    obj[proto][key] = 'polluted';  // VULNERABLE
}

// [TP-PROTO-005] Object.prototype direct access
function vulnerableObjectProto(prop, value) {
    Object.prototype[prop] = value;  // VULNERABLE: direct Object.prototype modification
}

// [TP-PROTO-006] Array prototype pollution
function vulnerableArrayProto(prop, value) {
    Array.prototype[prop] = value;  // VULNERABLE: affects all arrays
}

// [TP-PROTO-007] Function prototype pollution
function vulnerableFunctionProto(prop, value) {
    Function.prototype[prop] = value;  // VULNERABLE: affects all functions
}

// ============================================================================
// JSON.PARSE BASED POLLUTION
// ============================================================================

// [TP-JSON-001] JSON.parse from URL directly merged
function vulnerableJsonUrl() {
    var data = JSON.parse(decodeURIComponent(location.search.slice(1)));
    var config = {};
    for (var key in data) {
        config[key] = data[key];  // VULNERABLE
    }
    return config;
}

// [TP-JSON-002] JSON.parse from postMessage
function vulnerableJsonPostMessage(event) {
    var data = JSON.parse(event.data);
    for (var prop in data) {
        globalSettings[prop] = data[prop];  // VULNERABLE
    }
}

// [TP-JSON-003] JSON.parse from WebSocket
function vulnerableJsonWebSocket(ws) {
    ws.onmessage = function(event) {
        var msg = JSON.parse(event.data);
        for (var key in msg.config) {
            appConfig[key] = msg.config[key];  // VULNERABLE
        }
    };
}

// [TP-JSON-004] JSON.parse from fetch response
function vulnerableJsonFetch(url) {
    fetch(url).then(function(r) { return r.json(); }).then(function(data) {
        for (var key in data) {
            settings[key] = data[key];  // VULNERABLE: 2nd order pollution
        }
    });
}

// [TP-JSON-005] JSON.parse from localStorage
function vulnerableJsonStorage() {
    var saved = JSON.parse(localStorage.getItem('userPrefs'));
    for (var k in saved) {
        preferences[k] = saved[k];  // VULNERABLE
    }
}

// ============================================================================
// LIBRARY-SPECIFIC PATTERNS
// ============================================================================

// [TP-LIB-001] Lodash _.merge
function vulnerableLodashMerge(input) {
    var config = { safe: true };
    _.merge(config, input);  // VULNERABLE
    return config;
}

// [TP-LIB-002] Lodash _.mergeWith
function vulnerableLodashMergeWith(input) {
    _.mergeWith({}, input, function(objValue, srcValue) {
        return srcValue;  // VULNERABLE
    });
}

// [TP-LIB-003] Lodash _.defaultsDeep
function vulnerableLodashDefaults(input) {
    _.defaultsDeep({}, input);  // VULNERABLE
}

// [TP-LIB-004] Lodash _.set with user path
function vulnerableLodashSet(obj, userPath, value) {
    _.set(obj, userPath, value);  // VULNERABLE if userPath contains __proto__
}

// [TP-LIB-005] jQuery $.extend deep
function vulnerablejQueryExtendDeep(input) {
    $.extend(true, {}, input);  // VULNERABLE: deep extend
}

// [TP-LIB-006] Hoek.merge (older versions)
function vulnerableHoekMerge(input) {
    Hoek.merge({}, input);  // VULNERABLE in older versions
}

// [TP-LIB-007] deeps library
function vulnerableDeeps(input) {
    deeps.merge({}, input);  // VULNERABLE
}

// [TP-LIB-008] merge-deep library
function vulnerableMergeDeep(input) {
    mergeDeep({}, input);  // VULNERABLE
}

// [TP-LIB-009] deepmerge library (older)
function vulnerableDeepMergeLib(input) {
    deepmerge({}, input);  // VULNERABLE in some versions
}

// [TP-LIB-010] object-path library
function vulnerableObjectPath(path, value) {
    objectPath.set({}, path, value);  // VULNERABLE
}

// [FP-LIB-001] jQuery shallow extend (safe)
function safejQueryExtendShallow(input) {
    $.extend({}, input);  // SAFER: shallow extend
}

// [FP-LIB-002] Object.assign to null proto
function safeObjectAssignNull(input) {
    var target = Object.create(null);
    Object.assign(target, input);  // SAFE: no prototype
}

// ============================================================================
// FRAMEWORK-SPECIFIC PATTERNS
// ============================================================================

// [TP-FW-001] Express.js middleware pollution
function vulnerableExpressMiddleware(req, res, next) {
    for (var key in req.body) {
        req.session[key] = req.body[key];  // VULNERABLE
    }
    next();
}

// [TP-FW-002] Koa.js context pollution
function vulnerableKoaMiddleware(ctx, next) {
    var data = ctx.request.body;
    for (var prop in data) {
        ctx.state[prop] = data[prop];  // VULNERABLE
    }
    return next();
}

// [TP-FW-003] Fastify plugin pollution
function vulnerableFastifyPlugin(fastify, opts) {
    fastify.addHook('preHandler', function(request, reply, done) {
        for (var key in request.body) {
            request.user[key] = request.body[key];  // VULNERABLE
        }
        done();
    });
}

// [TP-FW-004] Hapi.js handler pollution
function vulnerableHapiHandler(request, h) {
    var payload = request.payload;
    for (var key in payload) {
        request.server.settings[key] = payload[key];  // VULNERABLE
    }
    return h.response('OK');
}

// [TP-FW-005] NestJS service pollution
function vulnerableNestService(dto) {
    var entity = {};
    for (var key in dto) {
        entity[key] = dto[key];  // VULNERABLE
    }
    return entity;
}

// ============================================================================
// CLASS-BASED PATTERNS
// ============================================================================

// [TP-CLASS-001] Class method with prototype pollution
function VulnerableClass() {
    this.config = {};
}

VulnerableClass.prototype.updateConfig = function(userConfig) {
    for (var key in userConfig) {
        this.config[key] = userConfig[key];  // VULNERABLE
    }
};

// [TP-CLASS-002] Static method pollution
VulnerableClass.mergeDefaults = function(defaults, overrides) {
    for (var key in overrides) {
        defaults[key] = overrides[key];  // VULNERABLE
    }
    return defaults;
};

// [TP-CLASS-003] Constructor pollution
function PollutableConstructor(options) {
    for (var key in options) {
        this[key] = options[key];  // VULNERABLE
    }
}

// ============================================================================
// ARRAY AND SPECIAL OBJECT PATTERNS
// ============================================================================

// [TP-ARR-001] Array-like iteration pollution
function vulnerableArrayLikeMerge(arrayLike, source) {
    for (var i in source) {
        arrayLike[i] = source[i];  // VULNERABLE
    }
}

// [TP-ARR-002] Object.entries iteration (still needs check)
function vulnerableEntriesMerge(target, source) {
    Object.entries(source).forEach(function(entry) {
        var key = entry[0];
        var value = entry[1];
        target[key] = value;  // Potentially vulnerable if source crafted
    });
}

// [TP-ARR-003] Spread in reduce
function vulnerableReduceMerge(sources) {
    return sources.reduce(function(acc, source) {
        for (var key in source) {
            acc[key] = source[key];  // VULNERABLE
        }
        return acc;
    }, {});
}

// ============================================================================
// DEFENSIVE PATTERNS (FALSE POSITIVES - SHOULD NOT DETECT)
// ============================================================================

// [FP-DEF-001] Frozen object
function safeFrozenObject(input) {
    var config = Object.freeze({ safe: true });
    for (var key in input) {
        config[key] = input[key];  // Won't work - object is frozen
    }
    return config;
}

// [FP-DEF-002] Sealed object
function safeSealedObject(input) {
    var config = Object.seal({ safe: true, other: null });
    for (var key in input) {
        if (key in config) {
            config[key] = input[key];  // Only existing properties
        }
    }
    return config;
}

// [FP-DEF-003] Proxy with validation
function safeProxyObject(input) {
    var target = {};
    var proxy = new Proxy(target, {
        set: function(obj, prop, value) {
            if (prop === '__proto__' || prop === 'constructor') {
                return false;  // Block dangerous properties
            }
            obj[prop] = value;
            return true;
        }
    });

    for (var key in input) {
        proxy[key] = input[key];  // SAFE: proxy validates
    }
    return target;
}

// [FP-DEF-004] Using Map
function safeMapStorage(input) {
    var storage = new Map();
    for (var key in input) {
        storage.set(key, input[key]);  // SAFE: Map doesn't have prototype issues
    }
    return storage;
}

// [FP-DEF-005] JSON round-trip sanitization
function safeJsonRoundTrip(input) {
    var sanitized = JSON.parse(JSON.stringify(input));
    // __proto__ becomes a regular property after JSON round-trip
    var config = Object.create(null);
    for (var key in sanitized) {
        config[key] = sanitized[key];  // SAFER: null prototype
    }
    return config;
}

// ============================================================================
// REAL-WORLD CVE PATTERNS
// ============================================================================

// [TP-CVE-001] CVE-2019-10744 pattern (Lodash)
function cve201910744(userInput) {
    _.defaultsDeep({}, userInput);  // CVE-2019-10744
}

// [TP-CVE-002] CVE-2020-8203 pattern (Lodash)
function cve20208203(userInput) {
    _.zipObjectDeep(['a.b.c'], [userInput]);  // CVE-2020-8203
}

// [TP-CVE-003] CVE-2019-10747 pattern (set-value)
function cve201910747(obj, path, value) {
    setValue(obj, path, value);  // CVE-2019-10747
}

// [TP-CVE-004] CVE-2020-7598 pattern (minimist)
function cve20207598(args) {
    var parsed = minimist(args);  // CVE-2020-7598 (older versions)
    return parsed;
}

// [TP-CVE-005] CVE-2021-25928 pattern (safe-obj)
function cve202125928(obj, path, value) {
    safeObj.set(obj, path, value);  // CVE-2021-25928
}

console.log('Advanced Prototype Pollution test cases loaded');
