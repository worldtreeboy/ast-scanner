/**
 * Node.js & Express.js XSS and Prototype Pollution Test Cases
 * ============================================================
 * Server-side JavaScript vulnerabilities for XSS and Prototype Pollution only
 *
 * [TP] = True Positive - SHOULD be detected
 * [FP] = False Positive - Should NOT be detected (safe code)
 */

// ============================================================================
// EXPRESS.JS REQUEST HANDLERS - Prototype Pollution
// ============================================================================

// [TP-EXPRESS-001] Classic req.body prototype pollution
function vulnerableBodyMerge(req, res) {
    var config = { admin: false, role: 'user' };
    for (var key in req.body) {
        config[key] = req.body[key];  // VULNERABLE: req.body is user-controlled
    }
    res.json(config);
}

// [TP-EXPRESS-002] req.query prototype pollution
function vulnerableQueryMerge(req, res) {
    var options = {};
    for (var prop in req.query) {
        options[prop] = req.query[prop];  // VULNERABLE: req.query is user-controlled
    }
    return options;
}

// [TP-EXPRESS-003] req.params in for-in loop
function vulnerableParamsMerge(req, res) {
    var data = {};
    for (var p in req.params) {
        data[p] = req.params[p];  // VULNERABLE
    }
    res.send(data);
}

// [TP-EXPRESS-004] Nested object merge from request
function vulnerableNestedMerge(req, res) {
    var settings = { theme: 'light', lang: 'en' };
    var userSettings = req.body.settings;
    for (var key in userSettings) {
        if (typeof userSettings[key] === 'object') {
            settings[key] = settings[key] || {};
            Object.assign(settings[key], userSettings[key]);  // VULNERABLE
        } else {
            settings[key] = userSettings[key];  // VULNERABLE
        }
    }
    res.json(settings);
}

// [TP-EXPRESS-005] Lodash merge with req.body
function vulnerableLodashMerge(req, res) {
    var defaults = { safe: true };
    var result = _.merge(defaults, req.body);  // VULNERABLE
    res.json(result);
}

// [TP-EXPRESS-006] jQuery-style extend in Node
function vulnerableExtend(req, res) {
    var config = {};
    extend(true, config, req.body);  // VULNERABLE: deep extend
    res.json(config);
}

// [TP-EXPRESS-007] Object.assign with request data
function vulnerableObjectAssign(req, res) {
    var user = { id: 1, role: 'guest' };
    Object.assign(user, req.body);  // VULNERABLE
    res.json(user);
}

// [TP-EXPRESS-008] defaultsDeep with request
function vulnerableDefaultsDeep(req, res) {
    var config = { debug: false };
    _.defaultsDeep(config, req.body);  // VULNERABLE
    res.json(config);
}

// [TP-EXPRESS-009] Multiple sources merge
function vulnerableMultiMerge(req, res) {
    var result = {};
    var sources = [req.query, req.body, req.params];
    sources.forEach(function(source) {
        for (var key in source) {
            result[key] = source[key];  // VULNERABLE
        }
    });
    res.json(result);
}

// [TP-EXPRESS-010] Session pollution
function vulnerableSessionMerge(req, res) {
    for (var key in req.body) {
        req.session[key] = req.body[key];  // VULNERABLE
    }
    res.send('Session updated');
}

// [FP-EXPRESS-001] Safe merge with hasOwnProperty
function safeMergeWithCheck(req, res) {
    var config = {};
    for (var key in req.body) {
        if (req.body.hasOwnProperty(key)) {
            config[key] = req.body[key];  // SAFER: hasOwnProperty check
        }
    }
    res.json(config);
}

// [FP-EXPRESS-002] Safe merge with Object.keys
function safeMergeWithKeys(req, res) {
    var config = {};
    Object.keys(req.body).forEach(function(key) {
        config[key] = req.body[key];  // SAFE: Object.keys doesn't include prototype
    });
    res.json(config);
}

// [FP-EXPRESS-003] Safe merge with explicit filter
function safeMergeWithFilter(req, res) {
    var config = {};
    var dangerous = ['__proto__', 'constructor', 'prototype'];
    for (var key in req.body) {
        if (dangerous.indexOf(key) === -1) {
            config[key] = req.body[key];  // SAFE: filtered
        }
    }
    res.json(config);
}

// [FP-EXPRESS-004] Using null prototype object
function safeMergeNullProto(req, res) {
    var config = Object.create(null);
    for (var key in req.body) {
        config[key] = req.body[key];  // SAFER: no prototype chain
    }
    res.json(config);
}

// [FP-EXPRESS-005] Using Map instead of object
function safeMergeMap(req, res) {
    var config = new Map();
    for (var key in req.body) {
        config.set(key, req.body[key]);  // SAFE: Map doesn't have prototype issues
    }
    res.json(Object.fromEntries(config));
}

// ============================================================================
// EXPRESS.JS - Server-Side XSS (Response Reflection)
// ============================================================================

// [TP-XSS-001] Direct reflection of query param in HTML
function vulnerableReflection(req, res) {
    var name = req.query.name;
    res.send('<h1>Hello ' + name + '</h1>');  // VULNERABLE: reflected XSS
}

// [TP-XSS-002] HTML response with body data
function vulnerableBodyReflection(req, res) {
    var content = req.body.content;
    res.send('<div class="content">' + content + '</div>');  // VULNERABLE
}

// [TP-XSS-003] JSON in HTML context
function vulnerableJsonInHtml(req, res) {
    var data = req.query.data;
    res.send('<script>var config = ' + data + ';</script>');  // VULNERABLE
}

// [TP-XSS-004] Template rendering with unescaped data
function vulnerableRender(req, res) {
    var userInput = req.body.content;
    res.render('page', { content: userInput });  // May be vulnerable depending on template
}

// [TP-XSS-005] res.write with user input
function vulnerableResWrite(req, res) {
    var msg = req.query.message;
    res.write('<p>' + msg + '</p>');  // VULNERABLE
    res.end();
}

// [TP-XSS-006] HTML response with params
function vulnerableParamReflection(req, res) {
    var id = req.params.id;
    res.send('<a href="/item/' + id + '">Item ' + id + '</a>');  // VULNERABLE
}

// [TP-XSS-007] Error message reflection
function vulnerableErrorReflection(req, res) {
    var page = req.query.page;
    res.status(404).send('<h1>Page "' + page + '" not found</h1>');  // VULNERABLE
}

// [TP-XSS-008] Building HTML with user data
function vulnerableHtmlBuilder(req, res) {
    var items = req.body.items;
    var html = '<ul>';
    items.forEach(function(item) {
        html += '<li>' + item + '</li>';  // VULNERABLE
    });
    html += '</ul>';
    res.send(html);
}

// [TP-XSS-009] Attribute injection
function vulnerableAttributeInjection(req, res) {
    var url = req.query.url;
    res.send('<a href="' + url + '">Click here</a>');  // VULNERABLE: javascript: URLs
}

// [TP-XSS-010] Event handler injection
function vulnerableEventHandler(req, res) {
    var action = req.query.action;
    res.send('<button onclick="' + action + '">Click</button>');  // VULNERABLE
}

// [FP-XSS-001] Properly escaped output
function safeEscapedOutput(req, res) {
    var name = escapeHtml(req.query.name);
    res.send('<h1>Hello ' + name + '</h1>');  // SAFE: escaped
}

// [FP-XSS-002] JSON response (auto-escaped)
function safeJsonResponse(req, res) {
    res.json({ name: req.query.name });  // SAFE: JSON encoding
}

// [FP-XSS-003] Text content type
function safeTextResponse(req, res) {
    res.type('text/plain');
    res.send(req.query.data);  // SAFER: plain text
}

// [FP-XSS-004] Using template with auto-escaping
function safeTemplateEscaped(req, res) {
    var name = req.query.name;
    res.render('greeting', { name: name });  // Usually safe if template auto-escapes
}

// ============================================================================
// WEBSOCKET - Prototype Pollution
// ============================================================================

// [TP-WS-001] WebSocket message merge
io.on('connection', function(socket) {
    socket.on('updateSettings', function(data) {
        for (var key in data) {
            serverConfig[key] = data[key];  // VULNERABLE: prototype pollution
        }
    });
});

// [TP-WS-002] WebSocket deep merge
io.on('connection', function(socket) {
    socket.on('config', function(userConfig) {
        _.merge(appConfig, userConfig);  // VULNERABLE
    });
});

// [TP-WS-003] WebSocket Object.assign
io.on('connection', function(socket) {
    socket.on('update', function(payload) {
        Object.assign(globalState, payload);  // VULNERABLE
    });
});

// [TP-WS-004] WebSocket nested merge
io.on('connection', function(socket) {
    socket.on('deepUpdate', function(data) {
        for (var key in data) {
            if (typeof data[key] === 'object') {
                state[key] = state[key] || {};
                Object.assign(state[key], data[key]);  // VULNERABLE
            } else {
                state[key] = data[key];  // VULNERABLE
            }
        }
    });
});

// ============================================================================
// WEBSOCKET - XSS via Broadcast
// ============================================================================

// [TP-WS-XSS-001] Broadcasting user message (client-side XSS risk)
io.on('connection', function(socket) {
    socket.on('chat', function(message) {
        io.emit('message', message);  // User data broadcast - client may render as HTML
    });
});

// [TP-WS-XSS-002] User-controlled event name
io.on('connection', function(socket) {
    socket.on('custom', function(data) {
        io.emit(data.event, data.payload);  // VULNERABLE: event name injection
    });
});

// ============================================================================
// MIDDLEWARE PATTERNS - Prototype Pollution
// ============================================================================

// [TP-MW-001] Request extension middleware
function vulnerableMiddleware(req, res, next) {
    for (var key in req.body) {
        req.custom[key] = req.body[key];  // VULNERABLE
    }
    next();
}

// [TP-MW-002] Config merge middleware
function vulnerableConfigMiddleware(req, res, next) {
    var userConfig = req.headers['x-config'];
    if (userConfig) {
        var config = JSON.parse(userConfig);
        for (var key in config) {
            req.appConfig[key] = config[key];  // VULNERABLE
        }
    }
    next();
}

// [TP-MW-003] Cookie-based config pollution
function vulnerableCookieMiddleware(req, res, next) {
    var prefs = req.cookies.preferences;
    if (prefs) {
        var parsed = JSON.parse(prefs);
        for (var key in parsed) {
            req.userPrefs[key] = parsed[key];  // VULNERABLE
        }
    }
    next();
}

// ============================================================================
// API PATTERNS - Prototype Pollution
// ============================================================================

// [TP-API-001] PUT/PATCH update handler
app.put('/api/user/:id', function(req, res) {
    var user = users[req.params.id];
    for (var key in req.body) {
        user[key] = req.body[key];  // VULNERABLE
    }
    res.json(user);
});

// [TP-API-002] Bulk update endpoint
app.post('/api/settings/bulk', function(req, res) {
    var updates = req.body.updates;
    for (var key in updates) {
        globalSettings[key] = updates[key];  // VULNERABLE
    }
    res.json(globalSettings);
});

// [TP-API-003] Dynamic property setter
app.post('/api/config/:key', function(req, res) {
    var key = req.params.key;
    var value = req.body.value;
    config[key] = value;  // VULNERABLE: user controls key
    res.json({ success: true });
});

// [TP-API-004] GraphQL resolver pollution
var resolvers = {
    Mutation: {
        updateSettings: function(parent, args) {
            for (var key in args.input) {
                settings[key] = args.input[key];  // VULNERABLE
            }
            return settings;
        }
    }
};

// ============================================================================
// TEMPLATE ENGINE PATTERNS - XSS
// ============================================================================

// [TP-TPL-001] EJS unescaped output
app.get('/ejs-vuln', function(req, res) {
    var name = req.query.name;
    // In EJS template: <%- name %> is unescaped (vulnerable)
    // vs <%= name %> which is escaped (safe)
    res.render('page.ejs', { name: name, useUnescaped: true });
});

// [TP-TPL-002] Pug/Jade unescaped
app.get('/pug-vuln', function(req, res) {
    var content = req.body.content;
    // In Pug: != content is unescaped (vulnerable)
    // vs = content which is escaped (safe)
    res.render('page.pug', { content: content });
});

// [TP-TPL-003] Handlebars triple braces
app.get('/hbs-vuln', function(req, res) {
    var html = req.query.html;
    // In Handlebars: {{{ html }}} is unescaped (vulnerable)
    // vs {{ html }} which is escaped (safe)
    res.render('page.hbs', { html: html });
});

// [TP-TPL-004] Mustache unescaped
app.get('/mustache-vuln', function(req, res) {
    var data = req.query.data;
    // In Mustache: {{{ data }}} or {{& data }} is unescaped
    res.render('page.mustache', { data: data });
});

// [TP-TPL-005] Nunjucks safe filter misuse
app.get('/nunjucks-vuln', function(req, res) {
    var userHtml = req.body.html;
    // Using | safe filter on user input is vulnerable
    res.render('page.njk', { content: userHtml, markAsSafe: true });
});

// ============================================================================
// JSON PARSING - Prototype Pollution
// ============================================================================

// [TP-JSON-001] JSON.parse from header
function vulnerableJsonHeader(req, res) {
    var data = JSON.parse(req.headers['x-data']);
    for (var key in data) {
        config[key] = data[key];  // VULNERABLE
    }
    res.json(config);
}

// [TP-JSON-002] JSON.parse from query string
function vulnerableJsonQuery(req, res) {
    var options = JSON.parse(req.query.options);
    for (var key in options) {
        settings[key] = options[key];  // VULNERABLE
    }
    res.json(settings);
}

// [TP-JSON-003] JSON.parse from cookie
function vulnerableJsonCookie(req, res) {
    var prefs = JSON.parse(req.cookies.prefs);
    for (var key in prefs) {
        userPrefs[key] = prefs[key];  // VULNERABLE
    }
    res.json(userPrefs);
}

// ============================================================================
// CALLBACK/PROMISE PATTERNS - Pollution
// ============================================================================

// [TP-ASYNC-001] Pollution in callback
function vulnerableCallbackMerge(req, res) {
    fetchUserData(req.params.id, function(err, userData) {
        for (var key in req.body) {
            userData[key] = req.body[key];  // VULNERABLE
        }
        saveUser(userData);
        res.json(userData);
    });
}

// [TP-ASYNC-002] Pollution in promise chain
function vulnerablePromiseMerge(req, res) {
    getConfig().then(function(config) {
        for (var key in req.body) {
            config[key] = req.body[key];  // VULNERABLE
        }
        return saveConfig(config);
    }).then(function() {
        res.send('Updated');
    });
}

console.log('Node.js/Express.js XSS and Prototype Pollution test cases loaded');
