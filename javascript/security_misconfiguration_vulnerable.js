/**
 * Test cases for security misconfiguration vulnerabilities (JavaScript).
 * Targets rules in rules/traditional/security_misconfiguration.yml.
 * For security scanner testing only.
 */

const express = require('express');
const cors = require('cors');

// ---------------------------------------------------------------------------
// Vulnerable patterns
// ---------------------------------------------------------------------------

function vulnerable_cors_wildcard_middleware() {
    /** CORS middleware configured with wildcard origin allows any site
     *  to make cross-origin requests. */
    const app = express();
    app.use(cors({ origin: '*' }));
    return app;
}

function vulnerable_cors_wildcard_header(req, res) {
    /** Manually setting Access-Control-Allow-Origin to '*' has the same
     *  effect as the middleware wildcard. */
    res.header('Access-Control-Allow-Origin', '*');
    res.json({ data: 'open to the world' });
}

function vulnerable_express_no_helmet() {
    /** Serving static files without Helmet means the app lacks security
     *  headers such as X-Content-Type-Options, CSP, etc. */
    const app = express();
    app.use(express.static('public'));
    return app;
}

function vulnerable_cors_and_static_combined() {
    /** Combining CORS wildcard with static serving compounds the risk. */
    const app = express();
    app.use(cors({ origin: '*' }));
    app.use(express.static('public'));
    return app;
}

// ---------------------------------------------------------------------------
// Safe patterns
// ---------------------------------------------------------------------------

function safe_cors_restricted_origin() {
    /** CORS restricted to a specific trusted origin. */
    const app = express();
    app.use(cors({ origin: 'https://trusted.example.com' }));
    return app;
}

function safe_express_with_helmet() {
    /** Using Helmet sets sensible default security headers. */
    const helmet = require('helmet');
    const app = express();
    app.use(helmet());
    app.use(express.static('public'));
    return app;
}
