/**
 * Test cases for error handling vulnerabilities (JavaScript).
 * Targets rules in rules/traditional/error_handling.yml.
 * For security scanner testing only.
 */

// ---------------------------------------------------------------------------
// Vulnerable patterns
// ---------------------------------------------------------------------------

function vulnerable_empty_catch_block() {
    /** Empty catch block silently swallows errors, hiding failures. */
    try {
        JSON.parse(userInput);
    } catch (e) {}
}

function vulnerable_empty_catch_async() {
    /** Async variant -- promise rejections silently discarded. */
    try {
        await fetch('/api/data');
    } catch (err) {}
}

function vulnerable_error_stack_in_response(req, res) {
    /** Sending the full stack trace in the response leaks internal
     *  application details to the client. */
    try {
        processRequest(req);
    } catch (err) {
        res.send(err.stack);
    }
}

function vulnerable_error_message_in_json(req, res) {
    /** Returning err.message in a JSON response can expose sensitive
     *  information like file paths or SQL queries. */
    try {
        doWork(req.body);
    } catch (err) {
        res.json({error: err.message});
    }
}

function vulnerable_nested_empty_catch() {
    /** Nested empty catches can hide multiple layers of failures. */
    try {
        try {
            riskyInnerOperation();
        } catch (inner) {}
        riskyOuterOperation();
    } catch (outer) {}
}

// ---------------------------------------------------------------------------
// Safe patterns
// ---------------------------------------------------------------------------

function safe_catch_with_logging(req, res) {
    /** Catch the error, log it server-side, and return a generic message. */
    const logger = require('./logger');
    try {
        processRequest(req);
    } catch (err) {
        logger.error('Request processing failed', { error: err });
        res.status(500).json({ error: 'Internal server error' });
    }
}

function safe_error_response_generic(req, res) {
    /** Generic error JSON without any internal detail exposure. */
    try {
        doWork(req.body);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Something went wrong. Please try again.' });
    }
}
