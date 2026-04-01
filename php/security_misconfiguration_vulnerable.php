<?php
// Security Misconfiguration Vulnerable Test Cases

// Matches: php-display-errors-on (pattern-regex)
function vulnerable_display_errors() {
    ini_set("display_errors", "1");
}

// Matches: php-laravel-debug-true (pattern-regex)
// In .env: APP_DEBUG=true
// In config: 'debug' => true

// Matches: php-allow-url-include (pattern-regex)
function vulnerable_url_include() {
    ini_set("allow_url_include", "1");
}

// Safe: production config
function safe_config() {
    ini_set("display_errors", "0");
    ini_set("log_errors", "1");
}
