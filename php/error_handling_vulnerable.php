<?php
// Error Handling Vulnerable Test Cases

// Matches: php-error-reporting-all
function vulnerable_error_reporting() {
    error_reporting(E_ALL);
}

// Matches: php-exception-message-response
function vulnerable_exception_echo($e) {
    echo $e->getMessage();
}

// Matches: php-var-dump-debug
function vulnerable_var_dump($data) {
    var_dump($data);
}

// Safe: custom error handler
function safe_error_handler($e) {
    error_log($e->getMessage());
    echo "An error occurred. Please try again.";
}
