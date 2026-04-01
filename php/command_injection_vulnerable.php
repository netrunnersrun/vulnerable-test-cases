<?php
// Command Injection Vulnerable Test Cases

// Matches: php-exec
function vulnerable_exec($userInput) {
    return exec("ls " . $userInput);
}

// Matches: php-popen
function vulnerable_popen($userInput) {
    return popen($userInput, "r");
}

// Matches: php-eval
function vulnerable_eval($userInput) {
    eval($userInput);
}

// Matches: php-create-function
function vulnerable_create_function($userInput) {
    $func = create_function('$x', $userInput);
    return $func(1);
}

// Matches: php-backtick-exec (pattern-regex)
function vulnerable_backtick($cmd) {
    return `$cmd`;
}

// Safe: escapeshellarg
function safe_command($userInput) {
    return exec("ls " . escapeshellarg($userInput));
}
