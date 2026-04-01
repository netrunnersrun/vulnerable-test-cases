<?php
// XSS Vulnerable Test Cases

// Matches: php-echo-unescaped
function vulnerable_echo($userInput) {
    echo $userInput;
}

// Matches: php-xss-print
function vulnerable_print($userInput) {
    print($userInput);
}

// Matches: php-blade-unescaped (pattern-regex)
// In Blade template: {!! $userInput !!}

// Safe: htmlspecialchars
function safe_echo($userInput) {
    echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');
}
