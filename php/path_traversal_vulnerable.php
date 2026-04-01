<?php
// Path Traversal Vulnerable Test Cases

// Matches: php-path-traversal-file-get-contents
function vulnerable_file_get_contents($userInput) {
    return file_get_contents($userInput);
}

// Matches: php-path-traversal-fopen
function vulnerable_fopen($userInput) {
    return fopen($userInput, "r");
}

// Matches: php-path-traversal-readfile
function vulnerable_readfile($userInput) {
    readfile($userInput);
}

// Matches: php-path-traversal-include
function vulnerable_include($userInput) {
    include($userInput);
}

// Safe: basename and allowlist
function safe_read($userInput) {
    $allowed = ['page1.php', 'page2.php'];
    $file = basename($userInput);
    if (in_array($file, $allowed)) {
        return file_get_contents("/safe/dir/" . $file);
    }
    return false;
}
