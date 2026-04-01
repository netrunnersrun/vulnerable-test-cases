<?php
// SSRF Vulnerable Test Cases

// Matches: php-ssrf-curl
function vulnerable_curl($userInput) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $userInput);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    return curl_exec($ch);
}

// Matches: php-ssrf-file-get-contents-url
function vulnerable_file_get_contents_url($userUrl) {
    return file_get_contents($userUrl);
}

// Safe: URL validation
function safe_fetch($userInput) {
    $parsed = parse_url($userInput);
    $allowed = ['api.trusted.com'];
    if (!in_array($parsed['host'], $allowed)) {
        throw new Exception("Blocked URL");
    }
    return file_get_contents($userInput);
}
