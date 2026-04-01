<?php
// Deserialization Vulnerable Test Cases

// Matches: php-unserialize
function vulnerable_unserialize($userInput) {
    return unserialize($userInput);
}

// Matches: php-unserialize-cookie
function vulnerable_cookie_unserialize() {
    $data = $_COOKIE['session_data'];
    return unserialize($_COOKIE[$data]);
}

// Safe: use json_decode
function safe_deserialize($userInput) {
    return json_decode($userInput, true);
}
