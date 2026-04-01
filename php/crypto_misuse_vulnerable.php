<?php
// Crypto Misuse Vulnerable Test Cases

// Matches: php-md5-password
function vulnerable_md5($password) {
    return md5($password);
}

// Matches: php-sha1-password
function vulnerable_sha1($password) {
    return sha1($password);
}

// Matches: php-weak-rand
function vulnerable_rand() {
    return rand();
}

// Matches: php-mcrypt-usage
function vulnerable_mcrypt($data, $key) {
    return mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);
}

// Safe: password_hash and random_bytes
function safe_hash($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}
