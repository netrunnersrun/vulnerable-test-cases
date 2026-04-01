<?php
// SQL Injection Vulnerable Test Cases

// Matches: php-sqli-interpolation
function vulnerable_mysqli($conn, $userInput) {
    $result = $conn->query("SELECT * FROM users WHERE id = '$userInput'");
    return $result;
}

// Matches: php-sqli-pdo-query
function vulnerable_pdo($pdo, $userInput) {
    return $pdo->query("SELECT * FROM users WHERE email = '$userInput'");
}

// Matches: php-sqli-laravel-db-raw
function vulnerable_laravel_raw($userInput) {
    return DB::raw("SELECT * FROM users WHERE name = '$userInput'");
}

// Matches: php-sqli-laravel-whereraw
function vulnerable_whereraw($query, $userInput) {
    return $query->whereRaw("email = '$userInput'");
}

// Matches: php-sqli-wordpress-wpdb
function vulnerable_wordpress($wpdb, $userInput) {
    return $wpdb->query("SELECT * FROM wp_users WHERE user_login = '$userInput'");
}

// Safe: prepared statement
function safe_query($pdo, $userInput) {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->execute([$userInput]);
    return $stmt->fetchAll();
}
