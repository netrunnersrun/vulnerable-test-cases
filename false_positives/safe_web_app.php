<?php
/**
 * False positive test cases for PHP web application security.
 * All functions here are SAFE despite matching vulnerability patterns.
 */

// --- SQL Injection False Positives ---

/**
 * PDO prepared statement with bound parameters - NOT SQL injection.
 */
function getUserById(PDO $pdo, int $userId): ?array {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
    $stmt->execute(['id' => $userId]);
    return $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
}

/**
 * PDO prepared statement with positional parameters - NOT injection.
 */
function searchUsers(PDO $pdo, string $name): array {
    $stmt = $pdo->prepare("SELECT * FROM users WHERE name LIKE ?");
    $stmt->execute(["%{$name}%"]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

/**
 * Laravel Eloquent ORM query (parameterized internally) - NOT injection.
 */
function getActiveUsers(): string {
    // User::where('active', true)->orderBy('name')->get();
    return "Eloquent query with automatic parameter binding";
}

/**
 * WordPress $wpdb->prepare() with proper parameterization - SAFE.
 */
function getWpPost(object $wpdb, int $postId): string {
    // $wpdb->prepare() properly escapes parameters
    return $wpdb->prepare("SELECT * FROM wp_posts WHERE ID = %d", $postId);
}


// --- XSS False Positives ---

/**
 * Output encoded with htmlspecialchars - NOT XSS.
 */
function displayUserName(string $name): void {
    $safe = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    echo "<p>Welcome, {$safe}</p>";
}

/**
 * Output encoded with htmlentities - NOT XSS.
 */
function displayComment(string $comment): void {
    $safe = htmlentities($comment, ENT_QUOTES, 'UTF-8');
    echo "<div class='comment'>{$safe}</div>";
}

/**
 * Laravel Blade {{ }} syntax (auto-escapes) - SAFE.
 * Note: This is template code, not {!! !!} unescaped output.
 */
function getBladeTemplate(): string {
    return "{{ \$user->name }}"; // Double curly braces auto-escape
}


// --- Command Injection False Positives ---

/**
 * escapeshellarg() used for argument sanitization - SAFE.
 */
function compressFile(string $filename): void {
    $safeName = escapeshellarg(basename($filename));
    exec("gzip " . $safeName);
}

/**
 * Allowlisted command with no user input in command string - SAFE.
 */
function getSystemInfo(): string {
    // Hardcoded command, no user input
    return shell_exec("uname -a");
}

/**
 * Numeric-only parameter, not vulnerable to injection - SAFE.
 */
function resizeImage(int $width, int $height): void {
    if ($width <= 0 || $width > 4096 || $height <= 0 || $height > 4096) {
        throw new InvalidArgumentException("Invalid dimensions");
    }
    exec("convert input.png -resize {$width}x{$height} output.png");
}


// --- Path Traversal False Positives ---

/**
 * basename() strips directory traversal, extension validated - SAFE.
 */
function readUploadedFile(string $filename): string {
    $safeName = basename($filename);
    $allowedExtensions = ['txt', 'pdf', 'png', 'jpg'];
    $ext = pathinfo($safeName, PATHINFO_EXTENSION);
    if (!in_array($ext, $allowedExtensions, true)) {
        throw new RuntimeException("File type not allowed");
    }
    $fullPath = "/var/uploads/" . $safeName;
    return file_get_contents($fullPath);
}

/**
 * realpath() validates against base directory - SAFE.
 */
function serveStaticFile(string $requestedFile): string {
    $baseDir = realpath("/var/www/static");
    $filePath = realpath($baseDir . '/' . $requestedFile);
    if ($filePath === false || strpos($filePath, $baseDir) !== 0) {
        throw new RuntimeException("Access denied");
    }
    return file_get_contents($filePath);
}


// --- SSRF False Positives ---

/**
 * URL validated against allowlist before curl request - NOT SSRF.
 */
function fetchFromAllowedAPI(string $url): string {
    $parsed = parse_url($url);
    $allowedHosts = ['api.github.com', 'api.stripe.com'];
    if (!in_array($parsed['host'] ?? '', $allowedHosts, true)) {
        throw new RuntimeException("Host not allowed");
    }
    if (($parsed['scheme'] ?? '') !== 'https') {
        throw new RuntimeException("HTTPS required");
    }
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}


// --- Deserialization False Positives ---

/**
 * json_decode used instead of unserialize - SAFE.
 */
function parseUserData(string $json): array {
    $data = json_decode($json, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new RuntimeException("Invalid JSON");
    }
    return $data;
}

/**
 * unserialize with allowed_classes restriction - SAFE.
 */
function deserializeWithAllowlist(string $data): mixed {
    return unserialize($data, ['allowed_classes' => ['stdClass', 'DateTime']]);
}
