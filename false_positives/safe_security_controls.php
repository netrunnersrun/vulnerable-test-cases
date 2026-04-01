<?php
/**
 * False positive test cases for PHP security controls and configuration.
 * All patterns here are SAFE despite resembling vulnerabilities.
 */

// --- Crypto False Positives ---

/**
 * password_hash with bcrypt - SAFE password storage.
 * This is the correct way to hash passwords in PHP.
 */
function hashPassword(string $password): string {
    return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
}

/**
 * password_verify for authentication - SAFE.
 */
function verifyPassword(string $password, string $hash): bool {
    return password_verify($password, $hash);
}

/**
 * openssl_encrypt with AES-256-GCM - SAFE encryption.
 */
function encryptData(string $plaintext, string $key): array {
    $iv = random_bytes(12);
    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );
    return [
        'ciphertext' => base64_encode($ciphertext),
        'iv' => base64_encode($iv),
        'tag' => base64_encode($tag),
    ];
}

/**
 * random_bytes for secure token generation - SAFE.
 * NOT using rand() or mt_rand().
 */
function generateCSRFToken(): string {
    return bin2hex(random_bytes(32));
}

/**
 * MD5 for cache key generation (non-security context) - acceptable.
 * NOT used for passwords or authentication.
 */
function generateCacheKey(string $url): string {
    return 'cache_' . md5($url);
}


// --- XXE False Positives ---

/**
 * XML parsing with entity loading explicitly disabled - SAFE.
 */
function parseXmlSafely(string $xml): SimpleXMLElement {
    // Disable entity loading BEFORE parsing
    $previousValue = libxml_disable_entity_loader(true);
    $options = LIBXML_NONET | LIBXML_NOENT;
    $result = simplexml_load_string($xml, 'SimpleXMLElement', $options);
    libxml_disable_entity_loader($previousValue);
    if ($result === false) {
        throw new RuntimeException("Invalid XML");
    }
    return $result;
}

/**
 * DOMDocument with entity loading disabled - SAFE.
 */
function parseDomSafely(string $xml): DOMDocument {
    $dom = new DOMDocument();
    $dom->resolveExternals = false;
    $dom->substituteEntities = false;
    libxml_disable_entity_loader(true);
    $dom->loadXML($xml, LIBXML_NONET);
    return $dom;
}


// --- Security Misconfiguration False Positives ---

/**
 * Production error configuration - SAFE.
 * display_errors OFF, logging to file instead.
 */
function configureProductionErrors(): void {
    ini_set('display_errors', '0');
    ini_set('log_errors', '1');
    ini_set('error_log', '/var/log/php/error.log');
    error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);
}

/**
 * Laravel production configuration - SAFE.
 * Debug mode OFF, proper error handling.
 */
function getLaravelProdConfig(): array {
    return [
        'debug' => false,
        'env' => 'production',
        'log_level' => 'warning',
    ];
}

/**
 * allow_url_include explicitly disabled - SAFE.
 */
function securePhpConfig(): void {
    ini_set('allow_url_include', '0');
    ini_set('allow_url_fopen', '0');
    ini_set('expose_php', '0');
}


// --- Error Handling False Positives ---

/**
 * Custom error handler that logs internally and shows generic message - SAFE.
 */
function handleException(Throwable $e): void {
    // Log full details server-side
    error_log(sprintf(
        "[%s] %s in %s:%d\n%s",
        date('Y-m-d H:i:s'),
        $e->getMessage(),
        $e->getFile(),
        $e->getLine(),
        $e->getTraceAsString()
    ));
    // Return generic message to user (NOT the exception details)
    http_response_code(500);
    echo json_encode([
        'error' => 'An internal error occurred.',
        'request_id' => bin2hex(random_bytes(8)),
    ]);
}

/**
 * Validation errors returned to user (NOT stack traces) - SAFE.
 */
function validateRegistration(array $data): array {
    $errors = [];
    if (empty($data['email']) || !filter_var($data['email'], FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Valid email address is required';
    }
    if (empty($data['password']) || strlen($data['password']) < 12) {
        $errors[] = 'Password must be at least 12 characters';
    }
    if (empty($data['name']) || strlen($data['name']) > 100) {
        $errors[] = 'Name is required (max 100 characters)';
    }
    return $errors;
}


// --- CSRF False Positives ---

/**
 * Form with CSRF token included - SAFE.
 * The token is generated and validated server-side.
 */
function renderFormWithCSRF(): string {
    $token = generateCSRFToken();
    $_SESSION['csrf_token'] = $token;
    return sprintf(
        '<form method="post" action="/submit">
            <input type="hidden" name="csrf_token" value="%s">
            <input type="text" name="data">
            <button type="submit">Submit</button>
        </form>',
        htmlspecialchars($token, ENT_QUOTES, 'UTF-8')
    );
}

/**
 * CSRF token validation on POST requests - SAFE.
 */
function validateCSRFToken(string $submittedToken): bool {
    if (!isset($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $submittedToken);
}


// --- Secrets False Positives ---

/**
 * Database credentials from environment variables - NOT hardcoded.
 */
function getDatabaseConnection(): PDO {
    $host = getenv('DB_HOST') ?: 'localhost';
    $name = getenv('DB_NAME') ?: 'myapp';
    $user = getenv('DB_USER') ?: 'root';
    $pass = getenv('DB_PASSWORD');
    if ($pass === false) {
        throw new RuntimeException("DB_PASSWORD environment variable not set");
    }
    return new PDO(
        "mysql:host={$host};dbname={$name};charset=utf8mb4",
        $user,
        $pass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
}
