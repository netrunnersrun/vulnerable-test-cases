// Package falsepositives contains false positive test cases for Go system operations.
// All functions here are SAFE despite matching vulnerability patterns.
package falsepositives

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// --- Error Handling False Positives ---

// ProcessWithRecover uses deferred recover() to handle panics - SAFE.
func ProcessWithRecover(data []byte) (result string, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v", r)
			err = fmt.Errorf("internal processing error")
		}
	}()
	// Processing that might panic
	result = string(data)
	return
}

// HandleRequestWithContext uses context for timeout, not bare panic - SAFE.
func HandleRequestWithContext(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	select {
	case <-ctx.Done():
		http.Error(w, "Request timed out", http.StatusGatewayTimeout)
	default:
		w.Write([]byte("OK"))
	}
}


// --- Supply Chain False Positives ---

// LoadConfig reads config from a known, trusted path - SAFE.
func LoadConfig() (map[string]interface{}, error) {
	// Hardcoded path, no user input
	data, err := os.ReadFile("/etc/myapp/config.json")
	if err != nil {
		return nil, err
	}
	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return config, nil
}


// --- Security Misconfiguration False Positives ---

// SecureGinSetup creates Gin in release mode with security middleware - SAFE.
// Note: This is pseudocode showing correct patterns.
func SecureGinSetup() {
	// gin.SetMode(gin.ReleaseMode)
	// router := gin.New()
	// router.Use(gin.Recovery())
	// router.Use(securityHeaders())
	// router.Use(csrfMiddleware())
	log.Println("Gin configured in release mode with security middleware")
}

// SecureEchoSetup creates Echo with security middleware - SAFE.
func SecureEchoSetup() {
	// e := echo.New()
	// e.Use(middleware.Secure())
	// e.Use(middleware.CSRF())
	// e.Use(middleware.RateLimiter())
	log.Println("Echo configured with security middleware")
}

// SecureHTTPHeaders adds security headers to response - SAFE.
func SecureHTTPHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}


// --- Database False Positives ---

// TransactionalInsert uses transactions with parameterized queries - SAFE.
func TransactionalInsert(db *sql.DB, name, email string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("INSERT INTO users (name, email) VALUES ($1, $2)", name, email)
	if err != nil {
		return err
	}

	_, err = tx.Exec("INSERT INTO audit_log (action, target) VALUES ($1, $2)",
		"user_created", name)
	if err != nil {
		return err
	}

	return tx.Commit()
}


// --- Input Validation False Positives ---

// ValidateAndSanitize properly validates user input before use - SAFE.
func ValidateAndSanitize(input string) (string, error) {
	// Length check
	if len(input) > 500 {
		return "", fmt.Errorf("input too long")
	}
	// Strip dangerous characters
	sanitized := strings.Map(func(r rune) rune {
		if r == '<' || r == '>' || r == '\'' || r == '"' || r == '\\' {
			return -1
		}
		return r
	}, input)
	// Normalize whitespace
	sanitized = strings.TrimSpace(sanitized)
	if sanitized == "" {
		return "", fmt.Errorf("input is empty after sanitization")
	}
	return sanitized, nil
}
