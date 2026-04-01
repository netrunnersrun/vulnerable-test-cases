// Package falsepositives contains false positive test cases for Go security patterns.
// All functions here are SAFE despite matching vulnerability patterns.
package falsepositives

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"html"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// --- SQL Injection False Positives ---

// GetUserByID uses a parameterized query - NOT SQL injection.
func GetUserByID(db *sql.DB, userID int) (*sql.Row, error) {
	return db.QueryRow("SELECT * FROM users WHERE id = $1", userID), nil
}

// SearchProducts uses parameterized LIKE query - NOT injection.
func SearchProducts(db *sql.DB, term string) (*sql.Rows, error) {
	return db.Query("SELECT * FROM products WHERE name LIKE $1", "%"+term+"%")
}

// InsertUser uses parameterized insert - NOT injection.
func InsertUser(db *sql.DB, name, email string) (sql.Result, error) {
	return db.Exec("INSERT INTO users (name, email) VALUES ($1, $2)", name, email)
}


// --- Command Injection False Positives ---

// GetDiskUsage runs a hardcoded command with no user input - SAFE.
func GetDiskUsage() (string, error) {
	// Hardcoded args, no user input
	cmd := exec.Command("df", "-h", "/")
	out, err := cmd.Output()
	return string(out), err
}

// ResizeImage uses integer-validated dimensions only - SAFE.
func ResizeImage(widthStr, heightStr string) error {
	width, err := strconv.Atoi(widthStr)
	if err != nil || width <= 0 || width > 4096 {
		return fmt.Errorf("invalid width")
	}
	height, err := strconv.Atoi(heightStr)
	if err != nil || height <= 0 || height > 4096 {
		return fmt.Errorf("invalid height")
	}
	// execFile equivalent - no shell, validated numeric args only
	cmd := exec.Command("convert", "input.png", "-resize",
		fmt.Sprintf("%dx%d", width, height), "output.png")
	return cmd.Run()
}


// --- Path Traversal False Positives ---

// ReadConfigFile validates path against base directory - NOT path traversal.
func ReadConfigFile(filename string) ([]byte, error) {
	baseDir := "/etc/myapp/config"
	cleanName := filepath.Base(filename) // strips directory components
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+\.json$`).MatchString(cleanName) {
		return nil, fmt.Errorf("invalid config name")
	}
	fullPath := filepath.Join(baseDir, cleanName)
	absPath, err := filepath.Abs(fullPath)
	if err != nil || !strings.HasPrefix(absPath, baseDir) {
		return nil, fmt.Errorf("path traversal blocked")
	}
	return os.ReadFile(absPath)
}

// GetAvatar uses integer-only path component - SAFE.
func GetAvatar(userID int) ([]byte, error) {
	path := fmt.Sprintf("/data/avatars/%d.png", userID)
	return os.ReadFile(path)
}


// --- SSRF False Positives ---

// FetchAllowedURL validates URL against an allowlist - NOT SSRF.
func FetchAllowedURL(rawURL string) (*http.Response, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	allowedHosts := map[string]bool{
		"api.github.com":     true,
		"hooks.slack.com":    true,
	}
	if !allowedHosts[parsed.Hostname()] {
		return nil, fmt.Errorf("host not allowed: %s", parsed.Hostname())
	}
	if parsed.Scheme != "https" {
		return nil, fmt.Errorf("HTTPS required")
	}
	// Block private IPs
	ips, err := net.LookupIP(parsed.Hostname())
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.IsPrivate() || ip.IsLoopback() {
			return nil, fmt.Errorf("private IP blocked")
		}
	}
	client := &http.Client{Timeout: 10 * time.Second}
	return client.Get(rawURL)
}


// --- XSS False Positives ---

// RenderUserName uses html.EscapeString before writing - SAFE.
func RenderUserName(w http.ResponseWriter, name string) {
	safe := html.EscapeString(name)
	fmt.Fprintf(w, "<p>Hello, %s</p>", safe)
}

// RenderTemplate uses html/template (auto-escaping) - SAFE.
func RenderTemplate(w http.ResponseWriter, data interface{}) error {
	tmpl := template.Must(template.New("page").Parse(`
		<html><body>
		<h1>{{.Title}}</h1>
		<p>{{.Content}}</p>
		</body></html>
	`))
	return tmpl.Execute(w, data)
}


// --- Crypto False Positives ---

// GenerateChecksum uses SHA-256 (strong hash) for file integrity - SAFE.
func GenerateChecksum(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// GenerateSecureToken uses crypto/rand - SAFE.
func GenerateSecureToken() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}


// --- Error Handling False Positives ---

// HandleError logs details server-side, returns generic message - SAFE.
func HandleError(w http.ResponseWriter, err error) {
	// Log full error internally
	fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
	// Return generic message to client
	http.Error(w, "An internal error occurred. Please try again.", http.StatusInternalServerError)
}


// --- Server Config False Positives ---

// StartSecureServer uses TLS and proper timeouts - SAFE.
func StartSecureServer() error {
	srv := &http.Server{
		Addr:         ":443",
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return srv.ListenAndServeTLS("cert.pem", "key.pem")
}
