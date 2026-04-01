package main

import (
	"os"
	"path/filepath"
)

// Matches: go-path-traversal-os-open
func vulnerableOsOpen(userInput string) (*os.File, error) {
	return os.Open(userInput)
}

// Matches: go-path-traversal-readfile
func vulnerableReadFile(userInput string) ([]byte, error) {
	return os.ReadFile(userInput)
}

// Matches: go-path-traversal-filepath-join
func vulnerableFilepathJoin(userInput string) string {
	return filepath.Join("/uploads", userInput)
}

// Safe: validate and clean
func safeRead(userInput string) ([]byte, error) {
	clean := filepath.Clean(userInput)
	abs := filepath.Join("/safe/dir", clean)
	if !filepath.HasPrefix(abs, "/safe/dir") {
		return nil, fmt.Errorf("path traversal detected")
	}
	return os.ReadFile(abs)
}
