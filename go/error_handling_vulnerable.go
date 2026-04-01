package main

import (
	"net/http"
)

// Matches: go-error-ignored (existing pattern-regex)
func vulnerableErrorIgnored() {
	result, _ := someFunction()
	_ = result
}

// Matches: go-http-error-detail
func vulnerableHttpError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// Matches: go-panic-no-recover
func vulnerablePanic(msg string) {
	panic(msg)
}

// Safe: proper error handling
func safeErrorHandling(w http.ResponseWriter, err error) {
	log.Printf("Error: %v", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}
