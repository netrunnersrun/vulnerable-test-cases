package main

import "net/http"

// Matches: go-ssrf-http-get
func vulnerableHttpGet(userURL string) (*http.Response, error) {
	return http.Get(userURL)
}

// Matches: go-ssrf-http-newrequest
func vulnerableNewRequest(userURL string) (*http.Request, error) {
	return http.NewRequest("GET", userURL, nil)
}

// Safe: URL allowlist
func safeHttpGet(userURL string) (*http.Response, error) {
	// Validate URL against allowlist before making request
	return nil, fmt.Errorf("not implemented - validate URL first")
}
