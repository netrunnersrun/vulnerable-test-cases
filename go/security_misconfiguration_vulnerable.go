package main

import (
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
)

// Matches: go-cors-allow-all-origins (existing)
// AllowAllOrigins: true

// Matches: go-http-listenandserve-no-tls
func vulnerableNoTls() error {
	return http.ListenAndServe(":8080", nil)
}

// Matches: go-gin-debug-mode
func vulnerableGinDebug() {
	gin.SetMode(gin.DebugMode)
}

// Matches: go-http-no-timeout
func vulnerableNoTimeout() *http.Server {
	return &http.Server{Addr: ":8080"}
}

// Safe: TLS and production mode
func safeServer() error {
	gin.SetMode(gin.ReleaseMode)
	return http.ListenAndServeTLS(":443", "cert.pem", "key.pem", nil)
}
