package http

import (
	"net/http"
	"strconv"
	"strings"
)

// CORSConfig holds CORS configuration.
type CORSConfig struct {
	// AllowedOrigins is a list of origins allowed to make cross-origin requests.
	// Use "*" to allow all origins (not recommended for production with credentials).
	AllowedOrigins []string

	// AllowCredentials indicates whether the request can include credentials.
	AllowCredentials bool

	// AllowedMethods is a list of methods allowed for cross-origin requests.
	AllowedMethods []string

	// AllowedHeaders is a list of headers allowed in cross-origin requests.
	AllowedHeaders []string

	// ExposedHeaders is a list of headers that browsers are allowed to access.
	ExposedHeaders []string

	// MaxAge indicates how long (in seconds) the results of a preflight request can be cached.
	MaxAge int
}

// DefaultCORSConfig returns a default CORS configuration suitable for development.
func DefaultCORSConfig() *CORSConfig {
	return &CORSConfig{
		AllowedOrigins:   []string{},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{},
		MaxAge:           86400, // 24 hours
	}
}

// CORSMiddleware returns a middleware that handles CORS.
func CORSMiddleware(config *CORSConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultCORSConfig()
	}

	// Build allowed origins map for fast lookup
	allowedOrigins := make(map[string]bool)
	allowAll := false
	for _, origin := range config.AllowedOrigins {
		if origin == "*" {
			allowAll = true
		}
		allowedOrigins[origin] = true
	}

	// Pre-compute header values
	allowMethods := strings.Join(config.AllowedMethods, ", ")
	allowHeaders := strings.Join(config.AllowedHeaders, ", ")
	exposeHeaders := strings.Join(config.ExposedHeaders, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			if origin != "" {
				allowed := allowAll || allowedOrigins[origin]
				if allowed {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					if config.AllowCredentials {
						w.Header().Set("Access-Control-Allow-Credentials", "true")
					}
					if exposeHeaders != "" {
						w.Header().Set("Access-Control-Expose-Headers", exposeHeaders)
					}
				}
			}

			// Handle preflight request
			if r.Method == http.MethodOptions {
				if origin != "" && (allowAll || allowedOrigins[origin]) {
					w.Header().Set("Access-Control-Allow-Methods", allowMethods)
					w.Header().Set("Access-Control-Allow-Headers", allowHeaders)
					if config.MaxAge > 0 {
						w.Header().Set("Access-Control-Max-Age", strconv.Itoa(config.MaxAge))
					}
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeadersConfig holds security headers configuration.
type SecurityHeadersConfig struct {
	// ContentSecurityPolicy sets the Content-Security-Policy header.
	// Example: "default-src 'self'; script-src 'self' 'unsafe-inline'"
	ContentSecurityPolicy string

	// XFrameOptions sets the X-Frame-Options header.
	// Options: "DENY", "SAMEORIGIN", or "ALLOW-FROM uri"
	XFrameOptions string

	// XContentTypeOptions sets the X-Content-Type-Options header.
	// Typically "nosniff"
	XContentTypeOptions string

	// ReferrerPolicy sets the Referrer-Policy header.
	// Options: "no-referrer", "same-origin", "strict-origin", etc.
	ReferrerPolicy string

	// StrictTransportSecurity sets the Strict-Transport-Security header.
	// Example: "max-age=31536000; includeSubDomains"
	// Only sent over HTTPS connections.
	StrictTransportSecurity string

	// PermissionsPolicy sets the Permissions-Policy header.
	// Example: "geolocation=(), microphone=()"
	PermissionsPolicy string

	// XSSProtection sets the X-XSS-Protection header.
	// Deprecated but still useful for older browsers. Typically "1; mode=block"
	XSSProtection string
}

// DefaultSecurityHeadersConfig returns a secure default configuration.
func DefaultSecurityHeadersConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		// Default CSP allows self-origin, inline styles for the login form
		ContentSecurityPolicy: "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
		XFrameOptions:         "DENY",
		XContentTypeOptions:   "nosniff",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
		XSSProtection:         "1; mode=block",
		PermissionsPolicy:     "geolocation=(), microphone=(), camera=()",
	}
}

// SecurityHeadersMiddleware returns a middleware that sets security headers.
func SecurityHeadersMiddleware(config *SecurityHeadersConfig) func(http.Handler) http.Handler {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set security headers
			if config.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
			}
			if config.XFrameOptions != "" {
				w.Header().Set("X-Frame-Options", config.XFrameOptions)
			}
			if config.XContentTypeOptions != "" {
				w.Header().Set("X-Content-Type-Options", config.XContentTypeOptions)
			}
			if config.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", config.ReferrerPolicy)
			}
			if config.XSSProtection != "" {
				w.Header().Set("X-XSS-Protection", config.XSSProtection)
			}
			if config.PermissionsPolicy != "" {
				w.Header().Set("Permissions-Policy", config.PermissionsPolicy)
			}

			// HSTS only on HTTPS
			if config.StrictTransportSecurity != "" && r.TLS != nil {
				w.Header().Set("Strict-Transport-Security", config.StrictTransportSecurity)
			}

			next.ServeHTTP(w, r)
		})
	}
}
