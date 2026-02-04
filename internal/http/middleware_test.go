package http

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware_AllowedOrigin(t *testing.T) {
	config := &CORSConfig{
		AllowedOrigins:   []string{"https://example.com", "https://app.example.com"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		MaxAge:           86400,
	}

	handler := CORSMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name           string
		origin         string
		expectAllowed  bool
		expectOrigin   string
	}{
		{
			name:          "allowed origin",
			origin:        "https://example.com",
			expectAllowed: true,
			expectOrigin:  "https://example.com",
		},
		{
			name:          "allowed subdomain origin",
			origin:        "https://app.example.com",
			expectAllowed: true,
			expectOrigin:  "https://app.example.com",
		},
		{
			name:          "disallowed origin",
			origin:        "https://evil.com",
			expectAllowed: false,
			expectOrigin:  "",
		},
		{
			name:          "no origin header",
			origin:        "",
			expectAllowed: false,
			expectOrigin:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			origin := w.Header().Get("Access-Control-Allow-Origin")
			if tt.expectAllowed {
				if origin != tt.expectOrigin {
					t.Errorf("Expected Access-Control-Allow-Origin %q, got %q", tt.expectOrigin, origin)
				}
				if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
					t.Error("Expected Access-Control-Allow-Credentials: true")
				}
			} else {
				if origin != "" {
					t.Errorf("Expected no Access-Control-Allow-Origin, got %q", origin)
				}
			}
		})
	}
}

func TestCORSMiddleware_Preflight(t *testing.T) {
	config := &CORSConfig{
		AllowedOrigins:   []string{"https://example.com"},
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "POST", "PUT"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		MaxAge:           3600,
	}

	handlerCalled := false
	handler := CORSMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Preflight should return 204 No Content
	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}

	// Handler should NOT be called for preflight
	if handlerCalled {
		t.Error("Handler should not be called for preflight requests")
	}

	// Check CORS headers
	if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
		t.Errorf("Expected Access-Control-Allow-Origin https://example.com, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
	if w.Header().Get("Access-Control-Allow-Methods") != "GET, POST, PUT" {
		t.Errorf("Expected Access-Control-Allow-Methods, got %q", w.Header().Get("Access-Control-Allow-Methods"))
	}
	if w.Header().Get("Access-Control-Allow-Headers") != "Authorization, Content-Type" {
		t.Errorf("Expected Access-Control-Allow-Headers, got %q", w.Header().Get("Access-Control-Allow-Headers"))
	}
	// Verify MaxAge is properly formatted as a number string (not rune conversion)
	if maxAge := w.Header().Get("Access-Control-Max-Age"); maxAge != "3600" {
		t.Errorf("Expected Access-Control-Max-Age '3600', got %q", maxAge)
	}
}

func TestCORSMiddleware_WildcardOrigin(t *testing.T) {
	config := &CORSConfig{
		AllowedOrigins:   []string{"*"},
		AllowCredentials: false,
		AllowedMethods:   []string{"GET"},
		AllowedHeaders:   []string{},
	}

	handler := CORSMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://any-domain.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Wildcard should allow any origin
	if w.Header().Get("Access-Control-Allow-Origin") != "https://any-domain.com" {
		t.Errorf("Expected wildcard to allow any origin, got %q", w.Header().Get("Access-Control-Allow-Origin"))
	}
}

func TestCORSMiddleware_DefaultConfig(t *testing.T) {
	// Test with nil config (should use defaults)
	handler := CORSMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Default config has empty AllowedOrigins, so no origin should be allowed
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("Default config should not allow any origins")
	}
}

func TestSecurityHeadersMiddleware_DefaultHeaders(t *testing.T) {
	config := DefaultSecurityHeadersConfig()

	handler := SecurityHeadersMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check all security headers are set
	expectedHeaders := map[string]string{
		"Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
		"X-Frame-Options":         "DENY",
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "strict-origin-when-cross-origin",
		"X-XSS-Protection":        "1; mode=block",
		"Permissions-Policy":      "geolocation=(), microphone=(), camera=()",
	}

	for header, expectedValue := range expectedHeaders {
		if actual := w.Header().Get(header); actual != expectedValue {
			t.Errorf("Expected %s: %q, got %q", header, expectedValue, actual)
		}
	}

	// HSTS should NOT be set for non-TLS requests
	if hsts := w.Header().Get("Strict-Transport-Security"); hsts != "" {
		t.Errorf("HSTS should not be set for non-TLS requests, got %q", hsts)
	}
}

func TestSecurityHeadersMiddleware_CustomConfig(t *testing.T) {
	config := &SecurityHeadersConfig{
		ContentSecurityPolicy: "default-src 'none'",
		XFrameOptions:         "SAMEORIGIN",
		XContentTypeOptions:   "nosniff",
	}

	handler := SecurityHeadersMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Header().Get("Content-Security-Policy") != "default-src 'none'" {
		t.Error("Custom CSP not applied")
	}
	if w.Header().Get("X-Frame-Options") != "SAMEORIGIN" {
		t.Error("Custom X-Frame-Options not applied")
	}
}

func TestSecurityHeadersMiddleware_EmptyConfig(t *testing.T) {
	// Empty config should not set any headers
	config := &SecurityHeadersConfig{}

	handler := SecurityHeadersMiddleware(config)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	securityHeaders := []string{
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
		"X-XSS-Protection",
		"Permissions-Policy",
		"Strict-Transport-Security",
	}

	for _, header := range securityHeaders {
		if value := w.Header().Get(header); value != "" {
			t.Errorf("Header %s should be empty with empty config, got %q", header, value)
		}
	}
}

func TestSecurityHeadersMiddleware_NilConfig(t *testing.T) {
	// Nil config should use defaults
	handler := SecurityHeadersMiddleware(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Should have default CSP
	if csp := w.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Default CSP should be set with nil config")
	}
}

func TestDefaultCORSConfig(t *testing.T) {
	config := DefaultCORSConfig()

	if len(config.AllowedOrigins) != 0 {
		t.Error("Default should have no allowed origins")
	}
	if !config.AllowCredentials {
		t.Error("Default should allow credentials")
	}
	if len(config.AllowedMethods) == 0 {
		t.Error("Default should have allowed methods")
	}
	if len(config.AllowedHeaders) == 0 {
		t.Error("Default should have allowed headers")
	}
}

func TestDefaultSecurityHeadersConfig(t *testing.T) {
	config := DefaultSecurityHeadersConfig()

	if config.ContentSecurityPolicy == "" {
		t.Error("Default should have CSP")
	}
	if config.XFrameOptions != "DENY" {
		t.Error("Default X-Frame-Options should be DENY")
	}
	if config.XContentTypeOptions != "nosniff" {
		t.Error("Default X-Content-Type-Options should be nosniff")
	}
	if config.ReferrerPolicy == "" {
		t.Error("Default should have Referrer-Policy")
	}
}
