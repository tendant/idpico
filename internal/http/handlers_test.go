package http

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthHandler_Healthz(t *testing.T) {
	handler := NewHealthHandler()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	handler.Healthz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", response["status"])
	}
}

func TestHealthHandler_Readyz(t *testing.T) {
	handler := NewHealthHandler()

	// Test when ready
	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	handler.Readyz(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 when ready, got %d", w.Code)
	}

	var response map[string]string
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if response["status"] != "ready" {
		t.Errorf("Expected status 'ready', got '%s'", response["status"])
	}

	// Test when not ready
	handler.SetReady(false)
	w = httptest.NewRecorder()
	handler.Readyz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503 when not ready, got %d", w.Code)
	}
}

func TestDiscoveryHandler_OpenIDConfiguration(t *testing.T) {
	handler := NewDiscoveryHandler("https://idp.example.com")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	handler.OpenIDConfiguration(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Expected Content-Type 'application/json', got '%s'", ct)
	}

	var discovery OIDCDiscovery
	if err := json.NewDecoder(w.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify discovery document
	if discovery.Issuer != "https://idp.example.com" {
		t.Errorf("Expected issuer 'https://idp.example.com', got '%s'", discovery.Issuer)
	}
	if discovery.AuthorizationEndpoint != "https://idp.example.com/authorize" {
		t.Errorf("Expected authorization_endpoint 'https://idp.example.com/authorize', got '%s'", discovery.AuthorizationEndpoint)
	}
	if discovery.TokenEndpoint != "https://idp.example.com/token" {
		t.Errorf("Expected token_endpoint 'https://idp.example.com/token', got '%s'", discovery.TokenEndpoint)
	}
	if discovery.UserinfoEndpoint != "https://idp.example.com/userinfo" {
		t.Errorf("Expected userinfo_endpoint 'https://idp.example.com/userinfo', got '%s'", discovery.UserinfoEndpoint)
	}
	if discovery.JwksURI != "https://idp.example.com/.well-known/jwks.json" {
		t.Errorf("Expected jwks_uri 'https://idp.example.com/.well-known/jwks.json', got '%s'", discovery.JwksURI)
	}

	// Check supported features
	if !contains(discovery.ScopesSupported, "openid") {
		t.Error("ScopesSupported should include 'openid'")
	}
	if !contains(discovery.ResponseTypesSupported, "code") {
		t.Error("ResponseTypesSupported should include 'code'")
	}
	if !contains(discovery.GrantTypesSupported, "authorization_code") {
		t.Error("GrantTypesSupported should include 'authorization_code'")
	}
	if !contains(discovery.CodeChallengeMethodsSupported, "S256") {
		t.Error("CodeChallengeMethodsSupported should include 'S256'")
	}
}

func TestDiscoveryHandler_OpenIDConfiguration_MethodNotAllowed(t *testing.T) {
	handler := NewDiscoveryHandler("https://idp.example.com")

	req := httptest.NewRequest(http.MethodPost, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	handler.OpenIDConfiguration(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405 for POST, got %d", w.Code)
	}
}

func TestDiscoveryHandler_TrailingSlashNormalization(t *testing.T) {
	// Issuer URL with trailing slash should be normalized
	handler := NewDiscoveryHandler("https://idp.example.com/")

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()

	handler.OpenIDConfiguration(w, req)

	var discovery OIDCDiscovery
	json.NewDecoder(w.Body).Decode(&discovery)

	// Should not have double slashes
	if discovery.Issuer != "https://idp.example.com" {
		t.Errorf("Trailing slash should be removed from issuer, got '%s'", discovery.Issuer)
	}
}

func TestIsValidReturnURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "valid relative URL",
			url:      "/dashboard",
			expected: true,
		},
		{
			name:     "valid relative URL with query",
			url:      "/callback?code=123",
			expected: true,
		},
		{
			name:     "invalid absolute URL with scheme",
			url:      "https://evil.com/callback",
			expected: false,
		},
		{
			name:     "invalid URL with host",
			url:      "//evil.com/callback",
			expected: false,
		},
		{
			name:     "empty URL",
			url:      "",
			expected: false,
		},
		{
			name:     "valid root URL",
			url:      "/",
			expected: true,
		},
		{
			name:     "valid deep path",
			url:      "/a/b/c/d",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidReturnURL(tt.url)
			if result != tt.expected {
				t.Errorf("isValidReturnURL(%q) = %v, expected %v", tt.url, result, tt.expected)
			}
		})
	}
}

// Helper function
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
