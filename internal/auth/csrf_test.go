package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCSRFGenerateToken(t *testing.T) {
	svc := NewCSRFService("test-secret-key-32-bytes-long!!", false, "")

	w := httptest.NewRecorder()
	token, err := svc.GenerateToken(w)
	if err != nil {
		t.Fatalf("GenerateToken failed: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	// Check cookie is set
	cookies := w.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == CSRFCookieName {
			found = true
			if c.Value != token {
				t.Error("Cookie value should match returned token")
			}
		}
	}
	if !found {
		t.Error("CSRF cookie should be set")
	}
}

func TestCSRFValidateToken(t *testing.T) {
	svc := NewCSRFService("test-secret-key-32-bytes-long!!", false, "")

	// Generate token
	w := httptest.NewRecorder()
	token, _ := svc.GenerateToken(w)

	// Create request with token
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("csrf_token="+token))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add cookie from response
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}

	// Validate
	if err := svc.ValidateToken(req); err != nil {
		t.Errorf("ValidateToken failed: %v", err)
	}
}

func TestCSRFValidateTokenMissing(t *testing.T) {
	svc := NewCSRFService("test-secret-key-32-bytes-long!!", false, "")

	// Request without CSRF token
	req := httptest.NewRequest(http.MethodPost, "/login", nil)

	if err := svc.ValidateToken(req); err == nil {
		t.Error("Expected error for missing token")
	}
}

func TestCSRFValidateTokenInvalid(t *testing.T) {
	svc := NewCSRFService("test-secret-key-32-bytes-long!!", false, "")

	// Generate real token
	w := httptest.NewRecorder()
	_, _ = svc.GenerateToken(w)

	// Create request with wrong token
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("csrf_token=wrong-token"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add cookie from response
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}

	if err := svc.ValidateToken(req); err == nil {
		t.Error("Expected error for invalid token")
	}
}

func TestCSRFClearToken(t *testing.T) {
	svc := NewCSRFService("test-secret-key-32-bytes-long!!", false, "")

	w := httptest.NewRecorder()
	svc.ClearToken(w)

	// Check cookie is cleared (MaxAge = -1 to delete)
	cookies := w.Result().Cookies()
	for _, c := range cookies {
		if c.Name == CSRFCookieName {
			if c.MaxAge != -1 {
				t.Errorf("CSRF cookie should have MaxAge=-1 when cleared, got %d", c.MaxAge)
			}
			if c.Value != "" {
				t.Error("CSRF cookie value should be empty when cleared")
			}
		}
	}
}

func TestCSRFTokenUniqueness(t *testing.T) {
	svc := NewCSRFService("test-secret-key-32-bytes-long!!", false, "")

	w1 := httptest.NewRecorder()
	token1, _ := svc.GenerateToken(w1)

	w2 := httptest.NewRecorder()
	token2, _ := svc.GenerateToken(w2)

	// Tokens should be different (different timestamps and random data)
	if token1 == token2 {
		t.Error("Tokens should be unique")
	}
}

// With Secure host-only cookies the token lives in a __Host- cookie, which
// another (sub)domain cannot set; validation reads the same name.
func TestCSRFHostPrefixWhenSecure(t *testing.T) {
	for _, tc := range []struct {
		secure bool
		domain string
		want   string
	}{
		{true, "", "__Host-idpico_csrf"},
		{true, "example.com", "idpico_csrf"}, // a Domain rules out __Host-
		{false, "", "idpico_csrf"},           // http (local dev) cannot use it
	} {
		svc := NewCSRFService("test-secret-key-32-bytes-long!!", tc.secure, tc.domain)
		w := httptest.NewRecorder()
		token, err := svc.GenerateToken(w)
		if err != nil {
			t.Fatal(err)
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != tc.want {
			t.Fatalf("secure=%v domain=%q: cookie %v, want %s", tc.secure, tc.domain, cookies, tc.want)
		}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("csrf_token="+token))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookies[0])
		if err := svc.ValidateToken(r); err != nil {
			t.Errorf("secure=%v domain=%q: %v", tc.secure, tc.domain, err)
		}
		// A token under the other name is not accepted.
		other := &http.Cookie{Name: "idpico_csrf", Value: token}
		if tc.want == "idpico_csrf" {
			other.Name = "__Host-idpico_csrf"
		}
		r = httptest.NewRequest(http.MethodPost, "/", strings.NewReader("csrf_token="+token))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(other)
		if err := svc.ValidateToken(r); err == nil {
			t.Errorf("secure=%v domain=%q: accepted a token under %s", tc.secure, tc.domain, other.Name)
		}
	}
}
