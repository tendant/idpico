package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"
)

const (
	// CSRFCookieName is the name of the CSRF cookie.
	CSRFCookieName = "idp_csrf"
	// CSRFTokenLength is the length of the CSRF token in bytes.
	CSRFTokenLength = 32
	// CSRFFormField is the form field name for CSRF token.
	CSRFFormField = "csrf_token"
	// CSRFTTL is how long CSRF tokens are valid.
	CSRFTTL = 1 * time.Hour
)

// CSRFService provides CSRF protection.
type CSRFService struct {
	secret       []byte
	cookieSecure bool
	cookieDomain string
}

// NewCSRFService creates a new CSRFService.
func NewCSRFService(secret string, cookieSecure bool, cookieDomain string) *CSRFService {
	return &CSRFService{
		secret:       []byte(secret),
		cookieSecure: cookieSecure,
		cookieDomain: cookieDomain,
	}
}

// GenerateToken generates a new CSRF token and sets it as a cookie.
func (s *CSRFService) GenerateToken(w http.ResponseWriter) (string, error) {
	// Generate random bytes
	tokenBytes := make([]byte, CSRFTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("failed to generate CSRF token: %w", err)
	}

	// Create token with timestamp
	timestamp := time.Now().Unix()
	data := fmt.Sprintf("%d:%s", timestamp, base64.RawURLEncoding.EncodeToString(tokenBytes))

	// Sign the token
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(data))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	token := fmt.Sprintf("%s.%s", data, signature)

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    token,
		Path:     "/",
		Domain:   s.cookieDomain,
		MaxAge:   int(CSRFTTL.Seconds()),
		HttpOnly: false, // JavaScript needs to read this for AJAX
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})

	return token, nil
}

// ValidateToken validates a CSRF token from form data against the cookie.
func (s *CSRFService) ValidateToken(r *http.Request) error {
	// Get token from form
	formToken := r.FormValue(CSRFFormField)
	if formToken == "" {
		// Also check header for AJAX requests
		formToken = r.Header.Get("X-CSRF-Token")
	}
	if formToken == "" {
		return fmt.Errorf("missing CSRF token")
	}

	// Get token from cookie
	cookie, err := r.Cookie(CSRFCookieName)
	if err != nil {
		return fmt.Errorf("missing CSRF cookie")
	}

	// Tokens must match
	if formToken != cookie.Value {
		return fmt.Errorf("CSRF token mismatch")
	}

	// Validate token format and signature
	return s.validateTokenFormat(formToken)
}

func (s *CSRFService) validateTokenFormat(token string) error {
	// Split into data and signature
	var data, signature string
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			data = token[:i]
			signature = token[i+1:]
			break
		}
	}
	if data == "" || signature == "" {
		return fmt.Errorf("invalid CSRF token format")
	}

	// Verify signature
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(data))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return fmt.Errorf("invalid CSRF token signature")
	}

	// Check timestamp
	var timestamp int64
	if _, err := fmt.Sscanf(data, "%d:", &timestamp); err != nil {
		return fmt.Errorf("invalid CSRF token timestamp")
	}

	if time.Since(time.Unix(timestamp, 0)) > CSRFTTL {
		return fmt.Errorf("CSRF token expired")
	}

	return nil
}

// ClearToken clears the CSRF cookie.
func (s *CSRFService) ClearToken(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CSRFCookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cookieDomain,
		MaxAge:   -1,
		HttpOnly: false,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}
