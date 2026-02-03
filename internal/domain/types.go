// Package domain defines the core types for the Identity Provider.
package domain

import (
	"time"
)

// User represents an identity in the system.
type User struct {
	ID           string    `json:"id"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash,omitempty"`
	DisplayName  string    `json:"display_name,omitempty"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Client represents an OAuth 2.0 / OIDC client application.
type Client struct {
	ID           string   `json:"id"`
	Secret       string   `json:"secret,omitempty"` // Empty for public clients
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	GrantTypes   []string `json:"grant_types"`   // e.g., authorization_code, refresh_token
	Scopes       []string `json:"scopes"`        // Allowed scopes
	Public       bool     `json:"public"`        // True for public clients (PKCE required)
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Session represents an authenticated user session.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
}

// IsExpired checks if the session has expired.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// AuthCode represents an OAuth 2.0 authorization code.
type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	UserID              string    `json:"user_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scope               string    `json:"scope"`
	CodeChallenge       string    `json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty"` // plain or S256
	Nonce               string    `json:"nonce,omitempty"`
	CreatedAt           time.Time `json:"created_at"`
	ExpiresAt           time.Time `json:"expires_at"`
	Used                bool      `json:"used"`
}

// IsExpired checks if the authorization code has expired.
func (a *AuthCode) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

// Token represents a refresh token stored in the database.
// Access tokens and ID tokens are JWTs and not stored.
type Token struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scope     string    `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Revoked   bool      `json:"revoked"`
}

// IsExpired checks if the token has expired.
func (t *Token) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsValid checks if the token is valid (not expired and not revoked).
func (t *Token) IsValid() bool {
	return !t.IsExpired() && !t.Revoked
}

// SigningKey represents a cryptographic key used for signing JWTs.
type SigningKey struct {
	ID         string    `json:"id"`          // Key ID (kid)
	Algorithm  string    `json:"algorithm"`   // e.g., EdDSA, RS256
	PrivateKey []byte    `json:"private_key"` // PEM or raw key bytes
	PublicKey  []byte    `json:"public_key"`  // PEM or raw key bytes
	Active     bool      `json:"active"`      // Currently used for signing
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`  // After this, key is only valid for verification
}

// IsExpired checks if the signing key has expired.
func (k *SigningKey) IsExpired() bool {
	return time.Now().After(k.ExpiresAt)
}
