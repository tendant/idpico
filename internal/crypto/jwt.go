package crypto

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents the JWT claims for ID tokens and access tokens.
type Claims struct {
	// Standard OIDC claims
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`

	// OAuth claims
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`

	// Custom claims
	Extra map[string]any `json:"extra,omitempty"`

	jwt.RegisteredClaims
}

// TokenGenerator generates and parses JWTs.
type TokenGenerator struct {
	keyPair  *KeyPair
	issuer   string
	audience string
}

// NewTokenGenerator creates a new TokenGenerator.
func NewTokenGenerator(keyPair *KeyPair, issuer, audience string) *TokenGenerator {
	return &TokenGenerator{
		keyPair:  keyPair,
		issuer:   issuer,
		audience: audience,
	}
}

// GenerateIDToken generates an OIDC ID token.
func (g *TokenGenerator) GenerateIDToken(subject string, expiry time.Duration, claims *Claims) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)

	if claims == nil {
		claims = &Claims{}
	}

	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    g.issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{g.audience},
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Minute)), // Clock skew tolerance
		ID:        uuid.New().String(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = g.keyPair.Kid

	tokenString, err := token.SignedString(g.keyPair.PrivateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// GenerateAccessToken generates an OAuth access token (JWT).
func (g *TokenGenerator) GenerateAccessToken(subject string, expiry time.Duration, scope, clientID string) (string, time.Time, error) {
	claims := &Claims{
		Scope:    scope,
		ClientID: clientID,
	}
	return g.GenerateIDToken(subject, expiry, claims)
}

// ParseToken parses and validates a JWT token.
func (g *TokenGenerator) ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Verify key ID matches
		kid, ok := token.Header["kid"].(string)
		if !ok || kid != g.keyPair.Kid {
			return nil, fmt.Errorf("unknown key ID: %v", token.Header["kid"])
		}

		return g.keyPair.PublicKey, nil
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return token, claims, nil
}

// GetKeyID returns the key ID used for signing.
func (g *TokenGenerator) GetKeyID() string {
	return g.keyPair.Kid
}
