package crypto

import (
	"context"
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
	keyPair    *KeyPair
	keyService *KeyService // For looking up keys by kid during verification
	issuer     string
	audience   string
}

// NewTokenGenerator creates a new TokenGenerator.
func NewTokenGenerator(keyPair *KeyPair, issuer, audience string) *TokenGenerator {
	return &TokenGenerator{
		keyPair:  keyPair,
		issuer:   issuer,
		audience: audience,
	}
}

// NewTokenGeneratorWithKeyService creates a TokenGenerator that can verify tokens
// signed by any key in the key service (for key rotation support).
func NewTokenGeneratorWithKeyService(keyPair *KeyPair, keyService *KeyService, issuer, audience string) *TokenGenerator {
	return &TokenGenerator{
		keyPair:    keyPair,
		keyService: keyService,
		issuer:     issuer,
		audience:   audience,
	}
}

// GenerateIDToken generates an OIDC ID token.
func (g *TokenGenerator) GenerateIDToken(subject string, expiry time.Duration, claims *Claims) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(expiry)

	if claims == nil {
		claims = &Claims{}
	}

	// Use ClientID as audience if set, otherwise fall back to default
	audience := g.audience
	if claims.ClientID != "" {
		audience = claims.ClientID
	}

	claims.RegisteredClaims = jwt.RegisteredClaims{
		Issuer:    g.issuer,
		Subject:   subject,
		Audience:  jwt.ClaimStrings{audience},
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
// If a KeyService is configured, it will look up keys by kid to support key rotation.
func (g *TokenGenerator) ParseToken(tokenString string) (*jwt.Token, *Claims, error) {
	return g.ParseTokenWithContext(context.Background(), tokenString)
}

// ParseTokenWithContext parses and validates a JWT token with a context.
func (g *TokenGenerator) ParseTokenWithContext(ctx context.Context, tokenString string) (*jwt.Token, *Claims, error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Get key ID from token
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing key ID in token header")
		}

		// If we have a KeyService, look up the key by kid (supports rotated keys)
		if g.keyService != nil {
			keyPair, err := g.keyService.GetKeyByID(ctx, kid)
			if err != nil {
				return nil, fmt.Errorf("unknown key ID: %s", kid)
			}
			// Don't verify with expired keys (unless token was issued before expiry)
			if keyPair.IsExpired() {
				return nil, fmt.Errorf("key has expired: %s", kid)
			}
			return keyPair.PublicKey, nil
		}

		// Fallback: verify key ID matches the current key
		if kid != g.keyPair.Kid {
			return nil, fmt.Errorf("unknown key ID: %s", kid)
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
