package crypto

import (
	"context"
	"encoding/json"
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

	// Group memberships (emitted when the "groups" scope is granted)
	Groups []string `json:"groups,omitempty"`

	// OAuth claims
	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`

	// Extra claims are serialized as top-level members alongside the
	// typed fields (e.g. "nonce", or groups under a custom claim name).
	Extra map[string]any `json:"-"`

	jwt.RegisteredClaims
}

// SetExtra records an additional top-level claim.
func (c *Claims) SetExtra(name string, value any) {
	if c.Extra == nil {
		c.Extra = make(map[string]any)
	}
	c.Extra[name] = value
}

// claimsJSON is Claims without the custom marshalling, to avoid recursion.
type claimsJSON Claims

// MarshalJSON flattens Extra into the top-level object.
func (c Claims) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(claimsJSON(c))
	if err != nil {
		return nil, err
	}
	// A granted-but-empty groups list must survive omitempty: "[]" tells the
	// client the user has no groups, absence means the scope was not granted.
	emptyGroups := c.Groups != nil && len(c.Groups) == 0
	if len(c.Extra) == 0 && !emptyGroups {
		return base, nil
	}

	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	if emptyGroups {
		merged["groups"] = json.RawMessage("[]")
	}
	for k, v := range c.Extra {
		if _, taken := merged[k]; taken {
			continue // typed fields win
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		merged[k] = raw
	}
	return json.Marshal(merged)
}

// UnmarshalJSON restores typed fields and collects unknown members into Extra.
func (c *Claims) UnmarshalJSON(data []byte) error {
	if err := json.Unmarshal(data, (*claimsJSON)(c)); err != nil {
		return err
	}
	var all map[string]any
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for k, v := range all {
		if !knownClaims[k] {
			c.SetExtra(k, v)
		}
	}
	return nil
}

// knownClaims are the JSON names of Claims' typed fields (including the
// embedded registered claims) that must not be duplicated into Extra.
var knownClaims = map[string]bool{
	"email": true, "email_verified": true, "name": true, "groups": true,
	"scope": true, "client_id": true,
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
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

	signingKey, err := g.signingKey(context.Background())
	if err != nil {
		return "", time.Time{}, err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = signingKey.Kid

	tokenString, err := token.SignedString(signingKey.PrivateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, expiresAt, nil
}

// GenerateAccessToken generates an OAuth access token (JWT).
func (g *TokenGenerator) GenerateAccessToken(subject string, expiry time.Duration, scope, clientID string) (string, time.Time, error) {
	return g.GenerateAccessTokenWithClaims(subject, expiry, &Claims{Scope: scope, ClientID: clientID})
}

// GenerateAccessTokenWithClaims generates an access token carrying claims in
// addition to scope and client_id (e.g. groups for resource servers).
func (g *TokenGenerator) GenerateAccessTokenWithClaims(subject string, expiry time.Duration, claims *Claims) (string, time.Time, error) {
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
	key, err := g.signingKey(context.Background())
	if err != nil {
		return ""
	}
	return key.Kid
}

// signingKey returns the key new tokens are signed with: the KeyService's
// current active key when one is attached (so rotation takes effect without
// restarting), otherwise the key the generator was constructed with.
func (g *TokenGenerator) signingKey(ctx context.Context) (*KeyPair, error) {
	if g.keyService == nil {
		return g.keyPair, nil
	}
	key, err := g.keyService.GetActiveKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get active signing key: %w", err)
	}
	return key, nil
}

// ValidateAccessToken validates an access token and returns its claims.
func (g *TokenGenerator) ValidateAccessToken(tokenString string) (*Claims, error) {
	token, claims, err := g.ParseToken(tokenString)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	// Verify issuer matches
	if claims.Issuer != g.issuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	return claims, nil
}
