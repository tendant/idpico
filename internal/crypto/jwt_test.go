package crypto

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestGenerateIDToken(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	gen := NewTokenGenerator(keyPair, "https://issuer.example.com", "https://audience.example.com")

	claims := &Claims{
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
	}

	token, expiresAt, err := gen.GenerateIDToken("user-123", 15*time.Minute, claims)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	// Token should be a JWT (3 parts separated by dots)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("Token should have 3 parts, got %d", len(parts))
	}

	// Expiry should be in the future
	if expiresAt.Before(time.Now()) {
		t.Error("Token expiry should be in the future")
	}
}

func TestGenerateAccessToken(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	gen := NewTokenGenerator(keyPair, "https://issuer.example.com", "https://audience.example.com")

	token, _, err := gen.GenerateAccessToken("user-123", 15*time.Minute, "openid profile", "client-id")
	if err != nil {
		t.Fatalf("GenerateAccessToken failed: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}
}

func TestParseToken(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	gen := NewTokenGenerator(keyPair, "https://issuer.example.com", "https://audience.example.com")

	claims := &Claims{
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
		Scope:         "openid profile email",
		ClientID:      "test-client",
	}

	tokenString, _, err := gen.GenerateIDToken("user-123", 15*time.Minute, claims)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}

	// Parse the token
	token, parsedClaims, err := gen.ParseToken(tokenString)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	if !token.Valid {
		t.Error("Token should be valid")
	}

	if parsedClaims.Email != "user@example.com" {
		t.Errorf("Expected email 'user@example.com', got '%s'", parsedClaims.Email)
	}

	if parsedClaims.Name != "Test User" {
		t.Errorf("Expected name 'Test User', got '%s'", parsedClaims.Name)
	}

	if parsedClaims.Subject != "user-123" {
		t.Errorf("Expected subject 'user-123', got '%s'", parsedClaims.Subject)
	}

	if parsedClaims.Issuer != "https://issuer.example.com" {
		t.Errorf("Expected issuer 'https://issuer.example.com', got '%s'", parsedClaims.Issuer)
	}
}

func TestParseTokenExpired(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	gen := NewTokenGenerator(keyPair, "https://issuer.example.com", "https://audience.example.com")

	// Generate token that expires immediately
	tokenString, _, err := gen.GenerateIDToken("user-123", -time.Minute, nil)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}

	// Parsing should fail due to expiry
	_, _, err = gen.ParseToken(tokenString)
	if err == nil {
		t.Error("Expected error for expired token")
	}
}

func TestParseTokenWrongKey(t *testing.T) {
	keyPair1, _ := GenerateKeyPair(2048)
	keyPair2, _ := GenerateKeyPair(2048)

	gen1 := NewTokenGenerator(keyPair1, "https://issuer.example.com", "https://audience.example.com")
	gen2 := NewTokenGenerator(keyPair2, "https://issuer.example.com", "https://audience.example.com")

	// Generate with key 1
	tokenString, _, err := gen1.GenerateIDToken("user-123", 15*time.Minute, nil)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}

	// Try to parse with key 2 (different kid)
	_, _, err = gen2.ParseToken(tokenString)
	if err == nil {
		t.Error("Expected error when parsing with different key")
	}
}

func TestParseTokenInvalid(t *testing.T) {
	keyPair, _ := GenerateKeyPair(2048)
	gen := NewTokenGenerator(keyPair, "https://issuer.example.com", "https://audience.example.com")

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"garbage", "not-a-jwt"},
		{"incomplete", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
		{"tampered", "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIn0.tampered"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := gen.ParseToken(tt.token)
			if err == nil {
				t.Error("Expected error for invalid token")
			}
		})
	}
}

func TestGetKeyID(t *testing.T) {
	keyPair, _ := GenerateKeyPair(2048)
	gen := NewTokenGenerator(keyPair, "https://issuer.example.com", "https://audience.example.com")

	kid := gen.GetKeyID()
	if kid == "" {
		t.Error("Key ID should not be empty")
	}

	if kid != keyPair.Kid {
		t.Errorf("Key ID mismatch: expected %s, got %s", keyPair.Kid, kid)
	}
}

func TestTokenContainsKeyID(t *testing.T) {
	keyPair, _ := GenerateKeyPair(2048)
	gen := NewTokenGenerator(keyPair, "https://issuer.example.com", "https://audience.example.com")

	tokenString, _, err := gen.GenerateIDToken("user-123", 15*time.Minute, nil)
	if err != nil {
		t.Fatalf("GenerateIDToken failed: %v", err)
	}

	// Parse and check kid header
	token, _, err := gen.ParseToken(tokenString)
	if err != nil {
		t.Fatalf("ParseToken failed: %v", err)
	}

	kid, ok := token.Header["kid"].(string)
	if !ok {
		t.Error("Token should have kid header")
	}

	if kid != keyPair.Kid {
		t.Errorf("Token kid mismatch: expected %s, got %s", keyPair.Kid, kid)
	}
}

func TestClaims_ExtraFlattenedTopLevel(t *testing.T) {
	kp, _ := GenerateKeyPair(2048)
	gen := NewTokenGenerator(kp, "http://idpico", "http://idpico")

	claims := &Claims{Email: "a@example.com", Groups: []string{"admins", "devs"}}
	claims.SetExtra("nonce", "n-123")
	claims.SetExtra("roles", []string{"admins"})
	claims.SetExtra("email", "override-ignored@example.com") // typed field wins

	token, _, err := gen.GenerateIDToken("sub-1", time.Minute, claims)
	if err != nil {
		t.Fatalf("GenerateIDToken: %v", err)
	}

	// Decode the payload directly to check the wire format.
	parts := strings.Split(token, ".")
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if raw["nonce"] != "n-123" {
		t.Errorf("nonce should be a top-level claim, got %v (payload %s)", raw["nonce"], payload)
	}
	if _, nested := raw["extra"]; nested {
		t.Error("extra must not be serialized as a nested object")
	}
	if raw["email"] != "a@example.com" {
		t.Errorf("typed field should win over Extra, got %v", raw["email"])
	}
	if g, ok := raw["groups"].([]any); !ok || len(g) != 2 {
		t.Errorf("groups claim missing: %v", raw["groups"])
	}
	if r, ok := raw["roles"].([]any); !ok || len(r) != 1 {
		t.Errorf("custom claim missing: %v", raw["roles"])
	}

	// Parsing round-trips typed fields and puts unknown claims in Extra.
	_, parsed, err := gen.ParseToken(token)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if parsed.Extra["nonce"] != "n-123" || len(parsed.Groups) != 2 || parsed.Subject != "sub-1" {
		t.Errorf("parsed claims wrong: %+v", parsed)
	}
	if _, dup := parsed.Extra["email"]; dup {
		t.Error("typed claims must not be duplicated into Extra on parse")
	}
}

func TestClaims_EmptyGroupsSerializedAsList(t *testing.T) {
	granted, _ := json.Marshal(Claims{Groups: []string{}})
	if !strings.Contains(string(granted), `"groups":[]`) {
		t.Errorf("granted-but-empty groups should serialize as [], got %s", granted)
	}
	notGranted, _ := json.Marshal(Claims{})
	if strings.Contains(string(notGranted), "groups") {
		t.Errorf("nil groups should be omitted, got %s", notGranted)
	}
}

func TestIssuedAtOf(t *testing.T) {
	keyPair, _ := GenerateKeyPair(2048)
	g := NewTokenGenerator(keyPair, "https://idp.example.com", "https://idp.example.com")
	before := time.Now()
	raw, _, err := g.GenerateAccessToken("sub", time.Minute, "openid", "app")
	if err != nil {
		t.Fatal(err)
	}
	_, claims, err := g.ParseToken(raw)
	if err != nil {
		t.Fatal(err)
	}
	issued := IssuedAtOf(claims)
	if issued.Before(before.Add(-time.Millisecond)) || issued.After(time.Now().Add(time.Millisecond)) {
		t.Errorf("issue time from jti = %s, want about now (%s)", issued, before)
	}
	if issued.Nanosecond() == 0 && before.Nanosecond() > 10*int(time.Millisecond) {
		t.Errorf("issue time should carry sub-second precision, got %s", issued)
	}
	// A token whose jti is not time-ordered falls back to iat.
	claims.ID = "opaque"
	if got := IssuedAtOf(claims); !got.Equal(claims.IssuedAt.Time) {
		t.Errorf("fallback = %s, want iat %s", got, claims.IssuedAt.Time)
	}
}
