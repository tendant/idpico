package crypto

import (
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
