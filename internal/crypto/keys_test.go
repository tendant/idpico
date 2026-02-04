package crypto

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if keyPair.Kid == "" {
		t.Error("Key ID should not be empty")
	}

	if keyPair.Alg != "RS256" {
		t.Errorf("Expected algorithm RS256, got %s", keyPair.Alg)
	}

	if keyPair.PrivateKey == nil {
		t.Error("Private key should not be nil")
	}

	if keyPair.PublicKey == nil {
		t.Error("Public key should not be nil")
	}

	if keyPair.Active != true {
		t.Error("New key should be active")
	}
}

func TestKeyPairPEMRoundTrip(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	originalKid := keyPair.Kid

	// GenerateKeyPair already serializes to PEM
	if len(keyPair.PrivateKeyPEM) == 0 {
		t.Error("PrivateKeyPEM should not be empty after GenerateKeyPair")
	}

	if len(keyPair.PublicKeyPEM) == 0 {
		t.Error("PublicKeyPEM should not be empty after GenerateKeyPair")
	}

	// Clear the key objects
	keyPair.PrivateKey = nil
	keyPair.PublicKey = nil

	// Load from PEM
	if err := keyPair.LoadFromPEM(); err != nil {
		t.Fatalf("LoadFromPEM failed: %v", err)
	}

	if keyPair.PrivateKey == nil {
		t.Error("Private key should be restored after LoadFromPEM")
	}

	if keyPair.PublicKey == nil {
		t.Error("Public key should be restored after LoadFromPEM")
	}

	if keyPair.Kid != originalKid {
		t.Error("Key ID should be preserved after round trip")
	}
}

func TestKeyPairToJWK(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	jwk := keyPair.ToJWK()

	if jwk.Kty != "RSA" {
		t.Errorf("Expected kty RSA, got %s", jwk.Kty)
	}

	if jwk.Use != "sig" {
		t.Errorf("Expected use sig, got %s", jwk.Use)
	}

	if jwk.Kid != keyPair.Kid {
		t.Errorf("Key ID mismatch: expected %s, got %s", keyPair.Kid, jwk.Kid)
	}

	if jwk.Alg != "RS256" {
		t.Errorf("Expected alg RS256, got %s", jwk.Alg)
	}

	if jwk.N == "" {
		t.Error("JWK modulus (n) should not be empty")
	}

	if jwk.E == "" {
		t.Error("JWK exponent (e) should not be empty")
	}
}

func TestKeyPairIsExpired(t *testing.T) {
	keyPair, _ := GenerateKeyPair(2048)

	// New key should not be expired
	if keyPair.IsExpired() {
		t.Error("New key should not be expired")
	}
}

func TestGenerateKeyPairDifferentKids(t *testing.T) {
	key1, _ := GenerateKeyPair(2048)
	key2, _ := GenerateKeyPair(2048)

	if key1.Kid == key2.Kid {
		t.Error("Different key pairs should have different key IDs")
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKeyPair(2048)
	}
}
