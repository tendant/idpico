package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestValidateCodeVerifierS256(t *testing.T) {
	// Standard test vector from RFC 7636
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// Compute the challenge
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	if !ValidateCodeVerifier(verifier, challenge, "S256") {
		t.Error("Valid S256 verifier should pass")
	}
}

func TestValidateCodeVerifierS256Invalid(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	// Compute challenge for different verifier
	hash := sha256.Sum256([]byte("wrong-verifier"))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	if ValidateCodeVerifier(verifier, challenge, "S256") {
		t.Error("Invalid S256 verifier should fail")
	}
}

func TestValidateCodeVerifierPlain(t *testing.T) {
	verifier := "my-plain-verifier"
	challenge := verifier // Plain method: challenge == verifier

	if !ValidateCodeVerifier(verifier, challenge, "plain") {
		t.Error("Valid plain verifier should pass")
	}
}

func TestValidateCodeVerifierPlainInvalid(t *testing.T) {
	verifier := "my-plain-verifier"
	challenge := "different-challenge"

	if ValidateCodeVerifier(verifier, challenge, "plain") {
		t.Error("Invalid plain verifier should fail")
	}
}

func TestValidateCodeVerifierNoPKCE(t *testing.T) {
	// No PKCE used: both challenge and verifier should be empty
	if !ValidateCodeVerifier("", "", "") {
		t.Error("No PKCE (empty challenge and verifier) should pass")
	}

	// Challenge provided but no verifier
	if ValidateCodeVerifier("", "some-challenge", "S256") {
		t.Error("Missing verifier when challenge exists should fail")
	}
}

func TestValidateCodeVerifierUnknownMethod(t *testing.T) {
	if ValidateCodeVerifier("verifier", "challenge", "unknown") {
		t.Error("Unknown method should fail")
	}
}

func TestValidateCodeVerifierRFCVector(t *testing.T) {
	// Test vector from RFC 7636 Appendix B
	// code_verifier = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
	// code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if !ValidateCodeVerifier(verifier, challenge, "S256") {
		t.Error("RFC 7636 test vector should validate")
	}
}

func TestValidateCodeVerifierEmptyChallengeWithVerifier(t *testing.T) {
	// If no challenge was stored, but verifier is provided, should fail
	if ValidateCodeVerifier("some-verifier", "", "") {
		t.Error("Verifier without challenge should fail")
	}
}

// Benchmark PKCE validation
func BenchmarkValidateCodeVerifierS256(b *testing.B) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	for i := 0; i < b.N; i++ {
		ValidateCodeVerifier(verifier, challenge, "S256")
	}
}
