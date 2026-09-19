package crypto

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateKeyPairForAlg(t *testing.T) {
	for _, alg := range SupportedAlgorithms {
		kp, err := GenerateKeyPairForAlg(alg)
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		if kp.Alg != alg || kp.PrivateKey == nil || kp.PublicKey == nil || kp.Kid == "" {
			t.Errorf("%s: bad key pair %+v", alg, kp)
		}
	}
	if _, err := GenerateKeyPairForAlg("HS256"); err == nil {
		t.Error("HS256 must be refused: symmetric keys have no place in a JWKS")
	}
}

func TestEd25519PEMRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPairForAlg(AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(kp.PrivateKeyPEM), "BEGIN PRIVATE KEY") {
		t.Errorf("Ed25519 private key should be PKCS#8, got %s", kp.PrivateKeyPEM[:30])
	}

	restored := &KeyPair{Kid: kp.Kid, Alg: kp.Alg, PrivateKeyPEM: kp.PrivateKeyPEM, PublicKeyPEM: kp.PublicKeyPEM}
	if err := restored.LoadFromPEM(); err != nil {
		t.Fatalf("LoadFromPEM: %v", err)
	}
	if !restored.PrivateKey.(ed25519.PrivateKey).Equal(kp.PrivateKey) || !restored.PublicKey.(ed25519.PublicKey).Equal(kp.PublicKey) {
		t.Error("restored key material differs")
	}

	// A row whose alg column disagrees with its material must not load.
	mislabelled := &KeyPair{Kid: kp.Kid, Alg: AlgRS256, PrivateKeyPEM: kp.PrivateKeyPEM, PublicKeyPEM: kp.PublicKeyPEM}
	if err := mislabelled.LoadFromPEM(); err == nil {
		t.Error("an Ed25519 key labelled RS256 must be rejected")
	}

	// Rows from before the alg column was populated are RSA.
	rsaKP, _ := GenerateKeyPair(2048)
	legacy := &KeyPair{Kid: rsaKP.Kid, PrivateKeyPEM: rsaKP.PrivateKeyPEM, PublicKeyPEM: rsaKP.PublicKeyPEM}
	if err := legacy.LoadFromPEM(); err != nil || legacy.Alg != AlgRS256 {
		t.Errorf("legacy RSA row should load as RS256, got alg=%q err=%v", legacy.Alg, err)
	}
}

func TestEd25519JWK(t *testing.T) {
	kp, _ := GenerateKeyPairForAlg(AlgEdDSA)
	b, _ := json.Marshal(kp.ToJWK())
	var m map[string]string
	json.Unmarshal(b, &m)
	if m["kty"] != "OKP" || m["crv"] != "Ed25519" || m["alg"] != "EdDSA" || m["x"] == "" || m["use"] != "sig" || m["kid"] != kp.Kid {
		t.Errorf("bad OKP JWK: %s", b)
	}
	if _, ok := m["n"]; ok {
		t.Errorf("OKP JWK must not carry RSA fields: %s", b)
	}

	rsaKP, _ := GenerateKeyPair(2048)
	b, _ = json.Marshal(rsaKP.ToJWK())
	m = map[string]string{}
	json.Unmarshal(b, &m)
	if m["kty"] != "RSA" || m["n"] == "" || m["e"] == "" {
		t.Errorf("bad RSA JWK: %s", b)
	}
	if _, ok := m["crv"]; ok {
		t.Errorf("RSA JWK must not carry OKP fields: %s", b)
	}
}

func TestEdDSATokenRoundTrip(t *testing.T) {
	kp, _ := GenerateKeyPairForAlg(AlgEdDSA)
	gen := NewTokenGenerator(kp, "https://issuer.example.com", "aud")

	tokenString, _, err := gen.GenerateIDToken("user-1", time.Minute, &Claims{Email: "u@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	token, claims, err := gen.ParseToken(tokenString)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if token.Header["alg"] != "EdDSA" || token.Header["kid"] != kp.Kid || claims.Email != "u@example.com" {
		t.Errorf("header=%v claims=%+v", token.Header, claims)
	}
}

// A token signed with one algorithm must not verify against a key of the
// other, even when the kid matches: alg is bound to the key, not the token.
func TestAlgorithmConfusionRejected(t *testing.T) {
	rsaKP, _ := GenerateKeyPair(2048)
	edKP, _ := GenerateKeyPairForAlg(AlgEdDSA)

	repo := newMemKeyRepo()
	repo.Save(context.Background(), rsaKP)
	repo.Save(context.Background(), edKP)
	repo.SetActive(context.Background(), edKP.Kid)
	svc := NewKeyService(repo)
	gen := NewTokenGeneratorWithKeyService(edKP, svc, "iss", "aud")

	// Forge: claim the RSA key's kid but sign with EdDSA (attacker holds no RSA key).
	claims := jwt.MapClaims{"sub": "x", "iss": "iss", "aud": "aud", "exp": time.Now().Add(time.Minute).Unix()}
	forged := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	forged.Header["kid"] = rsaKP.Kid
	s, _ := forged.SignedString(edKP.PrivateKey)
	if _, _, err := gen.ParseToken(s); err == nil || !strings.Contains(err.Error(), "does not match key") {
		t.Errorf("EdDSA token naming an RS256 kid should be rejected, got %v", err)
	}

	// And HMAC with the public key as secret, the classic confusion.
	hm := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	hm.Header["kid"] = rsaKP.Kid
	s, _ = hm.SignedString(rsaKP.PublicKeyPEM)
	if _, _, err := gen.ParseToken(s); err == nil || !strings.Contains(err.Error(), "unexpected signing method") {
		t.Errorf("HS256 must be rejected, got %v", err)
	}
}

// Switching the configured algorithm rotates to a key of the new kind while
// the old key keeps verifying tokens it signed.
func TestKeyServiceAlgorithmSwitch(t *testing.T) {
	ctx := context.Background()
	repo := newMemKeyRepo()

	rsaSvc := NewKeyService(repo)
	first, err := rsaSvc.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.Alg != AlgRS256 {
		t.Fatalf("default should be RS256, got %s", first.Alg)
	}
	gen := NewTokenGeneratorWithKeyService(first, rsaSvc, "iss", "aud")
	oldToken, _, _ := gen.GenerateIDToken("u", time.Minute, &Claims{})

	edSvc := NewKeyService(repo, WithAlgorithm(AlgEdDSA))
	if got, _ := edSvc.EnsureActiveKey(ctx); got.Kid != first.Kid {
		t.Error("EnsureActiveKey must keep the existing active key regardless of algorithm")
	}
	second, err := edSvc.RotateKey(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if second.Alg != AlgEdDSA {
		t.Errorf("rotated key should be EdDSA, got %s", second.Alg)
	}

	gen = NewTokenGeneratorWithKeyService(second, edSvc, "iss", "aud")
	newToken, _, _ := gen.GenerateIDToken("u", time.Minute, &Claims{})
	for name, tok := range map[string]string{"old RS256 token": oldToken, "new EdDSA token": newToken} {
		if _, _, err := gen.ParseToken(tok); err != nil {
			t.Errorf("%s should verify during the grace period: %v", name, err)
		}
	}
}
