package oidc

import (
	"context"
	"testing"

	"github.com/tendant/idpico/internal/domain"
	"github.com/tendant/idpico/internal/store/sqlite"
)

func TestVerifyClientSecret(t *testing.T) {
	hash, err := HashClientSecret("s3cret")
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	if !IsHashedClientSecret(hash) || IsHashedClientSecret("s3cret") {
		t.Error("IsHashedClientSecret misclassifies values")
	}

	cases := []struct {
		name         string
		stored, in   string
		wantOK, want bool // want = legacy
	}{
		{"hashed match", hash, "s3cret", true, false},
		{"hashed mismatch", hash, "nope", false, false},
		{"legacy plaintext match", "s3cret", "s3cret", true, true},
		{"legacy plaintext mismatch", "s3cret", "nope", false, true},
		{"empty stored", "", "", false, false},
		{"empty presented", hash, "", false, false},
	}
	for _, tc := range cases {
		ok, legacy := VerifyClientSecret(tc.stored, tc.in)
		if ok != tc.wantOK || legacy != tc.want {
			t.Errorf("%s: got ok=%v legacy=%v, want ok=%v legacy=%v", tc.name, ok, legacy, tc.wantOK, tc.want)
		}
	}
}

func TestAuthenticateClient_UpgradesLegacySecret(t *testing.T) {
	ctx := context.Background()
	s, err := sqlite.NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	defer s.Close()

	// A client created before secrets were hashed
	s.Clients().Create(ctx, &domain.Client{ID: "legacy", Name: "Legacy", Secret: "plain-secret"})
	client, _ := s.Clients().GetByID(ctx, "legacy")

	if authenticateClient(ctx, s.Clients(), client, "wrong") {
		t.Fatal("wrong secret must not authenticate")
	}
	stored, _ := s.Clients().GetByID(ctx, "legacy")
	if stored.Secret != "plain-secret" {
		t.Error("failed auth must not modify the stored secret")
	}

	if !authenticateClient(ctx, s.Clients(), client, "plain-secret") {
		t.Fatal("correct secret should authenticate")
	}
	stored, _ = s.Clients().GetByID(ctx, "legacy")
	if !IsHashedClientSecret(stored.Secret) {
		t.Errorf("successful auth should upgrade the stored secret to a hash, got %q", stored.Secret)
	}
	if ok, legacy := VerifyClientSecret(stored.Secret, "plain-secret"); !ok || legacy {
		t.Error("upgraded hash should verify the same secret")
	}

	// Public clients never need a secret
	s.Clients().Create(ctx, &domain.Client{ID: "spa", Name: "SPA", Public: true})
	spa, _ := s.Clients().GetByID(ctx, "spa")
	if !authenticateClient(ctx, s.Clients(), spa, "") {
		t.Error("public client should authenticate without a secret")
	}
}
