package sqlite

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
	"github.com/tendant/simple-idp/internal/store/storetest"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(context.Background(), filepath.Join(t.TempDir(), "idp.db"))
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store { return newTestStore(t) })
}

func TestConformance_InMemory(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s, err := NewStore(context.Background(), ":memory:")
		if err != nil {
			t.Fatalf("NewStore(:memory:) failed: %v", err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	})
}

func TestPersistenceAcrossRestarts(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "idp.db")

	s1, err := NewStore(ctx, path)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	client := &domain.Client{
		ID:           "persist-client",
		Name:         "Persist",
		RedirectURIs: []string{"http://localhost:3000/callback", "http://localhost:8081/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid"},
		Public:       true,
	}
	if err := s1.Clients().Create(ctx, client); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	s1.Close()

	// Reopening must be idempotent with respect to migrations.
	s2, err := NewStore(ctx, path)
	if err != nil {
		t.Fatalf("NewStore (reopen) failed: %v", err)
	}
	defer s2.Close()

	found, err := s2.Clients().GetByID(ctx, "persist-client")
	if err != nil {
		t.Fatalf("client should be persisted: %v", err)
	}
	if len(found.RedirectURIs) != 2 || found.RedirectURIs[1] != "http://localhost:8081/callback" {
		t.Errorf("redirect URIs not round-tripped: %v", found.RedirectURIs)
	}
	if !found.Public {
		t.Error("public flag not round-tripped")
	}
	if found.CreatedAt.IsZero() || !found.CreatedAt.Equal(client.CreatedAt) {
		t.Errorf("created_at not round-tripped: got %v want %v", found.CreatedAt, client.CreatedAt)
	}
}

func TestClient_NilSlicesRoundTripAsEmpty(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.Clients().Create(ctx, &domain.Client{ID: "c", Name: "c"}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	c, err := s.Clients().GetByID(ctx, "c")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if c.RedirectURIs == nil || c.GrantTypes == nil || c.Scopes == nil {
		t.Error("expected empty (non-nil) slices")
	}
	if len(c.RedirectURIs)+len(c.GrantTypes)+len(c.Scopes) != 0 {
		t.Error("expected empty slices")
	}
}

func TestUser_UpdateDuplicateEmail(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	s.Users().Create(ctx, &domain.User{ID: "u1", Email: "a@example.com"})
	s.Users().Create(ctx, &domain.User{ID: "u2", Email: "b@example.com"})

	u2, _ := s.Users().GetByID(ctx, "u2")
	u2.Email = "a@example.com"
	err := s.Users().Update(ctx, u2)
	if !idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
		t.Errorf("expected already-exists on duplicate email update, got %v", err)
	}
}

func TestSigningKey_ZeroExpiryRoundTrips(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	if err := s.SigningKeys().Create(ctx, &domain.SigningKey{ID: "k", Algorithm: "RS256"}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	k, err := s.SigningKeys().GetByID(ctx, "k")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if !k.ExpiresAt.IsZero() {
		t.Errorf("zero ExpiresAt should round-trip as zero, got %v", k.ExpiresAt)
	}
}

func TestSigningKey_OnlyOneActive(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)

	s.SigningKeys().Create(ctx, &domain.SigningKey{ID: "k1", Active: true})
	s.SigningKeys().Create(ctx, &domain.SigningKey{ID: "k2", Active: true})

	k1, _ := s.SigningKeys().GetByID(ctx, "k1")
	if k1.Active {
		t.Error("creating a second active key should deactivate the first")
	}
	active, err := s.SigningKeys().GetActive(ctx)
	if err != nil || active.ID != "k2" {
		t.Errorf("expected k2 active, got %v (err %v)", active, err)
	}
}

// KeyRepository (crypto.KeyRepository) tests, driven through the real KeyService.

func TestKeyRepository_KeyServiceLifecycle(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "idp.db")

	s1, err := NewStore(ctx, path)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	svc := crypto.NewKeyService(s1.Keys())

	key, err := svc.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatalf("EnsureActiveKey failed: %v", err)
	}
	if key.PrivateKey == nil {
		t.Fatal("generated key should have RSA material")
	}
	s1.Close()

	// Reopen: the same key must come back and be loadable from PEM.
	s2, err := NewStore(ctx, path)
	if err != nil {
		t.Fatalf("NewStore (reopen) failed: %v", err)
	}
	defer s2.Close()
	svc = crypto.NewKeyService(s2.Keys())

	loaded, err := svc.GetActiveKey(ctx)
	if err != nil {
		t.Fatalf("GetActiveKey failed: %v", err)
	}
	if loaded.Kid != key.Kid {
		t.Errorf("expected kid %s after reopen, got %s", key.Kid, loaded.Kid)
	}
	if loaded.PrivateKey == nil || loaded.PublicKey == nil {
		t.Error("key should be restored from PEM")
	}
	if loaded.PrivateKey.N.Cmp(key.PrivateKey.N) != 0 {
		t.Error("restored private key differs from generated key")
	}

	// Rotate: old key stays for verification with an expiry, new key is active.
	newKey, err := svc.RotateKey(ctx, time.Hour)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
	if newKey.Kid == key.Kid {
		t.Error("rotation should produce a new kid")
	}
	active, _ := svc.GetActiveKey(ctx)
	if active.Kid != newKey.Kid {
		t.Errorf("expected active kid %s, got %s", newKey.Kid, active.Kid)
	}
	old, err := svc.GetKeyByID(ctx, key.Kid)
	if err != nil {
		t.Fatalf("old key should still exist: %v", err)
	}
	if old.Active || old.ExpiresAt.IsZero() {
		t.Errorf("old key should be inactive with an expiry: active=%v expires=%v", old.Active, old.ExpiresAt)
	}

	jwks, err := svc.GetJWKS(ctx)
	if err != nil {
		t.Fatalf("GetJWKS failed: %v", err)
	}
	if len(jwks.Keys) != 2 {
		t.Errorf("expected 2 keys in JWKS, got %d", len(jwks.Keys))
	}

	// Expire the old key and clean up.
	old.ExpiresAt = time.Now().Add(-time.Minute)
	if err := s2.Keys().Save(ctx, old); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if err := svc.CleanupExpiredKeys(ctx); err != nil {
		t.Fatalf("CleanupExpiredKeys failed: %v", err)
	}
	if _, err := s2.Keys().GetByID(ctx, key.Kid); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("expired key should be deleted, got %v", err)
	}
	if _, err := s2.Keys().GetByID(ctx, newKey.Kid); err != nil {
		t.Errorf("active key must survive cleanup: %v", err)
	}
}

func TestKeyRepository_SetActiveUnknown(t *testing.T) {
	s := newTestStore(t)
	err := s.Keys().SetActive(context.Background(), "nope")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestDSN(t *testing.T) {
	if got := dsn("file:custom.db?_pragma=foo"); got != "file:custom.db?_pragma=foo" {
		t.Errorf("full DSN should pass through, got %s", got)
	}
	if got := dsn(":memory:"); !strings.Contains(got, "busy_timeout") || strings.Contains(got, "journal_mode") {
		t.Errorf("memory DSN should skip WAL, got %s", got)
	}
	if got := dsn("data/idp.db"); !strings.Contains(got, "_pragma=journal_mode(WAL)") {
		t.Errorf("file DSN should enable WAL, got %s", got)
	}
}

func TestPragmasApplied(t *testing.T) {
	s := newTestStore(t)

	var mode string
	if err := s.DB().QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("PRAGMA journal_mode: %v", err)
	}
	if mode != "wal" {
		t.Errorf("expected journal_mode=wal, got %q", mode)
	}

	var busy int
	if err := s.DB().QueryRow(`PRAGMA busy_timeout`).Scan(&busy); err != nil {
		t.Fatalf("PRAGMA busy_timeout: %v", err)
	}
	if busy != 5000 {
		t.Errorf("expected busy_timeout=5000, got %d", busy)
	}

	var fk int
	if err := s.DB().QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil {
		t.Fatalf("PRAGMA foreign_keys: %v", err)
	}
	if fk != 1 {
		t.Error("expected foreign_keys=ON")
	}
}

// Referential integrity

func TestForeignKeys_RejectUnknownReferences(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	exp := time.Now().Add(time.Hour)

	s.Users().Create(ctx, &domain.User{ID: "u1", Email: "u1@example.com"})
	s.Clients().Create(ctx, &domain.Client{ID: "c1", Name: "c1"})

	cases := []struct {
		name string
		err  error
	}{
		{"session unknown user", s.Sessions().Create(ctx, &domain.Session{ID: "s", UserID: "nope", ExpiresAt: exp})},
		{"token unknown user", s.Tokens().Create(ctx, &domain.Token{ID: "t1", UserID: "nope", ClientID: "c1", ExpiresAt: exp})},
		{"token unknown client", s.Tokens().Create(ctx, &domain.Token{ID: "t2", UserID: "u1", ClientID: "nope", ExpiresAt: exp})},
		{"auth code unknown user", s.AuthCodes().Create(ctx, &domain.AuthCode{Code: "a1", UserID: "nope", ClientID: "c1", ExpiresAt: exp})},
		{"auth code unknown client", s.AuthCodes().Create(ctx, &domain.AuthCode{Code: "a2", UserID: "u1", ClientID: "nope", ExpiresAt: exp})},
	}
	for _, tc := range cases {
		if !idperrors.IsCode(tc.err, idperrors.CodeInvalidInput) {
			t.Errorf("%s: expected invalid_input, got %v", tc.name, tc.err)
		}
	}
}

func TestForeignKeys_CascadeOnUserDelete(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	exp := time.Now().Add(time.Hour)

	s.Users().Create(ctx, &domain.User{ID: "u1", Email: "u1@example.com"})
	s.Users().Create(ctx, &domain.User{ID: "u2", Email: "u2@example.com"})
	s.Clients().Create(ctx, &domain.Client{ID: "c1", Name: "c1"})

	mustCreate(t, s.Sessions().Create(ctx, &domain.Session{ID: "s1", UserID: "u1", ExpiresAt: exp}))
	mustCreate(t, s.Sessions().Create(ctx, &domain.Session{ID: "s2", UserID: "u2", ExpiresAt: exp}))
	mustCreate(t, s.Tokens().Create(ctx, &domain.Token{ID: "t1", UserID: "u1", ClientID: "c1", ExpiresAt: exp}))
	mustCreate(t, s.AuthCodes().Create(ctx, &domain.AuthCode{Code: "a1", UserID: "u1", ClientID: "c1", ExpiresAt: exp}))

	if err := s.Users().Delete(ctx, "u1"); err != nil {
		t.Fatalf("Delete user failed: %v", err)
	}

	if _, err := s.Sessions().GetByID(ctx, "s1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("session should cascade on user delete, got %v", err)
	}
	if _, err := s.Tokens().GetByID(ctx, "t1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("token should cascade on user delete, got %v", err)
	}
	if _, err := s.AuthCodes().GetByCode(ctx, "a1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("auth code should cascade on user delete, got %v", err)
	}
	if _, err := s.Sessions().GetByID(ctx, "s2"); err != nil {
		t.Errorf("other user's session must survive: %v", err)
	}
}

func TestForeignKeys_CascadeOnClientDelete(t *testing.T) {
	ctx := context.Background()
	s := newTestStore(t)
	exp := time.Now().Add(time.Hour)

	s.Users().Create(ctx, &domain.User{ID: "u1", Email: "u1@example.com"})
	s.Clients().Create(ctx, &domain.Client{ID: "c1", Name: "c1"})
	s.Clients().Create(ctx, &domain.Client{ID: "c2", Name: "c2"})

	mustCreate(t, s.Tokens().Create(ctx, &domain.Token{ID: "t1", UserID: "u1", ClientID: "c1", ExpiresAt: exp}))
	mustCreate(t, s.Tokens().Create(ctx, &domain.Token{ID: "t2", UserID: "u1", ClientID: "c2", ExpiresAt: exp}))
	mustCreate(t, s.AuthCodes().Create(ctx, &domain.AuthCode{Code: "a1", UserID: "u1", ClientID: "c1", ExpiresAt: exp}))

	if err := s.Clients().Delete(ctx, "c1"); err != nil {
		t.Fatalf("Delete client failed: %v", err)
	}

	if _, err := s.Tokens().GetByID(ctx, "t1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("token should cascade on client delete, got %v", err)
	}
	if _, err := s.AuthCodes().GetByCode(ctx, "a1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("auth code should cascade on client delete, got %v", err)
	}
	if _, err := s.Tokens().GetByID(ctx, "t2"); err != nil {
		t.Errorf("other client's token must survive: %v", err)
	}
}

func mustCreate(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("create failed: %v", err)
	}
}
