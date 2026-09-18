package maintenance

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store/sqlite"
)

func newStore(t *testing.T) *sqlite.Store {
	t.Helper()
	s, err := sqlite.NewStore(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func quiet() Option {
	return WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestRunOnce_PurgesExpiredRows(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)

	s.Users().Create(ctx, &domain.User{ID: "u", Email: "u@example.com"})
	s.Clients().Create(ctx, &domain.Client{ID: "c", Name: "c"})

	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	s.Sessions().Create(ctx, &domain.Session{ID: "s-old", UserID: "u", ExpiresAt: past})
	s.Sessions().Create(ctx, &domain.Session{ID: "s-new", UserID: "u", ExpiresAt: future})
	s.AuthCodes().Create(ctx, &domain.AuthCode{Code: "a-old", UserID: "u", ClientID: "c", ExpiresAt: past})
	s.AuthCodes().Create(ctx, &domain.AuthCode{Code: "a-new", UserID: "u", ClientID: "c", ExpiresAt: future})
	s.Tokens().Create(ctx, &domain.Token{ID: "t-old", UserID: "u", ClientID: "c", ExpiresAt: past})
	s.Tokens().Create(ctx, &domain.Token{ID: "t-new", UserID: "u", ClientID: "c", ExpiresAt: future})
	s.VerificationTokens().Create(ctx, &domain.VerificationToken{TokenHash: "v-old", UserID: "u", Purpose: domain.PurposeEmailVerify, ExpiresAt: past})
	s.VerificationTokens().Create(ctx, &domain.VerificationToken{TokenHash: "v-new", UserID: "u", Purpose: domain.PurposeEmailVerify, ExpiresAt: future})

	if err := NewRunner(s, nil, quiet()).RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	gone := func(name string, err error) {
		t.Helper()
		if !idperrors.IsCode(err, idperrors.CodeNotFound) {
			t.Errorf("%s should be purged, got %v", name, err)
		}
	}
	kept := func(name string, err error) {
		t.Helper()
		if err != nil {
			t.Errorf("%s should be kept: %v", name, err)
		}
	}

	_, err := s.Sessions().GetByID(ctx, "s-old")
	gone("expired session", err)
	_, err = s.Sessions().GetByID(ctx, "s-new")
	kept("valid session", err)
	_, err = s.AuthCodes().GetByCode(ctx, "a-old")
	gone("expired auth code", err)
	_, err = s.AuthCodes().GetByCode(ctx, "a-new")
	kept("valid auth code", err)
	_, err = s.Tokens().GetByID(ctx, "t-old")
	gone("expired token", err)
	_, err = s.Tokens().GetByID(ctx, "t-new")
	kept("valid token", err)
	_, err = s.VerificationTokens().GetByHash(ctx, "v-old")
	gone("expired verification token", err)
	_, err = s.VerificationTokens().GetByHash(ctx, "v-new")
	kept("valid verification token", err)
}

func TestRunOnce_RotatesAndCleansKeys(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	keys := crypto.NewKeyService(s.Keys())

	first, err := keys.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatalf("EnsureActiveKey: %v", err)
	}

	// Not old enough yet: no rotation.
	r := NewRunner(s, keys, quiet(), WithKeyRotation(time.Hour, time.Hour))
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if active, _ := keys.GetActiveKey(ctx); active.Kid != first.Kid {
		t.Fatalf("key should not rotate before max age")
	}

	// Age the key past the threshold and run again: rotation happens, the
	// old key stays for verification.
	first.CreatedAt = time.Now().Add(-2 * time.Hour)
	if err := s.Keys().Save(ctx, first); err != nil {
		t.Fatalf("Save: %v", err)
	}
	keys = crypto.NewKeyService(s.Keys()) // drop the cached copy
	r = NewRunner(s, keys, quiet(), WithKeyRotation(time.Hour, time.Hour))
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	second, _ := keys.GetActiveKey(ctx)
	if second.Kid == first.Kid {
		t.Fatal("key should have rotated")
	}
	old, err := keys.GetKeyByID(ctx, first.Kid)
	if err != nil {
		t.Fatalf("old key must remain during grace period: %v", err)
	}
	if old.Active || old.ExpiresAt.IsZero() {
		t.Errorf("old key should be inactive with an expiry, got active=%v expires=%v", old.Active, old.ExpiresAt)
	}

	// Once the grace period has elapsed the old key is removed.
	old.ExpiresAt = time.Now().Add(-time.Minute)
	if err := s.Keys().Save(ctx, old); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := r.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if _, err := keys.GetKeyByID(ctx, first.Kid); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("expired key should be cleaned up, got %v", err)
	}
	if active, _ := keys.GetActiveKey(ctx); active.Kid != second.Kid {
		t.Error("active key must survive cleanup")
	}
}

func TestRunOnce_RotationDisabled(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	keys := crypto.NewKeyService(s.Keys())

	first, _ := keys.EnsureActiveKey(ctx)
	first.CreatedAt = time.Now().Add(-365 * 24 * time.Hour)
	s.Keys().Save(ctx, first)
	keys = crypto.NewKeyService(s.Keys())

	if err := NewRunner(s, keys, quiet()).RunOnce(ctx); err != nil { // no WithKeyRotation
		t.Fatalf("RunOnce: %v", err)
	}
	if active, _ := keys.GetActiveKey(ctx); active.Kid != first.Kid {
		t.Error("rotation should be disabled by default")
	}
}

func TestTokensSignedWithNewKeyAfterRotation(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	keys := crypto.NewKeyService(s.Keys())

	first, _ := keys.EnsureActiveKey(ctx)
	gen := crypto.NewTokenGeneratorWithKeyService(first, keys, "http://idp", "http://idp")

	before, _, err := gen.GenerateAccessToken("sub", time.Minute, "openid", "client")
	if err != nil {
		t.Fatalf("GenerateAccessToken: %v", err)
	}

	second, err := keys.RotateKey(ctx, time.Hour)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	if gen.GetKeyID() != second.Kid {
		t.Errorf("generator should sign with the new key, got kid %s", gen.GetKeyID())
	}

	after, _, _ := gen.GenerateAccessToken("sub", time.Minute, "openid", "client")
	for name, tok := range map[string]string{"pre-rotation": before, "post-rotation": after} {
		if _, _, err := gen.ParseToken(tok); err != nil {
			t.Errorf("%s token should verify: %v", name, err)
		}
	}
}

func TestRun_StopsOnContextCancel(t *testing.T) {
	s := newStore(t)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		NewRunner(s, nil, quiet(), WithInterval(time.Millisecond)).Run(ctx)
		close(done)
	}()

	time.Sleep(5 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}
