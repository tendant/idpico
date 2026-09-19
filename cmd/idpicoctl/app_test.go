package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/tendant/idpico/internal/auth"
	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/oidc"
	"github.com/tendant/idpico/internal/store/sqlite"
)

func newTestApp(t *testing.T) (*app, *sqlite.Store, *bytes.Buffer) {
	t.Helper()
	s, err := sqlite.NewStore(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	out := &bytes.Buffer{}
	return &app{store: s, keys: crypto.NewKeyService(s.Keys()), keyRepo: s.Keys(), out: out}, s, out
}

func run(t *testing.T, a *app, out *bytes.Buffer, line string) string {
	t.Helper()
	out.Reset()
	if err := a.run(context.Background(), strings.Fields(line)); err != nil {
		t.Fatalf("%q: %v", line, err)
	}
	return out.String()
}

func mustFail(t *testing.T, a *app, line string) {
	t.Helper()
	if err := a.run(context.Background(), strings.Fields(line)); err == nil {
		t.Fatalf("%q should fail", line)
	}
}

func TestUsers(t *testing.T) {
	a, s, out := newTestApp(t)
	ctx := context.Background()

	run(t, a, out, "user add alice@example.com -name Alice -password strong-pass-1 -admin -verified")
	u, err := s.Users().GetByEmail(ctx, "alice@example.com")
	if err != nil || u.DisplayName != "Alice" || !u.Admin || !u.EmailVerified || !u.Active {
		t.Fatalf("user not created as expected: %+v err=%v", u, err)
	}
	if ok, _ := auth.VerifyPassword("strong-pass-1", u.PasswordHash); !ok {
		t.Error("password should verify")
	}

	// Flags after the positional argument, generated password printed
	o := run(t, a, out, "user add bob@example.com -inactive")
	if !strings.Contains(o, "password: ") {
		t.Errorf("generated password should be printed, got %q", o)
	}
	b, _ := s.Users().GetByEmail(ctx, "bob@example.com")
	if b.Active {
		t.Error("-inactive should create a disabled user")
	}

	mustFail(t, a, "user add alice@example.com -password strong-pass-1") // duplicate
	mustFail(t, a, "user add carol@example.com -password short")         // policy

	o = run(t, a, out, "user list")
	if !strings.Contains(o, "alice@example.com") || !strings.Contains(o, "bob@example.com") {
		t.Errorf("list should show both users: %q", o)
	}

	run(t, a, out, "user passwd alice@example.com another-pass-1")
	u, _ = s.Users().GetByEmail(ctx, "alice@example.com")
	if ok, _ := auth.VerifyPassword("another-pass-1", u.PasswordHash); !ok {
		t.Error("passwd should update the hash")
	}

	run(t, a, out, "user set-admin alice@example.com false")
	u, _ = s.Users().GetByEmail(ctx, "alice@example.com")
	if u.Admin {
		t.Error("set-admin false should clear the flag")
	}
	mustFail(t, a, "user set-admin alice@example.com maybe")

	run(t, a, out, "user delete bob@example.com")
	if _, err := s.Users().GetByEmail(ctx, "bob@example.com"); err == nil {
		t.Error("user should be deleted")
	}
	mustFail(t, a, "user delete nobody@example.com")
}

func TestGroups(t *testing.T) {
	a, s, out := newTestApp(t)
	ctx := context.Background()
	run(t, a, out, "user add alice@example.com -password strong-pass-1")

	run(t, a, out, "group add admins -desc Administrators")
	mustFail(t, a, "group add Admins")
	run(t, a, out, "group add-member admins alice@example.com")
	mustFail(t, a, "group add-member admins nobody@example.com")

	if o := run(t, a, out, "group members admins"); !strings.Contains(o, "alice@example.com") {
		t.Errorf("members should list alice: %q", o)
	}
	if o := run(t, a, out, "group list"); !strings.Contains(o, "admins") || !strings.Contains(o, "1") {
		t.Errorf("list should show group with member count: %q", o)
	}

	run(t, a, out, "group remove-member admins alice@example.com")
	mustFail(t, a, "group remove-member admins alice@example.com")
	run(t, a, out, "group delete admins")
	if _, err := s.Groups().GetByName(ctx, "admins"); err == nil {
		t.Error("group should be deleted")
	}
}

func TestClients(t *testing.T) {
	a, s, out := newTestApp(t)
	ctx := context.Background()

	mustFail(t, a, "client add my-app") // no redirect
	o := run(t, a, out, "client add my-app -redirect http://localhost:3000/cb -redirect http://localhost:3001/cb -scopes openid")
	secret := strings.TrimSpace(strings.SplitN(o, "client_secret: ", 2)[1])
	c, err := s.Clients().GetByID(ctx, "my-app")
	if err != nil || len(c.RedirectURIs) != 2 || c.Name != "my-app" || c.Public || len(c.Scopes) != 1 {
		t.Fatalf("client not created as expected: %+v err=%v", c, err)
	}
	if ok, _ := oidc.VerifyClientSecret(c.Secret, secret); !ok {
		t.Error("printed secret should verify against the stored hash")
	}

	o = run(t, a, out, "client reset-secret my-app")
	newSecret := strings.TrimSpace(strings.SplitN(o, "client_secret: ", 2)[1])
	c, _ = s.Clients().GetByID(ctx, "my-app")
	if ok, _ := oidc.VerifyClientSecret(c.Secret, newSecret); !ok || newSecret == secret {
		t.Error("reset-secret should store a new secret")
	}

	o = run(t, a, out, "client add spa -public -skip-consent -redirect http://localhost:5173/cb")
	if strings.Contains(o, "client_secret") {
		t.Error("public client should not get a secret")
	}
	mustFail(t, a, "client reset-secret spa")
	if o := run(t, a, out, "client list"); !strings.Contains(o, "public") || !strings.Contains(o, "skipped") {
		t.Errorf("list should show client types: %q", o)
	}

	run(t, a, out, "client delete spa")
	if _, err := s.Clients().GetByID(ctx, "spa"); err == nil {
		t.Error("client should be deleted")
	}
}

func TestKeys(t *testing.T) {
	a, _, out := newTestApp(t)

	o := run(t, a, out, "key rotate -grace 1h")
	if !strings.Contains(o, "active key is now") {
		t.Errorf("rotate output: %q", o)
	}
	// On an empty store, rotate first ensures a key and then rotates: two keys, one active
	o = run(t, a, out, "key list")
	if strings.Count(o, "RS256") != 2 || strings.Count(o, "true") != 1 {
		t.Errorf("expected two keys with one active after first rotate, got %q", o)
	}
}

func TestUsage(t *testing.T) {
	a, _, _ := newTestApp(t)
	mustFail(t, a, "")
	mustFail(t, a, "user")
	mustFail(t, a, "bogus list")
	mustFail(t, a, "user bogus")
}
