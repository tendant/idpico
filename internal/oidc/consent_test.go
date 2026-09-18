package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store/sqlite"
)

func mustQuery(raw string) url.Values {
	q, err := url.ParseQuery(raw)
	if err != nil {
		panic(err)
	}
	return q
}

func newConsentService(t *testing.T) (*ConsentService, *sqlite.Store) {
	t.Helper()
	s, err := sqlite.NewStore(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	ctx := context.Background()
	s.Users().Create(ctx, &domain.User{ID: "u1", Email: "u1@example.com"})
	s.Clients().Create(ctx, &domain.Client{ID: "app", Name: "App"})
	s.Clients().Create(ctx, &domain.Client{ID: "first-party", Name: "Ours", SkipConsent: true})
	return NewConsentService(s.Consents()), s
}

func TestConsentService_GrantAndCheck(t *testing.T) {
	ctx := context.Background()
	svc, _ := newConsentService(t)
	app := &domain.Client{ID: "app"}

	if ok, _ := svc.IsGranted(ctx, "u1", app, []string{"openid"}); ok {
		t.Fatal("no consent yet: should not be granted")
	}

	if err := svc.Grant(ctx, "u1", "app", []string{"openid", "profile"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if ok, _ := svc.IsGranted(ctx, "u1", app, []string{"openid"}); !ok {
		t.Error("subset of granted scopes should be granted")
	}
	if ok, _ := svc.IsGranted(ctx, "u1", app, []string{"openid", "email"}); ok {
		t.Error("scope outside the grant should require consent")
	}

	// A later, narrower grant must not drop previously granted scopes.
	if err := svc.Grant(ctx, "u1", "app", []string{"email"}); err != nil {
		t.Fatalf("Grant: %v", err)
	}
	if ok, _ := svc.IsGranted(ctx, "u1", app, []string{"openid", "profile", "email"}); !ok {
		t.Error("grants should accumulate")
	}

	list, _ := svc.ListForUser(ctx, "u1")
	if len(list) != 1 {
		t.Errorf("expected one consent record, got %d", len(list))
	}

	if err := svc.Revoke(ctx, "u1", "app"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if ok, _ := svc.IsGranted(ctx, "u1", app, []string{"openid"}); ok {
		t.Error("revoked consent should not be granted")
	}
	if err := svc.Revoke(ctx, "u1", "app"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("revoking twice should be not found, got %v", err)
	}
}

func TestConsentService_SkipConsentClient(t *testing.T) {
	ctx := context.Background()
	svc, _ := newConsentService(t)

	ok, err := svc.IsGranted(ctx, "u1", &domain.Client{ID: "first-party", SkipConsent: true}, []string{"openid", "email"})
	if err != nil || !ok {
		t.Errorf("first-party client should skip consent, ok=%v err=%v", ok, err)
	}
}

func TestAuthorizeRequest_Prompt(t *testing.T) {
	svc := NewAuthorizeService(nil, nil, 0)

	req, err := svc.ParseAuthorizeQuery(mustQuery("client_id=c&redirect_uri=http://x/cb&response_type=code&scope=openid&prompt=login consent"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !req.HasPrompt("login") || !req.HasPrompt("consent") || req.HasPrompt("none") {
		t.Errorf("unexpected prompt parse: %v", req.Prompt)
	}

	if _, err := svc.ParseAuthorizeQuery(mustQuery("client_id=c&redirect_uri=http://x/cb&response_type=code&scope=openid&prompt=none login")); err == nil {
		t.Error("prompt=none combined with other values should be rejected")
	}
}
