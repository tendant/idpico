package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/domain"
	"github.com/tendant/idpico/internal/store/sqlite"
)

// revocationFixture wires TokenService and UserInfoService the way main.go
// does, on an in-memory SQLite store, so the store's revocation invariant
// is exercised end to end.
type revocationFixture struct {
	t        *testing.T
	ctx      context.Context
	store    *sqlite.Store
	tokens   *TokenService
	userinfo *UserInfoService
}

func newRevocationFixture(t *testing.T) *revocationFixture {
	t.Helper()
	ctx := context.Background()
	s, err := sqlite.NewStore(ctx, ":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	for _, c := range []*domain.Client{
		{ID: "app-a", Name: "A", Secret: "secret-a", RedirectURIs: []string{"http://a/cb"}, Scopes: []string{"openid", "offline_access"}},
		{ID: "app-b", Name: "B", Secret: "secret-b", RedirectURIs: []string{"http://b/cb"}, Scopes: []string{"openid", "offline_access"}},
	} {
		if err := s.Clients().Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	for _, u := range []*domain.User{{ID: "alice", Email: "alice@example.com", Active: true}, {ID: "bob", Email: "bob@example.com", Active: true}} {
		if err := s.Users().Create(ctx, u); err != nil {
			t.Fatal(err)
		}
	}

	keyPair, _ := crypto.GenerateKeyPair(2048)
	gen := crypto.NewTokenGenerator(keyPair, "https://idp.example.com", "https://idp.example.com")
	tokens := NewTokenService(s.Clients(), s.AuthCodes(), s.Tokens(), s.Users(), gen, "https://idp.example.com",
		15*time.Minute, 24*time.Hour, WithRevocations(s.Revocations()))
	userinfo := NewUserInfoService(s.Users(), gen, WithUserInfoRevocations(s.Revocations()))
	return &revocationFixture{t: t, ctx: ctx, store: s, tokens: tokens, userinfo: userinfo}
}

// issue runs an authorization-code exchange for user/client and returns the
// tokens and the code (for replay tests).
func (f *revocationFixture) issue(userID, clientID, secret string) (*TokenResponse, string) {
	f.t.Helper()
	code := uuid.New().String()
	client, _ := f.store.Clients().GetByID(f.ctx, clientID)
	if err := f.store.AuthCodes().Create(f.ctx, &domain.AuthCode{
		Code: code, ClientID: clientID, UserID: userID, RedirectURI: client.RedirectURIs[0],
		Scope: "openid offline_access", ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		f.t.Fatal(err)
	}
	resp, err := f.tokens.HandleAuthorizationCode(f.ctx, &TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: client.RedirectURIs[0], ClientID: clientID, ClientSecret: secret,
	})
	if err != nil {
		f.t.Fatalf("exchange for %s/%s: %v", userID, clientID, err)
	}
	return resp, code
}

func (f *revocationFixture) accepted(accessToken string) bool {
	f.t.Helper()
	_, err := f.userinfo.GetUserInfo(f.ctx, accessToken)
	return err == nil
}

func (f *revocationFixture) active(token, clientID, secret string) bool {
	f.t.Helper()
	resp, err := f.tokens.HandleIntrospection(f.ctx, &IntrospectionRequest{Token: token, ClientID: clientID, ClientSecret: secret})
	if err != nil {
		f.t.Fatalf("introspect: %v", err)
	}
	return resp.Active
}

func (f *revocationFixture) revoke(token, clientID, secret string) {
	f.t.Helper()
	if err := f.tokens.HandleRevocation(f.ctx, &RevocationRequest{Token: token, ClientID: clientID, ClientSecret: secret}); err != nil {
		f.t.Fatalf("revoke: %v", err)
	}
}

func TestRevokeAccessToken(t *testing.T) {
	f := newRevocationFixture(t)
	a, _ := f.issue("alice", "app-a", "secret-a")
	other, _ := f.issue("alice", "app-a", "secret-a")

	if !f.accepted(a.AccessToken) || !f.active(a.AccessToken, "app-a", "secret-a") {
		t.Fatal("fresh access token should be accepted")
	}

	// Another client cannot revoke it (RFC 7009 §2.1): still a 200, no effect.
	f.revoke(a.AccessToken, "app-b", "secret-b")
	if !f.accepted(a.AccessToken) {
		t.Error("a foreign client's revocation request must not take effect")
	}

	f.revoke(a.AccessToken, "app-a", "secret-a")
	if f.accepted(a.AccessToken) {
		t.Error("userinfo must refuse a revoked access token")
	}
	if f.active(a.AccessToken, "app-a", "secret-a") {
		t.Error("introspection must report a revoked access token inactive")
	}
	if !f.accepted(other.AccessToken) {
		t.Error("revoking one access token leaves the user's other tokens alone")
	}
}

func TestRevokeRefreshTokenRevokesGrant(t *testing.T) {
	f := newRevocationFixture(t)
	a, _ := f.issue("alice", "app-a", "secret-a")
	b, _ := f.issue("alice", "app-b", "secret-b")
	bob, _ := f.issue("bob", "app-a", "secret-a")

	// A foreign client cannot revoke the refresh token either.
	f.revoke(a.RefreshToken, "app-b", "secret-b")
	if !f.active(a.RefreshToken, "app-a", "secret-a") || !f.accepted(a.AccessToken) {
		t.Fatal("app-b must not be able to revoke app-a's tokens")
	}

	f.revoke(a.RefreshToken, "app-a", "secret-a")
	if f.active(a.RefreshToken, "app-a", "secret-a") {
		t.Error("refresh token should be revoked")
	}
	if f.accepted(a.AccessToken) {
		t.Error("the access token of the same grant should be revoked with it (RFC 7009 §2.1)")
	}
	if !f.accepted(b.AccessToken) || !f.accepted(bob.AccessToken) {
		t.Error("other clients and users are untouched")
	}
}

func TestCodeReuseRevokesAccessToken(t *testing.T) {
	f := newRevocationFixture(t)
	first, code := f.issue("alice", "app-a", "secret-a")
	client, _ := f.store.Clients().GetByID(f.ctx, "app-a")

	if _, err := f.tokens.HandleAuthorizationCode(f.ctx, &TokenRequest{
		GrantType: "authorization_code", Code: code, RedirectURI: client.RedirectURIs[0], ClientID: "app-a", ClientSecret: "secret-a",
	}); err == nil {
		t.Fatal("replayed code must be refused")
	}
	if f.accepted(first.AccessToken) {
		t.Error("access token issued from the replayed code should be revoked (RFC 6749 §4.1.2)")
	}
	if f.active(first.RefreshToken, "app-a", "secret-a") {
		t.Error("refresh token from the replayed code should be revoked")
	}
}

func TestRefreshReuseRevokesAccessToken(t *testing.T) {
	f := newRevocationFixture(t)
	first, _ := f.issue("alice", "app-a", "secret-a")
	second, err := f.tokens.HandleRefreshToken(f.ctx, &TokenRequest{GrantType: "refresh_token", RefreshToken: first.RefreshToken, ClientID: "app-a", ClientSecret: "secret-a"})
	if err != nil {
		t.Fatal(err)
	}
	if !f.accepted(second.AccessToken) {
		t.Fatal("token from the rotation should work")
	}
	// Replay the rotated-out refresh token: the whole grant is cut off.
	if _, err := f.tokens.HandleRefreshToken(f.ctx, &TokenRequest{GrantType: "refresh_token", RefreshToken: first.RefreshToken, ClientID: "app-a", ClientSecret: "secret-a"}); err == nil {
		t.Fatal("reused refresh token must be refused")
	}
	if f.accepted(first.AccessToken) || f.accepted(second.AccessToken) {
		t.Error("every access token of the grant should be revoked after refresh-token reuse")
	}
}

func TestBulkRevocationCoversAccessTokens(t *testing.T) {
	f := newRevocationFixture(t)
	a, _ := f.issue("alice", "app-a", "secret-a")
	b, _ := f.issue("alice", "app-b", "secret-b")
	bob, _ := f.issue("bob", "app-a", "secret-a")

	// What /account "sign out everywhere", a password change and the admin
	// UI do: revoke the user's refresh tokens.
	if err := f.store.Tokens().RevokeByUserID(f.ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if f.accepted(a.AccessToken) || f.accepted(b.AccessToken) {
		t.Error("all of alice's access tokens should be revoked")
	}
	if !f.accepted(bob.AccessToken) {
		t.Error("bob is untouched")
	}
	// Tokens issued afterwards are fine.
	time.Sleep(5 * time.Millisecond) // the jti carries the issue time to the millisecond
	again, _ := f.issue("alice", "app-a", "secret-a")
	if !f.accepted(again.AccessToken) {
		t.Error("a token issued after the revocation is valid")
	}

	// Admin "revoke client tokens" / delete client.
	if err := f.store.Tokens().RevokeByClientID(f.ctx, "app-a"); err != nil {
		t.Fatal(err)
	}
	if f.accepted(again.AccessToken) || f.accepted(bob.AccessToken) {
		t.Error("every user's access tokens for app-a should be revoked")
	}
}

// TestIDTokenClaimsByScope: the ID token carries the scope claims only for
// the scopes granted, includes given_name/family_name for profile, and a
// MinimalIDToken client gets none of them (they stay at UserInfo).
func TestIDTokenClaimsByScope(t *testing.T) {
	f := newRevocationFixture(t)
	alice, _ := f.store.Users().GetByID(f.ctx, "alice")
	alice.DisplayName, alice.GivenName, alice.FamilyName = "Alice Example", "Alice", "Example"
	if err := f.store.Users().Update(f.ctx, alice); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"app-a", "app-b"} {
		c, _ := f.store.Clients().GetByID(f.ctx, id)
		c.Scopes = []string{"openid", "profile", "email", "offline_access"}
		c.MinimalIDToken = id == "app-b"
		if err := f.store.Clients().Update(f.ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	claimsFor := func(t *testing.T, clientID, secret, scope string) (map[string]any, *UserInfoResponse) {
		t.Helper()
		code := "code-" + clientID + "-" + scope
		client, _ := f.store.Clients().GetByID(f.ctx, clientID)
		if err := f.store.AuthCodes().Create(f.ctx, &domain.AuthCode{Code: code, ClientID: clientID, UserID: "alice", RedirectURI: client.RedirectURIs[0], Scope: scope, ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
		resp, err := f.tokens.HandleAuthorizationCode(f.ctx, &TokenRequest{GrantType: "authorization_code", Code: code, RedirectURI: client.RedirectURIs[0], ClientID: clientID, ClientSecret: secret})
		if err != nil {
			t.Fatal(err)
		}
		_, claims, err := f.tokens.tokenGenerator.ParseToken(resp.IDToken)
		if err != nil {
			t.Fatal(err)
		}
		ui, err := f.userinfo.GetUserInfo(f.ctx, resp.AccessToken)
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]any{"email": claims.Email, "name": claims.Name}
		for k, v := range claims.Extra {
			m[k] = v
		}
		return m, ui
	}

	t.Run("openid only", func(t *testing.T) {
		id, ui := claimsFor(t, "app-a", "secret-a", "openid")
		if id["email"] != "" || id["name"] != "" || id["given_name"] != nil {
			t.Errorf("ID token for scope openid must not carry profile/email claims: %v", id)
		}
		if ui.Email != "" || ui.Name != "" {
			t.Errorf("userinfo for scope openid must not carry profile/email claims: %+v", ui)
		}
	})
	t.Run("profile and email", func(t *testing.T) {
		id, ui := claimsFor(t, "app-a", "secret-a", "openid profile email")
		if id["email"] != "alice@example.com" || id["name"] != "Alice Example" || id["given_name"] != "Alice" || id["family_name"] != "Example" {
			t.Errorf("ID token should carry email, name, given_name, family_name: %v", id)
		}
		if ui.Email != "alice@example.com" || ui.GivenName != "Alice" || ui.FamilyName != "Example" {
			t.Errorf("userinfo should carry the same: %+v", ui)
		}
	})
	t.Run("minimal ID token client", func(t *testing.T) {
		id, ui := claimsFor(t, "app-b", "secret-b", "openid profile email")
		if id["email"] != "" || id["name"] != "" || id["given_name"] != nil {
			t.Errorf("minimal ID token must not carry profile/email claims: %v", id)
		}
		if ui.Email != "alice@example.com" || ui.Name != "Alice Example" {
			t.Errorf("userinfo still carries them for a minimal-ID-token client: %+v", ui)
		}
	})
}
