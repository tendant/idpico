package oidc

import (
	"context"
	"testing"
	"time"

	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/domain"
)

// RP-Initiated Logout 1.0 §2/§3: post_logout_redirect_uri is honoured only
// for the client named by id_token_hint or client_id, exactly as registered.
func TestPostLogoutRedirect(t *testing.T) {
	svc, clientRepo, _, _, _ := setupTokenService()
	ctx := context.Background()
	clientRepo.Create(ctx, &domain.Client{ID: "app", RedirectURIs: []string{"https://app.example.com/cb", "https://app.example.com/bye?x=1"}})
	clientRepo.Create(ctx, &domain.Client{ID: "other", RedirectURIs: []string{"https://other.example.com/cb"}})

	hint := func(clientID string, ttl time.Duration) string {
		raw, _, err := svc.tokenGenerator.GenerateIDTokenFor("user-1", clientID, ttl, &crypto.Claims{})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	otherIssuer, _ := crypto.GenerateKeyPair(2048)
	foreign, _, _ := crypto.NewTokenGenerator(otherIssuer, "https://evil.example.com", "https://evil.example.com").GenerateIDTokenFor("user-1", "app", time.Minute, &crypto.Claims{})

	for _, tc := range []struct {
		name              string
		hint, client, uri string
		state, want       string
	}{
		{"hint names the client", hint("app", time.Minute), "", "https://app.example.com/cb", "s1", "https://app.example.com/cb?state=s1"},
		{"expired hint is still accepted", hint("app", -time.Hour), "", "https://app.example.com/cb", "", "https://app.example.com/cb"},
		{"client_id alone", "", "app", "https://app.example.com/cb", "", "https://app.example.com/cb"},
		{"state joins an existing query", "", "app", "https://app.example.com/bye?x=1", "s2", "https://app.example.com/bye?state=s2&x=1"},
		{"hint and client_id agree", hint("app", time.Minute), "app", "https://app.example.com/cb", "", "https://app.example.com/cb"},
		{"hint and client_id disagree", hint("app", time.Minute), "other", "https://other.example.com/cb", "", ""},
		{"uri registered for another client", hint("app", time.Minute), "", "https://other.example.com/cb", "", ""},
		{"uri not registered", "", "app", "https://app.example.com/cb/extra", "", ""},
		{"neither hint nor client_id", "", "", "https://app.example.com/cb", "", ""},
		{"unknown client", "", "nobody", "https://app.example.com/cb", "", ""},
		{"hint from another issuer", foreign, "", "https://app.example.com/cb", "", ""},
		{"garbage hint", "not-a-jwt", "", "https://app.example.com/cb", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.PostLogoutRedirect(ctx, tc.hint, tc.client, tc.uri, tc.state)
			if tc.want == "" {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
