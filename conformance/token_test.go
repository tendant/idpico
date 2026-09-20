//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSecurityToken covers the token endpoint's rejection behaviour (RFC
// 6749 §4.1.3, §5.2): codes are bound to one client, one redirect_uri and
// one use, and every failure is a well-formed JSON error.
func TestSecurityToken(t *testing.T) {
	t.Parallel() // sleeps past the throwaway server's short TTLs
	newCode := func(t *testing.T) string {
		t.Helper()
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", randomString(t, 8), "", ""), cfg.RedirectURI)
		return code
	}

	t.Run("replay_rejected", func(t *testing.T) {
		code := newCode(t)
		if tr := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI); tr.Status != 200 {
			t.Fatalf("first exchange: HTTP %d", tr.Status)
		}
		expectTokenError(t, exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI), 400, "invalid_grant")
	})

	t.Run("replay_revokes_grant", func(t *testing.T) {
		// RFC 6749 §4.1.2: a reused code SHOULD revoke the tokens it issued.
		// The refresh token from the first exchange must stop working.
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid offline_access", randomString(t, 8), "", ""), cfg.RedirectURI)
		first := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
		if first.Status != 200 || first.str("refresh_token") == "" {
			t.Skipf("no refresh token issued for offline_access (HTTP %d)", first.Status)
		}
		expectTokenError(t, exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI), 400, "invalid_grant")
		refreshed := tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.str("refresh_token")}}, &[2]string{cfg.ClientID, cfg.ClientSecret})
		expectTokenError(t, refreshed, 400, "invalid_grant")
		// ...and so must the access token issued from the replayed code.
		resp, body := userinfo(t, "Bearer "+first.str("access_token"))
		expectUnauthorized(t, resp, body)
		afterRevocation()
	})

	t.Run("revocation_endpoint", func(t *testing.T) {
		// RFC 7009: a revoked access token is refused, revoking a refresh
		// token also revokes the access token of its grant, and a client
		// cannot revoke another client's tokens.
		d := discovery(t)
		revocationEndpoint, _ := d.raw["revocation_endpoint"].(string)
		if revocationEndpoint == "" {
			t.Skip("no revocation_endpoint advertised")
		}
		revoke := func(t *testing.T, token, clientID, secret string) {
			t.Helper()
			req, _ := http.NewRequest(http.MethodPost, revocationEndpoint, strings.NewReader(url.Values{"token": {token}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.SetBasicAuth(clientID, secret)
			resp, body := send(t, http.DefaultClient, req)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("revoke: HTTP %d: %s", resp.StatusCode, redact(snippet(body)))
			}
		}
		issue := func(t *testing.T) tokenResponse {
			t.Helper()
			code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid offline_access", randomString(t, 8), "", ""), cfg.RedirectURI)
			tr := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
			if tr.Status != 200 {
				t.Fatalf("token: HTTP %d", tr.Status)
			}
			return tr
		}

		afterRevocation()
		a := issue(t)
		revoke(t, a.str("access_token"), cfg.OtherClientID, cfg.OtherClientSecret) // foreign client: no effect
		if resp, _ := userinfo(t, "Bearer "+a.str("access_token")); resp.StatusCode != http.StatusOK {
			t.Errorf("another client's revocation request took effect: HTTP %d", resp.StatusCode)
		}
		revoke(t, a.str("access_token"), cfg.ClientID, cfg.ClientSecret)
		resp, body := userinfo(t, "Bearer "+a.str("access_token"))
		expectUnauthorized(t, resp, body)

		b := issue(t)
		revoke(t, b.str("refresh_token"), cfg.ClientID, cfg.ClientSecret)
		defer afterRevocation()
		resp, body = userinfo(t, "Bearer "+b.str("access_token"))
		expectUnauthorized(t, resp, body)
		expectTokenError(t, tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {b.str("refresh_token")}}, &[2]string{cfg.ClientID, cfg.ClientSecret}), 400, "invalid_grant")
	})

	t.Run("code_bound_to_client", func(t *testing.T) {
		// A code issued to one client cannot be redeemed by another, even
		// with that client's valid credentials.
		code := newCode(t)
		expectTokenError(t, exchange(t, code, "", cfg.OtherClientID, cfg.OtherClientSecret, cfg.RedirectURI), 400, "invalid_grant")
		// ...nor by a public client that needs no credentials at all.
		expectTokenError(t, exchange(t, code, "", cfg.PublicClientID, "", cfg.RedirectURI), 400, "invalid_grant")
	})

	t.Run("code_bound_to_redirect_uri", func(t *testing.T) {
		expectTokenError(t, exchange(t, newCode(t), "", cfg.ClientID, cfg.ClientSecret, cfg.OtherRedirectURI), 400, "invalid_grant")
	})

	t.Run("unknown_code_rejected", func(t *testing.T) {
		expectTokenError(t, exchange(t, randomString(t, 24), "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI), 400, "invalid_grant")
	})

	t.Run("expired_code_rejected", func(t *testing.T) {
		if cfg.External() {
			t.Skip("needs the throwaway server's short IDPICO_AUTH_CODE_TTL")
		}
		code := newCode(t)
		time.Sleep(shortTTL + time.Second)
		expectTokenError(t, exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI), 400, "invalid_grant")
	})

	t.Run("wrong_secret_rejected", func(t *testing.T) {
		tr := exchange(t, newCode(t), "", cfg.ClientID, "not-the-secret", cfg.RedirectURI)
		expectTokenError(t, tr, 401, "invalid_client")
	})

	t.Run("missing_secret_rejected", func(t *testing.T) {
		// A confidential client cannot pose as public.
		tr := exchange(t, newCode(t), "", cfg.ClientID, "", cfg.RedirectURI)
		expectTokenError(t, tr, 401, "invalid_client")
	})

	t.Run("unknown_client_rejected", func(t *testing.T) {
		tr := exchange(t, newCode(t), "", "no-such-client", "secret", cfg.RedirectURI)
		expectTokenError(t, tr, 401, "invalid_client")
	})

	t.Run("unsupported_grant_types", func(t *testing.T) {
		basic := &[2]string{cfg.ClientID, cfg.ClientSecret}
		for _, grant := range []string{"password", "client_credentials", "implicit", "urn:ietf:params:oauth:grant-type:device_code"} {
			tr := tokenRequest(t, url.Values{
				"grant_type": {grant},
				"username":   {cfg.UserEmail},
				"password":   {cfg.UserPassword},
				"scope":      {"openid"},
			}, basic)
			if tr.Status != 400 || tr.str("error") != "unsupported_grant_type" {
				t.Errorf("grant_type=%s: want 400 unsupported_grant_type, got %d %s", grant, tr.Status, redact(string(tr.Raw)))
			}
			if _, ok := tr.Body["access_token"]; ok {
				t.Errorf("grant_type=%s issued a token", grant)
			}
		}
		tr := tokenRequest(t, url.Values{"code": {"x"}}, basic)
		expectTokenError(t, tr, 400, "invalid_request")
	})

	t.Run("error_responses_are_clean", func(t *testing.T) {
		for _, tr := range []tokenResponse{
			exchange(t, "bogus", "", cfg.ClientID, "wrong", cfg.RedirectURI),
			exchange(t, "bogus", "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI),
			tokenRequest(t, url.Values{"grant_type": {"authorization_code"}}, nil),
		} {
			if tr.str("error") == "" {
				t.Errorf("error response without error field: %s", redact(string(tr.Raw)))
			}
			if cc := tr.Header.Get("Cache-Control"); cc != "no-store" {
				t.Errorf("error response Cache-Control = %q, want no-store", cc)
			}
			assertNoSecrets(t, "token error response", tr.Raw)
		}
	})
}
