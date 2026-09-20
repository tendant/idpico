//go:build conformance

package conformance

import (
	"net/url"
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
