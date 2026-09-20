//go:build conformance

package conformance

import (
	"net/url"
	"testing"
)

// TestPKCE covers RFC 7636 with the S256 method, which is mandatory for
// public clients: a code bound to a challenge is redeemable only with the
// matching verifier, exactly once.
func TestPKCE(t *testing.T) {
	newCode := func(t *testing.T, challenge string) string {
		t.Helper()
		code, _ := obtainCode(t, authzParams(cfg.PublicClientID, cfg.RedirectURI, "openid", randomString(t, 8), "", challenge), cfg.RedirectURI)
		return code
	}

	t.Run("S256", func(t *testing.T) {
		verifier, challenge := pkce(t)
		tr := exchange(t, newCode(t, challenge), verifier, cfg.PublicClientID, "", cfg.RedirectURI)
		if tr.Status != 200 {
			t.Fatalf("HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
		}
		mustVerifyIDToken(t, tr.str("id_token"), idTokenExpectation{Issuer: discovery(t).Issuer, ClientID: cfg.PublicClientID})
	})

	t.Run("wrong_verifier_rejected", func(t *testing.T) {
		_, challenge := pkce(t)
		other, _ := pkce(t)
		tr := exchange(t, newCode(t, challenge), other, cfg.PublicClientID, "", cfg.RedirectURI)
		expectTokenError(t, tr, 400, "invalid_grant")
	})

	t.Run("missing_verifier_rejected", func(t *testing.T) {
		_, challenge := pkce(t)
		tr := exchange(t, newCode(t, challenge), "", cfg.PublicClientID, "", cfg.RedirectURI)
		expectTokenError(t, tr, 400, "invalid_grant")
	})

	t.Run("replay_rejected", func(t *testing.T) {
		verifier, challenge := pkce(t)
		code := newCode(t, challenge)
		if tr := exchange(t, code, verifier, cfg.PublicClientID, "", cfg.RedirectURI); tr.Status != 200 {
			t.Fatalf("first exchange: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
		}
		tr := exchange(t, code, verifier, cfg.PublicClientID, "", cfg.RedirectURI)
		expectTokenError(t, tr, 400, "invalid_grant")
	})

	// A public client must not be able to opt out of PKCE or downgrade it.
	// The client and redirect_uri are valid, so the error goes back to the
	// client (RFC 7636 §4.4.1).
	for _, tc := range []struct {
		name   string
		mutate func(url.Values)
	}{
		{"no_challenge", func(p url.Values) { p.Del("code_challenge"); p.Del("code_challenge_method") }},
		{"plain_method", func(p url.Values) { p.Set("code_challenge_method", "plain") }},
		{"unknown_method", func(p url.Values) { p.Set("code_challenge_method", "S512") }},
	} {
		t.Run("downgrade_"+tc.name+"_rejected", func(t *testing.T) {
			_, challenge := pkce(t)
			state := randomString(t, 8)
			p := authzParams(cfg.PublicClientID, cfg.RedirectURI, "openid", state, "", challenge)
			tc.mutate(p)
			resp, body := authorize(t, newHTTPClient(t), p)
			q := callback(t, resp, body, cfg.RedirectURI)
			if q.Get("error") != "invalid_request" {
				t.Errorf("error = %q (%s), want invalid_request", q.Get("error"), q.Get("error_description"))
			}
			if q.Get("state") != state {
				t.Errorf("state = %q, want %q", q.Get("state"), state)
			}
			if q.Get("code") != "" {
				t.Error("a code was issued despite the PKCE downgrade")
			}
		})
	}

	t.Run("confidential_client_with_pkce", func(t *testing.T) {
		// PKCE is optional for confidential clients, but once a challenge is
		// sent the verifier is required.
		verifier, challenge := pkce(t)
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", randomString(t, 8), "", challenge), cfg.RedirectURI)
		expectTokenError(t, exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI), 400, "invalid_grant")
		code, _ = obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", randomString(t, 8), "", challenge), cfg.RedirectURI)
		if tr := exchange(t, code, verifier, cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI); tr.Status != 200 {
			t.Errorf("HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
		}
	})
}
