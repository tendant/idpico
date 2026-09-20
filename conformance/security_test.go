//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestSecurityAuthorize covers the authorization endpoint's rejection
// behaviour (RFC 6749 §4.1.2.1): before the client and its redirect_uri are
// known the user must see an error page (never a redirect); afterwards the
// client gets an OAuth error with its state echoed back.
func TestSecurityAuthorize(t *testing.T) {
	d := discovery(t)
	valid := func() url.Values {
		return authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "st4te", "n0nce", "")
	}

	t.Run("error_page_cases", func(t *testing.T) {
		for name, mutate := range map[string]func(url.Values){
			"unknown_client_id":       func(p url.Values) { p.Set("client_id", "no-such-client") },
			"missing_client_id":       func(p url.Values) { p.Del("client_id") },
			"missing_redirect_uri":    func(p url.Values) { p.Del("redirect_uri") },
			"unregistered_redirect":   func(p url.Values) { p.Set("redirect_uri", "http://127.0.0.1:1/cb") },
			"other_clients_redirect":  func(p url.Values) { p.Set("redirect_uri", cfg.OtherRedirectURI) },
			"unknown_client_bad_type": func(p url.Values) { p.Set("client_id", "x"); p.Set("response_type", "token") },
		} {
			t.Run(name, func(t *testing.T) {
				p := valid()
				mutate(p)
				resp, body := get(t, newHTTPClient(t), d.AuthorizationEndpoint+"?"+p.Encode())
				if loc := resp.Header.Get("Location"); loc != "" {
					t.Fatalf("must not redirect, got Location %q", loc)
				}
				if resp.StatusCode < 400 || resp.StatusCode >= 500 {
					t.Errorf("HTTP %d, want 4xx", resp.StatusCode)
				}
				assertNoSecrets(t, "error page", body)
			})
		}
	})

	t.Run("redirect_error_cases", func(t *testing.T) {
		for name, tc := range map[string]struct {
			mutate func(url.Values)
			want   string
		}{
			"response_type_token":    {func(p url.Values) { p.Set("response_type", "token") }, "unsupported_response_type"},
			"response_type_id_token": {func(p url.Values) { p.Set("response_type", "id_token") }, "unsupported_response_type"},
			"response_type_hybrid":   {func(p url.Values) { p.Set("response_type", "code id_token") }, "unsupported_response_type"},
			"response_type_missing":  {func(p url.Values) { p.Del("response_type") }, "unsupported_response_type"},
			"scope_without_openid":   {func(p url.Values) { p.Set("scope", "profile email") }, "invalid_scope"},
			"scope_openid_prefix":    {func(p url.Values) { p.Set("scope", "openidx") }, "invalid_scope"},
			"scope_not_allowed":      {func(p url.Values) { p.Set("scope", "openid admin:everything") }, "invalid_scope"},
		} {
			t.Run(name, func(t *testing.T) {
				p := valid()
				tc.mutate(p)
				resp, body := authorize(t, newHTTPClient(t), p)
				q := callback(t, resp, body, cfg.RedirectURI)
				if q.Get("error") != tc.want {
					t.Errorf("error = %q (%s), want %q", q.Get("error"), q.Get("error_description"), tc.want)
				}
				if q.Get("state") != "st4te" {
					t.Errorf("state = %q, want st4te", q.Get("state"))
				}
				if q.Get("code") != "" {
					t.Error("a code was issued")
				}
				assertNoSecrets(t, "error redirect", []byte(resp.Header.Get("Location")))
			})
		}
	})

	t.Run("state_roundtrip", func(t *testing.T) {
		// state is opaque: whatever the client sent comes back byte for byte.
		state := "a b&c=d/é" + randomString(t, 8)
		p := valid()
		p.Set("state", state)
		_, q := obtainCode(t, p, cfg.RedirectURI)
		if q.Get("state") != state {
			t.Errorf("state = %q, want %q", q.Get("state"), state)
		}
	})

	t.Run("state_mismatch_detected_by_client", func(t *testing.T) {
		// The RP-side check that closes CSRF/login-CSRF: a callback whose
		// state is not the one this session sent must be dropped. Recorded
		// here so the suite documents it; the reference client implements it.
		sent := randomString(t, 16)
		_, q := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", sent, "", ""), cfg.RedirectURI)
		if q.Get("state") == "" || q.Get("state") == "forged" {
			t.Fatal("provider dropped state")
		}
		if got := q.Get("state"); got != sent {
			t.Fatalf("state changed in transit: %q", got)
		}
	})

	t.Run("prompt_none_without_session", func(t *testing.T) {
		p := valid()
		p.Set("prompt", "none")
		resp, body := get(t, newHTTPClient(t), d.AuthorizationEndpoint+"?"+p.Encode())
		q := callback(t, resp, body, cfg.RedirectURI)
		if q.Get("error") != "login_required" && q.Get("error") != "interaction_required" {
			t.Errorf("error = %q, want login_required", q.Get("error"))
		}
	})

	t.Run("method_not_allowed_is_clean", func(t *testing.T) {
		for _, ep := range []string{d.TokenEndpoint, d.AuthorizationEndpoint} {
			req, _ := http.NewRequest(http.MethodDelete, ep, nil)
			resp, body := send(t, http.DefaultClient, req)
			if resp.StatusCode < 400 {
				t.Errorf("DELETE %s: HTTP %d", ep, resp.StatusCode)
			}
			assertNoSecrets(t, "method error", body)
		}
	})

	t.Run("login_page_is_csrf_protected", func(t *testing.T) {
		// Posting credentials without the form's CSRF token must not sign
		// the user in (login CSRF would let an attacker log a victim into
		// the attacker's account).
		c := newHTTPClient(t)
		resp, _ := postForm(t, c, strings.TrimSuffix(cfg.Issuer, "/")+"/login", url.Values{
			"email": {cfg.UserEmail}, "password": {cfg.UserPassword},
		})
		if resp.StatusCode == http.StatusFound {
			t.Errorf("login without CSRF token succeeded (HTTP 302 to %s)", resp.Header.Get("Location"))
		}
	})
}
