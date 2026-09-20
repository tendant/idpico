//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"testing"
)

// TestRefreshToken covers the refresh_token grant (RFC 6749 §6, OIDC Core
// §12): issued only for offline_access, rotated on every use, narrowable but
// not widenable, bound to the client, and — since a rotated-out token seen
// again means it leaked — reuse cuts off the whole grant, access tokens
// included.
func TestRefreshToken(t *testing.T) {
	d := discovery(t)
	if !contains(d.GrantTypesSupported, "refresh_token") {
		t.Skip("refresh_token grant not advertised")
	}
	basic := &[2]string{cfg.ClientID, cfg.ClientSecret}
	refresh := func(t *testing.T, token string, extra url.Values) tokenResponse {
		t.Helper()
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}
		for k, v := range extra {
			form[k] = v
		}
		return tokenRequest(t, form, basic)
	}
	issue := func(t *testing.T, scope string) tokenResponse {
		t.Helper()
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, scope, randomString(t, 8), "", ""), cfg.RedirectURI)
		tr := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
		if tr.Status != 200 {
			t.Fatalf("token: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
		}
		return tr
	}

	t.Run("only_with_offline_access", func(t *testing.T) {
		if tr := issue(t, "openid profile"); tr.str("refresh_token") != "" {
			t.Error("a refresh token was issued without the offline_access scope")
		}
		if tr := issue(t, "openid offline_access"); tr.str("refresh_token") == "" {
			t.Error("no refresh token for offline_access")
		}
	})

	t.Run("rotation", func(t *testing.T) {
		first := issue(t, "openid profile email offline_access")
		second := refresh(t, first.str("refresh_token"), nil)
		if second.Status != 200 {
			t.Fatalf("refresh: HTTP %d: %s", second.Status, redact(string(second.Raw)))
		}
		for _, k := range []string{"access_token", "refresh_token", "id_token", "expires_in"} {
			if second.str(k) == "" && second.Body[k] == nil {
				t.Errorf("refresh response lacks %s", k)
			}
		}
		if second.str("refresh_token") == first.str("refresh_token") {
			t.Error("refresh token was not rotated")
		}
		if second.str("access_token") == first.str("access_token") {
			t.Error("access token was not renewed")
		}
		mustVerifyIDToken(t, second.str("id_token"), idTokenExpectation{Issuer: d.Issuer, ClientID: cfg.ClientID})
		expectUserinfo(t, def, second.str("access_token"), true)
		// The access token from before the rotation is still good: rotation
		// is not revocation.
		expectUserinfo(t, def, first.str("access_token"), true)
		// The rotated-out refresh token is dead...
		expectTokenError(t, refresh(t, first.str("refresh_token"), nil), 400, "invalid_grant")
		afterRevocation()
	})

	t.Run("reuse_cuts_off_the_grant", func(t *testing.T) {
		first := issue(t, "openid offline_access")
		second := refresh(t, first.str("refresh_token"), nil)
		if second.Status != 200 {
			t.Fatalf("refresh: HTTP %d", second.Status)
		}
		// Replaying the rotated-out token: every token of the grant dies,
		// including the current refresh token and both access tokens.
		expectTokenError(t, refresh(t, first.str("refresh_token"), nil), 400, "invalid_grant")
		expectTokenError(t, refresh(t, second.str("refresh_token"), nil), 400, "invalid_grant")
		for _, at := range []string{first.str("access_token"), second.str("access_token")} {
			resp, body := userinfo(t, "Bearer "+at)
			expectUnauthorized(t, resp, body)
		}
		afterRevocation()
	})

	t.Run("scope_can_narrow_not_widen", func(t *testing.T) {
		first := issue(t, "openid profile email offline_access")
		narrowed := refresh(t, first.str("refresh_token"), url.Values{"scope": {"openid offline_access"}})
		if narrowed.Status != 200 {
			t.Fatalf("narrowed refresh: HTTP %d: %s", narrowed.Status, redact(string(narrowed.Raw)))
		}
		if got := narrowed.str("scope"); got != "openid offline_access" {
			t.Errorf("scope after narrowing = %q, want %q", got, "openid offline_access")
		}
		expectTokenError(t, refresh(t, narrowed.str("refresh_token"), url.Values{"scope": {"openid profile email offline_access groups"}}), 400, "invalid_scope")
	})

	t.Run("bound_to_client", func(t *testing.T) {
		first := issue(t, "openid offline_access")
		wrongSecret := tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.str("refresh_token")}}, &[2]string{cfg.ClientID, "not-the-secret"})
		expectTokenError(t, wrongSecret, 401, "invalid_client")
		other := tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {first.str("refresh_token")}}, &[2]string{cfg.OtherClientID, cfg.OtherClientSecret})
		expectTokenError(t, other, 400, "invalid_grant")
		// Neither attempt consumed the token.
		if tr := refresh(t, first.str("refresh_token"), nil); tr.Status != 200 {
			t.Errorf("legitimate refresh after failed attempts: HTTP %d", tr.Status)
		}
	})

	t.Run("garbage_rejected", func(t *testing.T) {
		expectTokenError(t, refresh(t, randomString(t, 24), nil), 400, "invalid_grant")
		expectTokenError(t, tokenRequest(t, url.Values{"grant_type": {"refresh_token"}}, basic), 400, "invalid_request")
	})

	t.Run("error_responses_are_clean", func(t *testing.T) {
		tr := refresh(t, "nope", nil)
		if tr.Header.Get("Cache-Control") != "no-store" || tr.Header.Get("Content-Type") == "" {
			t.Errorf("error response headers: %v", tr.Header)
		}
		assertNoSecrets(t, "refresh error", tr.Raw)
		if resp, _ := userinfo(t, "Bearer x"); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("userinfo with junk: HTTP %d", resp.StatusCode)
		}
	})
}
