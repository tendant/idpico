//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Token introspection (RFC 7662) at introspection_endpoint.

func introspect(t *testing.T, token, hint string, basic *[2]string) (int, map[string]any) {
	t.Helper()
	ep, _ := discovery(t).raw["introspection_endpoint"].(string)
	if ep == "" {
		t.Fatal("no introspection_endpoint advertised")
	}
	form := url.Values{"token": {token}}
	if hint != "" {
		form.Set("token_type_hint", hint)
	}
	req, _ := http.NewRequest(http.MethodPost, ep, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic != nil {
		req.SetBasicAuth(basic[0], basic[1])
	}
	resp, body := send(t, def.client, req)
	var out map[string]any
	if resp.StatusCode == http.StatusOK {
		if err := jsonUnmarshal(body, &out); err != nil {
			t.Fatalf("introspection: non-JSON body: %s", redact(snippet(body)))
		}
	}
	return resp.StatusCode, out
}

func TestIntrospection(t *testing.T) {
	auth := &[2]string{cfg.ClientID, cfg.ClientSecret}
	code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid offline_access", "st", "", ""), cfg.RedirectURI)
	tr := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
	if tr.Status != http.StatusOK || tr.str("refresh_token") == "" {
		t.Fatalf("token: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
	}
	access, refreshToken, idToken := tr.str("access_token"), tr.str("refresh_token"), tr.str("id_token")
	sub, _ := claimsOf(t, idToken)["sub"].(string)

	active := func(t *testing.T, token, hint string) map[string]any {
		t.Helper()
		status, body := introspect(t, token, hint, auth)
		if status != http.StatusOK {
			t.Fatalf("HTTP %d, want 200", status)
		}
		if body["active"] != true {
			t.Fatalf("active = %v, want true", body["active"])
		}
		return body
	}
	inactive := func(t *testing.T, token string) {
		t.Helper()
		status, body := introspect(t, token, "", auth)
		if status != http.StatusOK {
			t.Fatalf("HTTP %d, want 200 (§2.2: an inactive token is not an error)", status)
		}
		if body["active"] != false {
			t.Fatalf("active = %v, want false", body["active"])
		}
		if len(body) != 1 {
			t.Errorf("inactive response carries more than active: %v (§2.2 SHOULD NOT)", body)
		}
	}

	t.Run("access_token", func(t *testing.T) {
		for _, hint := range []string{"", "access_token"} {
			body := active(t, access, hint)
			if body["sub"] != sub {
				t.Errorf("sub = %v, want %q", body["sub"], sub)
			}
			if body["client_id"] != cfg.ClientID {
				t.Errorf("client_id = %v, want %q", body["client_id"], cfg.ClientID)
			}
			if sc, _ := body["scope"].(string); !contains(strings.Fields(sc), "openid") {
				t.Errorf("scope = %v, want it to include openid", body["scope"])
			}
			if exp, ok := body["exp"].(float64); !ok || time.Unix(int64(exp), 0).Before(time.Now()) {
				t.Errorf("exp = %v, want a time in the future", body["exp"])
			}
		}
	})

	t.Run("refresh_token", func(t *testing.T) {
		body := active(t, refreshToken, "refresh_token")
		if body["client_id"] != cfg.ClientID {
			t.Errorf("client_id = %v, want %q", body["client_id"], cfg.ClientID)
		}
	})

	// A wrong token_type_hint must not make an active token look inactive
	// (§2.1: the server extends its search to all supported types).
	t.Run("wrong_hint_still_found", func(t *testing.T) {
		active(t, access, "refresh_token")
	})

	t.Run("id_token_is_not_active", func(t *testing.T) { inactive(t, idToken) })
	t.Run("unknown_token", func(t *testing.T) { inactive(t, "not-a-token") })
	t.Run("altered_access_token", func(t *testing.T) { inactive(t, flipSignature(access)) })

	t.Run("requires_client_authentication", func(t *testing.T) {
		// §2.1: the endpoint MUST require authorization.
		if status, _ := introspect(t, access, "", nil); status != http.StatusUnauthorized {
			t.Errorf("no credentials: HTTP %d, want 401", status)
		}
		if status, _ := introspect(t, access, "", &[2]string{cfg.ClientID, "wrong"}); status != http.StatusUnauthorized {
			t.Errorf("wrong secret: HTTP %d, want 401", status)
		}
		// A public client's ID is no credential.
		if status, _ := introspect(t, access, "", &[2]string{cfg.PublicClientID, ""}); status != http.StatusUnauthorized {
			t.Errorf("public client: HTTP %d, want 401", status)
		}
	})

	t.Run("rotated_refresh_token_is_inactive", func(t *testing.T) {
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid offline_access", "st", "", ""), cfg.RedirectURI)
		tr := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
		old := tr.str("refresh_token")
		next := tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {old}}, auth)
		if next.Status != http.StatusOK {
			t.Fatalf("refresh: HTTP %d: %s", next.Status, redact(string(next.Raw)))
		}
		inactive(t, old)
		active(t, next.str("refresh_token"), "")
	})

	t.Run("revoked_access_token_is_inactive", func(t *testing.T) {
		ep, _ := discovery(t).raw["revocation_endpoint"].(string)
		if ep == "" {
			t.Skip("no revocation_endpoint advertised")
		}
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "st", "", ""), cfg.RedirectURI)
		tok := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI).str("access_token")
		active(t, tok, "")
		req, _ := http.NewRequest(http.MethodPost, ep, strings.NewReader(url.Values{"token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
		if resp, body := send(t, def.client, req); resp.StatusCode != http.StatusOK {
			t.Fatalf("revoke: HTTP %d: %s", resp.StatusCode, redact(snippet(body)))
		}
		afterRevocation()
		inactive(t, tok)
	})

	// RFC 7009 §2.1: the caller identifies itself; anonymous revocation is
	// refused and the token stays active.
	t.Run("anonymous_revocation_refused", func(t *testing.T) {
		ep, _ := discovery(t).raw["revocation_endpoint"].(string)
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "st", "", ""), cfg.RedirectURI)
		tok := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI).str("access_token")
		req, _ := http.NewRequest(http.MethodPost, ep, strings.NewReader(url.Values{"token": {tok}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if resp, _ := send(t, def.client, req); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("anonymous revoke: HTTP %d, want 401", resp.StatusCode)
		}
		active(t, tok, "")
	})
}
