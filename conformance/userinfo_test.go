//go:build conformance

package conformance

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestUserInfo covers OIDC Core §5.3: the UserInfo endpoint returns the
// claims for the scopes granted, keyed by the same sub as the ID token, and
// refuses anything but a valid bearer token (RFC 6750).
func TestUserInfo(t *testing.T) {
	d := discovery(t)
	tr, nonce, _ := issued(t)
	idClaims := mustVerifyIDToken(t, tr.str("id_token"), idTokenExpectation{Issuer: d.Issuer, ClientID: cfg.ClientID, Nonce: nonce})

	t.Run("claims", func(t *testing.T) {
		resp, body := userinfo(t, "Bearer "+tr.str("access_token"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HTTP %d: %s", resp.StatusCode, redact(snippet(body)))
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		var ui map[string]any
		if err := json.Unmarshal(body, &ui); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if ui["sub"] == "" || ui["sub"] != idClaims["sub"] {
			t.Errorf("sub = %v, want the ID token's %v", ui["sub"], idClaims["sub"])
		}
		if v, _ := ui["email"].(string); !strings.EqualFold(v, cfg.UserEmail) {
			t.Errorf("email = %v, want %q", ui["email"], cfg.UserEmail)
		}
		if _, ok := ui["name"]; !ok {
			t.Error("name missing (scope profile was granted)")
		}
		assertNoSecrets(t, "userinfo", body)
	})

	t.Run("post_supported", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, d.UserinfoEndpoint, nil)
		req.Header.Set("Authorization", "Bearer "+tr.str("access_token"))
		resp, _ := send(t, http.DefaultClient, req)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("POST userinfo: HTTP %d", resp.StatusCode)
		}
	})

	t.Run("scope_limits_claims", func(t *testing.T) {
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "s", "", ""), cfg.RedirectURI)
		tr := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
		resp, body := userinfo(t, "Bearer "+tr.str("access_token"))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HTTP %d", resp.StatusCode)
		}
		var ui map[string]any
		_ = json.Unmarshal(body, &ui)
		if _, ok := ui["email"]; ok {
			t.Error("email returned although only scope openid was granted")
		}
		if ui["sub"] != idClaims["sub"] {
			t.Errorf("sub = %v, want %v", ui["sub"], idClaims["sub"])
		}
	})

	for name, header := range map[string]string{
		"no_token":     "",
		"basic_auth":   "Basic " + "Y29uZm9ybWFuY2UtY2xpZW50OmNvbmZvcm1hbmNlLXNlY3JldA==",
		"bearer_empty": "Bearer ",
		"bearer_junk":  "Bearer not-a-token",
		"id_token":     "Bearer " + tr.str("id_token") + "x",
	} {
		t.Run("rejects_"+name, func(t *testing.T) {
			resp, body := userinfo(t, header)
			expectUnauthorized(t, resp, body)
		})
	}
}
