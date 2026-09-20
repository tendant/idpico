//go:build conformance

package conformance

import (
	"testing"
)

// TestAuthorizationCode is the primary positive path (OIDC Core §3.1):
// authorization request, login, callback, code exchange, and independent
// ID token validation, for a confidential and a public client.
func TestAuthorizationCode(t *testing.T) {
	d := discovery(t)

	for _, tc := range []struct {
		name     string
		clientID string
		secret   string
	}{
		{"confidential_client", cfg.ClientID, cfg.ClientSecret},
		{"public_client_pkce", cfg.PublicClientID, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := randomString(t, 16)
			nonce := randomString(t, 16)
			verifier, challenge := pkce(t)

			params := authzParams(tc.clientID, cfg.RedirectURI, "openid profile email", state, nonce, challenge)
			resp, body := authorize(t, newHTTPClient(t), params)
			q := callback(t, resp, body, cfg.RedirectURI)

			t.Run("callback", func(t *testing.T) {
				if q.Get("error") != "" {
					t.Fatalf("error=%s: %s", q.Get("error"), q.Get("error_description"))
				}
				if q.Get("code") == "" {
					t.Fatal("no authorization code in callback")
				}
				if q.Get("state") != state {
					t.Errorf("state = %q, want %q", q.Get("state"), state)
				}
			})

			tr := exchange(t, q.Get("code"), verifier, tc.clientID, tc.secret, cfg.RedirectURI)
			t.Run("token_response", func(t *testing.T) {
				if tr.Status != 200 {
					t.Fatalf("HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
				}
				for _, k := range []string{"access_token", "id_token", "token_type", "expires_in"} {
					if _, ok := tr.Body[k]; !ok {
						t.Errorf("token response lacks %s", k)
					}
				}
				if tt := tr.str("token_type"); tt != "Bearer" && tt != "bearer" {
					t.Errorf("token_type = %q, want Bearer", tt)
				}
				if v, ok := tr.Body["expires_in"].(float64); !ok || v <= 0 {
					t.Errorf("expires_in = %v, want a positive number", tr.Body["expires_in"])
				}
				if cc := tr.Header.Get("Cache-Control"); cc != "no-store" {
					t.Errorf("Cache-Control = %q, want no-store (RFC 6749 §5.1)", cc)
				}
			})

			var claims map[string]any
			t.Run("id_token", func(t *testing.T) {
				claims = mustVerifyIDToken(t, tr.str("id_token"), idTokenExpectation{
					Issuer: d.Issuer, ClientID: tc.clientID, Nonce: nonce,
				})
				if claims["nonce"] != nonce {
					t.Errorf("nonce = %v, want %q", claims["nonce"], nonce)
				}
				if _, ok := claims["auth_time"]; !ok {
					t.Log("note: id_token has no auth_time (optional unless max_age was requested)")
				}
			})

			t.Run("code_single_use", func(t *testing.T) {
				again := exchange(t, q.Get("code"), verifier, tc.clientID, tc.secret, cfg.RedirectURI)
				expectTokenError(t, again, 400, "invalid_grant")
			})

			t.Run("userinfo_matches", func(t *testing.T) {
				resp, body := userinfo(t, "Bearer "+tr.str("access_token"))
				if resp.StatusCode != 200 {
					t.Fatalf("userinfo: HTTP %d", resp.StatusCode)
				}
				var ui map[string]any
				if err := jsonUnmarshal(body, &ui); err != nil {
					t.Fatalf("userinfo: %v", err)
				}
				if ui["sub"] != claims["sub"] {
					t.Errorf("userinfo sub %v != id_token sub %v", ui["sub"], claims["sub"])
				}
			})
		})
	}

	t.Run("client_secret_post", func(t *testing.T) {
		state := randomString(t, 16)
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", state, "", ""), cfg.RedirectURI)
		tr := tokenRequest(t, formValues(map[string]string{
			"grant_type":    "authorization_code",
			"code":          code,
			"redirect_uri":  cfg.RedirectURI,
			"client_id":     cfg.ClientID,
			"client_secret": cfg.ClientSecret,
		}), nil)
		if tr.Status != 200 {
			t.Fatalf("client_secret_post: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
		}
		mustVerifyIDToken(t, tr.str("id_token"), idTokenExpectation{Issuer: d.Issuer, ClientID: cfg.ClientID})
	})
}
