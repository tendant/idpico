//go:build conformance

package conformance

import (
	"net/http"
	"strings"
	"testing"
)

// TestSecurityRedirectURI checks exact redirect_uri matching (OIDC Core
// §3.1.2.1, RFC 6749 §3.1.2.3). An unregistered URI must produce an error
// page and never a redirect, since redirecting would send the code (or the
// error) to the attacker's URL.
func TestSecurityRedirectURI(t *testing.T) {
	registered := cfg.StrictRedirectURI // https://app.example.com/callback
	if !strings.HasPrefix(registered, "https://") {
		t.Skipf("CONFORMANCE_STRICT_REDIRECT_URI %q is not https, table does not apply", registered)
	}
	base := strings.TrimSuffix(registered, "/callback")
	host := strings.TrimPrefix(base, "https://")

	t.Run("exact_match_accepted", func(t *testing.T) {
		p := authzParams(cfg.StrictClientID, registered, "openid", "s", "", "")
		resp, body := get(t, newHTTPClient(t), discovery(t).AuthorizationEndpoint+"?"+p.Encode())
		// Not logged in: the provider sends the user to its login page. Any
		// other answer means the registered URI was not accepted.
		if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/login") {
			t.Fatalf("registered redirect_uri refused: HTTP %d %s: %s", resp.StatusCode, resp.Header.Get("Location"), redact(snippet(body)))
		}
	})

	for name, uri := range map[string]string{
		"trailing_slash":   registered + "/",
		"subpath":          registered + "/foo",
		"suffix_domain":    "https://" + host + ".evil.com/callback",
		"other_host":       "https://evil.com/callback",
		"scheme_downgrade": "http://" + host + "/callback",
		"added_query":      registered + "?x=1",
		"userinfo_in_url":  "https://" + host + "@evil.com/callback",
		"different_port":   "https://" + host + ":8443/callback",
		"case_changed":     "https://" + strings.ToUpper(host) + "/callback",
		"parent_path":      base + "/",
	} {
		t.Run(name+"_rejected", func(t *testing.T) {
			p := authzParams(cfg.StrictClientID, uri, "openid", "s", "", "")
			resp, body := get(t, newHTTPClient(t), discovery(t).AuthorizationEndpoint+"?"+p.Encode())
			if loc := resp.Header.Get("Location"); loc != "" {
				t.Fatalf("redirected to %q for unregistered redirect_uri %q", loc, uri)
			}
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Errorf("HTTP %d for unregistered redirect_uri, want 4xx", resp.StatusCode)
			}
			assertNoSecrets(t, "error page", body)
		})
	}

	t.Run("token_exchange_binds_redirect_uri", func(t *testing.T) {
		// RFC 6749 §4.1.3: redirect_uri at /token must equal the one used at
		// /authorize.
		code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "s", "", ""), cfg.RedirectURI)
		expectTokenError(t, exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI+"/"), 400, "invalid_grant")
	})
}
