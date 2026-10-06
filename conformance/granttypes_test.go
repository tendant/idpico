//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// A client may use only the grant types it is registered for (RFC 6749 §2,
// §4.1.2.1, §5.2 unauthorized_client). The clients are provisioned with
// idpicoctl on the throwaway server, so this needs no external setup and is
// skipped against CONFORMANCE_ISSUER.
func TestGrantTypes(t *testing.T) {
	if defInst == nil {
		t.Skip("needs the throwaway server to provision clients (CONFORMANCE_ISSUER is set)")
	}
	addClient := func(id, grantTypes string) string {
		out := defInst.idpicoctl(t, "client", "add", id, "-redirect", cfg.RedirectURI,
			"-scopes", "openid offline_access", "-grant-types", grantTypes)
		for _, line := range strings.Split(out, "\n") {
			if s, ok := strings.CutPrefix(line, "client_secret: "); ok {
				return strings.TrimSpace(s)
			}
		}
		t.Fatalf("no client_secret in idpicoctl output")
		return ""
	}
	codeOnly, codeOnlySecret := "conformance-code-only", addClient("conformance-code-only", "authorization_code")
	refreshOnly := "conformance-refresh-only"
	addClient(refreshOnly, "refresh_token")

	t.Run("code_only_client_gets_no_refresh_token", func(t *testing.T) {
		code, _ := obtainCode(t, authzParams(codeOnly, cfg.RedirectURI, "openid offline_access", "st", "", ""), cfg.RedirectURI)
		tr := exchange(t, code, "", codeOnly, codeOnlySecret, cfg.RedirectURI)
		if tr.Status != http.StatusOK {
			t.Fatalf("token: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
		}
		if tr.str("refresh_token") != "" {
			t.Error("issued a refresh token to a client without the refresh_token grant")
		}
	})

	t.Run("code_only_client_cannot_refresh", func(t *testing.T) {
		tr := tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"anything"}}, &[2]string{codeOnly, codeOnlySecret})
		expectTokenError(t, tr, http.StatusBadRequest, "unauthorized_client")
	})

	t.Run("client_without_code_grant_is_refused_at_authorize", func(t *testing.T) {
		resp, body := authorize(t, newHTTPClient(t), authzParams(refreshOnly, cfg.RedirectURI, "openid", "st", "", ""))
		q := callback(t, resp, body, cfg.RedirectURI)
		if q.Get("error") != "unauthorized_client" {
			t.Errorf("error = %q, want unauthorized_client (RFC 6749 §4.1.2.1)", q.Get("error"))
		}
		if q.Get("state") != "st" {
			t.Errorf("state = %q, want st", q.Get("state"))
		}
	})
}
