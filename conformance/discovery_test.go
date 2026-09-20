//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestDiscovery covers OpenID Connect Discovery 1.0 §3-4: the metadata
// document downstream clients rely on to find everything else.
func TestDiscovery(t *testing.T) {
	d := discovery(t)

	t.Run("document", func(t *testing.T) {
		resp, body := get(t, http.DefaultClient, strings.TrimSuffix(cfg.Issuer, "/")+"/.well-known/openid-configuration")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("HTTP %d", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
		assertNoSecrets(t, "discovery document", body)
	})

	t.Run("issuer", func(t *testing.T) {
		if d.Issuer != strings.TrimSuffix(cfg.Issuer, "/") {
			t.Errorf("issuer = %q, want %q", d.Issuer, cfg.Issuer)
		}
		u, err := url.Parse(d.Issuer)
		if err != nil || u.Scheme == "" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
			t.Errorf("issuer %q must be an absolute URL without query or fragment", d.Issuer)
		}
	})

	t.Run("endpoints", func(t *testing.T) {
		for name, ep := range map[string]string{
			"authorization_endpoint": d.AuthorizationEndpoint,
			"token_endpoint":         d.TokenEndpoint,
			"jwks_uri":               d.JWKSURI,
			"userinfo_endpoint":      d.UserinfoEndpoint,
		} {
			if ep == "" {
				t.Errorf("%s missing", name)
				continue
			}
			if !strings.HasPrefix(ep, d.Issuer+"/") {
				t.Errorf("%s = %q is not under the issuer %q", name, ep, d.Issuer)
			}
			if _, err := url.ParseRequestURI(ep); err != nil {
				t.Errorf("%s = %q: %v", name, ep, err)
			}
		}
	})

	t.Run("capabilities", func(t *testing.T) {
		if !contains(d.ResponseTypesSupported, "code") {
			t.Errorf("response_types_supported %v lacks code", d.ResponseTypesSupported)
		}
		if len(d.SubjectTypesSupported) == 0 {
			t.Error("subject_types_supported missing")
		}
		if len(d.IDTokenSigningAlgValuesSupported) == 0 {
			t.Error("id_token_signing_alg_values_supported missing")
		}
		if contains(d.IDTokenSigningAlgValuesSupported, "none") {
			t.Error("id_token_signing_alg_values_supported must not offer none")
		}
		if !contains(d.ScopesSupported, "openid") {
			t.Errorf("scopes_supported %v lacks openid", d.ScopesSupported)
		}
		if !contains(d.CodeChallengeMethodsSupported, "S256") {
			t.Errorf("code_challenge_methods_supported %v lacks S256", d.CodeChallengeMethodsSupported)
		}
		if !contains(d.TokenEndpointAuthMethodsSupported, "none") {
			t.Errorf("token_endpoint_auth_methods_supported %v lacks none (public clients)", d.TokenEndpointAuthMethodsSupported)
		}
		// Unsupported optional features must be declared, since the
		// request_uri_parameter_supported default is true.
		for _, k := range []string{"request_parameter_supported", "request_uri_parameter_supported", "claims_parameter_supported"} {
			if v, ok := d.raw[k].(bool); !ok || v {
				t.Errorf("%s = %v, want false", k, d.raw[k])
			}
		}
		if !contains(d.GrantTypesSupported, "authorization_code") {
			t.Errorf("grant_types_supported %v lacks authorization_code", d.GrantTypesSupported)
		}
	})
}
