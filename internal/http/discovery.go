package http

import (
	"encoding/json"
	"net/http"
	"strings"
)

// OIDCDiscovery represents the OIDC discovery document.
type OIDCDiscovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	RevocationEndpointAuthMethods     []string `json:"revocation_endpoint_auth_methods_supported,omitempty"`
	IntrospectionEndpointAuthMethods  []string `json:"introspection_endpoint_auth_methods_supported,omitempty"`
}

// DiscoveryHandler handles OIDC discovery endpoints.
type DiscoveryHandler struct {
	issuerURL   string
	groupsClaim string // empty when groups are not supported
}

// NewDiscoveryHandler creates a new DiscoveryHandler. groupsClaim names the
// claim group memberships are released under, or "" if groups are disabled.
func NewDiscoveryHandler(issuerURL, groupsClaim string) *DiscoveryHandler {
	return &DiscoveryHandler{
		issuerURL:   strings.TrimSuffix(issuerURL, "/"),
		groupsClaim: groupsClaim,
	}
}

// OpenIDConfiguration handles the /.well-known/openid-configuration endpoint.
func (h *DiscoveryHandler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	scopes := []string{"openid", "profile", "email", "offline_access"}
	claims := []string{"iss", "sub", "aud", "exp", "iat", "email", "email_verified", "name"}
	if h.groupsClaim != "" {
		scopes = append(scopes, "groups")
		claims = append(claims, h.groupsClaim)
	}

	discovery := OIDCDiscovery{
		Issuer:                h.issuerURL,
		AuthorizationEndpoint: h.issuerURL + "/authorize",
		TokenEndpoint:         h.issuerURL + "/token",
		UserinfoEndpoint:      h.issuerURL + "/userinfo",
		JwksURI:               h.issuerURL + "/.well-known/jwks.json",
		EndSessionEndpoint:    h.issuerURL + "/logout",
		RevocationEndpoint:    h.issuerURL + "/revoke",
		IntrospectionEndpoint: h.issuerURL + "/introspect",

		ScopesSupported: scopes,

		ResponseTypesSupported: []string{
			"code",
		},

		ResponseModesSupported: []string{
			"query",
		},

		GrantTypesSupported: []string{
			"authorization_code",
			"refresh_token",
		},

		SubjectTypesSupported: []string{
			"public",
		},

		IDTokenSigningAlgValuesSupported: []string{
			"RS256",
		},

		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"none", // For public clients with PKCE
		},

		ClaimsSupported: claims,

		CodeChallengeMethodsSupported: []string{
			"S256",
		},

		RevocationEndpointAuthMethods: []string{
			"client_secret_basic",
			"client_secret_post",
		},

		IntrospectionEndpointAuthMethods: []string{
			"client_secret_basic",
			"client_secret_post",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
