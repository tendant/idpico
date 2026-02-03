package http

import (
	"encoding/json"
	"net/http"
	"strings"
)

// OIDCDiscovery represents the OIDC discovery document.
type OIDCDiscovery struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                          string   `json:"jwks_uri"`
	RegistrationEndpoint             string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ResponseModesSupported           []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ClaimsSupported                  []string `json:"claims_supported,omitempty"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported,omitempty"`
}

// DiscoveryHandler handles OIDC discovery endpoints.
type DiscoveryHandler struct {
	issuerURL string
}

// NewDiscoveryHandler creates a new DiscoveryHandler.
func NewDiscoveryHandler(issuerURL string) *DiscoveryHandler {
	return &DiscoveryHandler{
		issuerURL: strings.TrimSuffix(issuerURL, "/"),
	}
}

// OpenIDConfiguration handles the /.well-known/openid-configuration endpoint.
func (h *DiscoveryHandler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	discovery := OIDCDiscovery{
		Issuer:                h.issuerURL,
		AuthorizationEndpoint: h.issuerURL + "/authorize",
		TokenEndpoint:         h.issuerURL + "/token",
		UserinfoEndpoint:      h.issuerURL + "/userinfo",
		JwksURI:               h.issuerURL + "/.well-known/jwks.json",

		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
			"offline_access",
		},

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

		ClaimsSupported: []string{
			"iss",
			"sub",
			"aud",
			"exp",
			"iat",
			"email",
			"email_verified",
			"name",
		},

		CodeChallengeMethodsSupported: []string{
			"S256",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(discovery); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}
