//go:build conformance

// Package conformance is a black-box OpenID Connect conformance suite for
// IDPico. It knows only an issuer URL and test credentials, talks to the
// server exclusively over HTTP, and verifies tokens with a JOSE library the
// server does not use. It must never import IDPico's internal packages; see
// noimports_test.go and CONFORMANCE.md.
//
// Build tag: go test -tags conformance ./conformance/
package conformance

import (
	"os"
)

// Config describes the provider under test and the clients and user that
// must be provisioned on it. Every field can be overridden with a
// CONFORMANCE_* environment variable; the defaults match what TestMain
// bootstraps on the throwaway server it starts.
type Config struct {
	// Issuer is the provider's issuer URL. When CONFORMANCE_ISSUER is set the
	// suite targets that running instance instead of starting its own.
	Issuer string

	// Confidential client used for the primary positive flow.
	ClientID     string
	ClientSecret string
	RedirectURI  string

	// Public client (no secret): PKCE S256 is mandatory.
	PublicClientID string

	// A second confidential client with its own redirect URI, for
	// cross-client code redemption.
	OtherClientID     string
	OtherClientSecret string
	OtherRedirectURI  string

	// A client whose only redirect URI is an https:// URL, for the redirect
	// URI matching table. The suite never follows redirects, so it need not
	// resolve.
	StrictClientID     string
	StrictClientSecret string
	StrictRedirectURI  string

	// Test user (must be active with a verified email).
	UserEmail    string
	UserPassword string

	// Verbose logs every request and response (redacted) through t.Log.
	Verbose bool
}

func loadConfig() Config {
	c := Config{
		Issuer:             os.Getenv("CONFORMANCE_ISSUER"),
		ClientID:           "conformance-client",
		ClientSecret:       "conformance-secret",
		RedirectURI:        "http://127.0.0.1:18081/callback",
		PublicClientID:     "conformance-public",
		OtherClientID:      "conformance-other",
		OtherClientSecret:  "conformance-other-secret",
		OtherRedirectURI:   "http://127.0.0.1:18082/callback",
		StrictClientID:     "conformance-strict",
		StrictClientSecret: "conformance-strict-secret",
		StrictRedirectURI:  "https://app.example.com/callback",
		UserEmail:          "alice@example.com",
		UserPassword:       "test-password",
		Verbose:            os.Getenv("CONFORMANCE_VERBOSE") != "",
	}
	env := func(dst *string, key string) {
		if v := os.Getenv(key); v != "" {
			*dst = v
		}
	}
	env(&c.ClientID, "CONFORMANCE_CLIENT_ID")
	env(&c.ClientSecret, "CONFORMANCE_CLIENT_SECRET")
	env(&c.RedirectURI, "CONFORMANCE_REDIRECT_URI")
	env(&c.PublicClientID, "CONFORMANCE_PUBLIC_CLIENT_ID")
	env(&c.OtherClientID, "CONFORMANCE_OTHER_CLIENT_ID")
	env(&c.OtherClientSecret, "CONFORMANCE_OTHER_CLIENT_SECRET")
	env(&c.OtherRedirectURI, "CONFORMANCE_OTHER_REDIRECT_URI")
	env(&c.StrictClientID, "CONFORMANCE_STRICT_CLIENT_ID")
	env(&c.StrictClientSecret, "CONFORMANCE_STRICT_CLIENT_SECRET")
	env(&c.StrictRedirectURI, "CONFORMANCE_STRICT_REDIRECT_URI")
	env(&c.UserEmail, "CONFORMANCE_USER_EMAIL")
	env(&c.UserPassword, "CONFORMANCE_USER_PASSWORD")
	return c
}

// External reports whether the suite targets a server it did not start.
// Tests that depend on the throwaway server's short token lifetimes skip
// themselves in that case.
func (c Config) External() bool { return os.Getenv("CONFORMANCE_ISSUER") != "" }

// bootstrapClients is the IDPICO_BOOTSTRAP_CLIENTS value that provisions
// the four clients above on the throwaway server (empty secret = public).
func (c Config) bootstrapClients() string {
	return c.ClientID + "|" + c.ClientSecret + "|" + c.RedirectURI +
		"," + c.PublicClientID + "||" + c.RedirectURI +
		"," + c.OtherClientID + "|" + c.OtherClientSecret + "|" + c.OtherRedirectURI +
		"," + c.StrictClientID + "|" + c.StrictClientSecret + "|" + c.StrictRedirectURI
}

// bootstrapUsers is the matching IDPICO_BOOTSTRAP_USERS value.
func (c Config) bootstrapUsers() string {
	return c.UserEmail + ":" + c.UserPassword + ":Alice Conformance"
}
