//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// RP-Initiated Logout 1.0 at the end_session_endpoint: the session ends, and
// the user agent is sent to post_logout_redirect_uri (with state, §3) only
// when that URI is registered for the client the request names through
// id_token_hint or client_id (§2). Anything else must not be followed: an
// open redirect on logout is as exploitable as one on /authorize.

func endSessionEndpoint(t *testing.T) string {
	t.Helper()
	ep, _ := discovery(t).raw["end_session_endpoint"].(string)
	if ep == "" {
		t.Fatal("no end_session_endpoint advertised")
	}
	return ep
}

// signIn logs the test user in through the confidential client on a fresh
// browser and returns the browser and the ID token issued.
func signIn(t *testing.T) (*http.Client, string) {
	t.Helper()
	c := newHTTPClient(t)
	resp, body := authorize(t, c, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "st", "", ""))
	q := callback(t, resp, body, cfg.RedirectURI)
	tr := exchange(t, q.Get("code"), "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
	if tr.Status != http.StatusOK || tr.str("id_token") == "" {
		t.Fatalf("token: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
	}
	if !hasSession(t, c) {
		t.Fatal("no session after sign-in")
	}
	return c, tr.str("id_token")
}

// hasSession reports whether the browser is still signed in: prompt=none
// yields a code only then (OIDC Core §3.1.2.1).
func hasSession(t *testing.T, c *http.Client) bool {
	t.Helper()
	p := authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "probe", "", "")
	p.Set("prompt", "none")
	resp, body := get(t, c, discovery(t).AuthorizationEndpoint+"?"+p.Encode())
	return callback(t, resp, body, cfg.RedirectURI).Get("code") != ""
}

// logout sends an end-session request from the browser, as a GET query or a
// POST form, and returns where the provider redirects.
func logout(t *testing.T, c *http.Client, method string, params url.Values) *url.URL {
	t.Helper()
	ep := endSessionEndpoint(t)
	var resp *http.Response
	var body []byte
	if method == http.MethodPost {
		resp, body = postForm(t, c, ep, params)
	} else {
		resp, body = get(t, c, ep+"?"+params.Encode())
	}
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther && resp.StatusCode != http.StatusOK {
		t.Fatalf("logout: HTTP %d: %s", resp.StatusCode, redact(snippet(body)))
	}
	loc, err := url.Parse(resolve(t, ep, resp.Header.Get("Location")))
	if err != nil {
		t.Fatal(err)
	}
	return loc
}

func withoutQuery(u *url.URL) string {
	v := *u
	v.RawQuery, v.Fragment = "", ""
	return v.String()
}

func TestLogout(t *testing.T) {
	t.Run("id_token_hint_returns_to_client_with_state", func(t *testing.T) {
		c, idToken := signIn(t)
		loc := logout(t, c, http.MethodGet, url.Values{
			"id_token_hint":            {idToken},
			"post_logout_redirect_uri": {cfg.RedirectURI},
			"state":                    {"bye"},
		})
		if withoutQuery(loc) != cfg.RedirectURI {
			t.Errorf("redirected to %q, want %q", loc, cfg.RedirectURI)
		}
		if got := loc.Query().Get("state"); got != "bye" {
			t.Errorf("state = %q, want bye (RP-Initiated Logout §3)", got)
		}
		if hasSession(t, c) {
			t.Error("session survived logout")
		}
	})

	t.Run("client_id_in_post_form", func(t *testing.T) {
		c, _ := signIn(t)
		loc := logout(t, c, http.MethodPost, url.Values{
			"client_id":                {cfg.ClientID},
			"post_logout_redirect_uri": {cfg.RedirectURI},
		})
		if withoutQuery(loc) != cfg.RedirectURI {
			t.Errorf("redirected to %q, want %q (§2: POST must be supported)", loc, cfg.RedirectURI)
		}
		if hasSession(t, c) {
			t.Error("session survived logout")
		}
	})

	t.Run("without_redirect", func(t *testing.T) {
		c, idToken := signIn(t)
		logout(t, c, http.MethodGet, url.Values{"id_token_hint": {idToken}})
		if hasSession(t, c) {
			t.Error("session survived logout")
		}
	})

	// Each case must neither follow the URI nor leave the session alive.
	refused := func(name string, params func(idToken string) url.Values) {
		t.Run(name, func(t *testing.T) {
			c, idToken := signIn(t)
			p := params(idToken)
			loc := logout(t, c, http.MethodGet, p)
			target := p.Get("post_logout_redirect_uri")
			if strings.HasPrefix(loc.String(), target) {
				t.Errorf("followed post_logout_redirect_uri %q", target)
			}
			if hasSession(t, c) {
				t.Error("session survived logout")
			}
		})
	}
	refused("unregistered_uri", func(idToken string) url.Values {
		return url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {"https://attacker.example/after-logout"}}
	})
	refused("uri_registered_for_another_client", func(idToken string) url.Values {
		return url.Values{"id_token_hint": {idToken}, "post_logout_redirect_uri": {cfg.OtherRedirectURI}}
	})
	refused("client_id_contradicts_hint", func(idToken string) url.Values {
		return url.Values{"id_token_hint": {idToken}, "client_id": {cfg.OtherClientID}, "post_logout_redirect_uri": {cfg.OtherRedirectURI}}
	})
	refused("no_client_named", func(string) url.Values {
		return url.Values{"post_logout_redirect_uri": {cfg.RedirectURI}}
	})
	refused("forged_hint", func(idToken string) url.Values {
		return url.Values{"id_token_hint": {flipSignature(idToken)}, "post_logout_redirect_uri": {cfg.RedirectURI}}
	})
}
