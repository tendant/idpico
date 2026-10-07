//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestPasskeySecondStep: a user registers a passkey on /account and an
// authorization request then completes with password + passkey; the ID
// token's amr says so (RFC 8176 swk, mfa). WebAuthn refuses IP-address
// origins, so this runs its own instance with an http://localhost issuer
// (a secure context for browsers). Throwaway server only.
func TestPasskeySecondStep(t *testing.T) {
	if cfg.External() {
		t.Skip("starts its own instance with a localhost issuer")
	}
	inst := startInstance(t, "", map[string]string{"IDPICO_ISSUER_URL": "http://localhost:{port}"})
	p := inst.provider()
	const email, password = "passkey@example.com", "passkey-password"
	inst.idpicoctl(t, "user", "add", email, "-password", password, "-verified")
	base := inst.issuer
	dev := newSoftAuthenticator(base, "localhost")

	signIn := func(c *http.Client, loginURL string) *http.Response {
		t.Helper()
		_, body := get(t, c, loginURL)
		form := url.Values{"email": {email}, "password": {password}, "csrf_token": {formValue(body, "csrf_token")}}
		if v := formValue(body, "return_url"); v != "" {
			form.Set("return_url", v)
		}
		resp, _ := postForm(t, c, loginURL, form)
		return resp
	}
	// Register on /account.
	c := p.newHTTPClient(t)
	signIn(c, base+"/login")
	_, page := get(t, c, base+"/account")
	if !strings.Contains(string(page), "data-passkey-register") {
		t.Fatalf("account page offers no passkey registration: %s", snippet(page))
	}
	csrf := formValue(page, "csrf_token")
	resp, options := postForm(t, c, base+"/account/passkeys/register/begin", url.Values{"csrf_token": {csrf}, "current_password": {password}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("register begin: HTTP %d: %s", resp.StatusCode, snippet(options))
	}
	cred, err := dev.Create(options)
	if err != nil {
		t.Fatal(err)
	}
	resp, body := postForm(t, c, base+"/account/passkeys/register/finish", url.Values{"csrf_token": {csrf}, "name": {"Soft"}, "credential": {cred}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "recovery_codes") {
		t.Fatalf("register finish: HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	// Authorization request in a fresh browser: password, then passkey.
	c = p.newHTTPClient(t)
	params := authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "st", "nn", "")
	authURL := p.discovery(t).AuthorizationEndpoint + "?" + params.Encode()
	resp, _ = get(t, c, authURL)
	resp = signIn(c, resolve(t, authURL, resp.Header.Get("Location")))
	codeURL := resolve(t, authURL, resp.Header.Get("Location"))
	if !strings.Contains(codeURL, "/login/code") {
		t.Fatalf("after the password: %s, want the second step", codeURL)
	}
	_, page = get(t, c, codeURL)
	if !strings.Contains(string(page), "data-passkey-login") {
		t.Fatalf("code page offers no passkey: %s", snippet(page))
	}
	csrf = formValue(page, "csrf_token")
	resp, options = postForm(t, c, base+"/login/passkey/begin", url.Values{"csrf_token": {csrf}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login begin: HTTP %d: %s", resp.StatusCode, snippet(options))
	}
	assertion, err := dev.Get(options)
	if err != nil {
		t.Fatal(err)
	}
	ret, _ := url.Parse(codeURL)
	resp, body = postForm(t, c, base+"/login/passkey/finish", url.Values{"csrf_token": {csrf}, "credential": {assertion}, "return_url": {ret.Query().Get("return_url")}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login finish: HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	resp, body = p.authorize(t, c, params)
	q := callback(t, resp, body, cfg.RedirectURI)
	tr := p.exchange(t, q.Get("code"), "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
	if tr.Status != http.StatusOK {
		t.Fatalf("token: HTTP %d", tr.Status)
	}
	claims := p.mustVerifyIDToken(t, tr.str("id_token"), idTokenExpectation{Issuer: p.discovery(t).Issuer, ClientID: cfg.ClientID, Nonce: "nn"})
	if got := amrOf(claims); !contains(got, "pwd") || !contains(got, "swk") || !contains(got, "mfa") {
		t.Errorf("amr = %v, want pwd, swk and mfa", got)
	}
}
