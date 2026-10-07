//go:build conformance

package conformance

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// totp computes an RFC 6238 code (SHA-1, 6 digits, 30 s) independently of
// IDPico's implementation.
func totp(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatalf("secret %q: %v", secret, err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

var totpSecretRe = regexp.MustCompile(`name="secret" value="([A-Z2-7]+)"`)

// TestTwoStepSignIn: a user with an authenticator completes an
// authorization request only after the code step, and the relying party
// sees an ordinary code flow. Provisioned with idpicoctl; throwaway server only.
func TestTwoStepSignIn(t *testing.T) {
	if defInst == nil {
		t.Skip("needs the throwaway server to provision a user (CONFORMANCE_ISSUER is set)")
	}
	const email, password = "two-step@example.com", "two-step-password"
	defInst.idpicoctl(t, "user", "add", email, "-password", password, "-verified")
	base := cfg.Issuer

	signIn := func(c *http.Client, loginURL string) (*http.Response, []byte) {
		t.Helper()
		_, body := get(t, c, loginURL)
		form := url.Values{"email": {email}, "password": {password}, "csrf_token": {formValue(body, "csrf_token")}}
		if v := formValue(body, "return_url"); v != "" {
			form.Set("return_url", v)
		}
		return postForm(t, c, loginURL, form)
	}

	// Enroll on /account.
	c := newHTTPClient(t)
	if resp, _ := signIn(c, base+"/login"); resp.StatusCode != http.StatusFound {
		t.Fatalf("password sign-in: HTTP %d", resp.StatusCode)
	}
	_, body := get(t, c, base+"/account/two-step")
	m := totpSecretRe.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no secret on the setup page: %s", snippet(body))
	}
	secret := string(m[1])
	resp, body := postForm(t, c, base+"/account/two-step/enable", url.Values{
		"csrf_token": {formValue(body, "csrf_token")}, "secret": {secret}, "code": {totp(t, secret, time.Now())},
	})
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "recovery codes") {
		t.Fatalf("enable: HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	// A fresh browser runs an authorization request.
	c = newHTTPClient(t)
	params := authzParams(cfg.ClientID, cfg.RedirectURI, "openid email", "st", "nn", "")
	authURL := discovery(t).AuthorizationEndpoint + "?" + params.Encode()
	resp, _ = get(t, c, authURL)
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/login") {
		t.Fatalf("authorize without a session: HTTP %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, _ = signIn(c, resolve(t, authURL, resp.Header.Get("Location")))
	codeURL := resolve(t, authURL, resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound || !strings.Contains(codeURL, "/login/code") {
		t.Fatalf("after the password: HTTP %d to %s, want the code step", resp.StatusCode, codeURL)
	}

	// Before the code, the browser has no session: prompt=none says so.
	none := authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "probe", "", "")
	none.Set("prompt", "none")
	r, b := get(t, c, discovery(t).AuthorizationEndpoint+"?"+none.Encode())
	if q := callback(t, r, b, cfg.RedirectURI); q.Get("error") != "login_required" {
		t.Fatalf("between password and code: prompt=none gave %v, want login_required", q)
	}

	_, body = get(t, c, codeURL)
	submit := func(code string) *http.Response {
		form := url.Values{"csrf_token": {formValue(body, "csrf_token")}, "code": {code}}
		if v := formValue(body, "return_url"); v != "" {
			form.Set("return_url", v)
		}
		resp, b := postForm(t, c, resolve(t, codeURL, "/login/code"), form)
		body = b
		return resp
	}
	if resp := submit("000000"); resp.StatusCode == http.StatusFound {
		t.Fatal("a wrong code was accepted")
	}
	// The enrollment used the current time step; the next one is due.
	resp = submit(totp(t, secret, time.Now().Add(30*time.Second)))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("right code: HTTP %d: %s", resp.StatusCode, snippet(body))
	}

	// Back at /authorize with a session: consent, then the callback.
	resp, body = authorize(t, c, params)
	q := callback(t, resp, body, cfg.RedirectURI)
	if q.Get("code") == "" || q.Get("state") != "st" {
		t.Fatalf("callback: %v", q)
	}
	tr := exchange(t, q.Get("code"), "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
	if tr.Status != http.StatusOK {
		t.Fatalf("token: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
	}
	claims := mustVerifyIDToken(t, tr.str("id_token"), idTokenExpectation{Issuer: discovery(t).Issuer, ClientID: cfg.ClientID, Nonce: "nn"})
	if claims["email"] != email {
		t.Errorf("ID token email = %v, want %s", claims["email"], email)
	}
	// amr (OIDC Core §2, RFC 8176) says a second factor was used.
	if got := amrOf(claims); !contains(got, "pwd") || !contains(got, "otp") || !contains(got, "mfa") {
		t.Errorf("amr = %v, want pwd, otp and mfa", got)
	}
}

func amrOf(claims map[string]any) []string {
	var out []string
	list, _ := claims["amr"].([]any)
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// A password-only sign-in says so: amr is ["pwd"].
func TestAMRPasswordOnly(t *testing.T) {
	code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid", "st", "nn", ""), cfg.RedirectURI)
	tr := exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
	if tr.Status != http.StatusOK {
		t.Fatalf("token: HTTP %d", tr.Status)
	}
	claims := mustVerifyIDToken(t, tr.str("id_token"), idTokenExpectation{Issuer: discovery(t).Issuer, ClientID: cfg.ClientID, Nonce: "nn"})
	if got := amrOf(claims); len(got) != 1 || got[0] != "pwd" {
		t.Errorf("amr = %v, want [pwd]", got)
	}
}
