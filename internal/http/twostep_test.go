package http

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tendant/idpico/internal/auth"
)

// twoStepClient is a browser for the two-step tests: cookie jar, no
// redirects followed, CSRF token picked up from the cookie.
type twoStepClient struct {
	t        *testing.T
	env      *testEnv
	http     *http.Client
	codePage string // where the password step sent the browser
}

func (c *twoStepClient) get(path string) (*http.Response, string) {
	c.t.Helper()
	resp, err := c.http.Get(c.env.server.URL + path)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (c *twoStepClient) post(path string, form url.Values) (*http.Response, string) {
	c.t.Helper()
	for _, ck := range c.http.Jar.Cookies(mustParseURL(c.env.server.URL)) {
		if ck.Name == "idpico_csrf" {
			form.Set("csrf_token", ck.Value)
		}
	}
	resp, err := c.http.PostForm(c.env.server.URL+path, form)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (c *twoStepClient) hasSession() bool {
	for _, ck := range c.http.Jar.Cookies(mustParseURL(c.env.server.URL)) {
		if ck.Name == auth.SessionCookieName && ck.Value != "" {
			return true
		}
	}
	return false
}

// password submits the login form and returns the redirect target.
func (c *twoStepClient) password(returnURL string) string {
	c.t.Helper()
	c.get("/login")
	form := url.Values{"email": {"test@example.com"}, "password": {"password123"}}
	if returnURL != "" {
		form.Set("return_url", returnURL)
	}
	resp, body := c.post("/login", form)
	if resp.StatusCode != http.StatusFound {
		c.t.Fatalf("login: HTTP %d: %s", resp.StatusCode, body)
	}
	c.codePage = resp.Header.Get("Location")
	return c.codePage
}

// code submits the code form as the browser would: fetched from where the
// password step redirected, with its hidden fields.
func (c *twoStepClient) code(code string) *http.Response {
	c.t.Helper()
	page := c.codePage
	if !strings.HasPrefix(page, "/login/code") {
		page = "/login/code"
	}
	_, body := c.get(page)
	form := url.Values{"code": {code}}
	if m := returnURLRe.FindStringSubmatch(body); m != nil {
		form.Set("return_url", html.UnescapeString(m[1]))
	}
	resp, _ := c.post("/login/code", form)
	return resp
}

var (
	totpSecretRe = regexp.MustCompile(`name="secret" value="([A-Z2-7]+)"`)
	recoveryRe   = regexp.MustCompile(`\b[a-z2-7]{5}-[a-z2-7]{5}\b`)
	returnURLRe  = regexp.MustCompile(`name="return_url" value="([^"]*)"`)
	preRe        = regexp.MustCompile(`(?s)<pre[^>]*>(.*?)</pre>`)
)

func TestIntegration_TwoStepSignIn(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		ctx := context.Background()
		c := &twoStepClient{t: t, env: env, http: newClientWithCookies()}

		// Enroll from /account: a secret as QR, proved with one code.
		if loc := c.password(""); loc != "/" {
			t.Fatalf("password-only login redirected to %q", loc)
		}
		resp, body := c.get("/account/two-step")
		m := totpSecretRe.FindStringSubmatch(body)
		if resp.StatusCode != http.StatusOK || m == nil || !strings.Contains(body, "data:image/png;base64,") {
			t.Fatalf("setup page: HTTP %d, secret/QR missing:\n%s", resp.StatusCode, body)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("setup page Cache-Control = %q, want no-store", cc)
		}
		secret := m[1]
		if resp, _ := c.post("/account/two-step/enable", url.Values{"secret": {secret}, "code": {"000000"}}); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("wrong enrollment code: HTTP %d, want 400", resp.StatusCode)
		}
		now, _ := auth.GenerateTOTP(secret, time.Now())
		resp, body = c.post("/account/two-step/enable", url.Values{"secret": {secret}, "code": {now}})
		var recovery []string
		if pre := preRe.FindStringSubmatch(body); pre != nil {
			recovery = recoveryRe.FindAllString(pre[1], -1)
		}
		if resp.StatusCode != http.StatusOK || len(recovery) != auth.RecoveryCodeCount {
			t.Fatalf("enable: HTTP %d, %d recovery codes shown", resp.StatusCode, len(recovery))
		}
		if u, _ := env.store.Users().GetByEmail(ctx, "test@example.com"); !u.TOTPEnabled() || u.TOTPSecret != secret {
			t.Fatal("two-step not stored")
		}
		if _, body := c.get("/account"); strings.Contains(body, secret) {
			t.Error("the account page shows the secret after setup")
		}

		// The password alone no longer signs in; the code page does, and
		// the return URL survives the extra step.
		c = &twoStepClient{t: t, env: env, http: newClientWithCookies()}
		loc := c.password("/authorize?client_id=x")
		if !strings.HasPrefix(loc, "/login/code") || !strings.Contains(loc, url.QueryEscape("/authorize?client_id=x")) {
			t.Fatalf("after password: redirected to %q, want /login/code with the return URL", loc)
		}
		if c.hasSession() {
			t.Fatal("a session was issued before the code")
		}
		if resp := c.code("123456"); resp.StatusCode != http.StatusUnauthorized || c.hasSession() {
			t.Fatalf("wrong code: HTTP %d, session=%v", resp.StatusCode, c.hasSession())
		}
		// The enrollment consumed the current step; the next one is due.
		next, _ := auth.GenerateTOTP(secret, time.Now().Add(30*time.Second))
		resp = c.code(next)
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/authorize?client_id=x" || !c.hasSession() {
			t.Fatalf("right code: HTTP %d to %q, session=%v", resp.StatusCode, resp.Header.Get("Location"), c.hasSession())
		}

		// The same code never works twice.
		c = &twoStepClient{t: t, env: env, http: newClientWithCookies()}
		c.password("")
		if resp := c.code(next); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("replayed code: HTTP %d, want 401", resp.StatusCode)
		}

		// A recovery code works once, typed any way.
		if resp := c.code(strings.ToUpper(strings.ReplaceAll(recovery[0], "-", ""))); resp.StatusCode != http.StatusFound || !c.hasSession() {
			t.Fatalf("recovery code: HTTP %d", resp.StatusCode)
		}
		c = &twoStepClient{t: t, env: env, http: newClientWithCookies()}
		c.password("")
		if resp := c.code(recovery[0]); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("reused recovery code: HTTP %d, want 401", resp.StatusCode)
		}
	})
}

// Each password entry allows a few codes; after that the password is due
// again, whatever the lockout setting.
func TestIntegration_TwoStepAttemptLimit(t *testing.T) {
	env := setupTestEnv(t, "sqlite")
	defer env.cleanup()
	ctx := context.Background()
	secret, _ := auth.NewTOTPSecret()
	u, _ := env.store.Users().GetByEmail(ctx, "test@example.com")
	u.TOTPSecret = secret
	if err := env.store.Users().Update(ctx, u); err != nil {
		t.Fatal(err)
	}

	c := &twoStepClient{t: t, env: env, http: newClientWithCookies()}
	c.password("")
	var resp *http.Response
	for i := 0; i < 5; i++ {
		resp = c.code("000000")
	}
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?") {
		t.Fatalf("after 5 wrong codes: HTTP %d to %q, want back to /login", resp.StatusCode, resp.Header.Get("Location"))
	}
	right, _ := auth.GenerateTOTP(secret, time.Now())
	if resp := c.code(right); resp.StatusCode != http.StatusFound || c.hasSession() {
		t.Errorf("a right code after the limit was accepted (HTTP %d, session=%v)", resp.StatusCode, c.hasSession())
	}
}

func TestIntegration_TwoStepDisableNeedsCode(t *testing.T) {
	env := setupTestEnv(t, "sqlite")
	defer env.cleanup()
	ctx := context.Background()
	secret, _ := auth.NewTOTPSecret()
	u, _ := env.store.Users().GetByEmail(ctx, "test@example.com")
	u.TOTPSecret = secret
	env.store.Users().Update(ctx, u)

	c := &twoStepClient{t: t, env: env, http: newClientWithCookies()}
	c.password("")
	first, _ := auth.GenerateTOTP(secret, time.Now())
	if resp := c.code(first); resp.StatusCode != http.StatusFound {
		t.Fatalf("sign in: HTTP %d", resp.StatusCode)
	}
	c.get("/account")
	if resp, _ := c.post("/account/two-step/disable", url.Values{"code": {"000000"}}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("disable with a wrong code: HTTP %d, want 400", resp.StatusCode)
	}
	if u, _ := env.store.Users().GetByID(ctx, u.ID); !u.TOTPEnabled() {
		t.Fatal("turned off without a valid code")
	}
	next, _ := auth.GenerateTOTP(secret, time.Now().Add(30*time.Second))
	c.get("/account")
	if resp, _ := c.post("/account/two-step/disable", url.Values{"code": {next}}); resp.StatusCode != http.StatusFound {
		t.Errorf("disable: HTTP %d", resp.StatusCode)
	}
	if u, _ := env.store.Users().GetByID(ctx, u.ID); u.TOTPEnabled() {
		t.Error("still on after disable")
	}
}
