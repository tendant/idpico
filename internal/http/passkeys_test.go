package http

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/tendant/idpico/internal/testutil/softauthn"
)

// The test env's relying party is http://localhost (see setupTestEnv).
func newSoftAuthenticator() *softauthn.Authenticator {
	return softauthn.New("http://localhost", "localhost")
}

func decodeJSON(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("not JSON: %v: %s", err, body)
	}
}

// addPasskey registers a passkey from /account and returns the reply.
func (c *twoStepClient) addPasskey(dev *softauthn.Authenticator, password, name string) (*http.Response, map[string]any) {
	c.t.Helper()
	c.get("/account")
	resp, body := c.post("/account/passkeys/register/begin", url.Values{"current_password": {password}})
	if resp.StatusCode != http.StatusOK {
		var out map[string]any
		decodeJSON(c.t, body, &out)
		return resp, out
	}
	cred, err := dev.Create([]byte(body))
	if err != nil {
		c.t.Fatalf("authenticator create: %v", err)
	}
	resp, body = c.post("/account/passkeys/register/finish", url.Values{"name": {name}, "credential": {cred}})
	var out map[string]any
	decodeJSON(c.t, body, &out)
	return resp, out
}

// passkeyStep answers the code page with the passkey, as passkeys.js does.
func (c *twoStepClient) passkeyStep(dev *softauthn.Authenticator, returnURL string) (*http.Response, map[string]any) {
	c.t.Helper()
	c.get(c.codePage)
	resp, body := c.post("/login/passkey/begin", url.Values{})
	if resp.StatusCode != http.StatusOK {
		c.t.Fatalf("passkey begin: HTTP %d: %s", resp.StatusCode, body)
	}
	assertion, err := dev.Get([]byte(body))
	if err != nil {
		c.t.Fatalf("authenticator get: %v", err)
	}
	resp, body = c.post("/login/passkey/finish", url.Values{"credential": {assertion}, "return_url": {returnURL}})
	var out map[string]any
	decodeJSON(c.t, body, &out)
	return resp, out
}

func TestIntegration_PasskeySecondStep(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		ctx := context.Background()
		dev := newSoftAuthenticator()

		// Register from /account: the current password is required.
		c := &twoStepClient{t: t, env: env, http: newClientWithCookies()}
		c.password("")
		if resp, out := c.addPasskey(dev, "wrong-password", "Phone"); resp.StatusCode != http.StatusBadRequest || out["error"] == nil {
			t.Fatalf("register with a wrong password: HTTP %d %v", resp.StatusCode, out)
		}
		resp, out := c.addPasskey(dev, "password123", "Phone")
		codes, _ := out["recovery_codes"].([]any)
		if resp.StatusCode != http.StatusOK || len(codes) != 10 {
			t.Fatalf("register: HTTP %d %v, want 10 recovery codes (first second step)", resp.StatusCode, out)
		}
		if _, body := c.get("/account"); !strings.Contains(body, "Phone") {
			t.Error("account page does not list the passkey")
		}

		// The password alone no longer signs in; the passkey finishes it.
		c = &twoStepClient{t: t, env: env, http: newClientWithCookies()}
		if loc := c.password("/authorize?client_id=x"); !strings.HasPrefix(loc, "/login/code") {
			t.Fatalf("after password: %q, want the code page", loc)
		}
		if _, body := c.get(c.codePage); !strings.Contains(body, "Use a passkey") || !strings.Contains(body, "passkeys.js") {
			t.Error("code page does not offer the passkey")
		}
		resp, out = c.passkeyStep(dev, "/authorize?client_id=x")
		if resp.StatusCode != http.StatusOK || out["redirect"] != "/authorize?client_id=x" || !c.hasSession() {
			t.Fatalf("passkey step: HTTP %d %v session=%v", resp.StatusCode, out, c.hasSession())
		}
		sessions, _ := env.store.Sessions().ListByUserID(ctx, env.testUser.ID)
		var amr string
		for _, s := range sessions {
			if strings.Contains(strings.Join(s.AMR, " "), "swk") {
				amr = strings.Join(s.AMR, " ")
			}
		}
		if amr != "pwd swk mfa user" {
			t.Errorf("session amr = %q, want pwd swk mfa user", amr)
		}
		list, _ := env.store.Passkeys().ListByUserID(ctx, env.testUser.ID)
		if len(list) != 1 || list[0].LastUsedAt.IsZero() {
			t.Errorf("passkey use not recorded: %+v", list)
		}

		// A page on another origin (phishing) gets a signature the server refuses.
		phished := newSoftAuthenticator()
		*phished = *dev
		phished.Origin = "https://evil.example"
		c = &twoStepClient{t: t, env: env, http: newClientWithCookies()}
		c.password("")
		if resp, _ := c.passkeyStep(phished, ""); resp.StatusCode != http.StatusUnauthorized || c.hasSession() {
			t.Errorf("assertion for another origin: HTTP %d session=%v, want 401", resp.StatusCode, c.hasSession())
		}

		// Recovery codes stand in for the passkey.
		c = &twoStepClient{t: t, env: env, http: newClientWithCookies()}
		c.password("")
		if resp := c.code(codes[0].(string)); resp.StatusCode != http.StatusFound || !c.hasSession() {
			t.Fatalf("recovery code: HTTP %d", resp.StatusCode)
		}

		// Removing the last passkey needs the password and ends the second step.
		c.get("/account")
		if resp, _ := c.post("/account/passkeys/"+list[0].ID+"/remove", url.Values{"current_password": {"nope"}}); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("remove with a wrong password: HTTP %d", resp.StatusCode)
		}
		c.get("/account")
		if resp, _ := c.post("/account/passkeys/"+list[0].ID+"/remove", url.Values{"current_password": {"password123"}}); resp.StatusCode != http.StatusFound {
			t.Fatalf("remove: HTTP %d", resp.StatusCode)
		}
		if u, _ := env.store.Users().GetByID(ctx, env.testUser.ID); len(u.RecoveryCodes) != 0 {
			t.Error("recovery codes kept after the last second step was removed")
		}
		c = &twoStepClient{t: t, env: env, http: newClientWithCookies()}
		if loc := c.password(""); loc != "/" {
			t.Errorf("password-only sign-in after removal went to %q", loc)
		}
	})
}

// One signed assertion cannot be used twice: the challenge is single use.
func TestIntegration_PasskeyAssertionReplay(t *testing.T) {
	env := setupTestEnv(t, "sqlite")
	defer env.cleanup()
	dev := newSoftAuthenticator()
	c := &twoStepClient{t: t, env: env, http: newClientWithCookies()}
	c.password("")
	if resp, _ := c.addPasskey(dev, "password123", "Key"); resp.StatusCode != http.StatusOK {
		t.Fatal("register failed")
	}

	c = &twoStepClient{t: t, env: env, http: newClientWithCookies()}
	c.password("")
	c.get(c.codePage)
	_, options := c.post("/login/passkey/begin", url.Values{})
	assertion, _ := dev.Get([]byte(options))
	// Submitted twice on the same pending login: the second has no challenge.
	if resp, body := c.post("/login/passkey/finish", url.Values{"credential": {"garbage"}}); resp.StatusCode == http.StatusOK {
		t.Fatalf("garbage accepted: %s", body)
	}
	if resp, _ := c.post("/login/passkey/finish", url.Values{"credential": {assertion}}); resp.StatusCode == http.StatusOK {
		t.Error("an assertion was accepted after its challenge had been used")
	}
}

// Requests without a CSRF token or pending login are client errors, never 500.
func TestIntegration_PasskeyEndpointsRejectBareRequests(t *testing.T) {
	env := setupTestEnv(t, "sqlite")
	defer env.cleanup()
	for _, path := range []string{"/login/passkey/begin", "/login/passkey/finish"} {
		resp, err := http.Post(env.server.URL+path, "application/x-www-form-urlencoded", strings.NewReader(""))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode < 400 || resp.StatusCode >= 500 {
			t.Errorf("POST %s without CSRF or pending login: HTTP %d, want 4xx", path, resp.StatusCode)
		}
	}
}
