package http

import (
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/oidc"
)

// playgroundEnv builds a server whose issuer URL is the test listener, so the
// playground's absolute redirect URI points back at the test server.
func playgroundEnv(t *testing.T, env *testEnv) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	issuer := "http://" + ts.Listener.Addr().String()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	activeKey, _ := env.keyService.GetActiveKey(t.Context())
	tokenGenerator := crypto.NewTokenGeneratorWithKeyService(activeKey, env.keyService, issuer, issuer)
	authorizeService := oidc.NewAuthorizeService(env.store.Clients(), env.store.AuthCodes(), 10*time.Minute)
	groupClaims := oidc.NewGroupClaims(env.store.Groups(), "")
	tokenService := oidc.NewTokenService(env.store.Clients(), env.store.AuthCodes(), env.store.Tokens(), env.store.Users(),
		tokenGenerator, issuer, 15*time.Minute, time.Hour, oidc.WithGroupClaims(groupClaims))
	userInfoService := oidc.NewUserInfoService(env.store.Users(), tokenGenerator, oidc.WithUserInfoGroups(groupClaims))

	srv := NewServer(":0",
		WithLogger(logger),
		WithIssuerURL(issuer),
		WithKeyService(env.keyService),
		WithAuthService(env.authService),
		WithOIDCServices(authorizeService, tokenService, userInfoService),
		WithConsentService(oidc.NewConsentService(env.store.Consents())),
		WithPlayground(env.store.Clients()),
	)
	ts.Config.Handler = srv.Router()
	ts.Start()
	t.Cleanup(ts.Close)
	return ts
}

func TestPlayground_FullFlow(t *testing.T) {
	env := setupTestEnv(t, "sqlite")
	defer env.cleanup()
	ts := playgroundEnv(t, env)
	base := ts.URL
	ctx := t.Context()

	// The client was registered with the right redirect URI
	pg, err := env.store.Clients().GetByID(ctx, PlaygroundClientID)
	if err != nil || pg.RedirectURIs[0] != base+"/playground/callback" || !oidc.IsHashedClientSecret(pg.Secret) {
		t.Fatalf("playground client not registered as expected: %+v err=%v", pg, err)
	}

	client := newClientWithCookies()
	status, body := get(t, client, base+"/playground")
	if status != http.StatusOK || !strings.Contains(body, "OIDC Playground") {
		t.Fatalf("playground page: %d", status)
	}

	// Start: redirected to /authorize with PKCE + nonce
	form := url.Values{"scope": {"profile", "email", "groups", "offline_access"}, "csrf_token": {csrfCookie(client, base)}}
	resp, _ := client.PostForm(base+"/playground/start", form)
	resp.Body.Close()
	authURL := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(authURL, "/authorize?") {
		t.Fatalf("start should redirect to /authorize, got %d %s", resp.StatusCode, authURL)
	}
	q := mustParseURL(authURL).Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" || !strings.Contains(q.Get("scope"), "offline_access") {
		t.Errorf("authorize request missing PKCE/nonce/state/scope: %v", q)
	}

	// Not signed in: authorize sends us to login; sign in and come back
	resp, _ = client.Get(base + authURL)
	resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("expected login redirect, got %s", resp.Header.Get("Location"))
	}
	loginAs(t, client, base, "test@example.com", "password123")

	// Consent page, allow, land on the callback
	resp, _ = client.Get(base + authURL)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected consent page, got %d", resp.StatusCode)
	}
	resp = submitConsent(t, client, base, mustParseURL(authURL).RawQuery, "allow")
	resp.Body.Close()
	callback := resp.Header.Get("Location")
	if !strings.HasPrefix(callback, base+"/playground/callback?") {
		t.Fatalf("expected redirect to playground callback, got %s", callback)
	}
	resp, _ = client.Get(callback)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "flash=") {
		t.Fatalf("callback should redirect with a flash, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Result page shows decoded tokens, userinfo, groups, verified nonce
	// (JSON is HTML-escaped inside <pre>, so compare the unescaped text)
	status, body = get(t, client, base+"/playground")
	body = html.UnescapeString(body)
	if status != http.StatusOK {
		t.Fatalf("result page: %d", status)
	}
	for _, want := range []string{"ID token claims", `"email": "test@example.com"`, `"groups"`, "devs", "nonce verified", "/userinfo", "Refresh tokens", "Revoke refresh token"} {
		if !strings.Contains(body, want) {
			t.Errorf("result page should contain %q", want)
		}
	}

	// Introspect
	resp, _ = client.PostForm(base+"/playground/introspect", url.Values{"csrf_token": {csrfCookie(client, base)}})
	resp.Body.Close()
	_, body = get(t, client, base+"/playground")
	if !strings.Contains(html.UnescapeString(body), `"active": true`) {
		t.Error("introspection result should show the token as active")
	}

	// Refresh
	resp, _ = client.PostForm(base+"/playground/refresh", url.Values{"csrf_token": {csrfCookie(client, base)}})
	resp.Body.Close()
	_, body = get(t, client, base+"/playground")
	if !strings.Contains(body, "refresh_token") || !strings.Contains(html.UnescapeString(body), "POST /token (refresh_token) → 200") {
		t.Error("refresh should succeed and show the new token response")
	}

	// Revoke, then refresh fails
	resp, _ = client.PostForm(base+"/playground/revoke", url.Values{"csrf_token": {csrfCookie(client, base)}})
	resp.Body.Close()
	resp, _ = client.PostForm(base+"/playground/refresh", url.Values{"csrf_token": {csrfCookie(client, base)}})
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Errorf("refresh after revoke should fail, got %s", resp.Header.Get("Location"))
	}

	// RP-initiated logout sends id_token_hint and comes back to the playground
	resp, _ = client.PostForm(base+"/playground/logout", url.Values{"csrf_token": {csrfCookie(client, base)}})
	resp.Body.Close()
	loc := mustParseURL(resp.Header.Get("Location"))
	if loc.Path != "/logout" || loc.Query().Get("id_token_hint") == "" || loc.Query().Get("post_logout_redirect_uri") != "/playground" {
		t.Errorf("expected RP-initiated logout redirect, got %s", resp.Header.Get("Location"))
	}
	resp, _ = client.Get(base + resp.Header.Get("Location"))
	resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Location"), "/playground") {
		t.Errorf("IdP logout should return to the playground, got %s", resp.Header.Get("Location"))
	}
	if _, body := get(t, client, base+"/playground"); strings.Contains(body, "ID token claims") {
		t.Error("tokens should be forgotten after logout")
	}
}

func TestPlayground_BadStateAndErrors(t *testing.T) {
	env := setupTestEnv(t, "sqlite")
	defer env.cleanup()
	ts := playgroundEnv(t, env)
	client := newClientWithCookies()

	resp, _ := client.Get(ts.URL + "/playground/callback?code=x&state=unknown")
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "expired+state") {
		t.Errorf("unknown state should be rejected, got %s", resp.Header.Get("Location"))
	}
	resp, _ = client.Get(ts.URL + "/playground/callback?error=access_denied&error_description=nope")
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "access_denied") {
		t.Errorf("authorization error should be surfaced, got %s", resp.Header.Get("Location"))
	}
	resp, _ = client.PostForm(ts.URL+"/playground/introspect", url.Values{})
	resp.Body.Close()
	if !strings.Contains(resp.Header.Get("Location"), "error=") {
		t.Error("actions without CSRF/session should redirect with an error")
	}
}
