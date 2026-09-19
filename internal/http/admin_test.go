package http

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/oidc"
)

// adminClient returns a cookie-jar client signed in as the admin user.
func adminClient(t *testing.T, env *testEnv) *http.Client {
	t.Helper()
	client := newClientWithCookies()
	loginAs(t, client, env.server.URL, "admin@example.com", "password123")
	return client
}

// get fetches a page and returns status + body.
func get(t *testing.T, client *http.Client, u string) (int, string) {
	t.Helper()
	resp, err := client.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// postForm submits a form with the current CSRF token and returns the response.
func postForm(t *testing.T, client *http.Client, base, path string, form url.Values) *http.Response {
	t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("csrf_token", csrfCookie(client, base))
	resp, err := client.PostForm(base+path, form)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

// postAndFollow submits and asserts a redirect, returning the Location.
func postAndFollow(t *testing.T, client *http.Client, base, path string, form url.Values) string {
	t.Helper()
	resp := postForm(t, client, base, path, form)
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST %s: expected redirect, got %d", path, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

func TestAdmin_Access(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL

		// Anonymous -> login with return_url
		anon := newClientWithCookies()
		resp, _ := anon.Get(base + "/admin/users")
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login?return_url=%2Fadmin%2Fusers") {
			t.Errorf("anonymous should redirect to login, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}

		// Regular user -> 403
		user := newClientWithCookies()
		loginAs(t, user, base, "test@example.com", "password123")
		if status, body := get(t, user, base+"/admin"); status != http.StatusForbidden || !strings.Contains(body, "not an administrator") {
			t.Errorf("non-admin should get 403, got %d", status)
		}

		// Admin -> dashboard
		admin := adminClient(t, env)
		status, body := get(t, admin, base+"/admin")
		if status != http.StatusOK || !strings.Contains(body, "Dashboard") || !strings.Contains(body, "admin@example.com") {
			t.Errorf("admin should see dashboard, got %d", status)
		}

		// Landing page routes admins to /admin and others to a status page
		resp, _ = admin.Get(base + "/")
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/admin" {
			t.Errorf("admin landing should redirect to /admin, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
		if status, body := get(t, user, base+"/"); status != http.StatusOK || !strings.Contains(body, "test@example.com") {
			t.Errorf("user landing should show signed-in page, got %d", status)
		}
		if status, body := get(t, anon, base+"/"); status != http.StatusOK || !strings.Contains(body, "Sign in") {
			t.Errorf("anonymous landing should offer sign in, got %d", status)
		}

		// POST without CSRF is rejected
		resp, _ = admin.PostForm(base+"/admin/keys/rotate", url.Values{})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("POST without CSRF should be 400, got %d", resp.StatusCode)
		}
	})
}

func TestAdmin_Users(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		ctx := context.Background()
		admin := adminClient(t, env)

		// List shows existing users
		if status, body := get(t, admin, base+"/admin/users"); status != http.StatusOK || !strings.Contains(body, "test@example.com") {
			t.Fatalf("user list should include test user, got %d", status)
		}

		// Create with password
		get(t, admin, base+"/admin/users/new")
		loc := postAndFollow(t, admin, base, "/admin/users", url.Values{
			"email": {"new@example.com"}, "display_name": {"New Person"}, "password": {"strong-password-1"},
			"active": {"1"}, "email_verified": {"1"},
		})
		if !strings.HasPrefix(loc, "/admin/users/") {
			t.Fatalf("expected redirect to user page, got %s", loc)
		}
		created, err := env.store.Users().GetByEmail(ctx, "new@example.com")
		if err != nil || created.DisplayName != "New Person" || !created.EmailVerified || created.Admin {
			t.Fatalf("created user wrong: %+v err=%v", created, err)
		}
		// The new user can sign in
		loginAs(t, newClientWithCookies(), base, "new@example.com", "strong-password-1")

		// Duplicate email and weak password are rejected
		get(t, admin, base+"/admin/users/new")
		resp := postForm(t, admin, base, "/admin/users", url.Values{"email": {"new@example.com"}, "password": {"strong-password-1"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("duplicate email should be 400, got %d", resp.StatusCode)
		}
		resp = postForm(t, admin, base, "/admin/users", url.Values{"email": {"x@example.com"}, "password": {"short"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("weak password should be 400, got %d", resp.StatusCode)
		}

		// Invite (blank password) sends a reset email
		mails := len(env.mailer.Messages)
		get(t, admin, base+"/admin/users/new")
		postAndFollow(t, admin, base, "/admin/users", url.Values{"email": {"invited@example.com"}, "active": {"1"}, "send_verification": {"1"}})
		if len(env.mailer.Messages) != mails+2 {
			t.Errorf("invite should send reset + verification emails, got %d new", len(env.mailer.Messages)-mails)
		}
		if tok := linkToken(t, env.mailer, "/verify-email"); tok == "" {
			t.Error("verification link missing")
		}

		// Update: rename, promote to admin; changing email clears verified
		page := "/admin/users/" + created.ID
		get(t, admin, base+page)
		postAndFollow(t, admin, base, page, url.Values{
			"email": {"renamed@example.com"}, "display_name": {"Renamed"}, "active": {"1"}, "admin": {"1"},
		})
		updated, _ := env.store.Users().GetByID(ctx, created.ID)
		if updated.Email != "renamed@example.com" || !updated.Admin || updated.EmailVerified {
			t.Errorf("update not applied: %+v", updated)
		}

		// Set password signs the user out everywhere
		userSession := newClientWithCookies()
		loginAs(t, userSession, base, "renamed@example.com", "strong-password-1")
		get(t, admin, base+page)
		postAndFollow(t, admin, base, page+"/password", url.Values{"password": {"another-password-1"}})
		resp, _ = userSession.Get(base + "/admin")
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("user's session should be revoked after admin password change, got %d", resp.StatusCode)
		}
		loginAs(t, newClientWithCookies(), base, "renamed@example.com", "another-password-1")

		// Consents: grant one, see it, revoke it
		env.store.Consents().Upsert(ctx, &domain.Consent{UserID: created.ID, ClientID: "test-client", Scopes: []string{"openid"}})
		if _, body := get(t, admin, base+page); !strings.Contains(body, "test-client") {
			t.Error("user page should list consents")
		}
		postAndFollow(t, admin, base, page+"/consents/test-client/revoke", nil)
		if _, err := env.store.Consents().Get(ctx, created.ID, "test-client"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
			t.Error("consent should be revoked")
		}

		// Self-protection: cannot delete or disable yourself, admin flag sticks
		self := "/admin/users/admin-user-id"
		get(t, admin, base+self)
		resp = postForm(t, admin, base, self+"/delete", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("self delete should be 400, got %d", resp.StatusCode)
		}
		get(t, admin, base+self)
		postAndFollow(t, admin, base, self, url.Values{"email": {"admin@example.com"}, "active": {"1"}}) // admin unchecked
		me, _ := env.store.Users().GetByID(ctx, "admin-user-id")
		if !me.Admin {
			t.Error("admin must not be able to drop their own admin flag")
		}
		get(t, admin, base+self)
		resp = postForm(t, admin, base, self, url.Values{"email": {"admin@example.com"}}) // active unchecked
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("disabling yourself should be 400, got %d", resp.StatusCode)
		}

		// Delete another user
		get(t, admin, base+page)
		loc = postAndFollow(t, admin, base, page+"/delete", nil)
		if !strings.HasPrefix(loc, "/admin/users") {
			t.Errorf("expected redirect to list, got %s", loc)
		}
		if _, err := env.store.Users().GetByID(ctx, created.ID); !idperrors.IsCode(err, idperrors.CodeNotFound) {
			t.Error("user should be deleted")
		}
	})
}

var secretRe = regexp.MustCompile(`<code>([A-Za-z0-9_-]{40,})</code>`)

func TestAdmin_Clients(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		ctx := context.Background()
		admin := adminClient(t, env)

		if status, body := get(t, admin, base+"/admin/clients"); status != http.StatusOK || !strings.Contains(body, "test-client") {
			t.Fatalf("client list should include test-client, got %d", status)
		}

		// Validation
		get(t, admin, base+"/admin/clients/new")
		resp := postForm(t, admin, base, "/admin/clients", url.Values{"id": {"bad id"}, "name": {"x"}, "redirect_uris": {"http://a/cb"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("bad client id should be 400, got %d", resp.StatusCode)
		}
		resp = postForm(t, admin, base, "/admin/clients", url.Values{"id": {"ok"}, "name": {"x"}, "redirect_uris": {"not a url"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("bad redirect uri should be 400, got %d", resp.StatusCode)
		}

		// Create confidential client: secret shown once, defaults applied
		resp = postForm(t, admin, base, "/admin/clients", url.Values{
			"id": {"my-app"}, "name": {"My App"},
			"redirect_uris": {"http://localhost:5000/cb\r\nhttp://localhost:5001/cb"},
		})
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected client page with secret, got %d", resp.StatusCode)
		}
		m := secretRe.FindStringSubmatch(string(body))
		if m == nil {
			t.Fatal("secret should be displayed once after creation")
		}
		secret := m[1]
		client, err := env.store.Clients().GetByID(ctx, "my-app")
		if err != nil {
			t.Fatalf("client not created: %v", err)
		}
		if ok, _ := oidc.VerifyClientSecret(client.Secret, secret); !ok || !oidc.IsHashedClientSecret(client.Secret) {
			t.Errorf("stored secret should be a hash of the displayed secret: %q", client.Secret)
		}
		if len(client.RedirectURIs) != 2 || client.Public || len(client.Scopes) == 0 || len(client.GrantTypes) == 0 {
			t.Errorf("client not created as expected: %+v", client)
		}
		storedHash := client.Secret

		// The secret works at the token endpoint (wrong secret is rejected)
		get(t, admin, base+"/admin/clients/my-app")
		if _, body := get(t, admin, base+"/admin/clients/my-app"); strings.Contains(body, secret) {
			t.Error("secret must not be shown on later visits")
		}
		// The page lists the endpoints a relying party needs, built from the issuer
		if _, body := get(t, admin, base+"/admin/clients/my-app"); !strings.Contains(body, "/.well-known/openid-configuration</code>") ||
			!strings.Contains(body, "/authorize</code>") || !strings.Contains(body, "/token</code>") || !strings.Contains(body, "/userinfo</code>") {
			t.Error("client page should list the OIDC endpoints")
		}

		// Update: make first-party, change redirect URIs
		postAndFollow(t, admin, base, "/admin/clients/my-app", url.Values{
			"name": {"My App v2"}, "redirect_uris": {"http://localhost:6000/cb"}, "skip_consent": {"1"},
			"scopes": {"openid"}, "grant_types": {"authorization_code"},
		})
		client, _ = env.store.Clients().GetByID(ctx, "my-app")
		if client.Name != "My App v2" || !client.SkipConsent || client.RedirectURIs[0] != "http://localhost:6000/cb" || client.Secret != storedHash {
			t.Errorf("update not applied (or secret changed): %+v", client)
		}

		// Per-client token lifetimes: "d" is accepted, blank means server default,
		// and the form echoes the stored value back in the same unit.
		postAndFollow(t, admin, base, "/admin/clients/my-app", url.Values{
			"name": {"My App v2"}, "redirect_uris": {"http://localhost:6000/cb"},
			"access_token_ttl": {"5m"}, "refresh_token_ttl": {"30d"},
		})
		client, _ = env.store.Clients().GetByID(ctx, "my-app")
		if client.AccessTokenTTL != 5*time.Minute || client.RefreshTokenTTL != 30*24*time.Hour {
			t.Errorf("token TTLs not stored: access=%v refresh=%v", client.AccessTokenTTL, client.RefreshTokenTTL)
		}
		if _, body := get(t, admin, base+"/admin/clients/my-app"); !strings.Contains(body, `value="5m"`) || !strings.Contains(body, `value="30d"`) {
			t.Error("client form should echo the stored lifetimes")
		}
		resp = postForm(t, admin, base, "/admin/clients/my-app", url.Values{
			"name": {"My App v2"}, "redirect_uris": {"http://localhost:6000/cb"}, "access_token_ttl": {"soon"},
		})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid lifetime should be rejected, got %d", resp.StatusCode)
		}
		postAndFollow(t, admin, base, "/admin/clients/my-app", url.Values{
			"name": {"My App v2"}, "redirect_uris": {"http://localhost:6000/cb"}, "access_token_ttl": {""}, "refresh_token_ttl": {""},
		})
		client, _ = env.store.Clients().GetByID(ctx, "my-app")
		if client.AccessTokenTTL != 0 || client.RefreshTokenTTL != 0 {
			t.Errorf("blank lifetimes should reset to server default: %+v", client)
		}

		// Regenerate secret
		get(t, admin, base+"/admin/clients/my-app")
		resp = postForm(t, admin, base, "/admin/clients/my-app/secret", nil)
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		m = secretRe.FindStringSubmatch(string(body))
		if resp.StatusCode != http.StatusOK || m == nil || m[1] == secret {
			t.Fatalf("regenerate should show a new secret, got %d", resp.StatusCode)
		}
		client, _ = env.store.Clients().GetByID(ctx, "my-app")
		if ok, _ := oidc.VerifyClientSecret(client.Secret, m[1]); !ok || client.Secret == storedHash {
			t.Error("new secret hash should be stored")
		}
		if ok, _ := oidc.VerifyClientSecret(client.Secret, secret); ok {
			t.Error("old secret must no longer verify")
		}

		// Public client has no secret
		get(t, admin, base+"/admin/clients/new")
		resp = postForm(t, admin, base, "/admin/clients", url.Values{"id": {"spa"}, "name": {"SPA"}, "redirect_uris": {"http://localhost:3000/cb"}, "public": {"1"}})
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if secretRe.MatchString(string(body)) {
			t.Error("public client should not get a secret")
		}
		spa, _ := env.store.Clients().GetByID(ctx, "spa")
		if spa == nil || !spa.Public || spa.Secret != "" {
			t.Errorf("public client wrong: %+v", spa)
		}

		// Revoke tokens + delete
		env.store.Tokens().Create(ctx, &domain.Token{ID: "tok", UserID: env.testUser.ID, ClientID: "my-app", ExpiresAt: time.Now().Add(time.Hour)})
		get(t, admin, base+"/admin/clients/my-app")
		postAndFollow(t, admin, base, "/admin/clients/my-app/revoke-tokens", nil)
		if tok, _ := env.store.Tokens().GetByID(ctx, "tok"); !tok.Revoked {
			t.Error("client tokens should be revoked")
		}
		get(t, admin, base+"/admin/clients/my-app")
		postAndFollow(t, admin, base, "/admin/clients/my-app/delete", nil)
		if _, err := env.store.Clients().GetByID(ctx, "my-app"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
			t.Error("client should be deleted")
		}
	})
}

func TestAdmin_Keys(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		ctx := context.Background()
		admin := adminClient(t, env)

		before, _ := env.keyService.GetActiveKey(ctx)
		status, body := get(t, admin, base+"/admin/keys")
		if status != http.StatusOK || !strings.Contains(body, before.Kid) {
			t.Fatalf("keys page should list the active key, got %d", status)
		}

		postAndFollow(t, admin, base, "/admin/keys/rotate", nil)
		after, _ := env.keyService.GetActiveKey(ctx)
		if after.Kid == before.Kid {
			t.Error("rotate should activate a new key")
		}
		_, body = get(t, admin, base+"/admin/keys")
		if !strings.Contains(body, before.Kid) || !strings.Contains(body, after.Kid) || !strings.Contains(body, "retiring") {
			t.Error("keys page should list both keys with the old one retiring")
		}
	})
}

func TestAdmin_Groups(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		ctx := context.Background()
		admin := adminClient(t, env)

		status, body := get(t, admin, base+"/admin/groups")
		if status != http.StatusOK || !strings.Contains(body, "devs") || !strings.Contains(body, "<code>groups</code>") {
			t.Fatalf("groups list should show existing groups and claim name, got %d", status)
		}

		// Create, duplicate rejected
		get(t, admin, base+"/admin/groups/new")
		loc := postAndFollow(t, admin, base, "/admin/groups", url.Values{"name": {"cluster-admins"}, "description": {"Full access"}})
		grp, err := env.store.Groups().GetByName(ctx, "cluster-admins")
		if err != nil || !strings.HasPrefix(loc, "/admin/groups/"+grp.ID) {
			t.Fatalf("group not created: %v %s", err, loc)
		}
		get(t, admin, base+"/admin/groups/new")
		resp := postForm(t, admin, base, "/admin/groups", url.Values{"name": {"Cluster-Admins"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("duplicate group name should be 400, got %d", resp.StatusCode)
		}

		// Add member by email, unknown email flashes an error
		page := "/admin/groups/" + grp.ID
		get(t, admin, base+page)
		postAndFollow(t, admin, base, page+"/members", url.Values{"email": {"test@example.com"}})
		if ids, _ := env.store.Groups().MemberIDs(ctx, grp.ID); len(ids) != 1 || ids[0] != env.testUser.ID {
			t.Errorf("member not added: %v", ids)
		}
		get(t, admin, base+page)
		loc = postAndFollow(t, admin, base, page+"/members", url.Values{"email": {"nobody@example.com"}})
		if !strings.Contains(loc, "No+user") {
			t.Errorf("unknown email should flash, got %s", loc)
		}
		if _, body := get(t, admin, base+page); !strings.Contains(body, "test@example.com") {
			t.Error("group page should list members")
		}

		// Update name; remove member
		postAndFollow(t, admin, base, page, url.Values{"name": {"admins"}, "description": {"renamed"}})
		if g, _ := env.store.Groups().GetByID(ctx, grp.ID); g.Name != "admins" {
			t.Errorf("rename not applied: %+v", g)
		}
		get(t, admin, base+page)
		postAndFollow(t, admin, base, page+"/members/"+env.testUser.ID+"/remove", nil)
		if ids, _ := env.store.Groups().MemberIDs(ctx, grp.ID); len(ids) != 0 {
			t.Errorf("member not removed: %v", ids)
		}

		// User page: checkboxes set membership
		userPage := "/admin/users/" + env.testUser.ID
		if _, body := get(t, admin, base+userPage); !strings.Contains(body, `value="`+grp.ID+`"`) || !strings.Contains(body, `value="grp-devs" checked`) {
			t.Error("user page should list all groups with current membership checked")
		}
		postAndFollow(t, admin, base, userPage+"/groups", url.Values{"group": {grp.ID, "grp-ops"}}) // drop devs, add admins+ops
		mine, _ := env.store.Groups().GroupsForUser(ctx, env.testUser.ID)
		if len(mine) != 2 || mine[0].Name != "admins" || mine[1].Name != "ops" {
			t.Errorf("membership not updated from user page: %v", groupNames(mine))
		}

		// Delete group
		get(t, admin, base+page)
		postAndFollow(t, admin, base, page+"/delete", nil)
		if _, err := env.store.Groups().GetByID(ctx, grp.ID); !idperrors.IsCode(err, idperrors.CodeNotFound) {
			t.Error("group should be deleted")
		}
		if mine, _ := env.store.Groups().GroupsForUser(ctx, env.testUser.ID); len(mine) != 1 {
			t.Errorf("deleted group should be removed from members, got %v", groupNames(mine))
		}
	})
}

func groupNames(groups []*domain.Group) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g.Name
	}
	return out
}

func TestAdmin_UserSessionsAndTokens(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		ctx := context.Background()
		admin := adminClient(t, env)

		// Two browser sessions for the test user, one refresh token
		s1 := newClientWithCookies()
		loginAs(t, s1, base, "test@example.com", "password123")
		s2 := newClientWithCookies()
		loginAs(t, s2, base, "test@example.com", "password123")
		tokens := pkceAuthorize(t, s1, base, "openid offline_access")
		if tokens.RefreshToken == "" {
			t.Fatal("expected a refresh token")
		}

		page := "/admin/users/" + env.testUser.ID
		_, body := get(t, admin, base+page)
		sessions, _ := env.store.Sessions().ListByUserID(ctx, env.testUser.ID)
		if len(sessions) != 2 {
			t.Fatalf("expected 2 sessions, got %d", len(sessions))
		}
		if !strings.Contains(body, "/sessions/"+sessions[0].ID+"/revoke") || !strings.Contains(body, "/tokens/"+tokens.RefreshToken+"/revoke") {
			t.Error("user page should list sessions and tokens with revoke actions")
		}

		// Revoke one session: that browser is signed out, the other still works
		postAndFollow(t, admin, base, page+"/sessions/"+sessions[1].ID+"/revoke", nil)
		if left, _ := env.store.Sessions().ListByUserID(ctx, env.testUser.ID); len(left) != 1 {
			t.Errorf("expected 1 session after revoke, got %d", len(left))
		}

		// Revoke the refresh token: it no longer refreshes
		get(t, admin, base+page)
		postAndFollow(t, admin, base, page+"/tokens/"+tokens.RefreshToken+"/revoke", nil)
		resp, _ := http.PostForm(base+"/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.RefreshToken}, "client_id": {"public-client"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("revoked refresh token should be rejected, got %d", resp.StatusCode)
		}

		// A session belonging to another user cannot be revoked through this user's page
		other, _ := env.store.Sessions().ListByUserID(ctx, "admin-user-id")
		get(t, admin, base+page)
		loc := postAndFollow(t, admin, base, page+"/sessions/"+other[0].ID+"/revoke", nil)
		if !strings.Contains(loc, "not+found") {
			t.Errorf("cross-user session revoke should be refused, got %s", loc)
		}
		if _, err := env.store.Sessions().GetByID(ctx, other[0].ID); err != nil {
			t.Error("admin's own session must be untouched")
		}
	})
}

func TestAdmin_AuditLog(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		ctx := context.Background()

		// Produce a spread of events: failed + successful login, consent, admin change, logout
		bad := newClientWithCookies()
		resp, _ := bad.Get(base + "/login")
		resp.Body.Close()
		resp, _ = bad.PostForm(base+"/login", url.Values{"email": {"test@example.com"}, "password": {"wrong"}, "csrf_token": {csrfCookie(bad, base)}})
		resp.Body.Close()

		user := newClientWithCookies()
		loginAs(t, user, base, "test@example.com", "password123")
		params := url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"openid"}}
		resp, _ = user.Get(base + "/authorize?" + params.Encode())
		resp.Body.Close()
		submitConsent(t, user, base, params.Encode(), "allow").Body.Close()
		resp, _ = user.Get(base + "/logout")
		resp.Body.Close()

		admin := adminClient(t, env)
		get(t, admin, base+"/admin/groups/new")
		postAndFollow(t, admin, base, "/admin/groups", url.Values{"name": {"audited"}})

		events, _ := env.store.Audit().List(ctx, 50)
		seen := map[string]*domain.AuditEvent{}
		for _, e := range events {
			if _, ok := seen[e.Action]; !ok {
				seen[e.Action] = e
			}
		}
		for _, want := range []string{"login.failure", "login.success", "consent.granted", "logout", "group.created"} {
			if seen[want] == nil {
				t.Errorf("expected an audit event %q, have %v", want, actions(events))
			}
		}
		if e := seen["login.failure"]; e != nil && (e.ActorID != "" || e.ActorEmail != "test@example.com" || e.IP == "") {
			t.Errorf("failed login should record the attempted email and IP without an actor ID: %+v", e)
		}
		if e := seen["group.created"]; e != nil && (e.ActorEmail != "admin@example.com" || e.TargetType != "group" || e.Detail != "audited") {
			t.Errorf("admin event should carry the acting admin and target: %+v", e)
		}
		if e := seen["consent.granted"]; e != nil && (e.TargetID != "test-client" || e.Detail != "openid") {
			t.Errorf("consent event should name the client and scope: %+v", e)
		}

		// The page renders them
		status, body := get(t, admin, base+"/admin/audit")
		if status != http.StatusOK || !strings.Contains(body, "login.failure") || !strings.Contains(body, "group.created") {
			t.Errorf("audit page should list events, got %d", status)
		}
	})
}

func actions(events []*domain.AuditEvent) []string {
	out := make([]string, len(events))
	for i, e := range events {
		out[i] = e.Action
	}
	return out
}
