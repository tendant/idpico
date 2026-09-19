package http

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tendant/idpico/internal/auth"
	"github.com/tendant/idpico/internal/domain"
)

func TestAccountPage(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		ctx := context.Background()
		me := env.testUser.ID

		// Anonymous: sent to login with a return URL.
		anon := newClientWithCookies()
		anon.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, _ := anon.Get(base + "/account")
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/login?return_url=%2Faccount") {
			t.Fatalf("anonymous /account: got %d -> %s", resp.StatusCode, resp.Header.Get("Location"))
		}

		// A plain (non-admin) user signs in from two browsers and holds tokens
		// and consents; another user's data must never show up or be touchable.
		me1 := newClientWithCookies()
		loginAs(t, me1, base, "test@example.com", "password123")
		me2 := newClientWithCookies()
		loginAs(t, me2, base, "test@example.com", "password123")
		other := newClientWithCookies()
		loginAs(t, other, base, "admin@example.com", "password123")

		mine := &domain.Token{ID: "rt-mine", UserID: me, ClientID: "test-client", Scope: "openid offline_access", ExpiresAt: time.Now().Add(time.Hour)}
		theirs := &domain.Token{ID: "rt-theirs", UserID: "admin-user-id", ClientID: "test-client", Scope: "openid offline_access", ExpiresAt: time.Now().Add(time.Hour)}
		env.store.Tokens().Create(ctx, mine)
		env.store.Tokens().Create(ctx, theirs)
		env.store.Consents().Upsert(ctx, &domain.Consent{ID: "c-mine", UserID: me, ClientID: "test-client", Scopes: []string{"openid"}, GrantedAt: time.Now()})

		status, body := get(t, me1, base+"/account")
		if status != http.StatusOK {
			t.Fatalf("/account: %d", status)
		}
		for _, want := range []string{"test@example.com", "this browser", "rt-mine", "/account/consents/test-client/revoke", "Change password"} {
			if !strings.Contains(body, want) {
				t.Errorf("/account should contain %q", want)
			}
		}
		if strings.Contains(body, "rt-theirs") || strings.Contains(body, "admin@example.com") {
			t.Error("/account must not show another user's data")
		}
		if strings.Count(body, "/account/sessions/") < 2 {
			t.Error("/account should list both of the user's sessions")
		}

		// Cannot revoke someone else's token, even by id.
		postAndFollow(t, me1, base, "/account/tokens/rt-theirs/revoke", nil)
		if tok, _ := env.store.Tokens().GetByID(ctx, "rt-theirs"); tok.Revoked {
			t.Error("must not revoke another user's token")
		}

		// Revoke own token and consent.
		postAndFollow(t, me1, base, "/account/tokens/rt-mine/revoke", nil)
		if tok, _ := env.store.Tokens().GetByID(ctx, "rt-mine"); !tok.Revoked {
			t.Error("own token should be revoked")
		}
		postAndFollow(t, me1, base, "/account/consents/test-client/revoke", nil)
		if _, err := env.store.Consents().Get(ctx, me, "test-client"); err == nil {
			t.Error("consent should be gone")
		}

		// Sign out everywhere else: browser 2 loses its session, browser 1 keeps it.
		postAndFollow(t, me1, base, "/account/sessions/revoke-others", nil)
		if status, _ := get(t, me1, base+"/account"); status != http.StatusOK {
			t.Errorf("current session should survive revoke-others, got %d", status)
		}
		me2.CheckRedirect = anon.CheckRedirect
		resp, _ = me2.Get(base + "/account")
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Errorf("other session should be signed out, got %d", resp.StatusCode)
		}
		if status, _ := get(t, other, base+"/account"); status != http.StatusOK {
			t.Errorf("another user's session must be untouched, got %d", status)
		}

		// Password change: wrong current password is refused; a good one signs
		// the user out and the new password works.
		resp = postForm(t, me1, base, "/account/password", url.Values{"current_password": {"nope"}, "new_password": {"n3w-password"}, "confirm_password": {"n3w-password"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("wrong current password: got %d", resp.StatusCode)
		}
		resp = postForm(t, me1, base, "/account/password", url.Values{"current_password": {"password123"}, "new_password": {"n3w-password"}, "confirm_password": {"different"}})
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("mismatched confirmation: got %d", resp.StatusCode)
		}
		loc := postAndFollow(t, me1, base, "/account/password", url.Values{"current_password": {"password123"}, "new_password": {"n3w-password"}, "confirm_password": {"n3w-password"}})
		if !strings.HasPrefix(loc, "/login?message=") {
			t.Errorf("password change should send the user to login, got %s", loc)
		}
		user, _ := env.store.Users().GetByID(ctx, me)
		if ok, _ := auth.VerifyPassword("n3w-password", user.PasswordHash); !ok {
			t.Error("new password should be stored")
		}
		fresh := newClientWithCookies()
		loginAs(t, fresh, base, "test@example.com", "n3w-password")
	})
}
