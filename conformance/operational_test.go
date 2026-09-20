//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-jose/go-jose/v4"
)

// Operational validation (design §25): what happens to identity state
// across restarts, backups, key rotation, upgrades and behind a reverse
// proxy. Each test starts its own instance(s); none uses the default
// server. Selected with -run Operational (make validate-operational) and
// excluded from the protocol suite with -skip Operational.

// grant is what a relying party holds after one login: the browser session
// (cookie jar), the tokens and the key that signed them.
type grant struct {
	client  *http.Client
	access  string
	refresh string
	idToken string
	kid     string
	sub     string
}

// loginAndExchange runs a complete flow for the confidential client with a
// fresh browser (login + consent) and returns everything issued.
func loginAndExchange(t *testing.T, p *provider) grant {
	t.Helper()
	c := p.newHTTPClient(t)
	resp, body := p.authorize(t, c, authzParams(cfg.ClientID, cfg.RedirectURI, "openid profile email offline_access", "st", "nn", ""))
	q := callback(t, resp, body, cfg.RedirectURI)
	if q.Get("code") == "" {
		t.Fatalf("no code: %v", q)
	}
	tr := p.exchange(t, q.Get("code"), "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
	if tr.Status != 200 {
		t.Fatalf("token: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
	}
	claims := p.mustVerifyIDToken(t, tr.str("id_token"), idTokenExpectation{Issuer: p.discovery(t).Issuer, ClientID: cfg.ClientID, Nonce: "nn"})
	sig, err := jose.ParseSigned(tr.str("id_token"), allowedAlgs)
	if err != nil {
		t.Fatal(err)
	}
	sub, _ := claims["sub"].(string)
	return grant{client: c, access: tr.str("access_token"), refresh: tr.str("refresh_token"), idToken: tr.str("id_token"), kid: sig.Signatures[0].Header.KeyID, sub: sub}
}

// activeKID returns the kid a freshly issued token carries, i.e. the key
// the server currently signs with.
func activeKID(t *testing.T, p *provider) string {
	t.Helper()
	return loginAndExchange(t, p).kid
}

// jwksKIDs lists the kids the provider publishes.
func jwksKIDs(t *testing.T, p *provider) []string {
	t.Helper()
	_, set := p.fetchJWKS(t)
	var kids []string
	for _, k := range set.Keys {
		kids = append(kids, k.KeyID)
	}
	return kids
}

// expectUserinfo asserts that the access token is (or is not) accepted.
func expectUserinfo(t *testing.T, p *provider, access string, ok bool) {
	t.Helper()
	resp, body := p.userinfo(t, "Bearer "+access)
	if ok && resp.StatusCode != http.StatusOK {
		t.Errorf("userinfo: HTTP %d, want 200: %s", resp.StatusCode, redact(snippet(body)))
	}
	if !ok && resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("userinfo: HTTP %d, want 401", resp.StatusCode)
	}
}

// revokeAccessToken revokes the confidential client's access token at the
// revocation endpoint.
func revokeAccessToken(t *testing.T, p *provider, access string) {
	t.Helper()
	ep, _ := p.discovery(t).raw["revocation_endpoint"].(string)
	if ep == "" {
		t.Skip("no revocation_endpoint advertised")
	}
	req, _ := http.NewRequest(http.MethodPost, ep, strings.NewReader(url.Values{"token": {access}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	if resp, body := send(t, p.client, req); resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: HTTP %d: %s", resp.StatusCode, redact(snippet(body)))
	}
}

// refresh redeems a refresh token and returns the new refresh token.
func refresh(t *testing.T, p *provider, token string) tokenResponse {
	t.Helper()
	return p.tokenRequest(t, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}}, &[2]string{cfg.ClientID, cfg.ClientSecret})
}

// resumeWithSession sends an authorization request with an existing browser
// session and asserts that it completes without a login or consent page.
func resumeWithSession(t *testing.T, p *provider, c *http.Client) {
	t.Helper()
	params := authzParams(cfg.ClientID, cfg.RedirectURI, "openid profile email offline_access", "again", "", "")
	resp, body := get(t, c, p.discovery(t).AuthorizationEndpoint+"?"+params.Encode())
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), cfg.RedirectURI) {
		t.Fatalf("existing session was not honoured: HTTP %d %s %s", resp.StatusCode, resp.Header.Get("Location"), redact(snippet(body)))
	}
	if q := callback(t, resp, body, cfg.RedirectURI); q.Get("code") == "" {
		t.Errorf("no code on resumed authorization: %v", q)
	}
}

// forEachStoreDriver runs fn against a sqlite and a file-backed instance.
// The two are independent servers on their own ports and directories, so
// they run concurrently; only the grace-period sleeps overlap.
func forEachStoreDriver(t *testing.T, fn func(t *testing.T, env map[string]string)) {
	for _, driver := range []string{"sqlite", "file"} {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()
			fn(t, map[string]string{"IDPICO_STORE_DRIVER": driver})
		})
	}
}

// TestOperationalRestart: everything a relying party and a user hold stays
// valid across a server restart — the signing key (kid), issued tokens,
// refresh tokens, the browser session and the remembered consent — with
// IDPICO_COOKIE_SECRET left unset both times, since sessions are opaque
// server-side records and do not depend on it.
func TestOperationalRestart(t *testing.T) {
	forEachStoreDriver(t, func(t *testing.T, env map[string]string) {
		inst := startInstance(t, "", env)
		p := inst.provider()

		before := loginAndExchange(t, p)
		kidsBefore := jwksKIDs(t, p)
		revoked := loginAndExchange(t, p)
		revokeAccessToken(t, p, revoked.access)

		inst.restart(t, nil)

		t.Run("signing_key", func(t *testing.T) {
			if got := jwksKIDs(t, p); strings.Join(got, ",") != strings.Join(kidsBefore, ",") {
				t.Errorf("JWKS changed across restart: %v -> %v", kidsBefore, got)
			}
			if kid := activeKID(t, p); kid != before.kid {
				t.Errorf("active kid changed across restart: %s -> %s", before.kid, kid)
			}
		})
		t.Run("access_token", func(t *testing.T) { expectUserinfo(t, p, before.access, true) })
		t.Run("revocation_survives", func(t *testing.T) { expectUserinfo(t, p, revoked.access, false) })
		t.Run("refresh_token", func(t *testing.T) {
			if tr := refresh(t, p, before.refresh); tr.Status != 200 {
				t.Errorf("refresh after restart: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
			}
		})
		t.Run("session_and_consent", func(t *testing.T) { resumeWithSession(t, p, before.client) })
		t.Run("users_and_clients", func(t *testing.T) {
			after := loginAndExchange(t, p) // fresh login: user, password, client secret, redirect URI
			if after.sub != before.sub {
				t.Errorf("sub changed across restart: %s -> %s", before.sub, after.sub)
			}
		})
	})
}

// TestOperationalBackupRestore: a copy of the data directory taken after a
// clean stop is a complete backup — restoring it elsewhere brings back the
// signing key, users, clients and live tokens.
func TestOperationalBackupRestore(t *testing.T) {
	forEachStoreDriver(t, func(t *testing.T, env map[string]string) {
		inst := startInstance(t, "", env)
		p := inst.provider()
		before := loginAndExchange(t, p)
		inst.stop()

		if env["IDPICO_STORE_DRIVER"] == "sqlite" {
			for _, f := range []string{"idpico.db-wal", "idpico.db-shm"} {
				if _, err := os.Stat(filepath.Join(inst.dataDir, f)); err == nil {
					t.Errorf("%s left behind after a clean stop; a file copy would not be self-contained", f)
				}
			}
		}

		backup := filepath.Join(t.TempDir(), "restore")
		if out, err := exec.Command("cp", "-a", inst.dataDir, backup).CombinedOutput(); err != nil {
			t.Fatalf("cp -a: %v: %s", err, out)
		}

		// Same port, so the issuer (and iss in the old tokens) is unchanged.
		restored := &instance{dataDir: backup, workDir: t.TempDir(), port: inst.port, env: map[string]string{}, logPath: filepath.Join(t.TempDir(), "server.log")}
		for k, v := range env {
			restored.env[k] = v
		}
		restored.restart(t, nil)
		t.Cleanup(restored.stop)
		rp := restored.provider()

		if kid := activeKID(t, rp); kid != before.kid {
			t.Errorf("restored instance signs with %s, backup had %s", kid, before.kid)
		}
		expectUserinfo(t, rp, before.access, true)
		if tr := refresh(t, rp, before.refresh); tr.Status != 200 {
			t.Errorf("refresh on restored instance: HTTP %d", tr.Status)
		}
		resumeWithSession(t, rp, before.client)
	})
}
