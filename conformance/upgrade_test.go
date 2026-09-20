//go:build conformance

package conformance

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // read-only look at goose_db_version; the same driver idpico uses
)

// upgradeFixture describes a data directory written by a previous release
// (scripts/upgrade-fixture.sh).
type upgradeFixture struct {
	Version      string `json:"version"`
	KID          string `json:"kid"`
	UserEmail    string `json:"user_email"`
	UserPassword string `json:"user_password"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RedirectURI  string `json:"redirect_uri"`
}

// TestOperationalUpgrade: the current release starts on a data directory
// from the previous release, applies its migrations forward, and the
// signing key, user (password hash), client (secret hash) and consent that
// release wrote keep working. Rollback (running the old release on the
// migrated directory) is not supported and not tested.
func TestOperationalUpgrade(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	fixtures, _ := filepath.Glob(filepath.Join("testdata", "upgrade", "*", "fixture.json"))
	if len(fixtures) == 0 {
		t.Skip("no upgrade fixtures under testdata/upgrade (scripts/upgrade-fixture.sh <tag>)")
	}
	for _, fixturePath := range fixtures {
		var fx upgradeFixture
		if b, err := os.ReadFile(fixturePath); err != nil {
			t.Fatal(err)
		} else if err := json.Unmarshal(b, &fx); err != nil {
			t.Fatal(err)
		}
		t.Run(fx.Version, func(t *testing.T) {
			if fx.UserEmail != cfg.UserEmail || fx.ClientID != cfg.ClientID || fx.RedirectURI != cfg.RedirectURI {
				t.Skipf("fixture was made for other credentials than this run's (%s / %s)", fx.UserEmail, fx.ClientID)
			}
			dataDir := t.TempDir()
			src := filepath.Join(filepath.Dir(fixturePath), "idpico.db")
			db, err := os.ReadFile(src)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dataDir, "idpico.db"), db, 0o600); err != nil {
				t.Fatal(err)
			}

			inst := startInstance(t, dataDir, nil)
			p := inst.provider()

			t.Run("migrations_applied", func(t *testing.T) {
				want := latestMigration(t, filepath.Join(root, "internal", "store", "migrations", "sqlite"))
				got := appliedMigration(t, filepath.Join(dataDir, "idpico.db"))
				if got != want {
					t.Errorf("goose_db_version = %d after start, want %d (the newest migration on disk)", got, want)
				}
			})
			t.Run("signing_key_kept", func(t *testing.T) {
				if kids := jwksKIDs(t, p); len(kids) != 1 || kids[0] != fx.KID {
					t.Errorf("JWKS = %v, want the %s key %s", kids, fx.Version, fx.KID)
				}
				if kid := activeKID(t, p); kid != fx.KID {
					t.Errorf("signing with %s, want the %s key %s", kid, fx.Version, fx.KID)
				}
			})
			t.Run("user_client_and_consent_kept", func(t *testing.T) {
				// A fresh browser: the password hash and client secret hash
				// written by the old release must verify, and the consent it
				// recorded must spare the user the consent page.
				c := p.newHTTPClient(t)
				params := authzParams(cfg.ClientID, cfg.RedirectURI, "openid profile email offline_access", "up", "", "")
				authURL := p.discovery(t).AuthorizationEndpoint + "?" + params.Encode()
				resp, body := get(t, c, authURL)
				if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "/login") {
					t.Fatalf("expected the login page, got HTTP %d %s", resp.StatusCode, resp.Header.Get("Location"))
				}
				next := login(t, c, resolve(t, authURL, resp.Header.Get("Location")))
				resp, body = get(t, c, next)
				if resp.StatusCode == http.StatusOK && strings.Contains(string(body), `action="/consent"`) {
					t.Fatal("consent page shown although the old release recorded consent for these scopes")
				}
				q := callback(t, resp, body, cfg.RedirectURI)
				tr := p.exchange(t, q.Get("code"), "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
				if tr.Status != 200 {
					t.Fatalf("token: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
				}
				p.mustVerifyIDToken(t, tr.str("id_token"), idTokenExpectation{Issuer: p.discovery(t).Issuer, ClientID: cfg.ClientID})
			})
		})
	}
}

var migrationFile = regexp.MustCompile(`^(\d+)_.*\.sql$`)

// latestMigration is the highest migration number shipped in dir.
func latestMigration(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	latest := 0
	for _, e := range entries {
		if m := migrationFile.FindStringSubmatch(e.Name()); m != nil {
			if n, _ := strconv.Atoi(m[1]); n > latest {
				latest = n
			}
		}
	}
	if latest == 0 {
		t.Fatalf("no migrations in %s", dir)
	}
	return latest
}

// appliedMigration reads goose's version table from the database file.
func appliedMigration(t *testing.T, path string) int {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v int
	if err := db.QueryRow("SELECT COALESCE(MAX(version_id), 0) FROM goose_db_version").Scan(&v); err != nil {
		t.Fatalf("goose_db_version: %v", err)
	}
	return v
}
