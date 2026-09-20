//go:build conformance

package conformance

import (
	"database/sql"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	_ "modernc.org/sqlite" // read-only look at goose_db_version; the same driver idpico uses
)

// TestOperationalUpgrade: the current build starts on a data directory that
// a previous release wrote, applies its migrations forward, and the
// signing key, user (password hash), client (secret hash) and consent that
// release wrote keep working. The previous release is built from its git
// tag at test time and writes the data itself — nothing is checked in.
// Rollback (running the old release on the migrated directory) is not
// supported and not tested.
//
// UPGRADE_FROM=v0.0.5,v0.0.4 selects the releases; the default is the two
// most recent tags before the current build.
func TestOperationalUpgrade(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range upgradeSources(t, root) {
		t.Run(tag, func(t *testing.T) {
			old := buildRelease(t, root, tag)
			dataDir := t.TempDir()

			// The previous release runs first and produces a real
			// installation: its schema, its signing key, its password and
			// secret hashes, one login with consent and a refresh token.
			prev := &instance{dataDir: dataDir, workDir: t.TempDir(), env: map[string]string{}, binary: old}
			prev.logPath = filepath.Join(prev.workDir, "server.log")
			var perr error
			if prev.port, perr = freePort(); perr != nil {
				t.Fatal(perr)
			}
			prev.restart(t, nil)
			t.Cleanup(prev.stop)
			pp := prev.provider()
			before := loginAndExchange(t, pp)
			versionBefore := appliedMigration(t, filepath.Join(dataDir, "idpico.db"))
			prev.stop()

			// Now the current build, on the same directory and port.
			cur := &instance{dataDir: dataDir, workDir: t.TempDir(), port: prev.port, env: map[string]string{}}
			cur.logPath = filepath.Join(cur.workDir, "server.log")
			cur.restart(t, nil)
			t.Cleanup(cur.stop)
			p := cur.provider()

			t.Run("migrations_applied", func(t *testing.T) {
				want := latestMigration(t, filepath.Join(root, "internal", "store", "migrations", "sqlite"))
				got := appliedMigration(t, filepath.Join(dataDir, "idpico.db"))
				if got != want {
					t.Errorf("goose_db_version = %d after start, want %d (the newest migration on disk)", got, want)
				}
				if got < versionBefore {
					t.Errorf("version went backwards: %d -> %d", versionBefore, got)
				}
				t.Logf("%s wrote schema version %d; current build migrated it to %d", tag, versionBefore, got)
			})
			t.Run("signing_key_kept", func(t *testing.T) {
				if kids := jwksKIDs(t, p); len(kids) != 1 || kids[0] != before.kid {
					t.Errorf("JWKS = %v, want the %s key %s", kids, tag, before.kid)
				}
				if kid := activeKID(t, p); kid != before.kid {
					t.Errorf("signing with %s, want the %s key %s", kid, tag, before.kid)
				}
				expectUserinfo(t, p, before.access, true) // issued by the old release
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
				// The refresh token the old release issued still rotates.
				if rt := refresh(t, p, before.refresh); rt.Status != 200 {
					t.Errorf("refresh token from %s: HTTP %d: %s", tag, rt.Status, redact(string(rt.Raw)))
				}
			})
		})
	}
}

// oldestUpgradeSource is the first release whose data directory the
// current build supports upgrading from (v0.0.3 introduced the IDPICO_*
// configuration the harness uses).
const oldestUpgradeSource = "v0.0.3"

var releaseTag = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// upgradeSources lists the release tags to upgrade from: UPGRADE_FROM, or
// the two newest tags at or after oldestUpgradeSource (excluding a tag
// that points at the current commit — that is not an upgrade).
func upgradeSources(t *testing.T, root string) []string {
	t.Helper()
	if v := os.Getenv("UPGRADE_FROM"); v != "" {
		return strings.Split(v, ",")
	}
	out, err := exec.Command("git", "-C", root, "tag", "--list", "v*").Output()
	if err != nil {
		t.Skipf("git tags unavailable (%v); set UPGRADE_FROM or fetch tags", err)
	}
	head, _ := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	var tags []string
	for _, tag := range strings.Fields(string(out)) {
		if !releaseTag.MatchString(tag) || versionLess(tag, oldestUpgradeSource) {
			continue
		}
		if c, _ := exec.Command("git", "-C", root, "rev-parse", tag+"^{commit}").Output(); string(c) == string(head) {
			continue
		}
		tags = append(tags, tag)
	}
	sort.Slice(tags, func(i, j int) bool { return versionLess(tags[j], tags[i]) }) // newest first
	if len(tags) == 0 {
		t.Skipf("no release tags at or after %s (shallow clone?); set UPGRADE_FROM or fetch tags", oldestUpgradeSource)
	}
	if len(tags) > 2 {
		tags = tags[:2]
	}
	return tags
}

func versionLess(a, b string) bool {
	pa, pb := releaseTag.FindStringSubmatch(a), releaseTag.FindStringSubmatch(b)
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return false
}

// buildRelease builds ./cmd/idpico from the given git tag and returns the
// binary's path. Sources come from git archive, so the working tree's
// uncommitted changes play no part.
func buildRelease(t *testing.T, root, tag string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	archive := exec.Command("git", "-C", root, "archive", "--format=tar", tag)
	untar := exec.Command("tar", "-x", "-C", src)
	pipe, err := archive.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	untar.Stdin = pipe
	if err := untar.Start(); err != nil {
		t.Fatal(err)
	}
	if err := archive.Run(); err != nil {
		t.Fatalf("git archive %s: %v", tag, err)
	}
	if err := untar.Wait(); err != nil {
		t.Fatalf("extract %s: %v", tag, err)
	}
	bin := filepath.Join(dir, "idpico-"+tag)
	build := exec.Command("go", "build", "-o", bin, "./cmd/idpico")
	build.Dir = src
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", tag, err, out)
	}
	return bin
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
