//go:build conformance

package conformance

import (
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// TestOperationalKeyRotation: a rotation publishes the new key next to the
// old one, tokens signed by the old key keep verifying for the grace
// period and are refused afterwards, the expired key leaves the JWKS, and
// changing the signing algorithm across a restart is a rotation too.
func TestOperationalKeyRotation(t *testing.T) {
	forEachStoreDriver(t, func(t *testing.T, env map[string]string) {
		inst := startInstance(t, "", env)
		p := inst.provider()

		g1 := loginAndExchange(t, p)
		k1 := g1.kid
		if kids := jwksKIDs(t, p); len(kids) != 1 || kids[0] != k1 {
			t.Fatalf("fresh instance should publish exactly its active key %s, got %v", k1, kids)
		}

		// Rotate with the CLI while the server is down (required for the
		// file driver, deterministic for sqlite: the server caches the
		// active key for a minute).
		const grace = 6 * time.Second
		inst.stop()
		rotatedAt := time.Now()
		out := inst.idpicoctl(t, "key", "rotate", "-grace", grace.String())
		if !strings.Contains(out, "active key is now") {
			t.Fatalf("unexpected rotate output: %s", out)
		}
		inst.restart(t, nil)

		var k2 string
		t.Run("new_key_published_next_to_old", func(t *testing.T) {
			kids := jwksKIDs(t, p)
			if len(kids) != 2 || !contains(kids, k1) {
				t.Fatalf("JWKS after rotation = %v, want the old key %s and one new key", kids, k1)
			}
			k2 = activeKID(t, p)
			if k2 == k1 || !contains(kids, k2) {
				t.Fatalf("new tokens are signed with %s; JWKS %v; old %s", k2, kids, k1)
			}
			raw, _ := p.fetchJWKS(t)
			assertNoSecrets(t, "JWKS", raw)
			for _, m := range []string{`"d"`, `"p"`, `"q"`} {
				if strings.Contains(string(raw), m) {
					t.Errorf("JWKS exposes private member %s", m)
				}
			}
		})
		if k2 == "" {
			return
		}

		t.Run("old_token_valid_during_grace", func(t *testing.T) {
			expectUserinfo(t, p, g1.access, true)
		})

		g2 := loginAndExchange(t, p)
		time.Sleep(time.Until(rotatedAt.Add(grace + time.Second)))

		t.Run("old_key_refused_after_grace", func(t *testing.T) {
			expectUserinfo(t, p, g1.access, false)
			expectUserinfo(t, p, g2.access, true)
			if kids := jwksKIDs(t, p); contains(kids, k1) {
				t.Errorf("JWKS still publishes the expired key %s: %v", k1, kids)
			}
		})

		inst.restart(t, nil) // maintenance runs at startup and deletes expired keys
		t.Run("expired_key_removed", func(t *testing.T) {
			if kids := jwksKIDs(t, p); len(kids) != 1 || kids[0] != k2 {
				t.Errorf("JWKS after cleanup = %v, want only %s", kids, k2)
			}
			if out := inst.idpicoctl(t, "key", "list"); strings.Contains(out, k1) || !strings.Contains(out, k2) {
				t.Errorf("idpicoctl key list disagrees with JWKS:\n%s", out)
			}
			expectUserinfo(t, p, g2.access, true)
		})

		t.Run("algorithm_change_rotates", func(t *testing.T) {
			inst.restart(t, map[string]string{"IDPICO_SIGNING_ALGORITHM": "EdDSA"})
			_, set := p.fetchJWKS(t)
			var kty []string
			for _, k := range set.Keys {
				kty = append(kty, k.Algorithm)
			}
			if len(set.Keys) != 2 || !contains(kty, "RS256") || !contains(kty, "EdDSA") {
				t.Fatalf("JWKS after algorithm change should hold the RS256 key and a new EdDSA key, got %v", kty)
			}
			g3 := loginAndExchange(t, p)
			sig, _ := jose.ParseSigned(g3.idToken, allowedAlgs)
			if alg := sig.Signatures[0].Header.Algorithm; alg != "EdDSA" {
				t.Errorf("new ID token alg = %s, want EdDSA", alg)
			}
			expectUserinfo(t, p, g2.access, true) // RS256 token from before the change
			expectUserinfo(t, p, g3.access, true)
		})
	})
}
