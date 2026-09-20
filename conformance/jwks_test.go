//go:build conformance

package conformance

import (
	"encoding/json"
	"testing"
)

// TestJWKS covers the published key set (RFC 7517) that relying parties use
// to verify ID tokens.
func TestJWKS(t *testing.T) {
	raw, set := fetchJWKS(t)

	t.Run("key_set", func(t *testing.T) {
		if len(set.Keys) == 0 {
			t.Fatal("JWK Set has no keys")
		}
		assertNoSecrets(t, "JWK Set", raw)
	})

	t.Run("signing_key", func(t *testing.T) {
		usable := 0
		for _, k := range set.Keys {
			if k.Use != "" && k.Use != "sig" {
				continue
			}
			if !k.Valid() || !k.IsPublic() {
				t.Errorf("key %q is not a valid public key", k.KeyID)
				continue
			}
			switch k.Algorithm {
			case "RS256", "EdDSA", "":
			default:
				t.Errorf("key %q advertises alg %q, which relying parties will not accept", k.KeyID, k.Algorithm)
			}
			usable++
		}
		if usable == 0 {
			t.Error("no usable signing key")
		}
	})

	t.Run("kid", func(t *testing.T) {
		seen := map[string]bool{}
		for _, k := range set.Keys {
			if k.KeyID == "" {
				t.Error("key without kid")
			}
			if seen[k.KeyID] {
				t.Errorf("duplicate kid %q", k.KeyID)
			}
			seen[k.KeyID] = true
		}
		_, again := fetchJWKS(t)
		for _, k := range again.Keys {
			if !seen[k.KeyID] {
				t.Errorf("kid %q appeared between two consecutive fetches", k.KeyID)
			}
		}
	})

	t.Run("no_private_material", func(t *testing.T) {
		var doc struct {
			Keys []map[string]any `json:"keys"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatal(err)
		}
		for _, k := range doc.Keys {
			for _, member := range []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth"} {
				if _, ok := k[member]; ok {
					t.Errorf("key %v exposes private member %q", k["kid"], member)
				}
			}
		}
	})
}
