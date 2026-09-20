//go:build conformance

package conformance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// issued runs one authorization and returns the token response, the nonce
// used and the JWKS, for tests that need a genuine token to start from.
func issued(t *testing.T) (tr tokenResponse, nonce string, set *jose.JSONWebKeySet) {
	t.Helper()
	nonce = randomString(t, 16)
	code, _ := obtainCode(t, authzParams(cfg.ClientID, cfg.RedirectURI, "openid profile email", randomString(t, 8), nonce, ""), cfg.RedirectURI)
	tr = exchange(t, code, "", cfg.ClientID, cfg.ClientSecret, cfg.RedirectURI)
	if tr.Status != 200 {
		t.Fatalf("token: HTTP %d: %s", tr.Status, redact(string(tr.Raw)))
	}
	_, set = fetchJWKS(t)
	return tr, nonce, set
}

// TestIDToken walks the relying-party validation steps of OIDC Core
// §3.1.3.7 one by one, using only public metadata and go-jose.
func TestIDToken(t *testing.T) {
	d := discovery(t)
	tr, nonce, set := issued(t)
	raw := tr.str("id_token")
	want := idTokenExpectation{Issuer: d.Issuer, ClientID: cfg.ClientID, Nonce: nonce}

	t.Run("parse", func(t *testing.T) {
		if _, err := jose.ParseSigned(raw, allowedAlgs); err != nil {
			t.Fatalf("id_token is not a JWS signed with an allowed alg: %v", err)
		}
	})

	t.Run("kid_resolves", func(t *testing.T) {
		sig, _ := jose.ParseSigned(raw, allowedAlgs)
		hdr := sig.Signatures[0].Header
		if hdr.KeyID == "" {
			t.Fatal("no kid header")
		}
		keys := set.Key(hdr.KeyID)
		if len(keys) != 1 {
			t.Fatalf("kid %q matches %d keys in JWKS, want 1", hdr.KeyID, len(keys))
		}
		if keys[0].Algorithm != "" && keys[0].Algorithm != hdr.Algorithm {
			t.Errorf("token alg %s but JWK alg %s", hdr.Algorithm, keys[0].Algorithm)
		}
		if !contains(d.IDTokenSigningAlgValuesSupported, hdr.Algorithm) {
			t.Errorf("token alg %s is not in id_token_signing_alg_values_supported %v", hdr.Algorithm, d.IDTokenSigningAlgValuesSupported)
		}
	})

	var claims map[string]any
	t.Run("signature", func(t *testing.T) {
		var err error
		claims, err = verifyIDToken(t, raw, set, want)
		if err != nil {
			t.Fatal(err)
		}
	})
	if claims == nil {
		return
	}

	t.Run("issuer", func(t *testing.T) {
		if claims["iss"] != d.Issuer {
			t.Errorf("iss = %v, want %q", claims["iss"], d.Issuer)
		}
	})
	t.Run("audience", func(t *testing.T) {
		if !audienceContains(claims["aud"], cfg.ClientID) {
			t.Errorf("aud = %v, want %q", claims["aud"], cfg.ClientID)
		}
		if list, ok := claims["aud"].([]any); ok && len(list) > 1 {
			if azp, _ := claims["azp"].(string); azp != cfg.ClientID {
				t.Errorf("multiple audiences require azp = %q, got %v", cfg.ClientID, claims["azp"])
			}
		}
	})
	t.Run("expiration", func(t *testing.T) {
		exp, _ := numericDate(claims["exp"])
		iat, _ := numericDate(claims["iat"])
		if !exp.After(iat) {
			t.Errorf("exp %s is not after iat %s", exp, iat)
		}
		if expiresIn, ok := tr.Body["expires_in"].(float64); ok && exp.Sub(iat) > time.Duration(expiresIn)*time.Second+time.Minute {
			t.Errorf("id_token lives %s but expires_in is %.0fs", exp.Sub(iat), expiresIn)
		}
	})
	t.Run("nonce", func(t *testing.T) {
		if claims["nonce"] != nonce {
			t.Errorf("nonce = %v, want %q", claims["nonce"], nonce)
		}
	})
	t.Run("subject", func(t *testing.T) {
		sub, _ := claims["sub"].(string)
		if sub == "" || len(sub) > 255 {
			t.Errorf("sub = %q: must be non-empty and at most 255 characters", sub)
		}
		if sub == cfg.UserEmail || sub == cfg.UserPassword {
			t.Errorf("sub must be an opaque identifier, got %q", sub)
		}
	})
	t.Run("standard_claims", func(t *testing.T) {
		if v, _ := claims["email"].(string); !strings.EqualFold(v, cfg.UserEmail) {
			t.Errorf("email = %v, want %q (scope email was granted)", claims["email"], cfg.UserEmail)
		}
	})
}

// TestSecurityJWT is the negative side: forged or damaged tokens must be
// refused by the provider (at /userinfo) and by an independent verifier.
func TestSecurityJWT(t *testing.T) {
	t.Parallel() // sleeps past the throwaway server's short TTLs
	d := discovery(t)
	tr, nonce, set := issued(t)
	access, id := tr.str("access_token"), tr.str("id_token")
	want := idTokenExpectation{Issuer: d.Issuer, ClientID: cfg.ClientID, Nonce: nonce}
	kid := jose.Header{}
	if sig, err := jose.ParseSigned(id, allowedAlgs); err == nil {
		kid = sig.Signatures[0].Header
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	accessClaims := claimsOf(t, access)

	// Provider side: every one of these must be rejected at /userinfo even
	// though the claims look right.
	forged := map[string]string{
		"modified_payload": withClaim(t, access, "sub", "someone-else"),
		"modified_scope":   withClaim(t, access, "scope", "openid profile email groups admin"),
		"modified_sig":     flipSignature(access),
		"unknown_rsa_key":  mintToken(t, jose.RS256, rsaKey, kid.KeyID, accessClaims),
		"unknown_ed_key":   mintToken(t, jose.EdDSA, edKey, kid.KeyID, accessClaims),
		"unknown_kid":      mintToken(t, jose.RS256, rsaKey, "no-such-kid", accessClaims),
		"alg_none":         unsignedToken(accessClaims),
		"hmac_with_kid":    mintToken(t, jose.HS256, []byte("a-32-byte-long-hmac-secret-value"), kid.KeyID, accessClaims),
		"two_segments":     strings.Join(strings.Split(access, ".")[:2], "."),
		"not_base64":       "eyJ..%%%.zzz",
		"empty":            "",
		"id_token_as_access_token_with_other_aud": withClaim(t, id, "aud", "someone-else"),
	}
	for name, tok := range forged {
		t.Run("userinfo_rejects_"+name, func(t *testing.T) {
			resp, body := userinfo(t, "Bearer "+tok)
			expectUnauthorized(t, resp, body)
			assertNoSecrets(t, "userinfo error", body, access, id)
		})
	}

	t.Run("userinfo_rejects_expired", func(t *testing.T) {
		if cfg.External() {
			t.Skip("needs the throwaway server's short IDPICO_ACCESS_TOKEN_TTL")
		}
		exp, _ := numericDate(accessClaims["exp"])
		time.Sleep(time.Until(exp) + time.Second)
		resp, body := userinfo(t, "Bearer "+access)
		expectUnauthorized(t, resp, body)
	})

	// Relying-party side: the independent verifier catches what the
	// provider cannot know about (the RP's own expectations).
	t.Run("verifier_rejects", func(t *testing.T) {
		cases := map[string]struct {
			token string
			want  idTokenExpectation
		}{
			"modified_payload": {withClaim(t, id, "sub", "x"), want},
			"modified_sig":     {flipSignature(id), want},
			"unknown_key":      {mintToken(t, jose.RS256, rsaKey, kid.KeyID, claimsOf(t, id)), want},
			"alg_none":         {unsignedToken(claimsOf(t, id)), want},
			"hmac":             {mintToken(t, jose.HS256, []byte("a-32-byte-long-hmac-secret-value"), kid.KeyID, claimsOf(t, id)), want},
			"malformed":        {"not.a.jwt", want},
			"wrong_issuer":     {id, idTokenExpectation{Issuer: "https://evil.example", ClientID: cfg.ClientID, Nonce: nonce}},
			"wrong_audience":   {id, idTokenExpectation{Issuer: d.Issuer, ClientID: cfg.OtherClientID, Nonce: nonce}},
			"wrong_nonce":      {id, idTokenExpectation{Issuer: d.Issuer, ClientID: cfg.ClientID, Nonce: "other"}},
		}
		for name, tc := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := verifyIDToken(t, tc.token, set, tc.want); !errors.Is(err, errTokenInvalid) {
					t.Errorf("verifier accepted the token (err=%v)", err)
				}
			})
		}
	})
}
