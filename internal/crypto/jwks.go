package crypto

import (
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key (public key only for JWKS endpoint): an RSA
// key carries n/e, an Ed25519 key (kty OKP) carries crv/x.
type JWK struct {
	Kty string `json:"kty"`           // Key type: "RSA" or "OKP"
	Use string `json:"use"`           // Key use: "sig"
	Kid string `json:"kid"`           // Key ID
	Alg string `json:"alg"`           // Algorithm: "RS256" or "EdDSA"
	N   string `json:"n,omitempty"`   // RSA modulus (base64url)
	E   string `json:"e,omitempty"`   // RSA exponent (base64url)
	Crv string `json:"crv,omitempty"` // OKP curve: "Ed25519"
	X   string `json:"x,omitempty"`   // OKP public key (base64url)
}

// ToJWK converts a KeyPair to a JWK (public key only).
func (kp *KeyPair) ToJWK() JWK {
	jwk := JWK{Use: KeyUse, Kid: kp.Kid, Alg: kp.Alg}
	switch pub := kp.PublicKey.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64URLEncode(pub.N.Bytes())
		jwk.E = base64URLEncode(big.NewInt(int64(pub.E)).Bytes())
	case ed25519.PublicKey:
		jwk.Kty = "OKP"
		jwk.Crv = "Ed25519"
		jwk.X = base64URLEncode(pub)
	}
	return jwk
}

// base64URLEncode encodes bytes to base64url without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
