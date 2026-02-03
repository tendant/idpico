package crypto

import (
	"encoding/base64"
	"math/big"
)

// JWKS represents a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key (public key only for JWKS endpoint).
type JWK struct {
	Kty string `json:"kty"`           // Key type: "RSA"
	Use string `json:"use"`           // Key use: "sig"
	Kid string `json:"kid"`           // Key ID
	Alg string `json:"alg"`           // Algorithm: "RS256"
	N   string `json:"n"`             // RSA modulus (base64url)
	E   string `json:"e"`             // RSA exponent (base64url)
}

// ToJWK converts a KeyPair to a JWK (public key only).
func (kp *KeyPair) ToJWK() JWK {
	return JWK{
		Kty: KeyType,
		Use: KeyUse,
		Kid: kp.Kid,
		Alg: kp.Alg,
		N:   base64URLEncode(kp.PublicKey.N.Bytes()),
		E:   base64URLEncode(big.NewInt(int64(kp.PublicKey.E)).Bytes()),
	}
}

// base64URLEncode encodes bytes to base64url without padding.
func base64URLEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
