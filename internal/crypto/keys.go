// Package crypto provides cryptographic utilities for JWT signing and JWKS.
package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	// DefaultKeySize is the default RSA key size in bits.
	DefaultKeySize = 2048
	// AlgRS256 signs with RSA (PKCS#1 v1.5, SHA-256): universally supported.
	AlgRS256 = "RS256"
	// AlgEdDSA signs with Ed25519: small keys and signatures, fast
	// verification; newer relying parties only.
	AlgEdDSA = "EdDSA"
	// Algorithm is the default JWT signing algorithm.
	Algorithm = AlgRS256
	// KeyUse is the JWK key use.
	KeyUse = "sig"
)

// SupportedAlgorithms lists the signing algorithms a key can be created with.
var SupportedAlgorithms = []string{AlgRS256, AlgEdDSA}

// ValidAlgorithm reports whether alg is one of SupportedAlgorithms.
func ValidAlgorithm(alg string) bool {
	for _, a := range SupportedAlgorithms {
		if a == alg {
			return true
		}
	}
	return false
}

// KeyPair is a signing key: RSA for RS256, Ed25519 for EdDSA. Alg says
// which, and the key material's concrete type always agrees with it.
type KeyPair struct {
	Kid        string           `json:"kid"`
	Alg        string           `json:"alg"`
	PrivateKey crypto.Signer    `json:"-"` // *rsa.PrivateKey or ed25519.PrivateKey
	PublicKey  crypto.PublicKey `json:"-"` // *rsa.PublicKey or ed25519.PublicKey
	CreatedAt  time.Time        `json:"created_at"`
	ExpiresAt  time.Time        `json:"expires_at"`
	Active     bool             `json:"active"`

	// For serialization
	PrivateKeyPEM []byte `json:"private_key_pem,omitempty"`
	PublicKeyPEM  []byte `json:"public_key_pem,omitempty"`
}

// GenerateKeyPair generates a new RSA key pair for RS256.
func GenerateKeyPair(keySize int) (*KeyPair, error) {
	if keySize == 0 {
		keySize = DefaultKeySize
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return newKeyPair(AlgRS256, privateKey, &privateKey.PublicKey)
}

// GenerateKeyPairForAlg generates a key pair for the given algorithm.
func GenerateKeyPairForAlg(alg string) (*KeyPair, error) {
	switch alg {
	case AlgRS256:
		return GenerateKeyPair(DefaultKeySize)
	case AlgEdDSA:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}
		return newKeyPair(AlgEdDSA, privateKey, publicKey)
	default:
		return nil, fmt.Errorf("unsupported signing algorithm %q (use %v)", alg, SupportedAlgorithms)
	}
}

func newKeyPair(alg string, privateKey crypto.Signer, publicKey crypto.PublicKey) (*KeyPair, error) {
	kp := &KeyPair{
		Kid:        uuid.New().String(),
		Alg:        alg,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		CreatedAt:  time.Now(),
		Active:     true,
	}
	if err := kp.serializeToPEM(); err != nil {
		return nil, err
	}
	return kp, nil
}

// serializeToPEM converts the keys to PEM format for storage. RSA private
// keys stay PKCS#1 ("RSA PRIVATE KEY") as shipped in v0.0.2; everything else
// is PKCS#8 / PKIX, which is what x509 offers for Ed25519.
func (kp *KeyPair) serializeToPEM() error {
	var privBlock *pem.Block
	switch k := kp.PrivateKey.(type) {
	case *rsa.PrivateKey:
		privBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	default:
		der, err := x509.MarshalPKCS8PrivateKey(kp.PrivateKey)
		if err != nil {
			return fmt.Errorf("failed to marshal private key: %w", err)
		}
		privBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	}
	kp.PrivateKeyPEM = pem.EncodeToMemory(privBlock)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	kp.PublicKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyBytes})
	return nil
}

// LoadFromPEM restores the key material from PEM after deserialization and
// checks that it matches Alg, so a mislabelled row cannot sign with the
// wrong algorithm.
func (kp *KeyPair) LoadFromPEM() error {
	if kp.PrivateKeyPEM == nil || kp.PublicKeyPEM == nil {
		return fmt.Errorf("PEM data is missing")
	}

	block, _ := pem.Decode(kp.PrivateKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}
	var privateKey crypto.Signer
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		privateKey = k
	default:
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		signer, ok := k.(crypto.Signer)
		if !ok {
			return fmt.Errorf("private key type %T cannot sign", k)
		}
		privateKey = signer
	}

	block, _ = pem.Decode(kp.PublicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode public key PEM")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	if kp.Alg == "" {
		kp.Alg = AlgRS256 // rows written before the column carried a value
	}
	switch kp.Alg {
	case AlgRS256:
		if _, ok := privateKey.(*rsa.PrivateKey); !ok {
			return fmt.Errorf("key %s is %s but its private key is %T", kp.Kid, kp.Alg, privateKey)
		}
		if _, ok := publicKey.(*rsa.PublicKey); !ok {
			return fmt.Errorf("key %s is %s but its public key is %T", kp.Kid, kp.Alg, publicKey)
		}
	case AlgEdDSA:
		if _, ok := privateKey.(ed25519.PrivateKey); !ok {
			return fmt.Errorf("key %s is %s but its private key is %T", kp.Kid, kp.Alg, privateKey)
		}
		if _, ok := publicKey.(ed25519.PublicKey); !ok {
			return fmt.Errorf("key %s is %s but its public key is %T", kp.Kid, kp.Alg, publicKey)
		}
	default:
		return fmt.Errorf("key %s has unsupported algorithm %q", kp.Kid, kp.Alg)
	}
	kp.PrivateKey = privateKey
	kp.PublicKey = publicKey
	return nil
}

// IsExpired checks if the key has expired.
func (kp *KeyPair) IsExpired() bool {
	if kp.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(kp.ExpiresAt)
}

// RandomToken returns n random bytes encoded as URL-safe base64, for
// secrets and one-time tokens.
func RandomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
