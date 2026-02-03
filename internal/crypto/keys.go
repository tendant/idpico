// Package crypto provides cryptographic utilities for JWT signing and JWKS.
package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	// DefaultKeySize is the default RSA key size in bits.
	DefaultKeySize = 2048
	// Algorithm is the JWT signing algorithm.
	Algorithm = "RS256"
	// KeyType is the JWK key type.
	KeyType = "RSA"
	// KeyUse is the JWK key use.
	KeyUse = "sig"
)

// KeyPair represents an RSA key pair for JWT signing.
type KeyPair struct {
	Kid        string          `json:"kid"`
	Alg        string          `json:"alg"`
	PrivateKey *rsa.PrivateKey `json:"-"`
	PublicKey  *rsa.PublicKey  `json:"-"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
	Active     bool            `json:"active"`

	// For serialization
	PrivateKeyPEM []byte `json:"private_key_pem,omitempty"`
	PublicKeyPEM  []byte `json:"public_key_pem,omitempty"`
}

// GenerateKeyPair generates a new RSA key pair.
func GenerateKeyPair(keySize int) (*KeyPair, error) {
	if keySize == 0 {
		keySize = DefaultKeySize
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	kp := &KeyPair{
		Kid:        uuid.New().String(),
		Alg:        Algorithm,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
		Active:     true,
	}

	// Serialize keys to PEM for storage
	if err := kp.serializeToPEM(); err != nil {
		return nil, err
	}

	return kp, nil
}

// serializeToPEM converts the keys to PEM format for storage.
func (kp *KeyPair) serializeToPEM() error {
	// Private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(kp.PrivateKey)
	kp.PrivateKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %w", err)
	}
	kp.PublicKeyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return nil
}

// LoadFromPEM restores the RSA keys from PEM format after deserialization.
func (kp *KeyPair) LoadFromPEM() error {
	if kp.PrivateKeyPEM == nil || kp.PublicKeyPEM == nil {
		return fmt.Errorf("PEM data is missing")
	}

	// Private key
	block, _ := pem.Decode(kp.PrivateKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}
	kp.PrivateKey = privateKey

	// Public key
	block, _ = pem.Decode(kp.PublicKeyPEM)
	if block == nil {
		return fmt.Errorf("failed to decode public key PEM")
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}
	kp.PublicKey = rsaPublicKey

	return nil
}

// IsExpired checks if the key has expired.
func (kp *KeyPair) IsExpired() bool {
	if kp.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(kp.ExpiresAt)
}
