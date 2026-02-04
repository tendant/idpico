package crypto

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// KeyRepository defines storage operations for signing keys.
type KeyRepository interface {
	GetByID(ctx context.Context, kid string) (*KeyPair, error)
	GetActive(ctx context.Context) (*KeyPair, error)
	GetAll(ctx context.Context) ([]*KeyPair, error)
	Save(ctx context.Context, keyPair *KeyPair) error
	SetActive(ctx context.Context, kid string) error
	Delete(ctx context.Context, kid string) error
}

// KeyService manages signing keys.
type KeyService struct {
	repo KeyRepository
	mu   sync.RWMutex
}

// KeyServiceOption configures the KeyService.
type KeyServiceOption func(*KeyService)

// NewKeyService creates a new KeyService.
func NewKeyService(repo KeyRepository, opts ...KeyServiceOption) *KeyService {
	s := &KeyService{
		repo: repo,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// EnsureActiveKey ensures there's an active signing key, generating one if needed.
func (s *KeyService) EnsureActiveKey(ctx context.Context) (*KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Try to get existing active key
	key, err := s.repo.GetActive(ctx)
	if err == nil && key != nil {
		// Restore RSA keys from PEM if needed
		if key.PrivateKey == nil {
			if err := key.LoadFromPEM(); err != nil {
				return nil, fmt.Errorf("failed to load key from PEM: %w", err)
			}
		}
		return key, nil
	}

	// Generate new key
	key, err = GenerateKeyPair(DefaultKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Save and activate
	if err := s.repo.Save(ctx, key); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	if err := s.repo.SetActive(ctx, key.Kid); err != nil {
		return nil, fmt.Errorf("failed to activate key: %w", err)
	}

	return key, nil
}

// GetActiveKey returns the current active signing key.
func (s *KeyService) GetActiveKey(ctx context.Context) (*KeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, err := s.repo.GetActive(ctx)
	if err != nil {
		return nil, err
	}

	// Restore RSA keys from PEM if needed
	if key.PrivateKey == nil {
		if err := key.LoadFromPEM(); err != nil {
			return nil, fmt.Errorf("failed to load key from PEM: %w", err)
		}
	}

	return key, nil
}

// GetJWKS returns all public keys in JWKS format.
func (s *KeyService) GetJWKS(ctx context.Context) (*JWKS, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys, err := s.repo.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	jwks := &JWKS{
		Keys: make([]JWK, 0, len(keys)),
	}

	for _, key := range keys {
		// Restore public key from PEM if needed
		if key.PublicKey == nil {
			if err := key.LoadFromPEM(); err != nil {
				continue // Skip invalid keys
			}
		}
		jwks.Keys = append(jwks.Keys, key.ToJWK())
	}

	return jwks, nil
}

// RotateKey generates a new key and sets it as active.
// The old key remains in JWKS for token verification until cleanup.
func (s *KeyService) RotateKey(ctx context.Context, expiresIn time.Duration) (*KeyPair, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Mark current active key as expiring
	oldKey, err := s.repo.GetActive(ctx)
	if err == nil && oldKey != nil {
		oldKey.Active = false
		oldKey.ExpiresAt = time.Now().Add(expiresIn)
		if err := s.repo.Save(ctx, oldKey); err != nil {
			return nil, fmt.Errorf("failed to update old key: %w", err)
		}
	}

	// Generate new key
	newKey, err := GenerateKeyPair(DefaultKeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Save and activate
	if err := s.repo.Save(ctx, newKey); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	if err := s.repo.SetActive(ctx, newKey.Kid); err != nil {
		return nil, fmt.Errorf("failed to activate key: %w", err)
	}

	return newKey, nil
}

// GetKeyByID returns a key by its ID (kid).
// Used for token verification to support rotated keys.
func (s *KeyService) GetKeyByID(ctx context.Context, kid string) (*KeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, err := s.repo.GetByID(ctx, kid)
	if err != nil {
		return nil, err
	}

	// Restore RSA keys from PEM if needed
	if key.PrivateKey == nil || key.PublicKey == nil {
		if err := key.LoadFromPEM(); err != nil {
			return nil, fmt.Errorf("failed to load key from PEM: %w", err)
		}
	}

	return key, nil
}

// CleanupExpiredKeys removes keys that have expired.
func (s *KeyService) CleanupExpiredKeys(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	keys, err := s.repo.GetAll(ctx)
	if err != nil {
		return err
	}

	for _, key := range keys {
		if key.IsExpired() && !key.Active {
			if err := s.repo.Delete(ctx, key.Kid); err != nil {
				return fmt.Errorf("failed to delete expired key %s: %w", key.Kid, err)
			}
		}
	}

	return nil
}
