package crypto

import (
	"context"
	"fmt"
	"sort"
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

	// active caches the current signing key so token issuance does not hit
	// the repository. It is refreshed by EnsureActiveKey and RotateKey, and
	// re-read from the repository once cacheTTL has elapsed so that a rotation
	// performed by another instance sharing the store is picked up.
	active   *KeyPair
	activeAt time.Time
	cacheTTL time.Duration
	now      func() time.Time

	// algorithm is what newly generated keys use; existing keys keep theirs.
	algorithm string
}

// DefaultActiveKeyCacheTTL bounds how stale the cached signing key can be.
const DefaultActiveKeyCacheTTL = time.Minute

// KeyServiceOption configures the KeyService.
type KeyServiceOption func(*KeyService)

// WithActiveKeyCacheTTL sets how long the active key is cached before being
// re-read from the repository. Zero disables caching.
func WithActiveKeyCacheTTL(ttl time.Duration) KeyServiceOption {
	return func(s *KeyService) { s.cacheTTL = ttl }
}

// WithAlgorithm sets the algorithm for keys the service generates
// (AlgRS256, the default, or AlgEdDSA).
func WithAlgorithm(alg string) KeyServiceOption {
	return func(s *KeyService) { s.algorithm = alg }
}

// NewKeyService creates a new KeyService.
func NewKeyService(repo KeyRepository, opts ...KeyServiceOption) *KeyService {
	s := &KeyService{
		repo:      repo,
		cacheTTL:  DefaultActiveKeyCacheTTL,
		now:       time.Now,
		algorithm: Algorithm,
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
		s.setActive(key)
		return key, nil
	}

	// Generate new key
	key, err = GenerateKeyPairForAlg(s.algorithm)
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

	s.setActive(key)
	return key, nil
}

// GetActiveKey returns the current active signing key. The key is served
// from an in-process cache (see WithActiveKeyCacheTTL); RotateKey refreshes it.
func (s *KeyService) GetActiveKey(ctx context.Context) (*KeyPair, error) {
	s.mu.RLock()
	if key := s.cachedActive(); key != nil {
		s.mu.RUnlock()
		return key, nil
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()
	if key := s.cachedActive(); key != nil {
		return key, nil
	}

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

	s.setActive(key)
	return key, nil
}

// cachedActive returns the cached key if it is still fresh. Caller holds mu.
func (s *KeyService) cachedActive() *KeyPair {
	if s.active == nil {
		return nil
	}
	if s.cacheTTL <= 0 || s.now().Sub(s.activeAt) >= s.cacheTTL {
		return nil
	}
	return s.active
}

// setActive stores key in the cache. Caller holds mu.
func (s *KeyService) setActive(key *KeyPair) {
	s.active = key
	s.activeAt = s.now()
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

// ListKeys returns every stored key, newest first, without loading RSA material.
func (s *KeyService) ListKeys(ctx context.Context) ([]*KeyPair, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	keys, err := s.repo.GetAll(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].CreatedAt.After(keys[j].CreatedAt) })
	return keys, nil
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
	newKey, err := GenerateKeyPairForAlg(s.algorithm)
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

	s.setActive(newKey)
	return newKey, nil
}

// Algorithm returns the algorithm newly generated keys use.
func (s *KeyService) Algorithm() string { return s.algorithm }

// ShouldRotate reports whether the active key is older than maxAge.
// A zero or negative maxAge disables rotation.
func (s *KeyService) ShouldRotate(ctx context.Context, maxAge time.Duration) (bool, error) {
	if maxAge <= 0 {
		return false, nil
	}
	key, err := s.GetActiveKey(ctx)
	if err != nil {
		return false, err
	}
	return time.Since(key.CreatedAt) >= maxAge, nil
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
