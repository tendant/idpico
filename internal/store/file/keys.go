package file

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"github.com/tendant/simple-idp/internal/crypto"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

// KeyRepository implements crypto.KeyRepository using file storage.
type KeyRepository struct {
	dataDir string
	mu      sync.RWMutex
}

type keysData struct {
	Keys      []*crypto.KeyPair `json:"keys"`
	ActiveKid string            `json:"active_kid"`
}

// NewKeyRepository creates a new file-based KeyRepository.
func NewKeyRepository(dataDir string) *KeyRepository {
	return &KeyRepository{
		dataDir: dataDir,
	}
}

func (r *KeyRepository) filePath() string {
	return filepath.Join(r.dataDir, "signing_keys.json")
}

func (r *KeyRepository) load() (*keysData, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	data, err := os.ReadFile(r.filePath())
	if os.IsNotExist(err) {
		return &keysData{Keys: []*crypto.KeyPair{}}, nil
	}
	if err != nil {
		return nil, err
	}

	var kd keysData
	if err := json.Unmarshal(data, &kd); err != nil {
		return nil, err
	}
	if kd.Keys == nil {
		kd.Keys = []*crypto.KeyPair{}
	}
	return &kd, nil
}

func (r *KeyRepository) save(kd *keysData) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	data, err := json.MarshalIndent(kd, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(r.filePath(), data, 0600)
}

// GetByID returns a key by its ID.
func (r *KeyRepository) GetByID(ctx context.Context, kid string) (*crypto.KeyPair, error) {
	kd, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load keys", err)
	}

	for _, key := range kd.Keys {
		if key.Kid == kid {
			return key, nil
		}
	}
	return nil, idperrors.NotFound("signing key", kid)
}

// GetActive returns the active signing key.
func (r *KeyRepository) GetActive(ctx context.Context) (*crypto.KeyPair, error) {
	kd, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load keys", err)
	}

	if kd.ActiveKid == "" {
		return nil, idperrors.NotFound("active signing key", "")
	}

	for _, key := range kd.Keys {
		if key.Kid == kd.ActiveKid {
			return key, nil
		}
	}
	return nil, idperrors.NotFound("active signing key", kd.ActiveKid)
}

// GetAll returns all signing keys.
func (r *KeyRepository) GetAll(ctx context.Context) ([]*crypto.KeyPair, error) {
	kd, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load keys", err)
	}
	return kd.Keys, nil
}

// Save saves a key.
func (r *KeyRepository) Save(ctx context.Context, keyPair *crypto.KeyPair) error {
	kd, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load keys", err)
	}

	// Update existing or append
	found := false
	for i, key := range kd.Keys {
		if key.Kid == keyPair.Kid {
			kd.Keys[i] = keyPair
			found = true
			break
		}
	}
	if !found {
		kd.Keys = append(kd.Keys, keyPair)
	}

	return r.save(kd)
}

// SetActive sets the active key.
func (r *KeyRepository) SetActive(ctx context.Context, kid string) error {
	kd, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load keys", err)
	}

	// Verify key exists
	found := false
	for _, key := range kd.Keys {
		if key.Kid == kid {
			found = true
			key.Active = true
		} else {
			key.Active = false
		}
	}
	if !found {
		return idperrors.NotFound("signing key", kid)
	}

	kd.ActiveKid = kid
	return r.save(kd)
}

// Delete removes a key.
func (r *KeyRepository) Delete(ctx context.Context, kid string) error {
	kd, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load keys", err)
	}

	for i, key := range kd.Keys {
		if key.Kid == kid {
			kd.Keys = append(kd.Keys[:i], kd.Keys[i+1:]...)
			if kd.ActiveKid == kid {
				kd.ActiveKid = ""
			}
			return r.save(kd)
		}
	}
	return idperrors.NotFound("signing key", kid)
}
