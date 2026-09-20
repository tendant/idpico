package crypto

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestGenerateKeyPair(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	if keyPair.Kid == "" {
		t.Error("Key ID should not be empty")
	}

	if keyPair.Alg != "RS256" {
		t.Errorf("Expected algorithm RS256, got %s", keyPair.Alg)
	}

	if keyPair.PrivateKey == nil {
		t.Error("Private key should not be nil")
	}

	if keyPair.PublicKey == nil {
		t.Error("Public key should not be nil")
	}

	if keyPair.Active != true {
		t.Error("New key should be active")
	}
}

func TestKeyPairPEMRoundTrip(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	originalKid := keyPair.Kid

	// GenerateKeyPair already serializes to PEM
	if len(keyPair.PrivateKeyPEM) == 0 {
		t.Error("PrivateKeyPEM should not be empty after GenerateKeyPair")
	}

	if len(keyPair.PublicKeyPEM) == 0 {
		t.Error("PublicKeyPEM should not be empty after GenerateKeyPair")
	}

	// Clear the key objects
	keyPair.PrivateKey = nil
	keyPair.PublicKey = nil

	// Load from PEM
	if err := keyPair.LoadFromPEM(); err != nil {
		t.Fatalf("LoadFromPEM failed: %v", err)
	}

	if keyPair.PrivateKey == nil {
		t.Error("Private key should be restored after LoadFromPEM")
	}

	if keyPair.PublicKey == nil {
		t.Error("Public key should be restored after LoadFromPEM")
	}

	if keyPair.Kid != originalKid {
		t.Error("Key ID should be preserved after round trip")
	}
}

func TestKeyPairToJWK(t *testing.T) {
	keyPair, err := GenerateKeyPair(2048)
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	jwk := keyPair.ToJWK()

	if jwk.Kty != "RSA" {
		t.Errorf("Expected kty RSA, got %s", jwk.Kty)
	}

	if jwk.Use != "sig" {
		t.Errorf("Expected use sig, got %s", jwk.Use)
	}

	if jwk.Kid != keyPair.Kid {
		t.Errorf("Key ID mismatch: expected %s, got %s", keyPair.Kid, jwk.Kid)
	}

	if jwk.Alg != "RS256" {
		t.Errorf("Expected alg RS256, got %s", jwk.Alg)
	}

	if jwk.N == "" {
		t.Error("JWK modulus (n) should not be empty")
	}

	if jwk.E == "" {
		t.Error("JWK exponent (e) should not be empty")
	}
}

func TestKeyPairIsExpired(t *testing.T) {
	keyPair, _ := GenerateKeyPair(2048)

	// New key should not be expired
	if keyPair.IsExpired() {
		t.Error("New key should not be expired")
	}
}

func TestGenerateKeyPairDifferentKids(t *testing.T) {
	key1, _ := GenerateKeyPair(2048)
	key2, _ := GenerateKeyPair(2048)

	if key1.Kid == key2.Kid {
		t.Error("Different key pairs should have different key IDs")
	}
}

func BenchmarkGenerateKeyPair(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateKeyPair(2048)
	}
}

// memKeyRepo is a minimal in-memory KeyRepository shared between services in tests.
type memKeyRepo struct {
	keys   map[string]*KeyPair
	active string
}

func newMemKeyRepo() *memKeyRepo { return &memKeyRepo{keys: map[string]*KeyPair{}} }

func (r *memKeyRepo) GetByID(_ context.Context, kid string) (*KeyPair, error) {
	if k, ok := r.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("not found")
}
func (r *memKeyRepo) GetActive(ctx context.Context) (*KeyPair, error) {
	if r.active == "" {
		return nil, fmt.Errorf("no active key")
	}
	return r.GetByID(ctx, r.active)
}
func (r *memKeyRepo) GetAll(context.Context) ([]*KeyPair, error) {
	out := make([]*KeyPair, 0, len(r.keys))
	for _, k := range r.keys {
		out = append(out, k)
	}
	return out, nil
}
func (r *memKeyRepo) Save(_ context.Context, k *KeyPair) error { r.keys[k.Kid] = k; return nil }
func (r *memKeyRepo) SetActive(_ context.Context, kid string) error {
	if _, ok := r.keys[kid]; !ok {
		return fmt.Errorf("not found")
	}
	for id, k := range r.keys {
		k.Active = id == kid
	}
	r.active = kid
	return nil
}
func (r *memKeyRepo) Delete(_ context.Context, kid string) error { delete(r.keys, kid); return nil }

func TestKeyService_ActiveKeyCacheExpires(t *testing.T) {
	ctx := context.Background()
	repo := newMemKeyRepo()

	now := time.Now()
	clock := func() time.Time { return now }

	// Two services over one repository, as two replicas sharing a database would be.
	a := NewKeyService(repo, WithActiveKeyCacheTTL(time.Minute))
	a.now = clock
	b := NewKeyService(repo, WithActiveKeyCacheTTL(time.Minute))
	b.now = clock

	first, err := a.EnsureActiveKey(ctx)
	if err != nil {
		t.Fatalf("EnsureActiveKey: %v", err)
	}
	if got, _ := b.GetActiveKey(ctx); got.Kid != first.Kid {
		t.Fatalf("b should load the active key from the repo")
	}

	second, err := a.RotateKey(ctx, time.Hour)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Within the TTL, b still serves its cached key.
	if got, _ := b.GetActiveKey(ctx); got.Kid != first.Kid {
		t.Errorf("b should serve cached key inside TTL, got %s", got.Kid)
	}

	// After the TTL, b re-reads and sees the rotation.
	now = now.Add(2 * time.Minute)
	if got, _ := b.GetActiveKey(ctx); got.Kid != second.Kid {
		t.Errorf("b should pick up rotated key after TTL, got %s want %s", got.Kid, second.Kid)
	}
}

func TestKeyService_CacheDisabled(t *testing.T) {
	ctx := context.Background()
	repo := newMemKeyRepo()

	a := NewKeyService(repo, WithActiveKeyCacheTTL(0))
	b := NewKeyService(repo, WithActiveKeyCacheTTL(0))

	first, _ := a.EnsureActiveKey(ctx)
	b.GetActiveKey(ctx)
	second, _ := a.RotateKey(ctx, time.Hour)

	if got, _ := b.GetActiveKey(ctx); got.Kid != second.Kid || got.Kid == first.Kid {
		t.Errorf("with caching disabled b should always see the current key, got %s", got.Kid)
	}
}

func TestKeyService_JWKSOmitsExpiredKeys(t *testing.T) {
	ctx := context.Background()
	repo := newMemKeyRepo()
	svc := NewKeyService(repo, WithActiveKeyCacheTTL(0))

	first, _ := svc.EnsureActiveKey(ctx)
	second, _ := svc.RotateKey(ctx, time.Hour)

	kids := func() []string {
		jwks, err := svc.GetJWKS(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, k := range jwks.Keys {
			out = append(out, k.Kid)
		}
		return out
	}
	if got := kids(); len(got) != 2 {
		t.Fatalf("during the grace period both keys are published, got %v", got)
	}

	// Grace over: the old key is refused by verification, so it must not be
	// offered to relying parties either, even before cleanup removes it.
	repo.keys[first.Kid].ExpiresAt = time.Now().Add(-time.Second)
	if got := kids(); len(got) != 1 || got[0] != second.Kid {
		t.Errorf("after the grace period only the active key is published, got %v", got)
	}
}
