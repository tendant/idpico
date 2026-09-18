package file

import (
	"context"
	"os"
	"testing"

	"github.com/tendant/idpico/internal/domain"
	"github.com/tendant/idpico/internal/store"
	"github.com/tendant/idpico/internal/store/storetest"
)

func setupTestStore(t *testing.T) (*Store, func()) {
	dir, err := os.MkdirTemp("", "idp-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	store, err := NewStore(dir)
	if err != nil {
		os.RemoveAll(dir)
		t.Fatalf("Failed to create store: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.RemoveAll(dir)
	}

	return store, cleanup
}

func TestNewStore(t *testing.T) {
	dir, err := os.MkdirTemp("", "idp-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	store, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	defer store.Close()

	if store.Users() == nil {
		t.Error("Users() should not return nil")
	}
	if store.Clients() == nil {
		t.Error("Clients() should not return nil")
	}
	if store.Sessions() == nil {
		t.Error("Sessions() should not return nil")
	}
	if store.AuthCodes() == nil {
		t.Error("AuthCodes() should not return nil")
	}
	if store.Tokens() == nil {
		t.Error("Tokens() should not return nil")
	}
	if store.SigningKeys() == nil {
		t.Error("SigningKeys() should not return nil")
	}
}

func TestConformance(t *testing.T) {
	storetest.Run(t, func(t *testing.T) store.Store {
		s, cleanup := setupTestStore(t)
		t.Cleanup(cleanup)
		return s
	})
}

// Test persistence across store restarts

func TestPersistenceAcrossRestarts(t *testing.T) {
	dir, err := os.MkdirTemp("", "idp-test-persist-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()

	// Create store and add data
	store1, err := NewStore(dir)
	if err != nil {
		t.Fatalf("Failed to create store: %v", err)
	}

	user := &domain.User{ID: "persist-user", Email: "persist@example.com", DisplayName: "Persist User"}
	store1.Users().Create(ctx, user)
	store1.Close()

	// Create new store instance with same dir
	store2, err := NewStore(dir)
	if err != nil {
		t.Fatalf("Failed to create second store: %v", err)
	}
	defer store2.Close()

	// Data should be persisted
	found, err := store2.Users().GetByID(ctx, "persist-user")
	if err != nil {
		t.Fatalf("User should be persisted: %v", err)
	}
	if found.Email != "persist@example.com" {
		t.Errorf("Expected email 'persist@example.com', got '%s'", found.Email)
	}
}
