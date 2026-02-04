package file

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
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

// User Repository Tests

func TestUserRepository_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Users()

	// Create
	user := &domain.User{
		ID:           "user-1",
		Email:        "test@example.com",
		DisplayName:  "Test User",
		PasswordHash: "hashed-password",
	}

	err := repo.Create(ctx, user)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Timestamps should be set
	if user.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if user.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}

	// GetByID
	found, err := repo.GetByID(ctx, "user-1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", found.Email)
	}

	// GetByEmail
	found, err = repo.GetByEmail(ctx, "test@example.com")
	if err != nil {
		t.Fatalf("GetByEmail failed: %v", err)
	}
	if found.ID != "user-1" {
		t.Errorf("Expected ID 'user-1', got '%s'", found.ID)
	}

	// Update
	found.DisplayName = "Updated Name"
	err = repo.Update(ctx, found)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	found, _ = repo.GetByID(ctx, "user-1")
	if found.DisplayName != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got '%s'", found.DisplayName)
	}

	// List
	users, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(users))
	}

	// Delete
	err = repo.Delete(ctx, "user-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = repo.GetByID(ctx, "user-1")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("GetByID should return not found after delete")
	}
}

func TestUserRepository_DuplicateEmail(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Users()

	user1 := &domain.User{ID: "user-1", Email: "test@example.com"}
	user2 := &domain.User{ID: "user-2", Email: "test@example.com"}

	repo.Create(ctx, user1)
	err := repo.Create(ctx, user2)

	if !idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
		t.Error("Should return already exists error for duplicate email")
	}
}

func TestUserRepository_DuplicateID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Users()

	user1 := &domain.User{ID: "user-1", Email: "test1@example.com"}
	user2 := &domain.User{ID: "user-1", Email: "test2@example.com"}

	repo.Create(ctx, user1)
	err := repo.Create(ctx, user2)

	if !idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
		t.Error("Should return already exists error for duplicate ID")
	}
}

// Client Repository Tests

func TestClientRepository_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Clients()

	// Create
	client := &domain.Client{
		ID:           "client-1",
		Name:         "Test Client",
		Secret:       "secret",
		Public:       false,
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile"},
	}

	err := repo.Create(ctx, client)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// GetByID
	found, err := repo.GetByID(ctx, "client-1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.Name != "Test Client" {
		t.Errorf("Expected name 'Test Client', got '%s'", found.Name)
	}

	// Update
	found.Name = "Updated Client"
	err = repo.Update(ctx, found)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// List
	clients, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(clients) != 1 {
		t.Errorf("Expected 1 client, got %d", len(clients))
	}

	// Delete
	err = repo.Delete(ctx, "client-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = repo.GetByID(ctx, "client-1")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("GetByID should return not found after delete")
	}
}

// Session Repository Tests

func TestSessionRepository_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Sessions()

	// Create
	session := &domain.Session{
		ID:        "session-1",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(ctx, session)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// GetByID
	found, err := repo.GetByID(ctx, "session-1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.UserID != "user-1" {
		t.Errorf("Expected UserID 'user-1', got '%s'", found.UserID)
	}

	// Delete
	err = repo.Delete(ctx, "session-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = repo.GetByID(ctx, "session-1")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("GetByID should return not found after delete")
	}
}

func TestSessionRepository_DeleteByUserID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Sessions()

	// Create multiple sessions for user-1
	repo.Create(ctx, &domain.Session{ID: "s1", UserID: "user-1", ExpiresAt: time.Now().Add(time.Hour)})
	repo.Create(ctx, &domain.Session{ID: "s2", UserID: "user-1", ExpiresAt: time.Now().Add(time.Hour)})
	repo.Create(ctx, &domain.Session{ID: "s3", UserID: "user-2", ExpiresAt: time.Now().Add(time.Hour)})

	// Delete user-1's sessions
	err := repo.DeleteByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}

	// user-1's sessions should be gone
	_, err = repo.GetByID(ctx, "s1")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("Session s1 should be deleted")
	}

	// user-2's session should remain
	_, err = repo.GetByID(ctx, "s3")
	if err != nil {
		t.Error("Session s3 should still exist")
	}
}

func TestSessionRepository_DeleteExpired(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Sessions()

	// Create expired and valid sessions
	repo.Create(ctx, &domain.Session{ID: "expired", UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour)})
	repo.Create(ctx, &domain.Session{ID: "valid", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})

	// Delete expired
	err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}

	// Expired should be gone
	_, err = repo.GetByID(ctx, "expired")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("Expired session should be deleted")
	}

	// Valid should remain
	_, err = repo.GetByID(ctx, "valid")
	if err != nil {
		t.Error("Valid session should still exist")
	}
}

// AuthCode Repository Tests

func TestAuthCodeRepository_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.AuthCodes()

	// Create
	code := &domain.AuthCode{
		Code:        "auth-code-1",
		ClientID:    "client-1",
		UserID:      "user-1",
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "openid",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		Used:        false,
	}

	err := repo.Create(ctx, code)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// GetByCode
	found, err := repo.GetByCode(ctx, "auth-code-1")
	if err != nil {
		t.Fatalf("GetByCode failed: %v", err)
	}
	if found.ClientID != "client-1" {
		t.Errorf("Expected ClientID 'client-1', got '%s'", found.ClientID)
	}
	if found.Used {
		t.Error("Code should not be used initially")
	}

	// MarkUsed
	err = repo.MarkUsed(ctx, "auth-code-1")
	if err != nil {
		t.Fatalf("MarkUsed failed: %v", err)
	}

	found, _ = repo.GetByCode(ctx, "auth-code-1")
	if !found.Used {
		t.Error("Code should be marked as used")
	}

	// Delete
	err = repo.Delete(ctx, "auth-code-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = repo.GetByCode(ctx, "auth-code-1")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("GetByCode should return not found after delete")
	}
}

func TestAuthCodeRepository_DeleteExpired(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.AuthCodes()

	// Create expired and valid codes
	repo.Create(ctx, &domain.AuthCode{Code: "expired", ClientID: "c1", UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour)})
	repo.Create(ctx, &domain.AuthCode{Code: "valid", ClientID: "c1", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})

	// Delete expired
	err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}

	// Expired should be gone
	_, err = repo.GetByCode(ctx, "expired")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("Expired code should be deleted")
	}

	// Valid should remain
	_, err = repo.GetByCode(ctx, "valid")
	if err != nil {
		t.Error("Valid code should still exist")
	}
}

// Token Repository Tests

func TestTokenRepository_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Tokens()

	// Create
	token := &domain.Token{
		ID:        "token-1",
		UserID:    "user-1",
		ClientID:  "client-1",
		Scope:     "openid profile",
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		Revoked:   false,
	}

	err := repo.Create(ctx, token)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// GetByID
	found, err := repo.GetByID(ctx, "token-1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.UserID != "user-1" {
		t.Errorf("Expected UserID 'user-1', got '%s'", found.UserID)
	}
	if found.Revoked {
		t.Error("Token should not be revoked initially")
	}

	// Revoke
	err = repo.Revoke(ctx, "token-1")
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}

	found, _ = repo.GetByID(ctx, "token-1")
	if !found.Revoked {
		t.Error("Token should be revoked")
	}
}

func TestTokenRepository_RevokeByUserID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Tokens()

	// Create tokens for different users
	repo.Create(ctx, &domain.Token{ID: "t1", UserID: "user-1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour)})
	repo.Create(ctx, &domain.Token{ID: "t2", UserID: "user-1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour)})
	repo.Create(ctx, &domain.Token{ID: "t3", UserID: "user-2", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour)})

	// Revoke user-1's tokens
	err := repo.RevokeByUserID(ctx, "user-1")
	if err != nil {
		t.Fatalf("RevokeByUserID failed: %v", err)
	}

	// user-1's tokens should be revoked
	t1, _ := repo.GetByID(ctx, "t1")
	if !t1.Revoked {
		t.Error("Token t1 should be revoked")
	}

	// user-2's token should not be revoked
	t3, _ := repo.GetByID(ctx, "t3")
	if t3.Revoked {
		t.Error("Token t3 should not be revoked")
	}
}

func TestTokenRepository_RevokeByClientID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Tokens()

	// Create tokens for different clients
	repo.Create(ctx, &domain.Token{ID: "t1", UserID: "u1", ClientID: "client-1", ExpiresAt: time.Now().Add(time.Hour)})
	repo.Create(ctx, &domain.Token{ID: "t2", UserID: "u1", ClientID: "client-2", ExpiresAt: time.Now().Add(time.Hour)})

	// Revoke client-1's tokens
	err := repo.RevokeByClientID(ctx, "client-1")
	if err != nil {
		t.Fatalf("RevokeByClientID failed: %v", err)
	}

	// client-1's token should be revoked
	t1, _ := repo.GetByID(ctx, "t1")
	if !t1.Revoked {
		t.Error("Token t1 should be revoked")
	}

	// client-2's token should not be revoked
	t2, _ := repo.GetByID(ctx, "t2")
	if t2.Revoked {
		t.Error("Token t2 should not be revoked")
	}
}

func TestTokenRepository_DeleteExpired(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.Tokens()

	// Create expired and valid tokens
	repo.Create(ctx, &domain.Token{ID: "expired", UserID: "u1", ClientID: "c1", ExpiresAt: time.Now().Add(-time.Hour)})
	repo.Create(ctx, &domain.Token{ID: "valid", UserID: "u1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour)})

	// Delete expired
	err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}

	// Expired should be gone
	_, err = repo.GetByID(ctx, "expired")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("Expired token should be deleted")
	}

	// Valid should remain
	_, err = repo.GetByID(ctx, "valid")
	if err != nil {
		t.Error("Valid token should still exist")
	}
}

// SigningKey Repository Tests

func TestSigningKeyRepository_CRUD(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.SigningKeys()

	// Create
	key := &domain.SigningKey{
		ID:         "key-1",
		Algorithm:  "RS256",
		PrivateKey: []byte("private-key-pem"),
		PublicKey:  []byte("public-key-pem"),
		Active:     true,
	}

	err := repo.Create(ctx, key)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// GetByID
	found, err := repo.GetByID(ctx, "key-1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.Algorithm != "RS256" {
		t.Errorf("Expected Algorithm 'RS256', got '%s'", found.Algorithm)
	}

	// GetActive
	active, err := repo.GetActive(ctx)
	if err != nil {
		t.Fatalf("GetActive failed: %v", err)
	}
	if active.ID != "key-1" {
		t.Errorf("Expected active key ID 'key-1', got '%s'", active.ID)
	}

	// GetAll
	all, err := repo.GetAll(ctx)
	if err != nil {
		t.Fatalf("GetAll failed: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("Expected 1 key, got %d", len(all))
	}

	// Create second key
	key2 := &domain.SigningKey{
		ID:         "key-2",
		Algorithm:  "RS256",
		PrivateKey: []byte("private-key-pem-2"),
		PublicKey:  []byte("public-key-pem-2"),
		Active:     false,
	}
	repo.Create(ctx, key2)

	// SetActive for key-2
	err = repo.SetActive(ctx, "key-2")
	if err != nil {
		t.Fatalf("SetActive failed: %v", err)
	}

	// key-2 should now be active
	active, _ = repo.GetActive(ctx)
	if active.ID != "key-2" {
		t.Errorf("Expected active key ID 'key-2', got '%s'", active.ID)
	}

	// key-1 should no longer be active
	key1, _ := repo.GetByID(ctx, "key-1")
	if key1.Active {
		t.Error("key-1 should no longer be active")
	}

	// Delete
	err = repo.Delete(ctx, "key-1")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = repo.GetByID(ctx, "key-1")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("GetByID should return not found after delete")
	}
}

func TestSigningKeyRepository_DuplicateID(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.SigningKeys()

	key1 := &domain.SigningKey{ID: "key-1", Algorithm: "RS256"}
	key2 := &domain.SigningKey{ID: "key-1", Algorithm: "RS256"}

	repo.Create(ctx, key1)
	err := repo.Create(ctx, key2)

	if !idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
		t.Error("Should return already exists error for duplicate ID")
	}
}

func TestSigningKeyRepository_NoActiveKey(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()
	repo := store.SigningKeys()

	// Create inactive key
	repo.Create(ctx, &domain.SigningKey{ID: "key-1", Algorithm: "RS256", Active: false})

	_, err := repo.GetActive(ctx)
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("Should return not found when no active key exists")
	}
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

// Test not found errors

func TestNotFoundErrors(t *testing.T) {
	store, cleanup := setupTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// User
	_, err := store.Users().GetByID(ctx, "nonexistent")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("User GetByID should return not found")
	}

	// Client
	_, err = store.Clients().GetByID(ctx, "nonexistent")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("Client GetByID should return not found")
	}

	// Session
	_, err = store.Sessions().GetByID(ctx, "nonexistent")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("Session GetByID should return not found")
	}

	// AuthCode
	_, err = store.AuthCodes().GetByCode(ctx, "nonexistent")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("AuthCode GetByCode should return not found")
	}

	// Token
	_, err = store.Tokens().GetByID(ctx, "nonexistent")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("Token GetByID should return not found")
	}

	// SigningKey
	_, err = store.SigningKeys().GetByID(ctx, "nonexistent")
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("SigningKey GetByID should return not found")
	}
}
