// Package storetest provides a conformance test suite that every store.Store
// implementation must pass. Backends call Run from their own test packages.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/store"
)

// Factory returns a fresh, empty store for a single test. Implementations
// should register cleanup with t.Cleanup.
type Factory func(t *testing.T) store.Store

// Run executes the store conformance suite against the stores produced by
// newStore. Every store.Store implementation should pass it.
func Run(t *testing.T, newStore Factory) {
	t.Helper()

	tests := []struct {
		name string
		fn   func(t *testing.T, newStore Factory)
	}{
		{"UserRepository_CRUD", UserRepository_CRUD},
		{"UserRepository_DuplicateEmail", UserRepository_DuplicateEmail},
		{"UserRepository_DuplicateID", UserRepository_DuplicateID},
		{"UserRepository_EmailCaseInsensitive", UserRepository_EmailCaseInsensitive},
		{"ClientRepository_CRUD", ClientRepository_CRUD},
		{"SessionRepository_CRUD", SessionRepository_CRUD},
		{"SessionRepository_DeleteByUserID", SessionRepository_DeleteByUserID},
		{"SessionRepository_DeleteExpired", SessionRepository_DeleteExpired},
		{"SessionRepository_ListByUserID", SessionRepository_ListByUserID},
		{"AuthCodeRepository_CRUD", AuthCodeRepository_CRUD},
		{"AuthCodeRepository_DeleteExpired", AuthCodeRepository_DeleteExpired},
		{"TokenRepository_CRUD", TokenRepository_CRUD},
		{"TokenRepository_RevokeByUserID", TokenRepository_RevokeByUserID},
		{"TokenRepository_RevokeByClientID", TokenRepository_RevokeByClientID},
		{"TokenRepository_DeleteExpired", TokenRepository_DeleteExpired},
		{"TokenRepository_ListByUserID", TokenRepository_ListByUserID},
		{"SigningKeyRepository_CRUD", SigningKeyRepository_CRUD},
		{"SigningKeyRepository_DuplicateID", SigningKeyRepository_DuplicateID},
		{"SigningKeyRepository_NoActiveKey", SigningKeyRepository_NoActiveKey},
		{"ConsentRepository_UpsertGetDelete", ConsentRepository_UpsertGetDelete},
		{"ConsentRepository_ListAndDeleteByUser", ConsentRepository_ListAndDeleteByUser},
		{"VerificationTokenRepository_Lifecycle", VerificationTokenRepository_Lifecycle},
		{"VerificationTokenRepository_DeleteByUserAndExpired", VerificationTokenRepository_DeleteByUserAndExpired},
		{"UserRepository_FlagsRoundTrip", UserRepository_FlagsRoundTrip},
		{"ClientRepository_SkipConsentRoundTrip", ClientRepository_SkipConsentRoundTrip},
		{"GroupRepository_CRUD", GroupRepository_CRUD},
		{"GroupRepository_Membership", GroupRepository_Membership},
		{"AuditRepository_AppendListPrune", AuditRepository_AppendListPrune},
		{"RevocationRepository_AccessToken", RevocationRepository_AccessToken},
		{"RevocationRepository_Watermarks", RevocationRepository_Watermarks},
		{"RevocationRepository_TokenRevokesGrant", RevocationRepository_TokenRevokesGrant},
		{"RevocationRepository_DeleteExpired", RevocationRepository_DeleteExpired},
		{"NotFoundErrors", NotFoundErrors},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, newStore)
		})
	}
}

// seedUsers creates placeholder users so rows that reference them satisfy
// foreign keys on backends that enforce them.
func seedUsers(t *testing.T, s store.Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := s.Users().Create(context.Background(), &domain.User{ID: id, Email: id + "@example.com", Active: true}); err != nil {
			t.Fatalf("seed user %s: %v", id, err)
		}
	}
}

// seedClients creates placeholder clients so rows that reference them satisfy
// foreign keys on backends that enforce them.
func seedClients(t *testing.T, s store.Store, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if err := s.Clients().Create(context.Background(), &domain.Client{ID: id, Name: id}); err != nil {
			t.Fatalf("seed client %s: %v", id, err)
		}
	}
}

// User Repository Tests

func UserRepository_CRUD(t *testing.T, newStore Factory) {
	store := newStore(t)

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

func UserRepository_DuplicateEmail(t *testing.T, newStore Factory) {
	store := newStore(t)

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

func UserRepository_DuplicateID(t *testing.T, newStore Factory) {
	store := newStore(t)

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

func UserRepository_EmailCaseInsensitive(t *testing.T, newStore Factory) {
	store := newStore(t)

	ctx := context.Background()
	repo := store.Users()

	if err := repo.Create(ctx, &domain.User{ID: "user-1", Email: "Alice@Example.com"}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Lookup ignores case
	found, err := repo.GetByEmail(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("GetByEmail should match case-insensitively: %v", err)
	}
	if found.ID != "user-1" {
		t.Errorf("Expected ID 'user-1', got '%s'", found.ID)
	}
	if found.Email != "Alice@Example.com" {
		t.Errorf("Email should be stored as given, got '%s'", found.Email)
	}

	// Uniqueness ignores case
	err = repo.Create(ctx, &domain.User{ID: "user-2", Email: "ALICE@example.com"})
	if !idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
		t.Errorf("Should return already exists for case-variant duplicate email, got %v", err)
	}
}

// Client Repository Tests

func ClientRepository_CRUD(t *testing.T, newStore Factory) {
	store := newStore(t)

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

func SessionRepository_CRUD(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "user-1")

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

func SessionRepository_DeleteByUserID(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "user-1", "user-2")

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

func SessionRepository_DeleteExpired(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1")

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

func AuthCodeRepository_CRUD(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "user-1")
	seedClients(t, store, "client-1")

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

func AuthCodeRepository_DeleteExpired(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1")
	seedClients(t, store, "c1")

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

func TokenRepository_CRUD(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "user-1")
	seedClients(t, store, "client-1")

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

func TokenRepository_RevokeByUserID(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "user-1", "user-2")
	seedClients(t, store, "c1")

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

func TokenRepository_RevokeByClientID(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1")
	seedClients(t, store, "client-1", "client-2")

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

func TokenRepository_DeleteExpired(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1")
	seedClients(t, store, "c1")

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

func SigningKeyRepository_CRUD(t *testing.T, newStore Factory) {
	store := newStore(t)

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

func SigningKeyRepository_DuplicateID(t *testing.T, newStore Factory) {
	store := newStore(t)

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

func SigningKeyRepository_NoActiveKey(t *testing.T, newStore Factory) {
	store := newStore(t)

	ctx := context.Background()
	repo := store.SigningKeys()

	// Create inactive key
	repo.Create(ctx, &domain.SigningKey{ID: "key-1", Algorithm: "RS256", Active: false})

	_, err := repo.GetActive(ctx)
	if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("Should return not found when no active key exists")
	}
}

// Test not found errors

func NotFoundErrors(t *testing.T, newStore Factory) {
	store := newStore(t)

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

func UserRepository_FlagsRoundTrip(t *testing.T, newStore Factory) {
	store := newStore(t)
	ctx := context.Background()

	u := &domain.User{ID: "u1", Email: "u1@example.com", DisplayName: "Ada Lovelace", GivenName: "Ada", FamilyName: "Lovelace", Active: true, EmailVerified: true, Admin: true}
	if err := store.Users().Create(ctx, u); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	got, _ := store.Users().GetByID(ctx, "u1")
	if !got.EmailVerified || !got.Admin {
		t.Errorf("flags not round-tripped on create: verified=%v admin=%v", got.EmailVerified, got.Admin)
	}
	if got.GivenName != "Ada" || got.FamilyName != "Lovelace" {
		t.Errorf("names not round-tripped on create: given=%q family=%q", got.GivenName, got.FamilyName)
	}

	got.EmailVerified, got.Admin = false, false
	got.GivenName, got.FamilyName = "Augusta", ""
	if err := store.Users().Update(ctx, got); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = store.Users().GetByID(ctx, "u1")
	if got.EmailVerified || got.Admin {
		t.Errorf("flags not round-tripped on update: verified=%v admin=%v", got.EmailVerified, got.Admin)
	}
	if got.GivenName != "Augusta" || got.FamilyName != "" {
		t.Errorf("names not round-tripped on update: given=%q family=%q", got.GivenName, got.FamilyName)
	}
}

func ClientRepository_SkipConsentRoundTrip(t *testing.T, newStore Factory) {
	store := newStore(t)
	ctx := context.Background()

	if err := store.Clients().Create(ctx, &domain.Client{ID: "c1", Name: "c1", SkipConsent: true, MinimalIDToken: true, AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: 36 * time.Hour}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	got, _ := store.Clients().GetByID(ctx, "c1")
	if !got.SkipConsent {
		t.Error("SkipConsent not round-tripped")
	}
	if !got.MinimalIDToken {
		t.Error("MinimalIDToken not round-tripped")
	}
	if got.AccessTokenTTL != 5*time.Minute || got.RefreshTokenTTL != 36*time.Hour {
		t.Errorf("token TTLs not round-tripped: access=%v refresh=%v", got.AccessTokenTTL, got.RefreshTokenTTL)
	}

	got.AccessTokenTTL, got.RefreshTokenTTL = 0, time.Hour
	got.MinimalIDToken = false
	if err := store.Clients().Update(ctx, got); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = store.Clients().GetByID(ctx, "c1")
	if got.AccessTokenTTL != 0 || got.RefreshTokenTTL != time.Hour {
		t.Errorf("token TTLs not round-tripped on update: access=%v refresh=%v", got.AccessTokenTTL, got.RefreshTokenTTL)
	}
	if got.MinimalIDToken {
		t.Error("MinimalIDToken not round-tripped on update")
	}
}

func ConsentRepository_UpsertGetDelete(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1")
	seedClients(t, store, "c1")
	ctx := context.Background()
	repo := store.Consents()

	if _, err := repo.Get(ctx, "u1", "c1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("Get before grant should be not found, got %v", err)
	}

	first := &domain.Consent{UserID: "u1", ClientID: "c1", Scopes: []string{"openid"}}
	if err := repo.Upsert(ctx, first); err != nil {
		t.Fatalf("Upsert failed: %v", err)
	}
	if first.ID == "" || first.GrantedAt.IsZero() {
		t.Error("Upsert should assign ID and GrantedAt")
	}

	got, err := repo.Get(ctx, "u1", "c1")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if !got.Covers([]string{"openid"}) || got.Covers([]string{"openid", "email"}) {
		t.Errorf("unexpected scopes %v", got.Scopes)
	}

	// Upsert again with wider scopes replaces the grant, keeping one row.
	if err := repo.Upsert(ctx, &domain.Consent{UserID: "u1", ClientID: "c1", Scopes: []string{"openid", "email"}}); err != nil {
		t.Fatalf("second Upsert failed: %v", err)
	}
	got, _ = repo.Get(ctx, "u1", "c1")
	if !got.Covers([]string{"openid", "email"}) {
		t.Errorf("scopes should be replaced, got %v", got.Scopes)
	}
	list, _ := repo.ListByUserID(ctx, "u1")
	if len(list) != 1 {
		t.Errorf("expected exactly one consent after upsert, got %d", len(list))
	}

	if err := repo.Delete(ctx, "u1", "c1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := repo.Get(ctx, "u1", "c1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("consent should be gone after delete")
	}
	if err := repo.Delete(ctx, "u1", "c1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("deleting missing consent should be not found, got %v", err)
	}
}

func ConsentRepository_ListAndDeleteByUser(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1", "u2")
	seedClients(t, store, "c1", "c2")
	ctx := context.Background()
	repo := store.Consents()

	repo.Upsert(ctx, &domain.Consent{UserID: "u1", ClientID: "c1", Scopes: []string{"openid"}})
	repo.Upsert(ctx, &domain.Consent{UserID: "u1", ClientID: "c2", Scopes: []string{"openid"}})
	repo.Upsert(ctx, &domain.Consent{UserID: "u2", ClientID: "c1", Scopes: []string{"openid"}})

	list, err := repo.ListByUserID(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUserID failed: %v", err)
	}
	if len(list) != 2 {
		t.Errorf("expected 2 consents for u1, got %d", len(list))
	}

	if err := repo.DeleteByUserID(ctx, "u1"); err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}
	list, _ = repo.ListByUserID(ctx, "u1")
	if len(list) != 0 {
		t.Errorf("u1 consents should be gone, got %d", len(list))
	}
	if _, err := repo.Get(ctx, "u2", "c1"); err != nil {
		t.Errorf("u2 consent must survive: %v", err)
	}
}

func VerificationTokenRepository_Lifecycle(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1")
	ctx := context.Background()
	repo := store.VerificationTokens()

	tok := &domain.VerificationToken{TokenHash: "h1", UserID: "u1", Purpose: domain.PurposePasswordReset, ExpiresAt: time.Now().Add(time.Hour)}
	if err := repo.Create(ctx, tok); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if tok.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if err := repo.Create(ctx, &domain.VerificationToken{TokenHash: "h1", UserID: "u1", Purpose: domain.PurposePasswordReset, ExpiresAt: time.Now().Add(time.Hour)}); !idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
		t.Errorf("duplicate hash should be already exists, got %v", err)
	}

	got, err := repo.GetByHash(ctx, "h1")
	if err != nil {
		t.Fatalf("GetByHash failed: %v", err)
	}
	if got.Used || !got.IsValid() || got.Purpose != domain.PurposePasswordReset {
		t.Errorf("unexpected token state: %+v", got)
	}

	if err := repo.MarkUsed(ctx, "h1"); err != nil {
		t.Fatalf("MarkUsed failed: %v", err)
	}
	got, _ = repo.GetByHash(ctx, "h1")
	if !got.Used || got.IsValid() {
		t.Error("token should be used and invalid")
	}
	if err := repo.MarkUsed(ctx, "missing"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("MarkUsed on missing token should be not found, got %v", err)
	}
	if _, err := repo.GetByHash(ctx, "missing"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("GetByHash on missing token should be not found, got %v", err)
	}
}

func VerificationTokenRepository_DeleteByUserAndExpired(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1", "u2")
	ctx := context.Background()
	repo := store.VerificationTokens()
	future := time.Now().Add(time.Hour)

	repo.Create(ctx, &domain.VerificationToken{TokenHash: "reset-1", UserID: "u1", Purpose: domain.PurposePasswordReset, ExpiresAt: future})
	repo.Create(ctx, &domain.VerificationToken{TokenHash: "verify-1", UserID: "u1", Purpose: domain.PurposeEmailVerify, ExpiresAt: future})
	repo.Create(ctx, &domain.VerificationToken{TokenHash: "reset-2", UserID: "u2", Purpose: domain.PurposePasswordReset, ExpiresAt: future})
	repo.Create(ctx, &domain.VerificationToken{TokenHash: "expired", UserID: "u2", Purpose: domain.PurposePasswordReset, ExpiresAt: time.Now().Add(-time.Hour)})

	// Delete one purpose for u1
	if err := repo.DeleteByUserID(ctx, "u1", domain.PurposePasswordReset); err != nil {
		t.Fatalf("DeleteByUserID failed: %v", err)
	}
	if _, err := repo.GetByHash(ctx, "reset-1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("reset-1 should be deleted")
	}
	if _, err := repo.GetByHash(ctx, "verify-1"); err != nil {
		t.Error("verify-1 (other purpose) should remain")
	}

	// Delete all purposes for u1
	if err := repo.DeleteByUserID(ctx, "u1", ""); err != nil {
		t.Fatalf("DeleteByUserID(all) failed: %v", err)
	}
	if _, err := repo.GetByHash(ctx, "verify-1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("verify-1 should be deleted")
	}

	// Expired purge
	if err := repo.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired failed: %v", err)
	}
	if _, err := repo.GetByHash(ctx, "expired"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("expired token should be purged")
	}
	if _, err := repo.GetByHash(ctx, "reset-2"); err != nil {
		t.Error("valid token should remain")
	}
}

func GroupRepository_CRUD(t *testing.T, newStore Factory) {
	store := newStore(t)
	ctx := context.Background()
	repo := store.Groups()

	g := &domain.Group{ID: "g1", Name: "Admins", Description: "Cluster admins"}
	if err := repo.Create(ctx, g); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	if g.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if err := repo.Create(ctx, &domain.Group{ID: "g2", Name: "admins"}); !idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
		t.Errorf("group names should be unique case-insensitively, got %v", err)
	}
	if err := repo.Create(ctx, &domain.Group{ID: "g1", Name: "Other"}); !idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
		t.Errorf("duplicate ID should be already exists, got %v", err)
	}

	got, err := repo.GetByName(ctx, "ADMINS")
	if err != nil || got.ID != "g1" {
		t.Fatalf("GetByName should be case-insensitive: %v %v", got, err)
	}

	got.Description = "Updated"
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = repo.GetByID(ctx, "g1")
	if got.Description != "Updated" {
		t.Error("Update not persisted")
	}

	repo.Create(ctx, &domain.Group{ID: "g3", Name: "beta"})
	list, _ := repo.List(ctx)
	if len(list) != 2 || list[0].Name != "Admins" || list[1].Name != "beta" {
		t.Errorf("List should be sorted by name, got %v", names(list))
	}

	if err := repo.Delete(ctx, "g1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := repo.GetByID(ctx, "g1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("group should be gone after delete")
	}
	if err := repo.Delete(ctx, "g1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("deleting missing group should be not found, got %v", err)
	}
}

func GroupRepository_Membership(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1", "u2")
	ctx := context.Background()
	repo := store.Groups()
	repo.Create(ctx, &domain.Group{ID: "g1", Name: "zeta"})
	repo.Create(ctx, &domain.Group{ID: "g2", Name: "alpha"})

	if err := repo.AddMember(ctx, "g1", "u1"); err != nil {
		t.Fatalf("AddMember failed: %v", err)
	}
	if err := repo.AddMember(ctx, "g1", "u1"); err != nil {
		t.Errorf("AddMember should be idempotent, got %v", err)
	}
	repo.AddMember(ctx, "g2", "u1")
	repo.AddMember(ctx, "g1", "u2")

	ids, _ := repo.MemberIDs(ctx, "g1")
	if len(ids) != 2 {
		t.Errorf("g1 should have 2 members, got %v", ids)
	}
	groups, _ := repo.GroupsForUser(ctx, "u1")
	if len(groups) != 2 || groups[0].Name != "alpha" || groups[1].Name != "zeta" {
		t.Errorf("GroupsForUser should list both sorted by name, got %v", names(groups))
	}

	if err := repo.RemoveMember(ctx, "g2", "u1"); err != nil {
		t.Fatalf("RemoveMember failed: %v", err)
	}
	if err := repo.RemoveMember(ctx, "g2", "u1"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("removing absent member should be not found, got %v", err)
	}

	// Deleting a group drops its memberships
	if err := repo.Delete(ctx, "g1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if groups, _ := repo.GroupsForUser(ctx, "u2"); len(groups) != 0 {
		t.Errorf("u2 should have no groups after g1 deleted, got %v", names(groups))
	}

	// RemoveUser drops a user from everything
	repo.AddMember(ctx, "g2", "u1")
	if err := repo.RemoveUser(ctx, "u1"); err != nil {
		t.Fatalf("RemoveUser failed: %v", err)
	}
	if ids, _ := repo.MemberIDs(ctx, "g2"); len(ids) != 0 {
		t.Errorf("u1 should be removed from g2, got %v", ids)
	}
}

func names(groups []*domain.Group) []string {
	out := make([]string, len(groups))
	for i, g := range groups {
		out[i] = g.Name
	}
	return out
}

func SessionRepository_ListByUserID(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1", "u2")
	ctx := context.Background()
	repo := store.Sessions()

	repo.Create(ctx, &domain.Session{ID: "old", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour), IPAddress: "1.1.1.1"})
	time.Sleep(2 * time.Millisecond)
	repo.Create(ctx, &domain.Session{ID: "new", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
	repo.Create(ctx, &domain.Session{ID: "expired", UserID: "u1", ExpiresAt: time.Now().Add(-time.Hour)})
	repo.Create(ctx, &domain.Session{ID: "other", UserID: "u2", ExpiresAt: time.Now().Add(time.Hour)})

	list, err := repo.ListByUserID(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUserID failed: %v", err)
	}
	if len(list) != 2 || list[0].ID != "new" || list[1].ID != "old" {
		t.Errorf("expected [new old] (unexpired, newest first), got %v", sessionIDs(list))
	}
	if list[1].IPAddress != "1.1.1.1" {
		t.Error("session fields should round-trip")
	}
	if list, _ := repo.ListByUserID(ctx, "nobody"); len(list) != 0 {
		t.Error("unknown user should have no sessions")
	}
}

func TokenRepository_ListByUserID(t *testing.T, newStore Factory) {
	store := newStore(t)
	seedUsers(t, store, "u1", "u2")
	seedClients(t, store, "c1")
	ctx := context.Background()
	repo := store.Tokens()

	repo.Create(ctx, &domain.Token{ID: "old", UserID: "u1", ClientID: "c1", Scope: "openid", ExpiresAt: time.Now().Add(time.Hour)})
	time.Sleep(2 * time.Millisecond)
	repo.Create(ctx, &domain.Token{ID: "new", UserID: "u1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour)})
	repo.Create(ctx, &domain.Token{ID: "expired", UserID: "u1", ClientID: "c1", ExpiresAt: time.Now().Add(-time.Hour)})
	repo.Create(ctx, &domain.Token{ID: "other", UserID: "u2", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour)})
	repo.Revoke(ctx, "old")

	list, err := repo.ListByUserID(ctx, "u1")
	if err != nil {
		t.Fatalf("ListByUserID failed: %v", err)
	}
	if len(list) != 2 || list[0].ID != "new" || list[1].ID != "old" {
		t.Errorf("expected [new old] (unexpired incl. revoked, newest first), got %v", tokenIDs(list))
	}
	if !list[1].Revoked || list[1].Scope != "openid" {
		t.Error("token fields should round-trip")
	}
}

func sessionIDs(list []*domain.Session) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = s.ID
	}
	return out
}

func tokenIDs(list []*domain.Token) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = s.ID
	}
	return out
}

func AuditRepository_AppendListPrune(t *testing.T, newStore Factory) {
	store := newStore(t)
	ctx := context.Background()
	repo := store.Audit()

	old := &domain.AuditEvent{At: time.Now().Add(-48 * time.Hour), Action: "login.success", ActorEmail: "a@example.com"}
	if err := repo.Append(ctx, old); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if old.ID == "" {
		t.Error("Append should assign an ID")
	}
	recent := &domain.AuditEvent{Action: "user.created", ActorID: "admin", ActorEmail: "admin@example.com", TargetType: "user", TargetID: "u1", Detail: "x", IP: "10.0.0.1"}
	if err := repo.Append(ctx, recent); err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if recent.At.IsZero() {
		t.Error("Append should stamp the time")
	}

	list, err := repo.List(ctx, 10)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(list) != 2 || list[0].Action != "user.created" || list[1].Action != "login.success" {
		t.Errorf("List should be newest first, got %v", list)
	}
	if list[0].TargetID != "u1" || list[0].IP != "10.0.0.1" || list[0].ActorEmail != "admin@example.com" {
		t.Errorf("fields not round-tripped: %+v", list[0])
	}
	if list, _ := repo.List(ctx, 1); len(list) != 1 || list[0].Action != "user.created" {
		t.Error("List should honour the limit")
	}

	if err := repo.DeleteBefore(ctx, time.Now().Add(-24*time.Hour)); err != nil {
		t.Fatalf("DeleteBefore failed: %v", err)
	}
	list, _ = repo.List(ctx, 10)
	if len(list) != 1 || list[0].Action != "user.created" {
		t.Errorf("old event should be pruned, got %v", list)
	}
}

// isRevoked is RevocationRepository.IsRevoked with a fatal error.
func isRevoked(t *testing.T, s store.Store, jti, userID, clientID string, issuedAt time.Time) bool {
	t.Helper()
	revoked, err := s.Revocations().IsRevoked(context.Background(), jti, userID, clientID, issuedAt)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	return revoked
}

func RevocationRepository_AccessToken(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()
	now := time.Now()

	if isRevoked(t, s, "jti-1", "u1", "c1", now) {
		t.Fatal("nothing revoked yet")
	}
	if err := s.Revocations().RevokeAccessToken(ctx, "jti-1", now.Add(time.Hour)); err != nil {
		t.Fatalf("RevokeAccessToken: %v", err)
	}
	if !isRevoked(t, s, "jti-1", "u1", "c1", now) {
		t.Error("jti-1 should be revoked")
	}
	if isRevoked(t, s, "jti-2", "u1", "c1", now) {
		t.Error("another token of the same user and client is untouched")
	}
	// Revoking the same token again is fine.
	if err := s.Revocations().RevokeAccessToken(ctx, "jti-1", now.Add(2*time.Hour)); err != nil {
		t.Fatalf("second RevokeAccessToken: %v", err)
	}
}

func RevocationRepository_Watermarks(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()
	repo := s.Revocations()
	// Sub-second precision matters: the issue time comes from a UUIDv7 jti
	// with millisecond resolution, and a token minted right after a
	// revocation must not be caught by it.
	cut := time.Now()
	before, after := cut.Add(-5*time.Millisecond), cut.Add(5*time.Millisecond)

	// user: every client
	if err := repo.RevokeBefore(ctx, domain.RevocationUser, "u1", cut); err != nil {
		t.Fatalf("RevokeBefore user: %v", err)
	}
	if !isRevoked(t, s, "a", "u1", "c1", before) || !isRevoked(t, s, "b", "u1", "c2", cut) {
		t.Error("u1 tokens issued at or before the cut should be revoked, for any client")
	}
	if isRevoked(t, s, "c", "u1", "c1", after) {
		t.Error("u1 token issued after the cut is valid")
	}
	if isRevoked(t, s, "d", "u2", "c1", before) {
		t.Error("u2 is untouched")
	}

	// user+client
	if err := repo.RevokeBefore(ctx, domain.RevocationUserClient, domain.UserClientKey("u2", "c1"), cut); err != nil {
		t.Fatalf("RevokeBefore user_client: %v", err)
	}
	if !isRevoked(t, s, "e", "u2", "c1", before) {
		t.Error("u2/c1 token before the cut should be revoked")
	}
	if isRevoked(t, s, "f", "u2", "c2", before) {
		t.Error("u2/c2 is untouched")
	}

	// client
	if err := repo.RevokeBefore(ctx, domain.RevocationClient, "c3", cut); err != nil {
		t.Fatalf("RevokeBefore client: %v", err)
	}
	if !isRevoked(t, s, "g", "u9", "c3", before) {
		t.Error("any user's c3 token before the cut should be revoked")
	}
	if isRevoked(t, s, "h", "u9", "c3", after) {
		t.Error("c3 token after the cut is valid")
	}

	// Upsert keeps the later cut: moving it back must not un-revoke.
	if err := repo.RevokeBefore(ctx, domain.RevocationUser, "u1", cut.Add(-time.Hour)); err != nil {
		t.Fatalf("RevokeBefore user again: %v", err)
	}
	if !isRevoked(t, s, "i", "u1", "c1", before) {
		t.Error("an earlier cut must not narrow an existing revocation")
	}
	if err := repo.RevokeBefore(ctx, domain.RevocationUser, "u1", after); err != nil {
		t.Fatalf("RevokeBefore user later: %v", err)
	}
	if !isRevoked(t, s, "j", "u1", "c1", after) {
		t.Error("a later cut widens the revocation")
	}
}

// Revoking refresh tokens revokes the access tokens of the same grant.
func RevocationRepository_TokenRevokesGrant(t *testing.T, newStore Factory) {
	s := newStore(t)
	seedUsers(t, s, "u1", "u2")
	seedClients(t, s, "c1", "c2")
	ctx := context.Background()
	tokens := s.Tokens()
	for _, tk := range []*domain.Token{
		{ID: "r1", UserID: "u1", ClientID: "c1"},
		{ID: "r2", UserID: "u1", ClientID: "c2"},
		{ID: "r3", UserID: "u2", ClientID: "c1"},
	} {
		tk.ExpiresAt = time.Now().Add(time.Hour)
		if err := tokens.Create(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}
	issued := time.Now().Add(-time.Second) // an access token minted just before

	if err := tokens.Revoke(ctx, "r1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if !isRevoked(t, s, "x", "u1", "c1", issued) {
		t.Error("Revoke(r1) should revoke u1's access tokens for c1")
	}
	if isRevoked(t, s, "x", "u1", "c2", issued) || isRevoked(t, s, "x", "u2", "c1", issued) {
		t.Error("Revoke(r1) must not touch other clients or users")
	}

	// Rotation retires a refresh token without cutting off the grant.
	if err := tokens.Rotate(ctx, "r2"); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if r2, _ := tokens.GetByID(ctx, "r2"); !r2.Revoked {
		t.Error("Rotate should mark the refresh token revoked")
	}
	if isRevoked(t, s, "x", "u1", "c2", issued) {
		t.Error("Rotate must not revoke the grant's access tokens")
	}
	if err := tokens.Rotate(ctx, "no-such"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Errorf("Rotate unknown token: %v, want NotFound", err)
	}

	if err := tokens.RevokeByClientID(ctx, "c2"); err != nil {
		t.Fatalf("RevokeByClientID: %v", err)
	}
	if !isRevoked(t, s, "x", "u1", "c2", issued) || !isRevoked(t, s, "x", "u7", "c2", issued) {
		t.Error("RevokeByClientID should revoke every user's access tokens for c2")
	}

	if err := tokens.RevokeByUserID(ctx, "u2"); err != nil {
		t.Fatalf("RevokeByUserID: %v", err)
	}
	if !isRevoked(t, s, "x", "u2", "c1", issued) || !isRevoked(t, s, "x", "u2", "c9", issued) {
		t.Error("RevokeByUserID should revoke u2's access tokens for every client")
	}
	// ...even when the user holds no refresh token at all (tokens issued
	// without offline_access).
	if err := tokens.RevokeByUserID(ctx, "u1-no-rows"); err != nil {
		t.Fatalf("RevokeByUserID without rows: %v", err)
	}
	if !isRevoked(t, s, "x", "u1-no-rows", "c1", issued) {
		t.Error("RevokeByUserID must record the revocation even with no refresh token rows")
	}
}

func RevocationRepository_DeleteExpired(t *testing.T, newStore Factory) {
	s := newStore(t)
	ctx := context.Background()
	repo := s.Revocations()
	now := time.Now()

	if err := repo.RevokeAccessToken(ctx, "gone", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.RevokeAccessToken(ctx, "live", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// A watermark far enough in the past to have expired.
	if err := repo.RevokeBefore(ctx, domain.RevocationUser, "old", now.Add(-domain.RevocationRetention-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repo.RevokeBefore(ctx, domain.RevocationUser, "recent", now); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteExpired(ctx); err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if isRevoked(t, s, "gone", "u", "c", now) {
		t.Error("expired jti row should be purged")
	}
	if !isRevoked(t, s, "live", "u", "c", now) {
		t.Error("live jti row should remain")
	}
	if isRevoked(t, s, "x", "old", "c", now.Add(-domain.RevocationRetention-2*time.Minute)) {
		t.Error("expired watermark should be purged")
	}
	if !isRevoked(t, s, "x", "recent", "c", now) {
		t.Error("recent watermark should remain")
	}
}
