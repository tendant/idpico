// Package storetest provides a conformance test suite that every store.Store
// implementation must pass. Backends call Run from their own test packages.
package storetest

import (
	"context"
	"testing"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
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
		{"AuthCodeRepository_CRUD", AuthCodeRepository_CRUD},
		{"AuthCodeRepository_DeleteExpired", AuthCodeRepository_DeleteExpired},
		{"TokenRepository_CRUD", TokenRepository_CRUD},
		{"TokenRepository_RevokeByUserID", TokenRepository_RevokeByUserID},
		{"TokenRepository_RevokeByClientID", TokenRepository_RevokeByClientID},
		{"TokenRepository_DeleteExpired", TokenRepository_DeleteExpired},
		{"SigningKeyRepository_CRUD", SigningKeyRepository_CRUD},
		{"SigningKeyRepository_DuplicateID", SigningKeyRepository_DuplicateID},
		{"SigningKeyRepository_NoActiveKey", SigningKeyRepository_NoActiveKey},
		{"ConsentRepository_UpsertGetDelete", ConsentRepository_UpsertGetDelete},
		{"ConsentRepository_ListAndDeleteByUser", ConsentRepository_ListAndDeleteByUser},
		{"VerificationTokenRepository_Lifecycle", VerificationTokenRepository_Lifecycle},
		{"VerificationTokenRepository_DeleteByUserAndExpired", VerificationTokenRepository_DeleteByUserAndExpired},
		{"UserRepository_FlagsRoundTrip", UserRepository_FlagsRoundTrip},
		{"ClientRepository_SkipConsentRoundTrip", ClientRepository_SkipConsentRoundTrip},
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

	u := &domain.User{ID: "u1", Email: "u1@example.com", Active: true, EmailVerified: true, Admin: true}
	if err := store.Users().Create(ctx, u); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	got, _ := store.Users().GetByID(ctx, "u1")
	if !got.EmailVerified || !got.Admin {
		t.Errorf("flags not round-tripped on create: verified=%v admin=%v", got.EmailVerified, got.Admin)
	}

	got.EmailVerified, got.Admin = false, false
	if err := store.Users().Update(ctx, got); err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	got, _ = store.Users().GetByID(ctx, "u1")
	if got.EmailVerified || got.Admin {
		t.Errorf("flags not round-tripped on update: verified=%v admin=%v", got.EmailVerified, got.Admin)
	}
}

func ClientRepository_SkipConsentRoundTrip(t *testing.T, newStore Factory) {
	store := newStore(t)
	ctx := context.Background()

	if err := store.Clients().Create(ctx, &domain.Client{ID: "c1", Name: "c1", SkipConsent: true}); err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	got, _ := store.Clients().GetByID(ctx, "c1")
	if !got.SkipConsent {
		t.Error("SkipConsent not round-tripped")
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
