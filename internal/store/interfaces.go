// Package store defines repository interfaces for persistence.
package store

import (
	"context"
	"time"

	"github.com/tendant/idpico/internal/domain"
)

// UserRepository defines operations for user persistence.
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByID(ctx context.Context, id string) (*domain.User, error)
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*domain.User, error)
}

// ClientRepository defines operations for OAuth client persistence.
type ClientRepository interface {
	Create(ctx context.Context, client *domain.Client) error
	GetByID(ctx context.Context, id string) (*domain.Client, error)
	Update(ctx context.Context, client *domain.Client) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*domain.Client, error)
}

// SessionRepository defines operations for session persistence.
type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) error
	GetByID(ctx context.Context, id string) (*domain.Session, error)
	Delete(ctx context.Context, id string) error
	DeleteByUserID(ctx context.Context, userID string) error
	DeleteExpired(ctx context.Context) error
	// ListByUserID returns the user's unexpired sessions, newest first.
	ListByUserID(ctx context.Context, userID string) ([]*domain.Session, error)
}

// AuthCodeRepository defines operations for authorization code persistence.
type AuthCodeRepository interface {
	Create(ctx context.Context, code *domain.AuthCode) error
	GetByCode(ctx context.Context, code string) (*domain.AuthCode, error)
	MarkUsed(ctx context.Context, code string) error
	Delete(ctx context.Context, code string) error
	DeleteExpired(ctx context.Context) error
}

// TokenRepository defines operations for refresh token persistence.
type TokenRepository interface {
	Create(ctx context.Context, token *domain.Token) error
	GetByID(ctx context.Context, id string) (*domain.Token, error)
	Revoke(ctx context.Context, id string) error
	RevokeByUserID(ctx context.Context, userID string) error
	RevokeByClientID(ctx context.Context, clientID string) error
	DeleteExpired(ctx context.Context) error
	// ListByUserID returns the user's unexpired tokens (revoked included), newest first.
	ListByUserID(ctx context.Context, userID string) ([]*domain.Token, error)
}

// SigningKeyRepository defines operations for signing key persistence.
type SigningKeyRepository interface {
	Create(ctx context.Context, key *domain.SigningKey) error
	GetByID(ctx context.Context, id string) (*domain.SigningKey, error)
	GetActive(ctx context.Context) (*domain.SigningKey, error)
	GetAll(ctx context.Context) ([]*domain.SigningKey, error)
	SetActive(ctx context.Context, id string) error
	Delete(ctx context.Context, id string) error
}

// ConsentRepository defines operations for remembered consent grants.
type ConsentRepository interface {
	// Upsert creates the consent or replaces the existing one for the same user and client.
	Upsert(ctx context.Context, consent *domain.Consent) error
	Get(ctx context.Context, userID, clientID string) (*domain.Consent, error)
	ListByUserID(ctx context.Context, userID string) ([]*domain.Consent, error)
	Delete(ctx context.Context, userID, clientID string) error
	DeleteByUserID(ctx context.Context, userID string) error
}

// VerificationTokenRepository defines operations for emailed single-use tokens.
type VerificationTokenRepository interface {
	Create(ctx context.Context, token *domain.VerificationToken) error
	GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error)
	MarkUsed(ctx context.Context, hash string) error
	// DeleteByUserID removes a user's tokens for one purpose (empty purpose = all).
	DeleteByUserID(ctx context.Context, userID, purpose string) error
	DeleteExpired(ctx context.Context) error
}

// GroupRepository defines operations for groups and memberships.
type GroupRepository interface {
	Create(ctx context.Context, group *domain.Group) error
	GetByID(ctx context.Context, id string) (*domain.Group, error)
	GetByName(ctx context.Context, name string) (*domain.Group, error)
	Update(ctx context.Context, group *domain.Group) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context) ([]*domain.Group, error)

	// AddMember is idempotent; RemoveMember returns NotFound if absent.
	AddMember(ctx context.Context, groupID, userID string) error
	RemoveMember(ctx context.Context, groupID, userID string) error
	// MemberIDs lists the user IDs in a group.
	MemberIDs(ctx context.Context, groupID string) ([]string, error)
	// GroupsForUser lists the groups a user belongs to, ordered by name.
	GroupsForUser(ctx context.Context, userID string) ([]*domain.Group, error)
	// RemoveUser drops a user from every group.
	RemoveUser(ctx context.Context, userID string) error
}

// AuditRepository is an append-only log of security-relevant actions.
type AuditRepository interface {
	Append(ctx context.Context, event *domain.AuditEvent) error
	// List returns the newest events, at most limit.
	List(ctx context.Context, limit int) ([]*domain.AuditEvent, error)
	DeleteBefore(ctx context.Context, cutoff time.Time) error
}

// Store aggregates all repositories.
type Store interface {
	Users() UserRepository
	Clients() ClientRepository
	Sessions() SessionRepository
	AuthCodes() AuthCodeRepository
	Tokens() TokenRepository
	SigningKeys() SigningKeyRepository
	Consents() ConsentRepository
	VerificationTokens() VerificationTokenRepository
	Groups() GroupRepository
	Audit() AuditRepository
	Close() error
}
