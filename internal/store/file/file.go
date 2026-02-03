// Package file implements file-based storage using JSON files.
package file

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
)

// Store implements store.Store using JSON files for persistence.
type Store struct {
	dataDir string
	mu      sync.RWMutex

	users       *userRepository
	clients     *clientRepository
	sessions    *sessionRepository
	authCodes   *authCodeRepository
	tokens      *tokenRepository
	signingKeys *signingKeyRepository
}

// Option configures the Store.
type Option func(*Store)

// NewStore creates a new file-based store.
func NewStore(dataDir string, opts ...Option) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	s := &Store{
		dataDir: dataDir,
	}

	for _, opt := range opts {
		opt(s)
	}

	// Initialize repositories
	s.users = &userRepository{store: s}
	s.clients = &clientRepository{store: s}
	s.sessions = &sessionRepository{store: s}
	s.authCodes = &authCodeRepository{store: s}
	s.tokens = &tokenRepository{store: s}
	s.signingKeys = &signingKeyRepository{store: s}

	return s, nil
}

func (s *Store) Users() store.UserRepository           { return s.users }
func (s *Store) Clients() store.ClientRepository       { return s.clients }
func (s *Store) Sessions() store.SessionRepository     { return s.sessions }
func (s *Store) AuthCodes() store.AuthCodeRepository   { return s.authCodes }
func (s *Store) Tokens() store.TokenRepository         { return s.tokens }
func (s *Store) SigningKeys() store.SigningKeyRepository { return s.signingKeys }
func (s *Store) Close() error                          { return nil }

// Helper methods for file operations

func (s *Store) filePath(name string) string {
	return filepath.Join(s.dataDir, name+".json")
}

func (s *Store) readFile(name string, v any) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.filePath(name))
	if os.IsNotExist(err) {
		return nil // Empty collection
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func (s *Store) writeFile(name string, v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.filePath(name), data, 0600)
}

// User Repository

type userRepository struct {
	store *Store
}

type usersData struct {
	Users []*domain.User `json:"users"`
}

func (r *userRepository) load() (*usersData, error) {
	var data usersData
	if err := r.store.readFile("users", &data); err != nil {
		return nil, err
	}
	if data.Users == nil {
		data.Users = []*domain.User{}
	}
	return &data, nil
}

func (r *userRepository) save(data *usersData) error {
	return r.store.writeFile("users", data)
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load users", err)
	}

	for _, u := range data.Users {
		if u.ID == user.ID {
			return idperrors.AlreadyExists("user", user.ID)
		}
		if u.Email == user.Email {
			return idperrors.AlreadyExists("user with email", user.Email)
		}
	}

	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now
	data.Users = append(data.Users, user)

	return r.save(data)
}

func (r *userRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load users", err)
	}

	for _, u := range data.Users {
		if u.ID == id {
			return u, nil
		}
	}
	return nil, idperrors.NotFound("user", id)
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load users", err)
	}

	for _, u := range data.Users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, idperrors.NotFound("user with email", email)
}

func (r *userRepository) Update(ctx context.Context, user *domain.User) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load users", err)
	}

	for i, u := range data.Users {
		if u.ID == user.ID {
			user.UpdatedAt = time.Now()
			data.Users[i] = user
			return r.save(data)
		}
	}
	return idperrors.NotFound("user", user.ID)
}

func (r *userRepository) Delete(ctx context.Context, id string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load users", err)
	}

	for i, u := range data.Users {
		if u.ID == id {
			data.Users = append(data.Users[:i], data.Users[i+1:]...)
			return r.save(data)
		}
	}
	return idperrors.NotFound("user", id)
}

func (r *userRepository) List(ctx context.Context) ([]*domain.User, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load users", err)
	}
	return data.Users, nil
}

// Client Repository

type clientRepository struct {
	store *Store
}

type clientsData struct {
	Clients []*domain.Client `json:"clients"`
}

func (r *clientRepository) load() (*clientsData, error) {
	var data clientsData
	if err := r.store.readFile("clients", &data); err != nil {
		return nil, err
	}
	if data.Clients == nil {
		data.Clients = []*domain.Client{}
	}
	return &data, nil
}

func (r *clientRepository) save(data *clientsData) error {
	return r.store.writeFile("clients", data)
}

func (r *clientRepository) Create(ctx context.Context, client *domain.Client) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load clients", err)
	}

	for _, c := range data.Clients {
		if c.ID == client.ID {
			return idperrors.AlreadyExists("client", client.ID)
		}
	}

	now := time.Now()
	client.CreatedAt = now
	client.UpdatedAt = now
	data.Clients = append(data.Clients, client)

	return r.save(data)
}

func (r *clientRepository) GetByID(ctx context.Context, id string) (*domain.Client, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load clients", err)
	}

	for _, c := range data.Clients {
		if c.ID == id {
			return c, nil
		}
	}
	return nil, idperrors.NotFound("client", id)
}

func (r *clientRepository) Update(ctx context.Context, client *domain.Client) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load clients", err)
	}

	for i, c := range data.Clients {
		if c.ID == client.ID {
			client.UpdatedAt = time.Now()
			data.Clients[i] = client
			return r.save(data)
		}
	}
	return idperrors.NotFound("client", client.ID)
}

func (r *clientRepository) Delete(ctx context.Context, id string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load clients", err)
	}

	for i, c := range data.Clients {
		if c.ID == id {
			data.Clients = append(data.Clients[:i], data.Clients[i+1:]...)
			return r.save(data)
		}
	}
	return idperrors.NotFound("client", id)
}

func (r *clientRepository) List(ctx context.Context) ([]*domain.Client, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load clients", err)
	}
	return data.Clients, nil
}

// Session Repository

type sessionRepository struct {
	store *Store
}

type sessionsData struct {
	Sessions []*domain.Session `json:"sessions"`
}

func (r *sessionRepository) load() (*sessionsData, error) {
	var data sessionsData
	if err := r.store.readFile("sessions", &data); err != nil {
		return nil, err
	}
	if data.Sessions == nil {
		data.Sessions = []*domain.Session{}
	}
	return &data, nil
}

func (r *sessionRepository) save(data *sessionsData) error {
	return r.store.writeFile("sessions", data)
}

func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load sessions", err)
	}

	session.CreatedAt = time.Now()
	data.Sessions = append(data.Sessions, session)

	return r.save(data)
}

func (r *sessionRepository) GetByID(ctx context.Context, id string) (*domain.Session, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load sessions", err)
	}

	for _, s := range data.Sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, idperrors.NotFound("session", id)
}

func (r *sessionRepository) Delete(ctx context.Context, id string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load sessions", err)
	}

	for i, s := range data.Sessions {
		if s.ID == id {
			data.Sessions = append(data.Sessions[:i], data.Sessions[i+1:]...)
			return r.save(data)
		}
	}
	return idperrors.NotFound("session", id)
}

func (r *sessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load sessions", err)
	}

	filtered := make([]*domain.Session, 0, len(data.Sessions))
	for _, s := range data.Sessions {
		if s.UserID != userID {
			filtered = append(filtered, s)
		}
	}
	data.Sessions = filtered

	return r.save(data)
}

func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load sessions", err)
	}

	now := time.Now()
	filtered := make([]*domain.Session, 0, len(data.Sessions))
	for _, s := range data.Sessions {
		if s.ExpiresAt.After(now) {
			filtered = append(filtered, s)
		}
	}
	data.Sessions = filtered

	return r.save(data)
}

// AuthCode Repository

type authCodeRepository struct {
	store *Store
}

type authCodesData struct {
	AuthCodes []*domain.AuthCode `json:"auth_codes"`
}

func (r *authCodeRepository) load() (*authCodesData, error) {
	var data authCodesData
	if err := r.store.readFile("auth_codes", &data); err != nil {
		return nil, err
	}
	if data.AuthCodes == nil {
		data.AuthCodes = []*domain.AuthCode{}
	}
	return &data, nil
}

func (r *authCodeRepository) save(data *authCodesData) error {
	return r.store.writeFile("auth_codes", data)
}

func (r *authCodeRepository) Create(ctx context.Context, code *domain.AuthCode) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load auth codes", err)
	}

	code.CreatedAt = time.Now()
	data.AuthCodes = append(data.AuthCodes, code)

	return r.save(data)
}

func (r *authCodeRepository) GetByCode(ctx context.Context, code string) (*domain.AuthCode, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load auth codes", err)
	}

	for _, ac := range data.AuthCodes {
		if ac.Code == code {
			return ac, nil
		}
	}
	return nil, idperrors.NotFound("auth code", code)
}

func (r *authCodeRepository) MarkUsed(ctx context.Context, code string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load auth codes", err)
	}

	for _, ac := range data.AuthCodes {
		if ac.Code == code {
			ac.Used = true
			return r.save(data)
		}
	}
	return idperrors.NotFound("auth code", code)
}

func (r *authCodeRepository) Delete(ctx context.Context, code string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load auth codes", err)
	}

	for i, ac := range data.AuthCodes {
		if ac.Code == code {
			data.AuthCodes = append(data.AuthCodes[:i], data.AuthCodes[i+1:]...)
			return r.save(data)
		}
	}
	return idperrors.NotFound("auth code", code)
}

func (r *authCodeRepository) DeleteExpired(ctx context.Context) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load auth codes", err)
	}

	now := time.Now()
	filtered := make([]*domain.AuthCode, 0, len(data.AuthCodes))
	for _, ac := range data.AuthCodes {
		if ac.ExpiresAt.After(now) {
			filtered = append(filtered, ac)
		}
	}
	data.AuthCodes = filtered

	return r.save(data)
}

// Token Repository

type tokenRepository struct {
	store *Store
}

type tokensData struct {
	Tokens []*domain.Token `json:"tokens"`
}

func (r *tokenRepository) load() (*tokensData, error) {
	var data tokensData
	if err := r.store.readFile("tokens", &data); err != nil {
		return nil, err
	}
	if data.Tokens == nil {
		data.Tokens = []*domain.Token{}
	}
	return &data, nil
}

func (r *tokenRepository) save(data *tokensData) error {
	return r.store.writeFile("tokens", data)
}

func (r *tokenRepository) Create(ctx context.Context, token *domain.Token) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load tokens", err)
	}

	token.CreatedAt = time.Now()
	data.Tokens = append(data.Tokens, token)

	return r.save(data)
}

func (r *tokenRepository) GetByID(ctx context.Context, id string) (*domain.Token, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load tokens", err)
	}

	for _, t := range data.Tokens {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, idperrors.NotFound("token", id)
}

func (r *tokenRepository) Revoke(ctx context.Context, id string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load tokens", err)
	}

	for _, t := range data.Tokens {
		if t.ID == id {
			t.Revoked = true
			return r.save(data)
		}
	}
	return idperrors.NotFound("token", id)
}

func (r *tokenRepository) RevokeByUserID(ctx context.Context, userID string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load tokens", err)
	}

	for _, t := range data.Tokens {
		if t.UserID == userID {
			t.Revoked = true
		}
	}

	return r.save(data)
}

func (r *tokenRepository) RevokeByClientID(ctx context.Context, clientID string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load tokens", err)
	}

	for _, t := range data.Tokens {
		if t.ClientID == clientID {
			t.Revoked = true
		}
	}

	return r.save(data)
}

func (r *tokenRepository) DeleteExpired(ctx context.Context) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load tokens", err)
	}

	now := time.Now()
	filtered := make([]*domain.Token, 0, len(data.Tokens))
	for _, t := range data.Tokens {
		if t.ExpiresAt.After(now) {
			filtered = append(filtered, t)
		}
	}
	data.Tokens = filtered

	return r.save(data)
}

// SigningKey Repository

type signingKeyRepository struct {
	store *Store
}

type signingKeysData struct {
	SigningKeys []*domain.SigningKey `json:"signing_keys"`
}

func (r *signingKeyRepository) load() (*signingKeysData, error) {
	var data signingKeysData
	if err := r.store.readFile("signing_keys", &data); err != nil {
		return nil, err
	}
	if data.SigningKeys == nil {
		data.SigningKeys = []*domain.SigningKey{}
	}
	return &data, nil
}

func (r *signingKeyRepository) save(data *signingKeysData) error {
	return r.store.writeFile("signing_keys", data)
}

func (r *signingKeyRepository) Create(ctx context.Context, key *domain.SigningKey) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load signing keys", err)
	}

	for _, k := range data.SigningKeys {
		if k.ID == key.ID {
			return idperrors.AlreadyExists("signing key", key.ID)
		}
	}

	key.CreatedAt = time.Now()
	data.SigningKeys = append(data.SigningKeys, key)

	return r.save(data)
}

func (r *signingKeyRepository) GetByID(ctx context.Context, id string) (*domain.SigningKey, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load signing keys", err)
	}

	for _, k := range data.SigningKeys {
		if k.ID == id {
			return k, nil
		}
	}
	return nil, idperrors.NotFound("signing key", id)
}

func (r *signingKeyRepository) GetActive(ctx context.Context) (*domain.SigningKey, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load signing keys", err)
	}

	for _, k := range data.SigningKeys {
		if k.Active {
			return k, nil
		}
	}
	return nil, idperrors.NotFound("active signing key", "")
}

func (r *signingKeyRepository) GetAll(ctx context.Context) ([]*domain.SigningKey, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load signing keys", err)
	}
	return data.SigningKeys, nil
}

func (r *signingKeyRepository) SetActive(ctx context.Context, id string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load signing keys", err)
	}

	found := false
	for _, k := range data.SigningKeys {
		if k.ID == id {
			k.Active = true
			found = true
		} else {
			k.Active = false
		}
	}

	if !found {
		return idperrors.NotFound("signing key", id)
	}

	return r.save(data)
}

func (r *signingKeyRepository) Delete(ctx context.Context, id string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load signing keys", err)
	}

	for i, k := range data.SigningKeys {
		if k.ID == id {
			data.SigningKeys = append(data.SigningKeys[:i], data.SigningKeys[i+1:]...)
			return r.save(data)
		}
	}
	return idperrors.NotFound("signing key", id)
}
