package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
)

// Service provides authentication functionality.
type Service struct {
	users    store.UserRepository
	sessions *SessionService
	csrf     *CSRFService
	logger   *slog.Logger
}

// ServiceOption configures the Service.
type ServiceOption func(*Service)

// WithLogger sets the logger for the service.
func WithLogger(logger *slog.Logger) ServiceOption {
	return func(s *Service) {
		s.logger = logger
	}
}

// NewService creates a new auth Service.
func NewService(users store.UserRepository, sessions *SessionService, csrf *CSRFService, opts ...ServiceOption) *Service {
	s := &Service{
		users:    users,
		sessions: sessions,
		csrf:     csrf,
		logger:   slog.Default(),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// Sessions returns the session service.
func (s *Service) Sessions() *SessionService {
	return s.sessions
}

// CSRF returns the CSRF service.
func (s *Service) CSRF() *CSRFService {
	return s.csrf
}

// Authenticate verifies user credentials and returns the user if valid.
func (s *Service) Authenticate(ctx context.Context, email, password string) (*domain.User, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			// Don't reveal whether user exists
			return nil, idperrors.New(idperrors.CodeUnauthorized, "invalid credentials")
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if !user.Active {
		return nil, idperrors.New(idperrors.CodeUnauthorized, "account is disabled")
	}

	valid, err := VerifyPassword(password, user.PasswordHash)
	if err != nil {
		s.logger.Error("password verification error", "error", err)
		return nil, idperrors.New(idperrors.CodeUnauthorized, "invalid credentials")
	}

	if !valid {
		return nil, idperrors.New(idperrors.CodeUnauthorized, "invalid credentials")
	}

	return user, nil
}

// Login authenticates a user and creates a session.
func (s *Service) Login(ctx context.Context, w http.ResponseWriter, r *http.Request, email, password string) (*domain.User, error) {
	// Validate CSRF token
	if err := s.csrf.ValidateToken(r); err != nil {
		return nil, idperrors.New(idperrors.CodeForbidden, "invalid CSRF token")
	}

	// Authenticate
	user, err := s.Authenticate(ctx, email, password)
	if err != nil {
		return nil, err
	}

	// Get existing session token for rotation
	var oldToken string
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		oldToken = cookie.Value
	}

	// Create new session (with rotation)
	_, token, err := s.sessions.RotateSession(ctx, oldToken, user.ID, r.UserAgent(), getClientIP(r))
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Set session cookie
	s.sessions.SetSessionCookie(w, token)

	// Clear CSRF token
	s.csrf.ClearToken(w)

	s.logger.Info("user logged in", "user_id", user.ID, "email", user.Email)

	return user, nil
}

// Logout terminates the user's session.
func (s *Service) Logout(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	// Get session from cookie
	cookie, err := r.Cookie(SessionCookieName)
	if err == nil && cookie.Value != "" {
		// Delete session
		if err := s.sessions.DeleteSession(ctx, cookie.Value); err != nil {
			s.logger.Warn("failed to delete session", "error", err)
		}
	}

	// Clear cookies
	s.sessions.ClearSessionCookie(w)
	s.csrf.ClearToken(w)

	return nil
}

// GetCurrentUser returns the currently authenticated user from the session.
func (s *Service) GetCurrentUser(ctx context.Context, r *http.Request) (*domain.User, error) {
	session, err := s.sessions.GetSessionFromRequest(ctx, r)
	if err != nil {
		return nil, err
	}

	user, err := s.users.GetByID(ctx, session.UserID)
	if err != nil {
		return nil, err
	}

	if !user.Active {
		return nil, idperrors.New(idperrors.CodeUnauthorized, "account is disabled")
	}

	return user, nil
}

// IsAuthenticated checks if the request has a valid session.
func (s *Service) IsAuthenticated(ctx context.Context, r *http.Request) bool {
	_, err := s.sessions.GetSessionFromRequest(ctx, r)
	return err == nil
}

// CreateUser creates a new user with a hashed password.
func (s *Service) CreateUser(ctx context.Context, email, password, displayName string) (*domain.User, error) {
	// Hash password
	hash, err := HashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	user := &domain.User{
		Email:        email,
		PasswordHash: hash,
		DisplayName:  displayName,
		Active:       true,
	}

	// Generate ID
	user.ID = generateID()

	if err := s.users.Create(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// getClientIP extracts the client IP from the request.
// Note: This IdP is for development use only and does not trust proxy headers
// (X-Forwarded-For, X-Real-IP) to prevent IP spoofing attacks.
func getClientIP(r *http.Request) string {
	// Only use direct RemoteAddr for security (no proxy header trust)
	return r.RemoteAddr
}

// generateID generates a unique ID.
func generateID() string {
	// Use UUID from google/uuid
	return generateUUID()
}
