package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
)

const (
	// SessionCookieName is the name of the session cookie.
	SessionCookieName = "idp_session"
	// SessionTokenLength is the length of the session token in bytes.
	SessionTokenLength = 32
)

// SessionService manages user sessions.
type SessionService struct {
	sessions     store.SessionRepository
	cookieSecret []byte
	cookieSecure bool
	cookieDomain string
	sessionTTL   time.Duration
}

// SessionServiceOption configures the SessionService.
type SessionServiceOption func(*SessionService)

// WithCookieSecure sets whether cookies should be secure (HTTPS only).
func WithCookieSecure(secure bool) SessionServiceOption {
	return func(s *SessionService) {
		s.cookieSecure = secure
	}
}

// WithCookieDomain sets the cookie domain.
func WithCookieDomain(domain string) SessionServiceOption {
	return func(s *SessionService) {
		s.cookieDomain = domain
	}
}

// WithSessionTTL sets the session duration.
func WithSessionTTL(ttl time.Duration) SessionServiceOption {
	return func(s *SessionService) {
		s.sessionTTL = ttl
	}
}

// NewSessionService creates a new SessionService.
func NewSessionService(sessions store.SessionRepository, cookieSecret string, opts ...SessionServiceOption) *SessionService {
	s := &SessionService{
		sessions:     sessions,
		cookieSecret: []byte(cookieSecret),
		cookieSecure: false,
		sessionTTL:   24 * time.Hour,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// CreateSession creates a new session for a user and returns the session token.
func (s *SessionService) CreateSession(ctx context.Context, userID, userAgent, ipAddress string) (*domain.Session, string, error) {
	// Generate session token
	tokenBytes := make([]byte, SessionTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, "", fmt.Errorf("failed to generate session token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Create session
	session := &domain.Session{
		ID:        token, // Use token as ID for simplicity in file storage
		UserID:    userID,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(s.sessionTTL),
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}

	if err := s.sessions.Create(ctx, session); err != nil {
		return nil, "", fmt.Errorf("failed to create session: %w", err)
	}

	return session, token, nil
}

// GetSession retrieves a session by token.
func (s *SessionService) GetSession(ctx context.Context, token string) (*domain.Session, error) {
	session, err := s.sessions.GetByID(ctx, token)
	if err != nil {
		return nil, err
	}

	if session.IsExpired() {
		// Clean up expired session
		_ = s.sessions.Delete(ctx, token)
		return nil, idperrors.New(idperrors.CodeSessionExpired, "session expired")
	}

	return session, nil
}

// DeleteSession deletes a session.
func (s *SessionService) DeleteSession(ctx context.Context, token string) error {
	return s.sessions.Delete(ctx, token)
}

// DeleteUserSessions deletes all sessions for a user.
func (s *SessionService) DeleteUserSessions(ctx context.Context, userID string) error {
	return s.sessions.DeleteByUserID(ctx, userID)
}

// SetSessionCookie sets the session cookie on the response.
func (s *SessionService) SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		Domain:   s.cookieDomain,
		MaxAge:   int(s.sessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie clears the session cookie.
func (s *SessionService) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		Domain:   s.cookieDomain,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

// GetSessionFromRequest retrieves the session from request cookies.
func (s *SessionService) GetSessionFromRequest(ctx context.Context, r *http.Request) (*domain.Session, error) {
	cookie, err := r.Cookie(SessionCookieName)
	if err != nil {
		return nil, idperrors.New(idperrors.CodeUnauthorized, "no session cookie")
	}

	return s.GetSession(ctx, cookie.Value)
}

// RotateSession creates a new session and invalidates the old one.
// This should be called after login for security.
func (s *SessionService) RotateSession(ctx context.Context, oldToken, userID, userAgent, ipAddress string) (*domain.Session, string, error) {
	// Delete old session
	if oldToken != "" {
		_ = s.sessions.Delete(ctx, oldToken)
	}

	// Create new session
	return s.CreateSession(ctx, userID, userAgent, ipAddress)
}
