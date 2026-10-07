package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tendant/idpico/internal/audit"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/metrics"
)

// Two-step sign-in. Login accepts the password of a user with an
// authenticator and returns ErrSecondFactorRequired instead of a session;
// the browser carries a pending-login cookie to /login/code, where
// CompleteSecondFactor takes a TOTP code or a recovery code.
//
// Pending logins live in memory: IDPico is a single instance, a restart only
// costs the password being typed again, and the attempt limit below holds
// even with account lockout turned off.

const (
	// PendingLoginCookieName carries a password-accepted login to the code step.
	PendingLoginCookieName = "idpico_pending_login"
	pendingLoginTTL        = 5 * time.Minute
	// pendingLoginAttempts is how many wrong codes one password entry allows.
	// Three codes are valid at any moment, so five guesses at a 6-digit code
	// succeed with probability 1.5e-5 before the password is needed again.
	pendingLoginAttempts = 5
)

var (
	// ErrSecondFactorRequired: the password was right; a code is due.
	ErrSecondFactorRequired = errors.New("second factor required")
	// ErrPendingLoginExpired: no pending login (expired, used up, restarted);
	// sign in with the password again.
	ErrPendingLoginExpired = errors.New("sign-in expired; enter your password again")
	// ErrInvalidCode: the code was wrong; the pending login is still usable.
	ErrInvalidCode = errors.New("invalid code")
)

type pendingLogin struct {
	userID   string
	email    string
	expires  time.Time
	attempts int
}

type pendingLogins struct {
	mu      sync.Mutex
	entries map[string]*pendingLogin
}

func newPendingLogins() *pendingLogins {
	return &pendingLogins{entries: map[string]*pendingLogin{}}
}

func (p *pendingLogins) add(user *domain.User) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(b)
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, e := range p.entries {
		if now.After(e.expires) {
			delete(p.entries, k)
		}
	}
	p.entries[token] = &pendingLogin{userID: user.ID, email: user.Email, expires: now.Add(pendingLoginTTL)}
	return token, nil
}

func (p *pendingLogins) get(token string) (pendingLogin, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[token]
	if !ok || time.Now().After(e.expires) {
		delete(p.entries, token)
		return pendingLogin{}, false
	}
	return *e, true
}

// fail counts a wrong code and reports whether the pending login survives.
func (p *pendingLogins) fail(token string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[token]
	if !ok {
		return false
	}
	e.attempts++
	if e.attempts >= pendingLoginAttempts {
		delete(p.entries, token)
		return false
	}
	return true
}

func (p *pendingLogins) remove(token string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.entries, token)
}

func (s *Service) setPendingCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: PendingLoginCookieName, Value: token, Path: "/login",
		Domain: s.sessions.cookieDomain, MaxAge: int(pendingLoginTTL.Seconds()),
		HttpOnly: true, Secure: s.sessions.cookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) clearPendingCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: PendingLoginCookieName, Value: "", Path: "/login",
		Domain: s.sessions.cookieDomain, MaxAge: -1,
		HttpOnly: true, Secure: s.sessions.cookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// HasPendingLogin reports whether the request carries a live pending login.
func (s *Service) HasPendingLogin(r *http.Request) bool {
	c, err := r.Cookie(PendingLoginCookieName)
	if err != nil {
		return false
	}
	_, ok := s.pending.get(c.Value)
	return ok
}

// CompleteSecondFactor finishes a pending login with a TOTP code or a
// recovery code and starts the session.
func (s *Service) CompleteSecondFactor(ctx context.Context, w http.ResponseWriter, r *http.Request, code string) (*domain.User, error) {
	if err := s.csrf.ValidateToken(r); err != nil {
		return nil, idperrors.New(idperrors.CodeForbidden, "invalid CSRF token")
	}
	c, err := r.Cookie(PendingLoginCookieName)
	if err != nil {
		return nil, ErrPendingLoginExpired
	}
	p, ok := s.pending.get(c.Value)
	if !ok {
		s.clearPendingCookie(w)
		return nil, ErrPendingLoginExpired
	}
	if s.lockout != nil && s.lockout.IsLocked(p.email) {
		s.pending.remove(c.Value)
		s.clearPendingCookie(w)
		metrics.RecordLogin("locked")
		return nil, idperrors.New(idperrors.CodeForbidden, "account is temporarily locked")
	}

	user, err := s.users.GetByID(ctx, p.userID)
	if err != nil || !user.Active || !user.TOTPEnabled() {
		// Disabled, deleted or reset since the password was accepted.
		s.pending.remove(c.Value)
		s.clearPendingCookie(w)
		return nil, ErrPendingLoginExpired
	}

	ok, err = s.consumeSecondFactor(ctx, r, user, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		if s.lockout != nil && s.lockout.RecordFailure(user.Email) {
			s.logger.Warn("account locked due to failed attempts", "email", user.Email)
			metrics.RecordAccountLockout()
		}
		s.audit.Record(ctx, audit.Event{ActorEmail: user.Email, Action: audit.LoginFailure, TargetType: "user", TargetID: user.ID, Detail: "wrong authenticator or recovery code", IP: audit.ClientIP(r)})
		metrics.RecordLogin("failure")
		if !s.pending.fail(c.Value) {
			s.clearPendingCookie(w)
			return nil, ErrPendingLoginExpired
		}
		return nil, ErrInvalidCode
	}

	s.pending.remove(c.Value)
	s.clearPendingCookie(w)
	if err := s.startSession(ctx, w, r, user); err != nil {
		return nil, err
	}
	return user, nil
}

// consumeSecondFactor checks a 6-digit TOTP code or a recovery code for the
// user and records its use (the time step, or the spent recovery code), so
// neither works twice. It reports false for a wrong code.
func (s *Service) consumeSecondFactor(ctx context.Context, r *http.Request, user *domain.User, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if code == "" || !user.TOTPEnabled() {
		return false, nil
	}
	if step, ok := VerifyTOTP(user.TOTPSecret, code, time.Now(), user.TOTPLastStep); ok {
		user.TOTPLastStep = step
		if err := s.users.Update(ctx, user); err != nil {
			return false, fmt.Errorf("failed to record code use: %w", err)
		}
		return true, nil
	}
	if rest, ok := UseRecoveryCode(user.RecoveryCodes, code); ok {
		user.RecoveryCodes = rest
		if err := s.users.Update(ctx, user); err != nil {
			return false, fmt.Errorf("failed to record recovery code use: %w", err)
		}
		s.audit.Record(ctx, audit.Event{Actor: user, Action: audit.TOTPRecoveryCodeUsed, TargetType: "user", TargetID: user.ID,
			Detail: fmt.Sprintf("%d left", len(rest)), IP: audit.ClientIP(r)})
		return true, nil
	}
	return false, nil
}

// EnableTOTP turns on two-step sign-in with secret once code proves the
// user's authenticator holds it. It returns the recovery codes, which are
// shown once and stored only as hashes.
func (s *Service) EnableTOTP(ctx context.Context, r *http.Request, user *domain.User, secret, code string) ([]string, error) {
	if user.TOTPEnabled() {
		return nil, idperrors.InvalidInput("an authenticator is already set up; turn it off first")
	}
	step, ok := VerifyTOTP(secret, code, time.Now(), 0)
	if !ok {
		return nil, ErrInvalidCode
	}
	codes, hashes, err := NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	user.TOTPSecret, user.TOTPLastStep, user.RecoveryCodes = strings.ToUpper(secret), step, hashes
	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	s.audit.Record(ctx, audit.Event{Actor: user, Action: audit.TOTPEnabled, TargetType: "user", TargetID: user.ID, IP: audit.ClientIP(r)})
	return codes, nil
}

// DisableTOTP turns two-step sign-in off; it takes a current code or a
// recovery code, so a session left open is not enough.
func (s *Service) DisableTOTP(ctx context.Context, r *http.Request, user *domain.User, code string) error {
	ok, err := s.consumeSecondFactor(ctx, r, user, code)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCode
	}
	ClearTOTP(user)
	if err := s.users.Update(ctx, user); err != nil {
		return err
	}
	s.audit.Record(ctx, audit.Event{Actor: user, Action: audit.TOTPDisabled, TargetType: "user", TargetID: user.ID, IP: audit.ClientIP(r)})
	return nil
}

// RenewRecoveryCodes replaces the recovery codes (all old ones stop
// working); it takes a current code or a recovery code.
func (s *Service) RenewRecoveryCodes(ctx context.Context, r *http.Request, user *domain.User, code string) ([]string, error) {
	ok, err := s.consumeSecondFactor(ctx, r, user, code)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrInvalidCode
	}
	codes, hashes, err := NewRecoveryCodes()
	if err != nil {
		return nil, err
	}
	user.RecoveryCodes = hashes
	if err := s.users.Update(ctx, user); err != nil {
		return nil, err
	}
	s.audit.Record(ctx, audit.Event{Actor: user, Action: audit.TOTPRecoveryCodesRenewed, TargetType: "user", TargetID: user.ID, IP: audit.ClientIP(r)})
	return codes, nil
}

// ClearTOTP removes the authenticator and recovery codes from user (the
// caller saves it); used to turn it off and by an admin reset.
func ClearTOTP(user *domain.User) {
	user.TOTPSecret, user.TOTPLastStep, user.RecoveryCodes = "", 0, nil
}
