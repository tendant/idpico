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

// Authentication method references (RFC 8176) recorded on the session and
// released as the ID token's amr claim. A recovery code counts as "otp".
const (
	AMRPassword        = "pwd"
	AMROneTimePassword = "otp"
	AMRMultiFactor     = "mfa"
)

var (
	// ErrSecondFactorRequired: the password was right; a code is due.
	ErrSecondFactorRequired = errors.New("second factor required")
	// ErrPendingLoginExpired: no pending login (expired, used up, restarted);
	// sign in with the password again.
	ErrPendingLoginExpired = errors.New("sign-in expired; enter your password again")
	// ErrInvalidCode: the code was wrong; the pending login is still usable.
	ErrInvalidCode = errors.New("invalid code")
	// ErrInvalidPassword: the current password, re-entered for a sensitive
	// change, was wrong.
	ErrInvalidPassword = errors.New("current password is incorrect")
	// ErrAccountLocked: too many failed password or code checks; try later.
	ErrAccountLocked = errors.New("account is temporarily locked")
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

// reserve counts an attempt before the code is checked, so concurrent
// submissions cannot exceed the limit; it reports false when the pending
// login is gone or used up.
func (p *pendingLogins) reserve(token string) (pendingLogin, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.entries[token]
	if !ok || time.Now().After(e.expires) || e.attempts >= pendingLoginAttempts {
		delete(p.entries, token)
		return pendingLogin{}, false
	}
	e.attempts++
	return *e, true
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
	p, ok := s.pending.reserve(c.Value)
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
		if p.attempts >= pendingLoginAttempts {
			s.pending.remove(c.Value)
			s.clearPendingCookie(w)
			return nil, ErrPendingLoginExpired
		}
		return nil, ErrInvalidCode
	}

	s.pending.remove(c.Value)
	s.clearPendingCookie(w)
	if err := s.startSession(ctx, w, r, user, AMRPassword, AMROneTimePassword, AMRMultiFactor); err != nil {
		return nil, err
	}
	return user, nil
}

// consumeSecondFactor checks a 6-digit TOTP code or a recovery code for the
// user and records its use (the time step, or the spent recovery code), so
// neither works twice. It reports false for a wrong code.
func (s *Service) consumeSecondFactor(ctx context.Context, r *http.Request, user *domain.User, code string) (bool, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}
	// Check and record under a per-user lock, against the stored user: two
	// concurrent requests with the same code must not both pass the
	// last-step check (single instance, so a process lock suffices).
	unlock := s.lockUser(user.ID)
	defer unlock()
	fresh, err := s.users.GetByID(ctx, user.ID)
	if err != nil {
		return false, err
	}
	*user = *fresh
	if !user.TOTPEnabled() {
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

func (s *Service) lockUser(id string) func() {
	m, _ := s.userLocks.LoadOrStore(id, &sync.Mutex{})
	mu := m.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// guarded runs a password or code check made from a signed-in session for
// a sensitive change. It refuses while the account is locked and counts a
// failed check towards lockout, so a stolen session cannot be used to
// guess the password or the authenticator code without limit.
func (s *Service) guarded(user *domain.User, check func() (bool, error), wrong error) error {
	if s.lockout != nil && s.lockout.IsLocked(user.Email) {
		return ErrAccountLocked
	}
	ok, err := check()
	if err != nil {
		return err
	}
	if !ok {
		if s.lockout != nil && s.lockout.RecordFailure(user.Email) {
			s.logger.Warn("account locked due to failed attempts", "email", user.Email)
			metrics.RecordAccountLockout()
		}
		return wrong
	}
	return nil
}

// VerifyCurrentPassword re-checks the signed-in user's password before a
// sensitive change, counting failures towards lockout.
func (s *Service) VerifyCurrentPassword(user *domain.User, password string) error {
	return s.guarded(user, func() (bool, error) {
		ok, err := VerifyPassword(password, user.PasswordHash)
		return err == nil && ok, nil
	}, ErrInvalidPassword)
}

// EnableTOTP turns on two-step sign-in with secret once code proves the
// user's authenticator holds it; the current password is required too, so
// an open session alone cannot attach an attacker's authenticator. It
// returns the recovery codes, which are shown once and stored only as hashes.
func (s *Service) EnableTOTP(ctx context.Context, r *http.Request, user *domain.User, password, secret, code string) ([]string, error) {
	if user.TOTPEnabled() {
		return nil, idperrors.InvalidInput("an authenticator is already set up; turn it off first")
	}
	if err := s.VerifyCurrentPassword(user, password); err != nil {
		return nil, err
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
	if err := s.guarded(user, func() (bool, error) { return s.consumeSecondFactor(ctx, r, user, code) }, ErrInvalidCode); err != nil {
		return err
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
	if err := s.guarded(user, func() (bool, error) { return s.consumeSecondFactor(ctx, r, user, code) }, ErrInvalidCode); err != nil {
		return nil, err
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
