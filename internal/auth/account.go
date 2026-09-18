package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/mail"
	"github.com/tendant/simple-idp/internal/store"
)

// MinPasswordLength is enforced wherever a password is set through the IdP.
const MinPasswordLength = 8

// AccountService handles self-service account flows that go through email:
// password reset and email-address verification. Tokens are random, single
// use, time limited, and only their SHA-256 hash is stored.
type AccountService struct {
	users    store.UserRepository
	tokens   store.VerificationTokenRepository
	sessions store.SessionRepository
	refresh  store.TokenRepository
	mailer   mail.Mailer
	baseURL  string
	logger   *slog.Logger

	resetTTL  time.Duration
	verifyTTL time.Duration
}

// AccountOption configures the AccountService.
type AccountOption func(*AccountService)

// WithAccountLogger sets the logger.
func WithAccountLogger(logger *slog.Logger) AccountOption {
	return func(s *AccountService) { s.logger = logger }
}

// WithResetTTL sets how long a password reset link stays valid.
func WithResetTTL(d time.Duration) AccountOption {
	return func(s *AccountService) { s.resetTTL = d }
}

// WithVerifyTTL sets how long an email verification link stays valid.
func WithVerifyTTL(d time.Duration) AccountOption {
	return func(s *AccountService) { s.verifyTTL = d }
}

// NewAccountService creates an AccountService. baseURL is the public issuer
// URL used to build links in emails.
func NewAccountService(
	users store.UserRepository,
	tokens store.VerificationTokenRepository,
	sessions store.SessionRepository,
	refresh store.TokenRepository,
	mailer mail.Mailer,
	baseURL string,
	opts ...AccountOption,
) *AccountService {
	s := &AccountService{
		users:     users,
		tokens:    tokens,
		sessions:  sessions,
		refresh:   refresh,
		mailer:    mailer,
		baseURL:   strings.TrimRight(baseURL, "/"),
		logger:    slog.Default(),
		resetTTL:  time.Hour,
		verifyTTL: 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ValidatePassword enforces the password policy.
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return idperrors.InvalidInput(fmt.Sprintf("password must be at least %d characters", MinPasswordLength))
	}
	return nil
}

// RequestPasswordReset emails a reset link to the address if an active
// account exists. It never reveals whether the address is known: unknown or
// disabled accounts return nil without sending anything.
func (s *AccountService) RequestPasswordReset(ctx context.Context, email string) error {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			s.logger.Info("password reset requested for unknown email", "email", email)
			return nil
		}
		return fmt.Errorf("failed to look up user: %w", err)
	}
	if !user.Active {
		s.logger.Info("password reset requested for disabled account", "user_id", user.ID)
		return nil
	}
	return s.SendPasswordReset(ctx, user)
}

// SendPasswordReset issues a reset token for the user and emails the link.
// Earlier unused reset tokens for the user are invalidated.
func (s *AccountService) SendPasswordReset(ctx context.Context, user *domain.User) error {
	token, err := s.issueToken(ctx, user.ID, domain.PurposePasswordReset, s.resetTTL)
	if err != nil {
		return err
	}

	link := s.link("/reset-password", token)
	msg := mail.Message{
		To:      user.Email,
		Subject: "Reset your password",
		Body: fmt.Sprintf("Hello %s,\n\nA password reset was requested for your account. Open the link below to choose a new password. It expires in %s.\n\n%s\n\nIf you did not request this, you can ignore this email.\n",
			displayName(user), humanDuration(s.resetTTL), link),
	}
	if err := s.mailer.Send(ctx, msg); err != nil {
		return fmt.Errorf("failed to send password reset email: %w", err)
	}
	s.logger.Info("password reset email sent", "user_id", user.ID)
	return nil
}

// ResetPassword consumes a reset token and sets the new password. All of the
// user's sessions and refresh tokens are revoked.
func (s *AccountService) ResetPassword(ctx context.Context, token, newPassword string) (*domain.User, error) {
	if err := ValidatePassword(newPassword); err != nil {
		return nil, err
	}

	vt, err := s.consumeToken(ctx, token, domain.PurposePasswordReset)
	if err != nil {
		return nil, err
	}

	user, err := s.users.GetByID(ctx, vt.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user: %w", err)
	}
	if err := s.SetPassword(ctx, user, newPassword); err != nil {
		return nil, err
	}

	s.logger.Info("password reset completed", "user_id", user.ID)
	return user, nil
}

// SetPassword hashes and stores a new password for the user and revokes the
// user's sessions and refresh tokens so every device must sign in again.
func (s *AccountService) SetPassword(ctx context.Context, user *domain.User, password string) error {
	if err := ValidatePassword(password); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	user.PasswordHash = hash
	if err := s.users.Update(ctx, user); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	if err := s.sessions.DeleteByUserID(ctx, user.ID); err != nil {
		s.logger.Warn("failed to revoke sessions after password change", "user_id", user.ID, "error", err)
	}
	if err := s.refresh.RevokeByUserID(ctx, user.ID); err != nil {
		s.logger.Warn("failed to revoke tokens after password change", "user_id", user.ID, "error", err)
	}
	// Any outstanding reset links are now moot.
	_ = s.tokens.DeleteByUserID(ctx, user.ID, domain.PurposePasswordReset)
	return nil
}

// SendEmailVerification emails the user a link that marks their address verified.
func (s *AccountService) SendEmailVerification(ctx context.Context, user *domain.User) error {
	token, err := s.issueToken(ctx, user.ID, domain.PurposeEmailVerify, s.verifyTTL)
	if err != nil {
		return err
	}

	link := s.link("/verify-email", token)
	msg := mail.Message{
		To:      user.Email,
		Subject: "Verify your email address",
		Body: fmt.Sprintf("Hello %s,\n\nPlease confirm that %s is your email address by opening the link below. It expires in %s.\n\n%s\n",
			displayName(user), user.Email, humanDuration(s.verifyTTL), link),
	}
	if err := s.mailer.Send(ctx, msg); err != nil {
		return fmt.Errorf("failed to send verification email: %w", err)
	}
	s.logger.Info("verification email sent", "user_id", user.ID)
	return nil
}

// VerifyEmail consumes a verification token and marks the user's email verified.
func (s *AccountService) VerifyEmail(ctx context.Context, token string) (*domain.User, error) {
	vt, err := s.consumeToken(ctx, token, domain.PurposeEmailVerify)
	if err != nil {
		return nil, err
	}

	user, err := s.users.GetByID(ctx, vt.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to load user: %w", err)
	}
	if !user.EmailVerified {
		user.EmailVerified = true
		if err := s.users.Update(ctx, user); err != nil {
			return nil, fmt.Errorf("failed to update user: %w", err)
		}
	}
	_ = s.tokens.DeleteByUserID(ctx, user.ID, domain.PurposeEmailVerify)

	s.logger.Info("email verified", "user_id", user.ID)
	return user, nil
}

// issueToken creates a fresh token for the purpose, replacing any earlier
// ones, and returns the raw value to embed in the link.
func (s *AccountService) issueToken(ctx context.Context, userID, purpose string, ttl time.Duration) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)

	if err := s.tokens.DeleteByUserID(ctx, userID, purpose); err != nil {
		return "", fmt.Errorf("failed to clear old tokens: %w", err)
	}
	if err := s.tokens.Create(ctx, &domain.VerificationToken{
		TokenHash: hashToken(token),
		UserID:    userID,
		Purpose:   purpose,
		ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
	}
	return token, nil
}

// consumeToken validates a raw token for the purpose and marks it used.
func (s *AccountService) consumeToken(ctx context.Context, token, purpose string) (*domain.VerificationToken, error) {
	invalid := idperrors.New(idperrors.CodeTokenInvalid, "this link is invalid or has expired")
	if token == "" {
		return nil, invalid
	}

	vt, err := s.tokens.GetByHash(ctx, hashToken(token))
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			return nil, invalid
		}
		return nil, fmt.Errorf("failed to load token: %w", err)
	}
	if vt.Purpose != purpose || !vt.IsValid() {
		return nil, invalid
	}
	if err := s.tokens.MarkUsed(ctx, vt.TokenHash); err != nil {
		return nil, fmt.Errorf("failed to mark token used: %w", err)
	}
	return vt, nil
}

func (s *AccountService) link(path, token string) string {
	return s.baseURL + path + "?token=" + url.QueryEscape(token)
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func displayName(u *domain.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		n := int(d / (24 * time.Hour))
		if n == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", n)
	case d >= time.Hour && d%time.Hour == 0:
		n := int(d / time.Hour)
		if n == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", n)
	default:
		return d.String()
	}
}
