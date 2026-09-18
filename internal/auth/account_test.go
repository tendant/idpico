package auth

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/mail"
	"github.com/tendant/simple-idp/internal/store/sqlite"
)

func newAccountService(t *testing.T) (*AccountService, *sqlite.Store, *mail.MemoryMailer) {
	t.Helper()
	s, err := sqlite.NewStore(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })

	ctx := context.Background()
	hash, _ := HashPassword("old-password")
	s.Users().Create(ctx, &domain.User{ID: "u1", Email: "alice@example.com", DisplayName: "Alice", PasswordHash: hash, Active: true})
	s.Users().Create(ctx, &domain.User{ID: "u2", Email: "off@example.com", PasswordHash: hash, Active: false})
	s.Clients().Create(ctx, &domain.Client{ID: "c", Name: "c"})
	s.Sessions().Create(ctx, &domain.Session{ID: "sess", UserID: "u1", ExpiresAt: time.Now().Add(time.Hour)})
	s.Tokens().Create(ctx, &domain.Token{ID: "rt", UserID: "u1", ClientID: "c", ExpiresAt: time.Now().Add(time.Hour)})

	mailer := &mail.MemoryMailer{}
	svc := NewAccountService(s.Users(), s.VerificationTokens(), s.Sessions(), s.Tokens(), mailer, "https://idp.example.com/")
	return svc, s, mailer
}

// tokenFromMail extracts the token query parameter from the link in the last email.
func tokenFromMail(t *testing.T, mailer *mail.MemoryMailer) string {
	t.Helper()
	msg := mailer.Last()
	if msg == nil {
		t.Fatal("expected an email to be sent")
	}
	for _, word := range strings.Fields(msg.Body) {
		if strings.HasPrefix(word, "https://idp.example.com/") {
			u, err := url.Parse(word)
			if err != nil {
				t.Fatalf("bad link %q: %v", word, err)
			}
			return u.Query().Get("token")
		}
	}
	t.Fatalf("no link in email body: %q", msg.Body)
	return ""
}

func TestPasswordReset_Flow(t *testing.T) {
	ctx := context.Background()
	svc, s, mailer := newAccountService(t)

	if err := svc.RequestPasswordReset(ctx, "Alice@Example.com"); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	msg := mailer.Last()
	if msg == nil || msg.To != "alice@example.com" || !strings.Contains(msg.Body, "/reset-password?token=") {
		t.Fatalf("unexpected email: %+v", msg)
	}
	token := tokenFromMail(t, mailer)

	// Weak password is rejected without consuming the token
	if _, err := svc.ResetPassword(ctx, token, "short"); !idperrors.IsCode(err, idperrors.CodeInvalidInput) {
		t.Fatalf("expected invalid_input for weak password, got %v", err)
	}

	user, err := svc.ResetPassword(ctx, token, "new-password-123")
	if err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if ok, _ := VerifyPassword("new-password-123", user.PasswordHash); !ok {
		t.Error("new password should verify")
	}
	stored, _ := s.Users().GetByID(ctx, "u1")
	if ok, _ := VerifyPassword("old-password", stored.PasswordHash); ok {
		t.Error("old password should no longer verify")
	}

	// Sessions and refresh tokens are revoked
	if _, err := s.Sessions().GetByID(ctx, "sess"); !idperrors.IsCode(err, idperrors.CodeNotFound) {
		t.Error("sessions should be revoked after password reset")
	}
	if rt, _ := s.Tokens().GetByID(ctx, "rt"); !rt.Revoked {
		t.Error("refresh tokens should be revoked after password reset")
	}

	// Token is single use
	if _, err := svc.ResetPassword(ctx, token, "another-password-1"); !idperrors.IsCode(err, idperrors.CodeTokenInvalid) {
		t.Errorf("reused token should be rejected, got %v", err)
	}
}

func TestPasswordReset_DoesNotRevealAccounts(t *testing.T) {
	ctx := context.Background()
	svc, _, mailer := newAccountService(t)

	if err := svc.RequestPasswordReset(ctx, "nobody@example.com"); err != nil {
		t.Errorf("unknown email should not error, got %v", err)
	}
	if err := svc.RequestPasswordReset(ctx, "off@example.com"); err != nil {
		t.Errorf("disabled account should not error, got %v", err)
	}
	if len(mailer.Messages) != 0 {
		t.Errorf("no email should be sent for unknown/disabled accounts, got %d", len(mailer.Messages))
	}
}

func TestPasswordReset_ThrottledPerAddress(t *testing.T) {
	ctx := context.Background()
	svc, s, mailer := newAccountService(t)
	now := time.Now()
	svc.now = func() time.Time { return now }

	svc.RequestPasswordReset(ctx, "alice@example.com")
	svc.RequestPasswordReset(ctx, "ALICE@example.com") // same mailbox, different case
	if len(mailer.Messages) != 1 {
		t.Fatalf("second request inside the interval should not send, got %d emails", len(mailer.Messages))
	}

	// Admin-triggered sends are not throttled
	user, _ := s.Users().GetByID(ctx, "u1")
	if err := svc.SendPasswordReset(ctx, user); err != nil || len(mailer.Messages) != 2 {
		t.Errorf("admin send should bypass throttle: err=%v emails=%d", err, len(mailer.Messages))
	}

	// After the interval the self-service request goes through again
	now = now.Add(3 * time.Minute)
	svc.RequestPasswordReset(ctx, "alice@example.com")
	if len(mailer.Messages) != 3 {
		t.Errorf("request after the interval should send, got %d emails", len(mailer.Messages))
	}
}

func TestPasswordReset_NewRequestInvalidatesOldToken(t *testing.T) {
	ctx := context.Background()
	svc, _, mailer := newAccountService(t)
	svc.resetInterval = 0 // test issues two requests back to back

	svc.RequestPasswordReset(ctx, "alice@example.com")
	first := tokenFromMail(t, mailer)
	svc.RequestPasswordReset(ctx, "alice@example.com")
	second := tokenFromMail(t, mailer)

	if _, err := svc.ResetPassword(ctx, first, "new-password-123"); !idperrors.IsCode(err, idperrors.CodeTokenInvalid) {
		t.Errorf("superseded token should be invalid, got %v", err)
	}
	if _, err := svc.ResetPassword(ctx, second, "new-password-123"); err != nil {
		t.Errorf("latest token should work: %v", err)
	}
}

func TestPasswordReset_ExpiredToken(t *testing.T) {
	ctx := context.Background()
	svc, _, mailer := newAccountService(t)
	svc.resetTTL = -time.Minute // already expired when issued

	svc.RequestPasswordReset(ctx, "alice@example.com")
	token := tokenFromMail(t, mailer)
	if _, err := svc.ResetPassword(ctx, token, "new-password-123"); !idperrors.IsCode(err, idperrors.CodeTokenInvalid) {
		t.Errorf("expired token should be invalid, got %v", err)
	}
}

func TestEmailVerification_Flow(t *testing.T) {
	ctx := context.Background()
	svc, s, mailer := newAccountService(t)

	user, _ := s.Users().GetByID(ctx, "u1")
	if err := svc.SendEmailVerification(ctx, user); err != nil {
		t.Fatalf("SendEmailVerification: %v", err)
	}
	if msg := mailer.Last(); msg == nil || !strings.Contains(msg.Body, "/verify-email?token=") {
		t.Fatalf("unexpected email: %+v", msg)
	}
	token := tokenFromMail(t, mailer)

	// A reset token cannot be used for verification and vice versa
	svc.RequestPasswordReset(ctx, "alice@example.com")
	resetToken := tokenFromMail(t, mailer)
	if _, err := svc.VerifyEmail(ctx, resetToken); !idperrors.IsCode(err, idperrors.CodeTokenInvalid) {
		t.Errorf("reset token must not verify email, got %v", err)
	}

	verified, err := svc.VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if !verified.EmailVerified {
		t.Error("user should be marked verified")
	}
	stored, _ := s.Users().GetByID(ctx, "u1")
	if !stored.EmailVerified {
		t.Error("verified flag should be persisted")
	}
	if _, err := svc.VerifyEmail(ctx, token); !idperrors.IsCode(err, idperrors.CodeTokenInvalid) {
		t.Errorf("verification token should be single use, got %v", err)
	}
}

func TestVerifyEmail_BadToken(t *testing.T) {
	svc, _, _ := newAccountService(t)
	for _, tok := range []string{"", "garbage"} {
		if _, err := svc.VerifyEmail(context.Background(), tok); !idperrors.IsCode(err, idperrors.CodeTokenInvalid) {
			t.Errorf("token %q should be invalid, got %v", tok, err)
		}
	}
}
