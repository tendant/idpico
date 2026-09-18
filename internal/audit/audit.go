// Package audit records security-relevant actions (sign-ins, consent,
// password changes, administrative changes) to the store's audit log.
package audit

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/tendant/idpico/internal/domain"
	"github.com/tendant/idpico/internal/store"
)

// Action names. Kept as dotted "<object>.<verb>" strings so the admin UI can
// filter by prefix.
const (
	LoginSuccess = "login.success"
	LoginFailure = "login.failure"
	LoginLocked  = "login.locked"
	Logout       = "logout"

	ConsentGranted = "consent.granted"
	ConsentDenied  = "consent.denied"

	PasswordResetRequested = "password.reset_requested"
	PasswordReset          = "password.reset"
	PasswordChanged        = "password.changed"
	EmailVerified          = "email.verified"

	KeyRotated = "key.rotated"

	UserCreated         = "user.created"
	UserInvited         = "user.invited"
	UserUpdated         = "user.updated"
	UserDeleted         = "user.deleted"
	UserSessionsRevoked = "user.sessions_revoked"
	UserSessionRevoked  = "user.session_revoked"
	UserTokenRevoked    = "user.token_revoked"
	UserConsentRevoked  = "user.consent_revoked"
	UserGroupsUpdated   = "user.groups_updated"

	GroupCreated       = "group.created"
	GroupUpdated       = "group.updated"
	GroupDeleted       = "group.deleted"
	GroupMemberAdded   = "group.member_added"
	GroupMemberRemoved = "group.member_removed"

	ClientCreated       = "client.created"
	ClientUpdated       = "client.updated"
	ClientSecretRotated = "client.secret_regenerated"
	ClientTokensRevoked = "client.tokens_revoked"
	ClientDeleted       = "client.deleted"
)

// Recorder appends events to the audit log. A nil *Recorder is safe to use
// and records nothing, so callers never need to nil-check.
type Recorder struct {
	repo   store.AuditRepository
	logger *slog.Logger
}

// NewRecorder creates a Recorder backed by repo.
func NewRecorder(repo store.AuditRepository, logger *slog.Logger) *Recorder {
	if logger == nil {
		logger = slog.Default()
	}
	return &Recorder{repo: repo, logger: logger}
}

// Event is what callers describe; the recorder fills in ID and time.
type Event struct {
	Actor      *domain.User // nil for anonymous actions
	ActorEmail string       // used when Actor is nil (e.g. failed login attempt)
	Action     string
	TargetType string
	TargetID   string
	Detail     string
	IP         string
}

// Record appends the event. Failures are logged, never returned: an audit
// write must not break the action it describes.
func (r *Recorder) Record(ctx context.Context, e Event) {
	if r == nil || r.repo == nil {
		return
	}
	ev := &domain.AuditEvent{
		ActorEmail: e.ActorEmail,
		Action:     e.Action,
		TargetType: e.TargetType,
		TargetID:   e.TargetID,
		Detail:     e.Detail,
		IP:         e.IP,
	}
	if e.Actor != nil {
		ev.ActorID = e.Actor.ID
		ev.ActorEmail = e.Actor.Email
	}
	if err := r.repo.Append(ctx, ev); err != nil {
		r.logger.Error("failed to record audit event", "action", e.Action, "error", err)
	}
}

// ClientIP returns the peer address of the request without the port.
func ClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
