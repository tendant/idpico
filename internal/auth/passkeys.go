package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/tendant/idpico/internal/audit"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/store"
)

// Passkeys (WebAuthn) as a second sign-in step, next to the authenticator
// app. A passkey is bound to the issuer's host name (the relying party ID),
// so passkeys stop working if IDPICO_ISSUER_URL moves to another host.
//
// Ceremony challenges live in memory, like pending logins: registration by
// user ID, sign-in on the pending login.

// AMR values (RFC 8176) for a passkey sign-in: proof of possession of a key
// that may be synced between devices (so "swk", not "hwk"), plus "user"
// when the authenticator verified the user (biometric or PIN).
const (
	AMRSoftwareKey      = "swk"
	AMRUserVerification = "user"
)

// passkeyCeremonyTTL bounds how long a registration challenge stays valid.
const passkeyCeremonyTTL = 5 * time.Minute

var (
	// ErrPasskeysUnavailable: passkeys need an https issuer (or localhost).
	ErrPasskeysUnavailable = fmt.Errorf("passkeys are not available on this server")
	// ErrPasskeyCeremony: no challenge is pending (expired or already used).
	ErrPasskeyCeremony = fmt.Errorf("passkey request expired; please try again")
)

type passkeySupport struct {
	wa   *webauthn.WebAuthn // nil: passkeys cannot be used (http issuer)
	repo store.PasskeyRepository

	mu            sync.Mutex
	registrations map[string]registrationCeremony // by user ID
}

type registrationCeremony struct {
	data    webauthn.SessionData
	expires time.Time
}

// WithPasskeys stores passkeys in repo and enables the WebAuthn ceremonies
// for issuerURL's host. With an http issuer other than localhost the
// browser refuses WebAuthn, so the ceremonies stay off; existing passkeys
// still count as a second step (sign in with a recovery code instead).
func WithPasskeys(repo store.PasskeyRepository, issuerURL string) ServiceOption {
	return func(s *Service) {
		p := &passkeySupport{repo: repo, registrations: map[string]registrationCeremony{}}
		if wa, err := newWebAuthn(issuerURL); err != nil {
			s.logger.Warn("passkeys disabled", "reason", err)
		} else {
			p.wa = wa
		}
		s.passkeys = p
	}
}

func newWebAuthn(issuerURL string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(issuerURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("issuer URL %q has no host", issuerURL)
	}
	host := u.Hostname()
	if u.Scheme != "https" && host != "localhost" {
		return nil, fmt.Errorf("WebAuthn needs an https issuer (or http://localhost), not %s", issuerURL)
	}
	if net.ParseIP(host) != nil {
		return nil, fmt.Errorf("WebAuthn needs a host name, not an IP address (%s)", host)
	}
	return webauthn.New(&webauthn.Config{
		RPID:          host,
		RPDisplayName: "IDPico",
		RPOrigins:     []string{u.Scheme + "://" + u.Host},
	})
}

// PasskeysAvailable reports whether users can register and use passkeys.
func (s *Service) PasskeysAvailable() bool { return s.passkeys != nil && s.passkeys.wa != nil }

// Passkeys lists the user's passkeys (none when the feature is off).
func (s *Service) Passkeys(ctx context.Context, userID string) ([]*domain.Passkey, error) {
	if s.passkeys == nil {
		return nil, nil
	}
	return s.passkeys.repo.ListByUserID(ctx, userID)
}

// hasSecondFactor reports whether signing in needs a second step: an
// authenticator app or at least one passkey. A store error counts as yes,
// so the check fails closed.
func (s *Service) hasSecondFactor(ctx context.Context, user *domain.User) bool {
	if user.TOTPEnabled() {
		return true
	}
	if s.passkeys == nil {
		return false
	}
	list, err := s.passkeys.repo.ListByUserID(ctx, user.ID)
	return err != nil || len(list) > 0
}

// webauthnUser adapts a user and their passkeys to the WebAuthn library.
// The user handle is the user ID: opaque and stable, never the email.
type webauthnUser struct {
	user  *domain.User
	creds []webauthn.Credential
}

func (u webauthnUser) WebAuthnID() []byte   { return []byte(u.user.ID) }
func (u webauthnUser) WebAuthnName() string { return u.user.Email }
func (u webauthnUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.Email
}
func (u webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Service) webauthnUser(ctx context.Context, user *domain.User) (webauthnUser, []*domain.Passkey, error) {
	list, err := s.passkeys.repo.ListByUserID(ctx, user.ID)
	if err != nil {
		return webauthnUser{}, nil, err
	}
	wu := webauthnUser{user: user}
	for _, p := range list {
		var c webauthn.Credential
		if err := json.Unmarshal(p.Credential, &c); err != nil {
			return webauthnUser{}, nil, fmt.Errorf("passkey %s: %w", p.ID, err)
		}
		wu.creds = append(wu.creds, c)
	}
	return wu, list, nil
}

// BeginPasskeyRegistration starts adding a passkey: it re-checks the
// current password (an open session alone cannot attach an attacker's
// passkey) and returns the options for navigator.credentials.create.
func (s *Service) BeginPasskeyRegistration(ctx context.Context, user *domain.User, password string) (*protocol.CredentialCreation, error) {
	if !s.PasskeysAvailable() {
		return nil, ErrPasskeysUnavailable
	}
	if err := s.VerifyCurrentPassword(user, password); err != nil {
		return nil, err
	}
	wu, _, err := s.webauthnUser(ctx, user)
	if err != nil {
		return nil, err
	}
	creation, data, err := s.passkeys.wa.BeginRegistration(wu,
		webauthn.WithExclusions(webauthn.Credentials(wu.creds).CredentialDescriptors()),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, err
	}
	s.passkeys.mu.Lock()
	s.passkeys.registrations[user.ID] = registrationCeremony{data: *data, expires: time.Now().Add(passkeyCeremonyTTL)}
	s.passkeys.mu.Unlock()
	return creation, nil
}

// FinishPasskeyRegistration verifies the browser's response and stores the
// passkey. If the user had no recovery codes yet, it creates them and
// returns them to be shown once.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, r *http.Request, user *domain.User, name string, response []byte) ([]string, error) {
	if !s.PasskeysAvailable() {
		return nil, ErrPasskeysUnavailable
	}
	s.passkeys.mu.Lock()
	ceremony, ok := s.passkeys.registrations[user.ID]
	delete(s.passkeys.registrations, user.ID)
	s.passkeys.mu.Unlock()
	if !ok || time.Now().After(ceremony.expires) {
		return nil, ErrPasskeyCeremony
	}

	parsed, err := protocol.ParseCredentialCreationResponseBytes(response)
	if err != nil {
		return nil, idperrors.InvalidInput("the passkey response could not be read")
	}
	wu, _, err := s.webauthnUser(ctx, user)
	if err != nil {
		return nil, err
	}
	cred, err := s.passkeys.wa.CreateCredential(wu, ceremony.data, parsed)
	if err != nil {
		return nil, idperrors.InvalidInput("the passkey could not be verified")
	}
	raw, err := json.Marshal(cred)
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	pk := &domain.Passkey{ID: base64.RawURLEncoding.EncodeToString(cred.ID), UserID: user.ID, Name: name, Credential: raw}
	if err := s.passkeys.repo.Create(ctx, pk); err != nil {
		return nil, err
	}
	s.audit.Record(ctx, audit.Event{Actor: user, Action: audit.PasskeyAdded, TargetType: "user", TargetID: user.ID, Detail: name, IP: audit.ClientIP(r)})

	// A second step needs a way back if the device is lost.
	if len(user.RecoveryCodes) == 0 {
		codes, hashes, err := NewRecoveryCodes()
		if err != nil {
			return nil, err
		}
		user.RecoveryCodes = hashes
		if err := s.users.Update(ctx, user); err != nil {
			return nil, err
		}
		return codes, nil
	}
	return nil, nil
}

// RemovePasskey deletes one of the user's passkeys after re-checking the
// current password. Removing the last second step also drops the recovery
// codes, which then stand in for nothing.
func (s *Service) RemovePasskey(ctx context.Context, r *http.Request, user *domain.User, id, password string) error {
	if s.passkeys == nil {
		return ErrPasskeysUnavailable
	}
	if err := s.VerifyCurrentPassword(user, password); err != nil {
		return err
	}
	if err := s.passkeys.repo.Delete(ctx, user.ID, id); err != nil {
		return err
	}
	s.audit.Record(ctx, audit.Event{Actor: user, Action: audit.PasskeyRemoved, TargetType: "user", TargetID: user.ID, Detail: id, IP: audit.ClientIP(r)})
	if !s.hasSecondFactor(ctx, user) && len(user.RecoveryCodes) > 0 {
		user.RecoveryCodes = nil
		return s.users.Update(ctx, user)
	}
	return nil
}

// PendingLoginHasPasskeys reports whether the pending login's user can use
// a passkey for the second step.
func (s *Service) PendingLoginHasPasskeys(ctx context.Context, r *http.Request) bool {
	if !s.PasskeysAvailable() {
		return false
	}
	c, err := r.Cookie(PendingLoginCookieName)
	if err != nil {
		return false
	}
	p, ok := s.pending.get(c.Value)
	if !ok {
		return false
	}
	list, err := s.passkeys.repo.ListByUserID(ctx, p.userID)
	return err == nil && len(list) > 0
}

// PendingLoginHasTOTP reports whether the pending login's user has an
// authenticator app, so the code page can ask for the right thing.
func (s *Service) PendingLoginHasTOTP(ctx context.Context, r *http.Request) bool {
	c, err := r.Cookie(PendingLoginCookieName)
	if err != nil {
		return false
	}
	p, ok := s.pending.get(c.Value)
	if !ok {
		return false
	}
	user, err := s.users.GetByID(ctx, p.userID)
	return err == nil && user.TOTPEnabled()
}

// BeginPasskeyLogin issues a challenge for the pending login's passkeys and
// returns the options for navigator.credentials.get.
func (s *Service) BeginPasskeyLogin(ctx context.Context, r *http.Request) (*protocol.CredentialAssertion, error) {
	if !s.PasskeysAvailable() {
		return nil, ErrPasskeysUnavailable
	}
	if err := s.csrf.ValidateToken(r); err != nil {
		return nil, idperrors.New(idperrors.CodeForbidden, "invalid CSRF token")
	}
	c, err := r.Cookie(PendingLoginCookieName)
	if err != nil {
		return nil, ErrPendingLoginExpired
	}
	p, ok := s.pending.get(c.Value)
	if !ok {
		return nil, ErrPendingLoginExpired
	}
	user, err := s.users.GetByID(ctx, p.userID)
	if err != nil {
		return nil, ErrPendingLoginExpired
	}
	wu, _, err := s.webauthnUser(ctx, user)
	if err != nil {
		return nil, err
	}
	if len(wu.creds) == 0 {
		return nil, ErrPasskeysUnavailable
	}
	assertion, data, err := s.passkeys.wa.BeginLogin(wu, webauthn.WithUserVerification(protocol.VerificationPreferred))
	if err != nil {
		return nil, err
	}
	if !s.pending.setPasskeyChallenge(c.Value, data) {
		return nil, ErrPendingLoginExpired
	}
	return assertion, nil
}

// CompletePasskeyLogin verifies the signed assertion for the pending login
// and starts the session. A failure counts like a wrong code.
func (s *Service) CompletePasskeyLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, response []byte) (*domain.User, error) {
	if !s.PasskeysAvailable() {
		return nil, ErrPasskeysUnavailable
	}
	token, user, attempts, err := s.reservePendingAttempt(ctx, w, r)
	if err != nil {
		return nil, err
	}
	challenge := s.pending.takePasskeyChallenge(token)
	if challenge == nil {
		return nil, ErrPasskeyCeremony
	}

	unlock := s.lockUser(user.ID)
	defer unlock()
	wu, list, err := s.webauthnUser(ctx, user)
	if err != nil {
		return nil, err
	}
	parsed, perr := protocol.ParseCredentialRequestResponseBytes(response)
	var cred *webauthn.Credential
	if perr == nil {
		cred, err = s.passkeys.wa.ValidateLogin(wu, *challenge, parsed)
	}
	// A counter that went backwards means a cloned authenticator: refuse.
	if perr != nil || err != nil || cred.Authenticator.CloneWarning {
		return nil, s.secondFactorFailed(ctx, w, r, user, token, attempts, "passkey not accepted")
	}

	id := base64.RawURLEncoding.EncodeToString(cred.ID)
	for _, p := range list {
		if p.ID != id {
			continue
		}
		raw, err := json.Marshal(cred)
		if err != nil {
			return nil, err
		}
		p.Credential, p.LastUsedAt = raw, time.Now()
		if err := s.passkeys.repo.Update(ctx, p); err != nil {
			return nil, fmt.Errorf("failed to record passkey use: %w", err)
		}
	}

	amr := []string{AMRPassword, AMRSoftwareKey, AMRMultiFactor}
	if parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		amr = append(amr, AMRUserVerification)
	}
	return user, s.finishPendingLogin(ctx, w, r, token, user, amr...)
}
