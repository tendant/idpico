// Package oidc implements OAuth 2.0 and OpenID Connect endpoints.
package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/metrics"
	"github.com/tendant/idpico/internal/store"
)

// AuthorizeRequest represents a parsed authorization request.
type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Prompt              []string // OIDC prompt values: none, login, consent, select_account
	MaxAge              int      // Seconds since authentication the session may be; -1 when absent

	maxAge string // raw max_age, validated by ValidateClient
	// Parameters for features IDPico does not implement. Their presence is
	// an error the client must hear about (OIDC Core §6.1, §6.2, §7.2.1)
	// rather than something to ignore, since the client expects the values
	// inside them to be honoured.
	hasRequest, hasRequestURI, hasRegistration bool
}

// RequiresFreshLogin reports whether the request insists on re-authentication:
// prompt=login, prompt=select_account (no account chooser exists, so the user
// signs in again), or a session older than max_age.
func (r *AuthorizeRequest) RequiresFreshLogin(authTime time.Time) bool {
	if r.HasPrompt("login") || r.HasPrompt("select_account") {
		return true
	}
	if r.MaxAge >= 0 && (authTime.IsZero() || time.Since(authTime) > time.Duration(r.MaxAge)*time.Second) {
		return true
	}
	return false
}

// HasPrompt reports whether the request carries the given prompt value.
func (r *AuthorizeRequest) HasPrompt(value string) bool {
	for _, p := range r.Prompt {
		if p == value {
			return true
		}
	}
	return false
}

// Scopes returns the requested scopes as a list.
func (r *AuthorizeRequest) Scopes() []string {
	return strings.Fields(r.Scope)
}

// AuthorizeService handles authorization requests.
type AuthorizeService struct {
	clients   store.ClientRepository
	authCodes store.AuthCodeRepository
	codeTTL   time.Duration
}

// NewAuthorizeService creates a new AuthorizeService.
func NewAuthorizeService(clients store.ClientRepository, authCodes store.AuthCodeRepository, codeTTL time.Duration) *AuthorizeService {
	return &AuthorizeService{
		clients:   clients,
		authCodes: authCodes,
		codeTTL:   codeTTL,
	}
}

// RedirectError is an authorization error that is delivered to the client's
// redirect URI (RFC 6749 §4.1.2.1). It is only returned once the client and
// redirect_uri have been validated, so redirecting to it is safe.
type RedirectError struct {
	Code        string // OAuth error code, e.g. invalid_request, invalid_scope
	Description string
}

func (e *RedirectError) Error() string { return e.Code + ": " + e.Description }

func redirectErr(code, format string, args ...any) error {
	return &RedirectError{Code: code, Description: fmt.Sprintf(format, args...)}
}

// ParseAuthorizeRequest parses an authorization request. Only client_id and
// redirect_uri are checked here, because without them there is nowhere to
// deliver an error; everything else is validated by ValidateClient.
func (s *AuthorizeService) ParseAuthorizeRequest(r *http.Request) (*AuthorizeRequest, error) {
	return s.ParseAuthorizeQuery(r.URL.Query())
}

// ParseAuthorizeQuery parses authorization request parameters. See
// ParseAuthorizeRequest.
func (s *AuthorizeService) ParseAuthorizeQuery(q url.Values) (*AuthorizeRequest, error) {
	req := &AuthorizeRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		ResponseType:        q.Get("response_type"),
		Scope:               q.Get("scope"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
		Prompt:              strings.Fields(q.Get("prompt")),
		MaxAge:              -1,
		maxAge:              q.Get("max_age"),
		hasRequest:          q.Has("request"),
		hasRequestURI:       q.Has("request_uri"),
		hasRegistration:     q.Has("registration"),
	}

	if req.ClientID == "" {
		return nil, idperrors.InvalidInput("client_id is required")
	}
	if req.RedirectURI == "" {
		return nil, idperrors.InvalidInput("redirect_uri is required")
	}
	return req, nil
}

// ValidateClient validates the client and redirect URI, then the rest of the
// request. An unknown client or unregistered redirect_uri is an InvalidInput
// error that must be shown to the user; every later failure is a
// RedirectError for the client (RFC 6749 §4.1.2.1, RFC 7636 §4.4.1).
func (s *AuthorizeService) ValidateClient(ctx contextInterface, req *AuthorizeRequest) (*domain.Client, error) {
	client, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			return nil, idperrors.InvalidInput("unknown client_id")
		}
		return nil, err
	}

	// Validate redirect URI (exact match required)
	validURI := false
	for _, uri := range client.RedirectURIs {
		if uri == req.RedirectURI {
			validURI = true
			break
		}
	}
	if !validURI {
		return nil, idperrors.InvalidInput("invalid redirect_uri")
	}

	// Request objects would carry parameters this server never reads; refuse
	// rather than silently authorize something other than what was asked.
	if req.hasRequest {
		return nil, redirectErr("request_not_supported", "request objects are not supported")
	}
	if req.hasRequestURI {
		return nil, redirectErr("request_uri_not_supported", "request_uri is not supported")
	}
	if req.hasRegistration {
		return nil, redirectErr("registration_not_supported", "the registration parameter is not supported")
	}

	if req.maxAge != "" {
		n, err := strconv.Atoi(req.maxAge)
		if err != nil || n < 0 {
			return nil, redirectErr("invalid_request", "max_age must be a non-negative integer")
		}
		req.MaxAge = n
	}

	// prompt=none is exclusive per OIDC Core 3.1.2.1
	if req.HasPrompt("none") && len(req.Prompt) > 1 {
		return nil, redirectErr("invalid_request", "prompt=none cannot be combined with other prompt values")
	}

	if req.ResponseType != "code" {
		return nil, redirectErr("unsupported_response_type", "response_type must be 'code'")
	}

	scopes := req.Scopes()
	hasOpenID := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return nil, redirectErr("invalid_scope", "scope must contain 'openid'")
	}

	// Public clients MUST use PKCE
	if client.Public && req.CodeChallenge == "" {
		return nil, redirectErr("invalid_request", "code_challenge is required for public clients")
	}

	// Only S256 is supported, as discovery advertises; "plain" (RFC 7636's
	// default when the method is omitted) offers no protection against a
	// leaked authorization request and is refused for every client.
	if req.CodeChallenge != "" && req.CodeChallengeMethod != "S256" {
		return nil, redirectErr("invalid_request", "code_challenge_method must be S256")
	}

	// Validate requested scopes against allowed scopes
	for _, scope := range scopes {
		allowed := false
		for _, s := range client.Scopes {
			if s == scope {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, redirectErr("invalid_scope", "scope '%s' not allowed for this client", scope)
		}
	}

	return client, nil
}

// CreateAuthCode creates an authorization code for the user. authTime is
// when the user's current session was established and is carried into the
// ID token's auth_time claim.
func (s *AuthorizeService) CreateAuthCode(ctx contextInterface, req *AuthorizeRequest, userID string, authTime time.Time) (*domain.AuthCode, error) {
	code := &domain.AuthCode{
		Code:                uuid.New().String(),
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		AuthTime:            authTime,
		ExpiresAt:           time.Now().Add(s.codeTTL),
		Used:                false,
	}

	if err := s.authCodes.Create(ctx, code); err != nil {
		return nil, fmt.Errorf("failed to create auth code: %w", err)
	}
	metrics.RecordAuthCodeIssued()

	return code, nil
}

// BuildAuthorizationResponse builds the redirect URL with the authorization code.
func (s *AuthorizeService) BuildAuthorizationResponse(redirectURI, code, state string) string {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// BuildErrorResponse builds the redirect URL with an error.
func (s *AuthorizeService) BuildErrorResponse(redirectURI, errorCode, errorDescription, state string) string {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errorCode)
	if errorDescription != "" {
		q.Set("error_description", errorDescription)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// ValidateCodeVerifier validates the PKCE code verifier against the stored challenge.
func ValidateCodeVerifier(codeVerifier, codeChallenge, codeChallengeMethod string) bool {
	if codeChallenge == "" {
		// No PKCE was used
		return codeVerifier == ""
	}

	if codeVerifier == "" {
		return false
	}

	switch codeChallengeMethod {
	case "plain":
		return codeVerifier == codeChallenge
	case "S256":
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		return computed == codeChallenge
	default:
		return false
	}
}

// contextInterface is a minimal context interface to avoid import cycles.
type contextInterface interface {
	Deadline() (deadline time.Time, ok bool)
	Done() <-chan struct{}
	Err() error
	Value(key any) any
}
