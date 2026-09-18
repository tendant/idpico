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
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
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

// ParseAuthorizeRequest parses and validates an authorization request.
func (s *AuthorizeService) ParseAuthorizeRequest(r *http.Request) (*AuthorizeRequest, error) {
	return s.ParseAuthorizeQuery(r.URL.Query())
}

// ParseAuthorizeQuery parses and validates authorization request parameters.
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
	}

	if v := q.Get("max_age"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, idperrors.InvalidInput("max_age must be a non-negative integer")
		}
		req.MaxAge = n
	}

	// prompt=none is exclusive per OIDC Core 3.1.2.1
	if req.HasPrompt("none") && len(req.Prompt) > 1 {
		return nil, idperrors.InvalidInput("prompt=none cannot be combined with other prompt values")
	}

	// Validate required parameters
	if req.ClientID == "" {
		return nil, idperrors.InvalidInput("client_id is required")
	}
	if req.RedirectURI == "" {
		return nil, idperrors.InvalidInput("redirect_uri is required")
	}
	if req.ResponseType != "code" {
		return nil, idperrors.InvalidInput("response_type must be 'code'")
	}

	// Validate scope contains openid
	if !strings.Contains(req.Scope, "openid") {
		return nil, idperrors.InvalidInput("scope must contain 'openid'")
	}

	return req, nil
}

// ValidateClient validates the client and redirect URI.
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

	// Public clients MUST use PKCE
	if client.Public && req.CodeChallenge == "" {
		return nil, idperrors.InvalidInput("code_challenge is required for public clients")
	}

	// Validate PKCE method if challenge is provided
	if req.CodeChallenge != "" {
		if req.CodeChallengeMethod == "" {
			req.CodeChallengeMethod = "plain" // Default per RFC 7636
		}
		if req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
			return nil, idperrors.InvalidInput("code_challenge_method must be 'S256' or 'plain'")
		}
		// We recommend S256
		if req.CodeChallengeMethod == "plain" && client.Public {
			return nil, idperrors.InvalidInput("public clients must use S256 code_challenge_method")
		}
	}

	// Validate requested scopes against allowed scopes
	requestedScopes := strings.Split(req.Scope, " ")
	for _, scope := range requestedScopes {
		if scope == "" {
			continue
		}
		allowed := false
		for _, s := range client.Scopes {
			if s == scope {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, idperrors.InvalidInput(fmt.Sprintf("scope '%s' not allowed for this client", scope))
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
