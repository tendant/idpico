// Package oidc implements OAuth 2.0 and OpenID Connect endpoints.
package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
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
	req := &AuthorizeRequest{
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		ResponseType:        r.URL.Query().Get("response_type"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		Nonce:               r.URL.Query().Get("nonce"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
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

// CreateAuthCode creates an authorization code for the user.
func (s *AuthorizeService) CreateAuthCode(ctx contextInterface, req *AuthorizeRequest, userID string) (*domain.AuthCode, error) {
	code := &domain.AuthCode{
		Code:                uuid.New().String(),
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
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
