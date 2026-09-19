package oidc

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/store"
)

// TokenRequest represents a parsed token request.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	CodeVerifier string
	RefreshToken string
	Scope        string
}

// RevocationRequest represents a token revocation request (RFC 7009).
type RevocationRequest struct {
	Token         string
	TokenTypeHint string // "access_token" or "refresh_token"
	ClientID      string
	ClientSecret  string
}

// IntrospectionRequest represents a token introspection request (RFC 7662).
type IntrospectionRequest struct {
	Token         string
	TokenTypeHint string // "access_token" or "refresh_token"
	ClientID      string
	ClientSecret  string
}

// IntrospectionResponse represents the introspection response.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
}

// TokenResponse represents the token endpoint response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// TokenService handles token requests.
type TokenService struct {
	clients        store.ClientRepository
	authCodes      store.AuthCodeRepository
	tokens         store.TokenRepository
	users          store.UserRepository
	tokenGenerator *crypto.TokenGenerator
	accessTTL      time.Duration
	refreshTTL     time.Duration
	issuer         string
	groupClaims    *GroupClaims // nil = never emit groups
}

// TokenServiceOption configures the TokenService.
type TokenServiceOption func(*TokenService)

// WithGroupClaims emits group memberships in tokens when the groups scope is granted.
func WithGroupClaims(gc *GroupClaims) TokenServiceOption {
	return func(s *TokenService) { s.groupClaims = gc }
}

// NewTokenService creates a new TokenService.
func NewTokenService(
	clients store.ClientRepository,
	authCodes store.AuthCodeRepository,
	tokens store.TokenRepository,
	users store.UserRepository,
	tokenGenerator *crypto.TokenGenerator,
	issuer string,
	accessTTL, refreshTTL time.Duration,
	opts ...TokenServiceOption,
) *TokenService {
	s := &TokenService{
		clients:        clients,
		authCodes:      authCodes,
		tokens:         tokens,
		users:          users,
		tokenGenerator: tokenGenerator,
		issuer:         issuer,
		accessTTL:      accessTTL,
		refreshTTL:     refreshTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ParseTokenRequest parses a token request from the HTTP request.
func (s *TokenService) ParseTokenRequest(r *http.Request) (*TokenRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, idperrors.InvalidInput("invalid form data")
	}

	req := &TokenRequest{
		GrantType:    r.FormValue("grant_type"),
		Code:         r.FormValue("code"),
		RedirectURI:  r.FormValue("redirect_uri"),
		ClientID:     r.FormValue("client_id"),
		ClientSecret: r.FormValue("client_secret"),
		CodeVerifier: r.FormValue("code_verifier"),
		RefreshToken: r.FormValue("refresh_token"),
		Scope:        r.FormValue("scope"),
	}

	// Check for client credentials in Authorization header (Basic auth)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Basic ") {
			decoded, err := base64.StdEncoding.DecodeString(auth[6:])
			if err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					req.ClientID = parts[0]
					req.ClientSecret = parts[1]
				}
			}
		}
	}

	if req.GrantType == "" {
		return nil, idperrors.InvalidInput("grant_type is required")
	}

	return req, nil
}

// HandleAuthorizationCode handles the authorization_code grant type.
func (s *TokenService) HandleAuthorizationCode(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	if req.Code == "" {
		return nil, idperrors.InvalidInput("code is required")
	}
	if req.RedirectURI == "" {
		return nil, idperrors.InvalidInput("redirect_uri is required")
	}

	// Authenticate the client before looking at the grant, so an
	// unauthenticated caller learns nothing about codes.
	client, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		return nil, idperrors.Unauthorized("invalid client")
	}
	if !authenticateClient(ctx, s.clients, client, req.ClientSecret) {
		return nil, idperrors.Unauthorized("invalid client credentials")
	}

	// Get the authorization code
	authCode, err := s.authCodes.GetByCode(ctx, req.Code)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			return nil, idperrors.InvalidGrant("invalid code")
		}
		return nil, err
	}

	// Validate code
	if authCode.Used {
		return nil, idperrors.InvalidGrant("code already used")
	}
	if authCode.IsExpired() {
		return nil, idperrors.InvalidGrant("code expired")
	}
	if authCode.ClientID != req.ClientID {
		return nil, idperrors.InvalidGrant("client_id mismatch")
	}
	if authCode.RedirectURI != req.RedirectURI {
		return nil, idperrors.InvalidGrant("redirect_uri mismatch")
	}

	// Validate PKCE
	if !ValidateCodeVerifier(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
		return nil, idperrors.InvalidGrant("invalid code_verifier")
	}

	// Mark code as used
	if err := s.authCodes.MarkUsed(ctx, req.Code); err != nil {
		return nil, fmt.Errorf("failed to mark code as used: %w", err)
	}

	// Get user
	user, err := s.users.GetByID(ctx, authCode.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Generate tokens
	return s.generateTokens(ctx, user, client, authCode.Scope, authCode.Nonce, authCode.AuthTime)
}

// HandleRefreshToken handles the refresh_token grant type.
func (s *TokenService) HandleRefreshToken(ctx context.Context, req *TokenRequest) (*TokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, idperrors.InvalidInput("refresh_token is required")
	}

	// Get the refresh token
	token, err := s.tokens.GetByID(ctx, req.RefreshToken)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			return nil, idperrors.InvalidGrant("invalid refresh_token")
		}
		return nil, err
	}
	if token.ClientID != req.ClientID {
		return nil, idperrors.InvalidGrant("client_id mismatch")
	}

	// Validate client
	client, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		return nil, idperrors.Unauthorized("invalid client")
	}

	// Validate client secret for confidential clients (constant-time comparison)
	if !authenticateClient(ctx, s.clients, client, req.ClientSecret) {
		return nil, idperrors.Unauthorized("invalid client credentials")
	}

	// A refresh token is single-use (rotation). Seeing a rotated-out one
	// again means it leaked and both holders are racing, so cut off the
	// whole grant for this user and client rather than just this token.
	if token.Revoked && !token.IsExpired() {
		if err := s.revokeGrant(ctx, token.UserID, token.ClientID); err != nil {
			return nil, fmt.Errorf("failed to revoke tokens after refresh token reuse: %w", err)
		}
		return nil, idperrors.InvalidGrant("refresh_token has already been used; all tokens for this client were revoked")
	}
	if !token.IsValid() {
		return nil, idperrors.InvalidGrant("refresh_token is invalid or expired")
	}

	// Get user; a disabled account must not keep minting tokens
	user, err := s.users.GetByID(ctx, token.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if !user.Active {
		return nil, idperrors.InvalidGrant("user account is disabled")
	}

	// The requested scope may narrow the original grant, never widen it
	scope := token.Scope
	if req.Scope != "" {
		if !scopeSubset(req.Scope, token.Scope) {
			return nil, idperrors.InvalidScope("requested scope exceeds the scope of the refresh token")
		}
		scope = req.Scope
	}

	// Revoke old refresh token (rotation)
	if err := s.tokens.Revoke(ctx, req.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	// Generate new tokens
	return s.generateTokens(ctx, user, client, scope, "", time.Time{})
}

// revokeGrant revokes every live token the user holds for the client.
func (s *TokenService) revokeGrant(ctx context.Context, userID, clientID string) error {
	tokens, err := s.tokens.ListByUserID(ctx, userID)
	if err != nil {
		return err
	}
	for _, t := range tokens {
		if t.ClientID != clientID || t.Revoked {
			continue
		}
		if err := s.tokens.Revoke(ctx, t.ID); err != nil {
			return err
		}
	}
	return nil
}

// scopeSubset reports whether every scope in requested is also in granted.
func scopeSubset(requested, granted string) bool {
	have := map[string]bool{}
	for _, sc := range strings.Fields(granted) {
		have[sc] = true
	}
	for _, sc := range strings.Fields(requested) {
		if !have[sc] {
			return false
		}
	}
	return true
}

// ParseRevocationRequest parses a token revocation request.
func (s *TokenService) ParseRevocationRequest(r *http.Request) (*RevocationRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, idperrors.InvalidInput("invalid form data")
	}

	req := &RevocationRequest{
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      r.FormValue("client_id"),
		ClientSecret:  r.FormValue("client_secret"),
	}

	// Check for client credentials in Authorization header (Basic auth)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Basic ") {
			decoded, err := base64.StdEncoding.DecodeString(auth[6:])
			if err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					req.ClientID = parts[0]
					req.ClientSecret = parts[1]
				}
			}
		}
	}

	if req.Token == "" {
		return nil, idperrors.InvalidInput("token is required")
	}

	return req, nil
}

// HandleRevocation handles token revocation (RFC 7009).
// Per RFC 7009, this endpoint always returns 200 OK regardless of whether
// the token was valid, revoked, or never existed - this prevents token
// enumeration attacks.
func (s *TokenService) HandleRevocation(ctx context.Context, req *RevocationRequest) error {
	// Validate client credentials if provided
	if req.ClientID != "" {
		client, err := s.clients.GetByID(ctx, req.ClientID)
		if err != nil {
			// Don't reveal client existence
			return nil
		}
		if !authenticateClient(ctx, s.clients, client, req.ClientSecret) {
			return idperrors.Unauthorized("invalid client credentials")
		}
	}

	// Try to revoke as refresh token
	if req.TokenTypeHint == "" || req.TokenTypeHint == "refresh_token" {
		if err := s.tokens.Revoke(ctx, req.Token); err == nil {
			return nil
		}
	}

	// For access tokens (JWTs), we can't truly revoke them since they're
	// stateless. The best we can do is acknowledge the request.
	// In a production system, you might maintain a blocklist.

	return nil
}

// ParseIntrospectionRequest parses a token introspection request.
func (s *TokenService) ParseIntrospectionRequest(r *http.Request) (*IntrospectionRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, idperrors.InvalidInput("invalid form data")
	}

	req := &IntrospectionRequest{
		Token:         r.FormValue("token"),
		TokenTypeHint: r.FormValue("token_type_hint"),
		ClientID:      r.FormValue("client_id"),
		ClientSecret:  r.FormValue("client_secret"),
	}

	// Check for client credentials in Authorization header (Basic auth)
	if auth := r.Header.Get("Authorization"); auth != "" {
		if strings.HasPrefix(auth, "Basic ") {
			decoded, err := base64.StdEncoding.DecodeString(auth[6:])
			if err == nil {
				parts := strings.SplitN(string(decoded), ":", 2)
				if len(parts) == 2 {
					req.ClientID = parts[0]
					req.ClientSecret = parts[1]
				}
			}
		}
	}

	if req.Token == "" {
		return nil, idperrors.InvalidInput("token is required")
	}

	return req, nil
}

// HandleIntrospection handles token introspection (RFC 7662).
func (s *TokenService) HandleIntrospection(ctx context.Context, req *IntrospectionRequest) (*IntrospectionResponse, error) {
	// Validate client credentials (introspection requires authentication)
	if req.ClientID == "" {
		return nil, idperrors.Unauthorized("client authentication required")
	}

	client, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		return nil, idperrors.Unauthorized("invalid client credentials")
	}
	if !authenticateClient(ctx, s.clients, client, req.ClientSecret) {
		return nil, idperrors.Unauthorized("invalid client credentials")
	}

	// Try to introspect as access token (JWT) first
	if req.TokenTypeHint == "" || req.TokenTypeHint == "access_token" {
		claims, err := s.tokenGenerator.ValidateAccessToken(req.Token)
		if err == nil {
			return &IntrospectionResponse{
				Active:    true,
				Scope:     claims.Scope,
				ClientID:  claims.ClientID,
				Sub:       claims.Subject,
				Iss:       claims.Issuer,
				Aud:       claims.ClientID,
				Exp:       claims.ExpiresAt.Unix(),
				Iat:       claims.IssuedAt.Unix(),
				TokenType: "Bearer",
			}, nil
		}
	}

	// Try to introspect as refresh token
	if req.TokenTypeHint == "" || req.TokenTypeHint == "refresh_token" {
		token, err := s.tokens.GetByID(ctx, req.Token)
		if err == nil && token.IsValid() {
			// Get user for username
			var username string
			if user, err := s.users.GetByID(ctx, token.UserID); err == nil {
				username = user.Email
			}

			return &IntrospectionResponse{
				Active:    true,
				Scope:     token.Scope,
				ClientID:  token.ClientID,
				Username:  username,
				Sub:       token.UserID,
				Exp:       token.ExpiresAt.Unix(),
				TokenType: "refresh_token",
			}, nil
		}
	}

	// Token is not active (invalid, expired, revoked, or doesn't exist)
	return &IntrospectionResponse{Active: false}, nil
}

func (s *TokenService) generateTokens(ctx context.Context, user *domain.User, client *domain.Client, scope, nonce string, authTime time.Time) (*TokenResponse, error) {
	// Build claims for ID token
	idTokenClaims := &crypto.Claims{
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Name:          user.DisplayName,
		ClientID:      client.ID,
	}

	// Add nonce if provided
	if nonce != "" {
		idTokenClaims.SetExtra("nonce", nonce)
	}
	// auth_time lets clients enforce max_age themselves
	if !authTime.IsZero() {
		idTokenClaims.SetExtra("auth_time", authTime.Unix())
	}

	// Group memberships go in both tokens: the ID token for the client, the
	// access token for resource servers that authorize on groups.
	accessTokenClaims := &crypto.Claims{Scope: scope, ClientID: client.ID}
	if err := s.groupClaims.Apply(ctx, user, scope, idTokenClaims); err != nil {
		return nil, err
	}
	if err := s.groupClaims.Apply(ctx, user, scope, accessTokenClaims); err != nil {
		return nil, err
	}

	// Generate ID token
	idToken, _, err := s.tokenGenerator.GenerateIDToken(user.ID, s.accessTTL, idTokenClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID token: %w", err)
	}

	// Generate access token
	accessToken, _, err := s.tokenGenerator.GenerateAccessTokenWithClaims(user.ID, s.accessTTL, accessTokenClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	response := &TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(s.accessTTL.Seconds()),
		IDToken:     idToken,
		Scope:       scope,
	}

	// Generate refresh token if offline_access scope is requested
	if strings.Contains(scope, "offline_access") {
		refreshToken := &domain.Token{
			ID:        uuid.New().String(),
			UserID:    user.ID,
			ClientID:  client.ID,
			Scope:     scope,
			ExpiresAt: time.Now().Add(s.refreshTTL),
			Revoked:   false,
		}

		if err := s.tokens.Create(ctx, refreshToken); err != nil {
			return nil, fmt.Errorf("failed to create refresh token: %w", err)
		}

		response.RefreshToken = refreshToken.ID
	}

	return response, nil
}
