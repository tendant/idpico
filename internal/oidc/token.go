package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
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
) *TokenService {
	return &TokenService{
		clients:        clients,
		authCodes:      authCodes,
		tokens:         tokens,
		users:          users,
		tokenGenerator: tokenGenerator,
		issuer:         issuer,
		accessTTL:      accessTTL,
		refreshTTL:     refreshTTL,
	}
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

	// Get the authorization code
	authCode, err := s.authCodes.GetByCode(ctx, req.Code)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			return nil, idperrors.InvalidInput("invalid code")
		}
		return nil, err
	}

	// Validate code
	if authCode.Used {
		return nil, idperrors.InvalidInput("code already used")
	}
	if authCode.IsExpired() {
		return nil, idperrors.InvalidInput("code expired")
	}
	if authCode.ClientID != req.ClientID {
		return nil, idperrors.InvalidInput("client_id mismatch")
	}
	if authCode.RedirectURI != req.RedirectURI {
		return nil, idperrors.InvalidInput("redirect_uri mismatch")
	}

	// Validate PKCE
	if !ValidateCodeVerifier(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
		return nil, idperrors.InvalidInput("invalid code_verifier")
	}

	// Validate client
	client, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		return nil, idperrors.InvalidInput("invalid client")
	}

	// Validate client secret for confidential clients (constant-time comparison)
	if !client.Public {
		if subtle.ConstantTimeCompare([]byte(req.ClientSecret), []byte(client.Secret)) != 1 {
			return nil, idperrors.Unauthorized("invalid client credentials")
		}
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
	return s.generateTokens(ctx, user, client, authCode.Scope, authCode.Nonce)
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
			return nil, idperrors.InvalidInput("invalid refresh_token")
		}
		return nil, err
	}

	// Validate token
	if !token.IsValid() {
		return nil, idperrors.InvalidInput("refresh_token is invalid or expired")
	}
	if token.ClientID != req.ClientID {
		return nil, idperrors.InvalidInput("client_id mismatch")
	}

	// Validate client
	client, err := s.clients.GetByID(ctx, req.ClientID)
	if err != nil {
		return nil, idperrors.InvalidInput("invalid client")
	}

	// Validate client secret for confidential clients (constant-time comparison)
	if !client.Public {
		if subtle.ConstantTimeCompare([]byte(req.ClientSecret), []byte(client.Secret)) != 1 {
			return nil, idperrors.Unauthorized("invalid client credentials")
		}
	}

	// Get user
	user, err := s.users.GetByID(ctx, token.UserID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Revoke old refresh token (rotation)
	if err := s.tokens.Revoke(ctx, req.RefreshToken); err != nil {
		return nil, fmt.Errorf("failed to revoke old token: %w", err)
	}

	// Use requested scope or original scope
	scope := req.Scope
	if scope == "" {
		scope = token.Scope
	}

	// Generate new tokens
	return s.generateTokens(ctx, user, client, scope, "")
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
		if !client.Public {
			if subtle.ConstantTimeCompare([]byte(req.ClientSecret), []byte(client.Secret)) != 1 {
				return idperrors.Unauthorized("invalid client credentials")
			}
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
	if !client.Public {
		if subtle.ConstantTimeCompare([]byte(req.ClientSecret), []byte(client.Secret)) != 1 {
			return nil, idperrors.Unauthorized("invalid client credentials")
		}
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

func (s *TokenService) generateTokens(ctx context.Context, user *domain.User, client *domain.Client, scope, nonce string) (*TokenResponse, error) {
	// Build claims for ID token
	idTokenClaims := &crypto.Claims{
		Email:         user.Email,
		EmailVerified: true, // Assume verified for now
		Name:          user.DisplayName,
		ClientID:      client.ID,
	}

	// Add nonce if provided
	if nonce != "" {
		if idTokenClaims.Extra == nil {
			idTokenClaims.Extra = make(map[string]any)
		}
		idTokenClaims.Extra["nonce"] = nonce
	}

	// Generate ID token
	idToken, _, err := s.tokenGenerator.GenerateIDToken(user.ID, s.accessTTL, idTokenClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ID token: %w", err)
	}

	// Generate access token
	accessToken, _, err := s.tokenGenerator.GenerateAccessToken(user.ID, s.accessTTL, scope, client.ID)
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
