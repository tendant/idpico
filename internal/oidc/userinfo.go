package oidc

import (
	"context"
	"strings"

	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
)

// UserInfoResponse represents the userinfo endpoint response.
type UserInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
}

// UserInfoService handles userinfo requests.
type UserInfoService struct {
	users          store.UserRepository
	tokenGenerator *crypto.TokenGenerator
}

// NewUserInfoService creates a new UserInfoService.
func NewUserInfoService(users store.UserRepository, tokenGenerator *crypto.TokenGenerator) *UserInfoService {
	return &UserInfoService{
		users:          users,
		tokenGenerator: tokenGenerator,
	}
}

// GetUserInfo returns user info for the given access token.
func (s *UserInfoService) GetUserInfo(ctx context.Context, accessToken string) (*UserInfoResponse, error) {
	// Parse and validate the access token
	token, claims, err := s.tokenGenerator.ParseToken(accessToken)
	if err != nil {
		return nil, idperrors.New(idperrors.CodeTokenInvalid, "invalid access token")
	}

	if !token.Valid {
		return nil, idperrors.New(idperrors.CodeTokenInvalid, "invalid access token")
	}

	// Get user ID from token subject
	subject, err := token.Claims.GetSubject()
	if err != nil {
		return nil, idperrors.New(idperrors.CodeTokenInvalid, "invalid token subject")
	}

	// Get user from database
	user, err := s.users.GetByID(ctx, subject)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			return nil, idperrors.New(idperrors.CodeNotFound, "user not found")
		}
		return nil, err
	}

	// Build response based on scopes
	response := &UserInfoResponse{
		Sub: user.ID,
	}

	scope := claims.Scope
	if scope == "" {
		// Default to basic scopes if not specified
		scope = "openid profile email"
	}

	// Add claims based on scope
	if strings.Contains(scope, "email") {
		response.Email = user.Email
		response.EmailVerified = true // Assume verified for now
	}

	if strings.Contains(scope, "profile") {
		response.Name = user.DisplayName
	}

	return response, nil
}

// ExtractBearerToken extracts the bearer token from the Authorization header.
func ExtractBearerToken(authHeader string) (string, error) {
	if authHeader == "" {
		return "", idperrors.Unauthorized("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", idperrors.Unauthorized("invalid authorization header")
	}

	return authHeader[7:], nil
}

// GetUserByID is a helper to get a user by ID.
func (s *UserInfoService) GetUserByID(ctx context.Context, userID string) (*domain.User, error) {
	return s.users.GetByID(ctx, userID)
}
