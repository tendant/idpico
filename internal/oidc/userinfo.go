package oidc

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/store"
)

// UserInfoResponse represents the userinfo endpoint response.
type UserInfoResponse struct {
	Sub           string   `json:"sub"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Groups        []string `json:"groups,omitempty"`

	// Extra holds additional top-level members (e.g. groups under a custom claim name).
	Extra map[string]any `json:"-"`
}

type userInfoJSON UserInfoResponse

// MarshalJSON flattens Extra into the top-level object.
func (r UserInfoResponse) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(userInfoJSON(r))
	emptyGroups := r.Groups != nil && len(r.Groups) == 0
	if err != nil || (len(r.Extra) == 0 && !emptyGroups) {
		return base, err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	if emptyGroups {
		merged["groups"] = json.RawMessage("[]")
	}
	for k, v := range r.Extra {
		if _, taken := merged[k]; taken {
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		merged[k] = raw
	}
	return json.Marshal(merged)
}

// UserInfoService handles userinfo requests.
type UserInfoService struct {
	users          store.UserRepository
	tokenGenerator *crypto.TokenGenerator
	groupClaims    *GroupClaims
}

// UserInfoOption configures the UserInfoService.
type UserInfoOption func(*UserInfoService)

// WithUserInfoGroups includes group memberships when the groups scope is granted.
func WithUserInfoGroups(gc *GroupClaims) UserInfoOption {
	return func(s *UserInfoService) { s.groupClaims = gc }
}

// NewUserInfoService creates a new UserInfoService.
func NewUserInfoService(users store.UserRepository, tokenGenerator *crypto.TokenGenerator, opts ...UserInfoOption) *UserInfoService {
	s := &UserInfoService{
		users:          users,
		tokenGenerator: tokenGenerator,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
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
		response.EmailVerified = user.EmailVerified
	}

	if strings.Contains(scope, "profile") {
		response.Name = user.DisplayName
	}

	if s.groupClaims != nil && hasScope(scope, ScopeGroups) {
		names, err := s.groupClaims.Names(ctx, user.ID)
		if err != nil {
			return nil, err
		}
		if s.groupClaims.ClaimName() == DefaultGroupsClaim {
			response.Groups = names
		} else {
			response.Extra = map[string]any{s.groupClaims.ClaimName(): names}
		}
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
