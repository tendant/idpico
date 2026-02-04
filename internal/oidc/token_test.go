package oidc

import (
	"context"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

// Mock token repository
type mockTokenRepository struct {
	tokens map[string]*domain.Token
}

func newMockTokenRepository() *mockTokenRepository {
	return &mockTokenRepository{
		tokens: make(map[string]*domain.Token),
	}
}

func (m *mockTokenRepository) Create(ctx context.Context, token *domain.Token) error {
	m.tokens[token.ID] = token
	return nil
}

func (m *mockTokenRepository) GetByID(ctx context.Context, id string) (*domain.Token, error) {
	token, ok := m.tokens[id]
	if !ok {
		return nil, idperrors.NotFound("token", id)
	}
	return token, nil
}

func (m *mockTokenRepository) Revoke(ctx context.Context, id string) error {
	if token, ok := m.tokens[id]; ok {
		token.Revoked = true
	}
	return nil
}

func (m *mockTokenRepository) RevokeByUserID(ctx context.Context, userID string) error {
	for _, token := range m.tokens {
		if token.UserID == userID {
			token.Revoked = true
		}
	}
	return nil
}

func (m *mockTokenRepository) RevokeByClientID(ctx context.Context, clientID string) error {
	for _, token := range m.tokens {
		if token.ClientID == clientID {
			token.Revoked = true
		}
	}
	return nil
}

func (m *mockTokenRepository) DeleteExpired(ctx context.Context) error {
	return nil
}

// Mock user repository
type mockUserRepository struct {
	users map[string]*domain.User
}

func newMockUserRepository() *mockUserRepository {
	return &mockUserRepository{
		users: make(map[string]*domain.User),
	}
}

func (m *mockUserRepository) Create(ctx context.Context, user *domain.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	user, ok := m.users[id]
	if !ok {
		return nil, idperrors.NotFound("user", id)
	}
	return user, nil
}

func (m *mockUserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, idperrors.NotFound("user", email)
}

func (m *mockUserRepository) Update(ctx context.Context, user *domain.User) error {
	m.users[user.ID] = user
	return nil
}

func (m *mockUserRepository) Delete(ctx context.Context, id string) error {
	delete(m.users, id)
	return nil
}

func (m *mockUserRepository) List(ctx context.Context) ([]*domain.User, error) {
	var users []*domain.User
	for _, u := range m.users {
		users = append(users, u)
	}
	return users, nil
}

func setupTokenService() (*TokenService, *mockClientRepository, *mockAuthCodeRepository, *mockTokenRepository, *mockUserRepository) {
	clientRepo := newMockClientRepository()
	authCodeRepo := newMockAuthCodeRepository()
	tokenRepo := newMockTokenRepository()
	userRepo := newMockUserRepository()

	// Generate a key pair for token signing
	keyPair, _ := crypto.GenerateKeyPair(2048)
	tokenGenerator := crypto.NewTokenGenerator(keyPair, "https://idp.example.com", "https://idp.example.com")

	svc := NewTokenService(
		clientRepo,
		authCodeRepo,
		tokenRepo,
		userRepo,
		tokenGenerator,
		"https://idp.example.com",
		15*time.Minute,
		7*24*time.Hour,
	)

	return svc, clientRepo, authCodeRepo, tokenRepo, userRepo
}

func TestParseTokenRequest(t *testing.T) {
	svc, _, _, _, _ := setupTokenService()

	tests := []struct {
		name        string
		body        string
		contentType string
		authHeader  string
		wantErr     bool
		errContains string
		checkFn     func(*TokenRequest) error
	}{
		{
			name:        "valid authorization_code request",
			body:        "grant_type=authorization_code&code=test-code&redirect_uri=http://localhost:3000/callback&client_id=test-app&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			contentType: "application/x-www-form-urlencoded",
			wantErr:     false,
			checkFn: func(req *TokenRequest) error {
				if req.GrantType != "authorization_code" {
					return idperrors.InvalidInput("wrong grant_type")
				}
				if req.Code != "test-code" {
					return idperrors.InvalidInput("wrong code")
				}
				return nil
			},
		},
		{
			name:        "valid refresh_token request",
			body:        "grant_type=refresh_token&refresh_token=test-refresh-token&client_id=test-app",
			contentType: "application/x-www-form-urlencoded",
			wantErr:     false,
			checkFn: func(req *TokenRequest) error {
				if req.GrantType != "refresh_token" {
					return idperrors.InvalidInput("wrong grant_type")
				}
				if req.RefreshToken != "test-refresh-token" {
					return idperrors.InvalidInput("wrong refresh_token")
				}
				return nil
			},
		},
		{
			name:        "missing grant_type",
			body:        "code=test-code",
			contentType: "application/x-www-form-urlencoded",
			wantErr:     true,
			errContains: "grant_type is required",
		},
		{
			name:        "basic auth header",
			body:        "grant_type=authorization_code&code=test-code&redirect_uri=http://localhost:3000/callback",
			contentType: "application/x-www-form-urlencoded",
			authHeader:  "Basic " + base64.StdEncoding.EncodeToString([]byte("test-client:test-secret")),
			wantErr:     false,
			checkFn: func(req *TokenRequest) error {
				if req.ClientID != "test-client" {
					return idperrors.InvalidInput("wrong client_id from basic auth")
				}
				if req.ClientSecret != "test-secret" {
					return idperrors.InvalidInput("wrong client_secret from basic auth")
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/token", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			tokenReq, err := svc.ParseTokenRequest(req)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("Error should contain '%s', got '%s'", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if tt.checkFn != nil {
					if err := tt.checkFn(tokenReq); err != nil {
						t.Errorf("Check failed: %v", err)
					}
				}
			}
		})
	}
}

func TestHandleAuthorizationCode(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		setupFn     func(*mockClientRepository, *mockAuthCodeRepository, *mockUserRepository)
		request     *TokenRequest
		wantErr     bool
		errContains string
	}{
		{
			name: "valid confidential client",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
				clientRepo.Create(ctx, &domain.Client{
					ID:           "confidential-app",
					Name:         "Confidential App",
					Secret:       "super-secret",
					Public:       false,
					RedirectURIs: []string{"https://app.example.com/callback"},
					Scopes:       []string{"openid", "profile"},
				})
				userRepo.Create(ctx, &domain.User{
					ID:          "user-123",
					Email:       "test@example.com",
					DisplayName: "Test User",
				})
				authCodeRepo.Create(ctx, &domain.AuthCode{
					Code:        "valid-code",
					ClientID:    "confidential-app",
					UserID:      "user-123",
					RedirectURI: "https://app.example.com/callback",
					Scope:       "openid profile",
					ExpiresAt:   time.Now().Add(10 * time.Minute),
					Used:        false,
				})
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "valid-code",
				RedirectURI:  "https://app.example.com/callback",
				ClientID:     "confidential-app",
				ClientSecret: "super-secret",
			},
			wantErr: false,
		},
		{
			name: "valid public client with PKCE",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
				clientRepo.Create(ctx, &domain.Client{
					ID:           "public-app",
					Name:         "Public App",
					Public:       true,
					RedirectURIs: []string{"http://localhost:3000/callback"},
					Scopes:       []string{"openid", "profile", "email"},
				})
				userRepo.Create(ctx, &domain.User{
					ID:          "user-123",
					Email:       "test@example.com",
					DisplayName: "Test User",
				})
				authCodeRepo.Create(ctx, &domain.AuthCode{
					Code:                "pkce-code",
					ClientID:            "public-app",
					UserID:              "user-123",
					RedirectURI:         "http://localhost:3000/callback",
					Scope:               "openid profile",
					CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
					CodeChallengeMethod: "S256",
					ExpiresAt:           time.Now().Add(10 * time.Minute),
					Used:                false,
				})
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "pkce-code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "public-app",
				CodeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
			},
			wantErr: false,
		},
		{
			name: "missing code",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
			},
			request: &TokenRequest{
				GrantType:   "authorization_code",
				RedirectURI: "http://localhost:3000/callback",
				ClientID:    "test-app",
			},
			wantErr:     true,
			errContains: "code is required",
		},
		{
			name: "invalid code",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
			},
			request: &TokenRequest{
				GrantType:   "authorization_code",
				Code:        "nonexistent-code",
				RedirectURI: "http://localhost:3000/callback",
				ClientID:    "test-app",
			},
			wantErr:     true,
			errContains: "invalid code",
		},
		{
			name: "expired code",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
				clientRepo.Create(ctx, &domain.Client{
					ID:           "confidential-app",
					Name:         "Confidential App",
					Secret:       "super-secret",
					Public:       false,
					RedirectURIs: []string{"https://app.example.com/callback"},
					Scopes:       []string{"openid"},
				})
				authCodeRepo.Create(ctx, &domain.AuthCode{
					Code:        "expired-code",
					ClientID:    "confidential-app",
					UserID:      "user-123",
					RedirectURI: "https://app.example.com/callback",
					Scope:       "openid",
					ExpiresAt:   time.Now().Add(-1 * time.Hour),
					Used:        false,
				})
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "expired-code",
				RedirectURI:  "https://app.example.com/callback",
				ClientID:     "confidential-app",
				ClientSecret: "super-secret",
			},
			wantErr:     true,
			errContains: "code expired",
		},
		{
			name: "used code",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
				clientRepo.Create(ctx, &domain.Client{
					ID:           "confidential-app",
					Name:         "Confidential App",
					Secret:       "super-secret",
					Public:       false,
					RedirectURIs: []string{"https://app.example.com/callback"},
					Scopes:       []string{"openid"},
				})
				authCodeRepo.Create(ctx, &domain.AuthCode{
					Code:        "used-code",
					ClientID:    "confidential-app",
					UserID:      "user-123",
					RedirectURI: "https://app.example.com/callback",
					Scope:       "openid",
					ExpiresAt:   time.Now().Add(10 * time.Minute),
					Used:        true,
				})
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "used-code",
				RedirectURI:  "https://app.example.com/callback",
				ClientID:     "confidential-app",
				ClientSecret: "super-secret",
			},
			wantErr:     true,
			errContains: "code already used",
		},
		{
			name: "client_id mismatch",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
				authCodeRepo.Create(ctx, &domain.AuthCode{
					Code:        "mismatch-code",
					ClientID:    "correct-client",
					UserID:      "user-123",
					RedirectURI: "https://app.example.com/callback",
					Scope:       "openid",
					ExpiresAt:   time.Now().Add(10 * time.Minute),
					Used:        false,
				})
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "mismatch-code",
				RedirectURI:  "https://app.example.com/callback",
				ClientID:     "wrong-client",
				ClientSecret: "super-secret",
			},
			wantErr:     true,
			errContains: "client_id mismatch",
		},
		{
			name: "redirect_uri mismatch",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
				authCodeRepo.Create(ctx, &domain.AuthCode{
					Code:        "redirect-code",
					ClientID:    "confidential-app",
					UserID:      "user-123",
					RedirectURI: "https://app.example.com/callback",
					Scope:       "openid",
					ExpiresAt:   time.Now().Add(10 * time.Minute),
					Used:        false,
				})
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "redirect-code",
				RedirectURI:  "https://wrong.example.com/callback",
				ClientID:     "confidential-app",
				ClientSecret: "super-secret",
			},
			wantErr:     true,
			errContains: "redirect_uri mismatch",
		},
		{
			name: "wrong client secret",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
				clientRepo.Create(ctx, &domain.Client{
					ID:           "confidential-app",
					Name:         "Confidential App",
					Secret:       "super-secret",
					Public:       false,
					RedirectURIs: []string{"https://app.example.com/callback"},
					Scopes:       []string{"openid", "profile"},
				})
				authCodeRepo.Create(ctx, &domain.AuthCode{
					Code:        "secret-code",
					ClientID:    "confidential-app",
					UserID:      "user-123",
					RedirectURI: "https://app.example.com/callback",
					Scope:       "openid profile",
					ExpiresAt:   time.Now().Add(10 * time.Minute),
					Used:        false,
				})
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "secret-code",
				RedirectURI:  "https://app.example.com/callback",
				ClientID:     "confidential-app",
				ClientSecret: "wrong-secret",
			},
			wantErr:     true,
			errContains: "invalid client credentials",
		},
		{
			name: "invalid PKCE verifier",
			setupFn: func(clientRepo *mockClientRepository, authCodeRepo *mockAuthCodeRepository, userRepo *mockUserRepository) {
				clientRepo.Create(ctx, &domain.Client{
					ID:           "public-app",
					Name:         "Public App",
					Public:       true,
					RedirectURIs: []string{"http://localhost:3000/callback"},
					Scopes:       []string{"openid", "profile"},
				})
				authCodeRepo.Create(ctx, &domain.AuthCode{
					Code:                "pkce-invalid-code",
					ClientID:            "public-app",
					UserID:              "user-123",
					RedirectURI:         "http://localhost:3000/callback",
					Scope:               "openid profile",
					CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
					CodeChallengeMethod: "S256",
					ExpiresAt:           time.Now().Add(10 * time.Minute),
					Used:                false,
				})
			},
			request: &TokenRequest{
				GrantType:    "authorization_code",
				Code:         "pkce-invalid-code",
				RedirectURI:  "http://localhost:3000/callback",
				ClientID:     "public-app",
				CodeVerifier: "wrong-verifier",
			},
			wantErr:     true,
			errContains: "invalid code_verifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh repositories for each test
			svc, clientRepo, authCodeRepo, _, userRepo := setupTokenService()
			if tt.setupFn != nil {
				tt.setupFn(clientRepo, authCodeRepo, userRepo)
			}

			response, err := svc.HandleAuthorizationCode(ctx, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("Error should contain '%s', got '%s'", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if response == nil {
					t.Error("Expected response, got nil")
					return
				}
				if response.AccessToken == "" {
					t.Error("AccessToken should not be empty")
				}
				if response.IDToken == "" {
					t.Error("IDToken should not be empty")
				}
				if response.TokenType != "Bearer" {
					t.Errorf("TokenType should be 'Bearer', got '%s'", response.TokenType)
				}
			}
		})
	}
}

func TestHandleRefreshToken(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name        string
		setupFn     func(*mockClientRepository, *mockTokenRepository, *mockUserRepository)
		request     *TokenRequest
		wantErr     bool
		errContains string
	}{
		{
			name: "valid refresh token",
			setupFn: func(clientRepo *mockClientRepository, tokenRepo *mockTokenRepository, userRepo *mockUserRepository) {
				clientRepo.Create(ctx, &domain.Client{
					ID:           "test-app",
					Name:         "Test App",
					Secret:       "test-secret",
					Public:       false,
					RedirectURIs: []string{"http://localhost:3000/callback"},
					Scopes:       []string{"openid", "profile", "offline_access"},
				})
				userRepo.Create(ctx, &domain.User{
					ID:          "user-123",
					Email:       "test@example.com",
					DisplayName: "Test User",
				})
				tokenRepo.Create(ctx, &domain.Token{
					ID:        "valid-refresh-token",
					UserID:    "user-123",
					ClientID:  "test-app",
					Scope:     "openid profile offline_access",
					ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
					Revoked:   false,
				})
			},
			request: &TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "valid-refresh-token",
				ClientID:     "test-app",
				ClientSecret: "test-secret",
			},
			wantErr: false,
		},
		{
			name: "missing refresh token",
			setupFn: func(clientRepo *mockClientRepository, tokenRepo *mockTokenRepository, userRepo *mockUserRepository) {
			},
			request: &TokenRequest{
				GrantType:    "refresh_token",
				ClientID:     "test-app",
				ClientSecret: "test-secret",
			},
			wantErr:     true,
			errContains: "refresh_token is required",
		},
		{
			name: "invalid refresh token",
			setupFn: func(clientRepo *mockClientRepository, tokenRepo *mockTokenRepository, userRepo *mockUserRepository) {
			},
			request: &TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "nonexistent-token",
				ClientID:     "test-app",
				ClientSecret: "test-secret",
			},
			wantErr:     true,
			errContains: "invalid refresh_token",
		},
		{
			name: "expired refresh token",
			setupFn: func(clientRepo *mockClientRepository, tokenRepo *mockTokenRepository, userRepo *mockUserRepository) {
				tokenRepo.Create(ctx, &domain.Token{
					ID:        "expired-refresh-token",
					UserID:    "user-123",
					ClientID:  "test-app",
					Scope:     "openid profile",
					ExpiresAt: time.Now().Add(-1 * time.Hour),
					Revoked:   false,
				})
			},
			request: &TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "expired-refresh-token",
				ClientID:     "test-app",
				ClientSecret: "test-secret",
			},
			wantErr:     true,
			errContains: "invalid or expired",
		},
		{
			name: "revoked refresh token",
			setupFn: func(clientRepo *mockClientRepository, tokenRepo *mockTokenRepository, userRepo *mockUserRepository) {
				tokenRepo.Create(ctx, &domain.Token{
					ID:        "revoked-refresh-token",
					UserID:    "user-123",
					ClientID:  "test-app",
					Scope:     "openid profile",
					ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
					Revoked:   true,
				})
			},
			request: &TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "revoked-refresh-token",
				ClientID:     "test-app",
				ClientSecret: "test-secret",
			},
			wantErr:     true,
			errContains: "invalid or expired",
		},
		{
			name: "wrong client_id",
			setupFn: func(clientRepo *mockClientRepository, tokenRepo *mockTokenRepository, userRepo *mockUserRepository) {
				tokenRepo.Create(ctx, &domain.Token{
					ID:        "mismatch-token",
					UserID:    "user-123",
					ClientID:  "correct-client",
					Scope:     "openid profile",
					ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
					Revoked:   false,
				})
			},
			request: &TokenRequest{
				GrantType:    "refresh_token",
				RefreshToken: "mismatch-token",
				ClientID:     "wrong-client",
				ClientSecret: "test-secret",
			},
			wantErr:     true,
			errContains: "client_id mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, clientRepo, _, tokenRepo, userRepo := setupTokenService()
			if tt.setupFn != nil {
				tt.setupFn(clientRepo, tokenRepo, userRepo)
			}

			response, err := svc.HandleRefreshToken(ctx, tt.request)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errContains != "" && !containsString(err.Error(), tt.errContains) {
					t.Errorf("Error should contain '%s', got '%s'", tt.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if response == nil {
					t.Error("Expected response, got nil")
					return
				}
				if response.AccessToken == "" {
					t.Error("AccessToken should not be empty")
				}
			}
		})
	}
}

func TestRefreshTokenRotation(t *testing.T) {
	svc, clientRepo, _, tokenRepo, userRepo := setupTokenService()

	ctx := context.Background()

	// Setup test data
	client := &domain.Client{
		ID:           "test-app",
		Name:         "Test App",
		Secret:       "test-secret",
		Public:       false,
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile", "offline_access"},
	}
	clientRepo.Create(ctx, client)

	testUser := &domain.User{
		ID:          "user-123",
		Email:       "test@example.com",
		DisplayName: "Test User",
	}
	userRepo.Create(ctx, testUser)

	// Create refresh token with offline_access scope
	originalToken := &domain.Token{
		ID:        "rotation-test-token",
		UserID:    "user-123",
		ClientID:  "test-app",
		Scope:     "openid profile offline_access",
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		Revoked:   false,
	}
	tokenRepo.Create(ctx, originalToken)

	// Use the refresh token
	request := &TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: "rotation-test-token",
		ClientID:     "test-app",
		ClientSecret: "test-secret",
	}

	response, err := svc.HandleRefreshToken(ctx, request)
	if err != nil {
		t.Fatalf("HandleRefreshToken failed: %v", err)
	}

	// Original token should be revoked
	oldToken, _ := tokenRepo.GetByID(ctx, "rotation-test-token")
	if oldToken != nil && !oldToken.Revoked {
		t.Error("Original refresh token should be revoked after use")
	}

	// New refresh token should be returned (because of offline_access scope)
	if response.RefreshToken == "" {
		t.Error("New refresh token should be returned")
	}

	// New token should be different
	if response.RefreshToken == "rotation-test-token" {
		t.Error("New refresh token should be different from old one")
	}
}
