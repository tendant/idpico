package oidc

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

// Mock implementations for testing
type mockClientRepository struct {
	clients map[string]*domain.Client
}

func newMockClientRepository() *mockClientRepository {
	return &mockClientRepository{
		clients: make(map[string]*domain.Client),
	}
}

func (m *mockClientRepository) Create(ctx context.Context, client *domain.Client) error {
	m.clients[client.ID] = client
	return nil
}

func (m *mockClientRepository) GetByID(ctx context.Context, id string) (*domain.Client, error) {
	client, ok := m.clients[id]
	if !ok {
		return nil, idperrors.NotFound("client", id)
	}
	return client, nil
}

func (m *mockClientRepository) Update(ctx context.Context, client *domain.Client) error {
	m.clients[client.ID] = client
	return nil
}

func (m *mockClientRepository) Delete(ctx context.Context, id string) error {
	delete(m.clients, id)
	return nil
}

func (m *mockClientRepository) List(ctx context.Context) ([]*domain.Client, error) {
	var clients []*domain.Client
	for _, c := range m.clients {
		clients = append(clients, c)
	}
	return clients, nil
}

type mockAuthCodeRepository struct {
	codes map[string]*domain.AuthCode
}

func newMockAuthCodeRepository() *mockAuthCodeRepository {
	return &mockAuthCodeRepository{
		codes: make(map[string]*domain.AuthCode),
	}
}

func (m *mockAuthCodeRepository) Create(ctx context.Context, code *domain.AuthCode) error {
	m.codes[code.Code] = code
	return nil
}

func (m *mockAuthCodeRepository) GetByCode(ctx context.Context, code string) (*domain.AuthCode, error) {
	authCode, ok := m.codes[code]
	if !ok {
		return nil, idperrors.NotFound("auth_code", code)
	}
	return authCode, nil
}

func (m *mockAuthCodeRepository) MarkUsed(ctx context.Context, code string) error {
	if authCode, ok := m.codes[code]; ok {
		authCode.Used = true
	}
	return nil
}

func (m *mockAuthCodeRepository) Delete(ctx context.Context, code string) error {
	delete(m.codes, code)
	return nil
}

func (m *mockAuthCodeRepository) DeleteExpired(ctx context.Context) error {
	return nil
}

func TestParseAuthorizeRequest(t *testing.T) {
	svc := NewAuthorizeService(newMockClientRepository(), newMockAuthCodeRepository(), 10*time.Minute)

	tests := []struct {
		name        string
		queryString string
		wantErr     bool
		errContains string
	}{
		{
			name:        "valid request",
			queryString: "client_id=test-app&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid%20profile",
			wantErr:     false,
		},
		{
			name:        "missing client_id",
			queryString: "redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid",
			wantErr:     true,
			errContains: "client_id is required",
		},
		{
			name:        "missing redirect_uri",
			queryString: "client_id=test-app&response_type=code&scope=openid",
			wantErr:     true,
			errContains: "redirect_uri is required",
		},
		{
			name:        "invalid response_type",
			queryString: "client_id=test-app&redirect_uri=http://localhost:3000/callback&response_type=token&scope=openid",
			wantErr:     true,
			errContains: "response_type must be 'code'",
		},
		{
			name:        "missing openid scope",
			queryString: "client_id=test-app&redirect_uri=http://localhost:3000/callback&response_type=code&scope=profile",
			wantErr:     true,
			errContains: "scope must contain 'openid'",
		},
		{
			name:        "with PKCE",
			queryString: "client_id=test-app&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/authorize?"+tt.queryString, nil)
			authReq, err := svc.ParseAuthorizeRequest(req)

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
				if authReq == nil {
					t.Error("Expected request, got nil")
				}
			}
		})
	}
}

func TestValidateClient(t *testing.T) {
	clientRepo := newMockClientRepository()
	authCodeRepo := newMockAuthCodeRepository()
	svc := NewAuthorizeService(clientRepo, authCodeRepo, 10*time.Minute)

	// Setup test clients
	publicClient := &domain.Client{
		ID:           "public-app",
		Name:         "Public App",
		Public:       true,
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile", "email"},
	}
	confidentialClient := &domain.Client{
		ID:           "confidential-app",
		Name:         "Confidential App",
		Secret:       "super-secret",
		Public:       false,
		RedirectURIs: []string{"https://app.example.com/callback"},
		Scopes:       []string{"openid", "profile"},
	}
	clientRepo.Create(context.Background(), publicClient)
	clientRepo.Create(context.Background(), confidentialClient)

	tests := []struct {
		name        string
		request     *AuthorizeRequest
		wantErr     bool
		errContains string
	}{
		{
			name: "valid public client with PKCE",
			request: &AuthorizeRequest{
				ClientID:            "public-app",
				RedirectURI:         "http://localhost:3000/callback",
				Scope:               "openid profile",
				CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
				CodeChallengeMethod: "S256",
			},
			wantErr: false,
		},
		{
			name: "public client without PKCE",
			request: &AuthorizeRequest{
				ClientID:    "public-app",
				RedirectURI: "http://localhost:3000/callback",
				Scope:       "openid",
			},
			wantErr:     true,
			errContains: "code_challenge is required for public clients",
		},
		{
			name: "public client with plain PKCE method",
			request: &AuthorizeRequest{
				ClientID:            "public-app",
				RedirectURI:         "http://localhost:3000/callback",
				Scope:               "openid",
				CodeChallenge:       "test-challenge",
				CodeChallengeMethod: "plain",
			},
			wantErr:     true,
			errContains: "public clients must use S256",
		},
		{
			name: "unknown client",
			request: &AuthorizeRequest{
				ClientID:    "unknown-app",
				RedirectURI: "http://localhost:3000/callback",
				Scope:       "openid",
			},
			wantErr:     true,
			errContains: "unknown client_id",
		},
		{
			name: "invalid redirect URI",
			request: &AuthorizeRequest{
				ClientID:            "public-app",
				RedirectURI:         "http://evil.com/callback",
				Scope:               "openid",
				CodeChallenge:       "test",
				CodeChallengeMethod: "S256",
			},
			wantErr:     true,
			errContains: "invalid redirect_uri",
		},
		{
			name: "scope not allowed",
			request: &AuthorizeRequest{
				ClientID:            "confidential-app",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "openid admin",
				CodeChallenge:       "test",
				CodeChallengeMethod: "S256",
			},
			wantErr:     true,
			errContains: "scope 'admin' not allowed",
		},
		{
			name: "confidential client without PKCE is OK",
			request: &AuthorizeRequest{
				ClientID:    "confidential-app",
				RedirectURI: "https://app.example.com/callback",
				Scope:       "openid profile",
			},
			wantErr: false,
		},
		{
			name: "invalid PKCE method",
			request: &AuthorizeRequest{
				ClientID:            "confidential-app",
				RedirectURI:         "https://app.example.com/callback",
				Scope:               "openid",
				CodeChallenge:       "test",
				CodeChallengeMethod: "invalid",
			},
			wantErr:     true,
			errContains: "code_challenge_method must be 'S256' or 'plain'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := svc.ValidateClient(context.Background(), tt.request)

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
				if client == nil {
					t.Error("Expected client, got nil")
				}
			}
		})
	}
}

func TestCreateAuthCode(t *testing.T) {
	clientRepo := newMockClientRepository()
	authCodeRepo := newMockAuthCodeRepository()
	svc := NewAuthorizeService(clientRepo, authCodeRepo, 10*time.Minute)

	req := &AuthorizeRequest{
		ClientID:            "test-app",
		RedirectURI:         "http://localhost:3000/callback",
		Scope:               "openid profile",
		State:               "test-state",
		Nonce:               "test-nonce",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}

	code, err := svc.CreateAuthCode(context.Background(), req, "user-123")
	if err != nil {
		t.Fatalf("CreateAuthCode failed: %v", err)
	}

	if code.Code == "" {
		t.Error("Code should not be empty")
	}
	if code.ClientID != req.ClientID {
		t.Errorf("ClientID mismatch: expected %s, got %s", req.ClientID, code.ClientID)
	}
	if code.UserID != "user-123" {
		t.Errorf("UserID mismatch: expected user-123, got %s", code.UserID)
	}
	if code.RedirectURI != req.RedirectURI {
		t.Errorf("RedirectURI mismatch: expected %s, got %s", req.RedirectURI, code.RedirectURI)
	}
	if code.Scope != req.Scope {
		t.Errorf("Scope mismatch: expected %s, got %s", req.Scope, code.Scope)
	}
	if code.CodeChallenge != req.CodeChallenge {
		t.Errorf("CodeChallenge mismatch")
	}
	if code.CodeChallengeMethod != req.CodeChallengeMethod {
		t.Errorf("CodeChallengeMethod mismatch")
	}
	if code.Nonce != req.Nonce {
		t.Errorf("Nonce mismatch")
	}
	if code.Used {
		t.Error("Code should not be marked as used")
	}
	if code.ExpiresAt.Before(time.Now()) {
		t.Error("Code should not be expired")
	}
}

func TestBuildAuthorizationResponse(t *testing.T) {
	svc := NewAuthorizeService(newMockClientRepository(), newMockAuthCodeRepository(), 10*time.Minute)

	tests := []struct {
		name        string
		redirectURI string
		code        string
		state       string
		wantContain []string
	}{
		{
			name:        "with state",
			redirectURI: "http://localhost:3000/callback",
			code:        "test-code-123",
			state:       "test-state",
			wantContain: []string{"code=test-code-123", "state=test-state"},
		},
		{
			name:        "without state",
			redirectURI: "http://localhost:3000/callback",
			code:        "test-code-123",
			state:       "",
			wantContain: []string{"code=test-code-123"},
		},
		{
			name:        "preserves existing query params",
			redirectURI: "http://localhost:3000/callback?existing=param",
			code:        "test-code",
			state:       "",
			wantContain: []string{"code=test-code", "existing=param"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := svc.BuildAuthorizationResponse(tt.redirectURI, tt.code, tt.state)

			for _, want := range tt.wantContain {
				if !containsString(result, want) {
					t.Errorf("Response should contain '%s', got '%s'", want, result)
				}
			}
		})
	}
}

func TestBuildErrorResponse(t *testing.T) {
	svc := NewAuthorizeService(newMockClientRepository(), newMockAuthCodeRepository(), 10*time.Minute)

	tests := []struct {
		name        string
		redirectURI string
		errorCode   string
		errorDesc   string
		state       string
		wantContain []string
	}{
		{
			name:        "full error",
			redirectURI: "http://localhost:3000/callback",
			errorCode:   "access_denied",
			errorDesc:   "User denied the request",
			state:       "test-state",
			wantContain: []string{"error=access_denied", "error_description=", "state=test-state"},
		},
		{
			name:        "without description",
			redirectURI: "http://localhost:3000/callback",
			errorCode:   "invalid_request",
			errorDesc:   "",
			state:       "",
			wantContain: []string{"error=invalid_request"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := svc.BuildErrorResponse(tt.redirectURI, tt.errorCode, tt.errorDesc, tt.state)

			for _, want := range tt.wantContain {
				if !containsString(result, want) {
					t.Errorf("Response should contain '%s', got '%s'", want, result)
				}
			}
		})
	}
}

func TestAuthCodeUniqueness(t *testing.T) {
	clientRepo := newMockClientRepository()
	authCodeRepo := newMockAuthCodeRepository()
	svc := NewAuthorizeService(clientRepo, authCodeRepo, 10*time.Minute)

	req := &AuthorizeRequest{
		ClientID:    "test-app",
		RedirectURI: "http://localhost:3000/callback",
		Scope:       "openid",
	}

	code1, _ := svc.CreateAuthCode(context.Background(), req, "user-1")
	code2, _ := svc.CreateAuthCode(context.Background(), req, "user-2")

	if code1.Code == code2.Code {
		t.Error("Auth codes should be unique")
	}
}

// Helper function
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
