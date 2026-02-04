package http

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tendant/simple-idp/internal/auth"
	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/domain"
	"github.com/tendant/simple-idp/internal/oidc"
	"github.com/tendant/simple-idp/internal/store/file"
)

// testEnv holds all the components needed for integration tests
type testEnv struct {
	server       *httptest.Server
	store        *file.Store
	authService  *auth.Service
	keyService   *crypto.KeyService
	testUser     *domain.User
	testClient   *domain.Client
	dataDir      string
	cookieSecret string
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()

	// Create temp data directory
	dataDir, err := os.MkdirTemp("", "idp-integration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}

	// Create file store
	store, err := file.NewStore(dataDir)
	if err != nil {
		os.RemoveAll(dataDir)
		t.Fatalf("Failed to create store: %v", err)
	}

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Create key repository and service
	keyRepo := file.NewKeyRepository(dataDir)
	keyService := crypto.NewKeyService(keyRepo)

	// Ensure we have an active signing key
	activeKey, err := keyService.EnsureActiveKey(ctx)
	if err != nil {
		store.Close()
		os.RemoveAll(dataDir)
		t.Fatalf("Failed to ensure active key: %v", err)
	}
	tokenGenerator := crypto.NewTokenGenerator(activeKey, "http://localhost:8080", "http://localhost:8080")

	// Create test user
	passwordHash, _ := auth.HashPassword("password123")
	testUser := &domain.User{
		ID:           "test-user-id",
		Email:        "test@example.com",
		PasswordHash: passwordHash,
		DisplayName:  "Test User",
		Active:       true,
	}
	if err := store.Users().Create(ctx, testUser); err != nil {
		store.Close()
		os.RemoveAll(dataDir)
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Create test client
	testClient := &domain.Client{
		ID:           "test-client",
		Name:         "Test Client",
		Secret:       "test-client-secret",
		Public:       false,
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
	}
	if err := store.Clients().Create(ctx, testClient); err != nil {
		store.Close()
		os.RemoveAll(dataDir)
		t.Fatalf("Failed to create test client: %v", err)
	}

	// Create public client for PKCE tests
	publicClient := &domain.Client{
		ID:           "public-client",
		Name:         "Public Client",
		Public:       true,
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile", "email"},
	}
	store.Clients().Create(ctx, publicClient)

	// Cookie secret
	cookieSecret := "test-cookie-secret-32-bytes-long!"

	// Create auth services
	sessionService := auth.NewSessionService(store.Sessions(), cookieSecret)
	csrfService := auth.NewCSRFService(cookieSecret, false, "")
	lockoutService := auth.NewLockoutService(5, 15*time.Minute)
	authService := auth.NewService(store.Users(), sessionService, csrfService,
		auth.WithLogger(logger),
		auth.WithLockout(lockoutService),
	)

	// Create OIDC services
	authorizeService := oidc.NewAuthorizeService(store.Clients(), store.AuthCodes(), 10*time.Minute)
	tokenService := oidc.NewTokenService(
		store.Clients(),
		store.AuthCodes(),
		store.Tokens(),
		store.Users(),
		tokenGenerator,
		"http://localhost:8080",
		15*time.Minute,
		7*24*time.Hour,
	)
	userInfoService := oidc.NewUserInfoService(store.Users(), tokenGenerator)

	// Create HTTP server
	server := NewServer(":0",
		WithLogger(logger),
		WithIssuerURL("http://localhost:8080"),
		WithKeyService(keyService),
		WithAuthService(authService),
		WithOIDCServices(authorizeService, tokenService, userInfoService),
	)

	// Start test server
	ts := httptest.NewServer(server.Router())

	return &testEnv{
		server:       ts,
		store:        store,
		authService:  authService,
		keyService:   keyService,
		testUser:     testUser,
		testClient:   testClient,
		dataDir:      dataDir,
		cookieSecret: cookieSecret,
	}
}

func (e *testEnv) cleanup() {
	e.server.Close()
	e.store.Close()
	os.RemoveAll(e.dataDir)
}

// Helper to create HTTP client with cookie jar
func newClientWithCookies() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

func TestIntegration_HealthEndpoints(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := &http.Client{}

	// Test /healthz
	resp, err := client.Get(env.server.URL + "/healthz")
	if err != nil {
		t.Fatalf("Failed to get /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for /healthz, got %d", resp.StatusCode)
	}

	// Test /readyz
	resp, err = client.Get(env.server.URL + "/readyz")
	if err != nil {
		t.Fatalf("Failed to get /readyz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 for /readyz, got %d", resp.StatusCode)
	}
}

func TestIntegration_OpenIDConfiguration(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := &http.Client{}
	resp, err := client.Get(env.server.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("Failed to get discovery: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var discovery OIDCDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		t.Fatalf("Failed to decode discovery: %v", err)
	}

	if discovery.Issuer != "http://localhost:8080" {
		t.Errorf("Expected issuer 'http://localhost:8080', got '%s'", discovery.Issuer)
	}
}

func TestIntegration_JWKS(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := &http.Client{}
	resp, err := client.Get(env.server.URL + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("Failed to get JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var jwks crypto.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatalf("Failed to decode JWKS: %v", err)
	}

	if len(jwks.Keys) == 0 {
		t.Error("JWKS should contain at least one key")
	}

	// Verify key structure
	key := jwks.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("Expected key type 'RSA', got '%s'", key.Kty)
	}
	if key.Use != "sig" {
		t.Errorf("Expected key use 'sig', got '%s'", key.Use)
	}
	if key.Alg != "RS256" {
		t.Errorf("Expected algorithm 'RS256', got '%s'", key.Alg)
	}
}

func TestIntegration_LoginPage(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := &http.Client{}
	resp, err := client.Get(env.server.URL + "/login")
	if err != nil {
		t.Fatalf("Failed to get login page: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check content type
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Expected Content-Type to contain 'text/html', got '%s'", ct)
	}
}

func TestIntegration_LoginWithInvalidCredentials(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := newClientWithCookies()

	// First get login page to get CSRF token
	resp, _ := client.Get(env.server.URL + "/login")
	resp.Body.Close()

	// Get CSRF token from cookie
	csrfToken := ""
	for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
		if cookie.Name == "idp_csrf" {
			csrfToken = cookie.Value
			break
		}
	}

	// Attempt login with invalid credentials
	form := url.Values{}
	form.Set("email", "wrong@example.com")
	form.Set("password", "wrongpassword")
	form.Set("csrf_token", csrfToken)

	resp, err := client.PostForm(env.server.URL+"/login", form)
	if err != nil {
		t.Fatalf("Failed to post login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for invalid credentials, got %d", resp.StatusCode)
	}
}

func TestIntegration_LoginAndLogout(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := newClientWithCookies()

	// Get login page to get CSRF token
	resp, _ := client.Get(env.server.URL + "/login")
	resp.Body.Close()

	// Get CSRF token from cookie
	csrfToken := ""
	for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
		if cookie.Name == "idp_csrf" {
			csrfToken = cookie.Value
			break
		}
	}

	// Login with valid credentials
	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "password123")
	form.Set("csrf_token", csrfToken)

	resp, err := client.PostForm(env.server.URL+"/login", form)
	if err != nil {
		t.Fatalf("Failed to post login: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected redirect after login, got status %d", resp.StatusCode)
	}

	// Verify session cookie is set
	hasSessionCookie := false
	for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
		if cookie.Name == "idp_session" {
			hasSessionCookie = true
			break
		}
	}
	if !hasSessionCookie {
		t.Error("Session cookie should be set after login")
	}

	// Logout
	resp, err = client.Get(env.server.URL + "/logout")
	if err != nil {
		t.Fatalf("Failed to logout: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected redirect after logout, got status %d", resp.StatusCode)
	}
}

func TestIntegration_AuthorizeWithoutAuth(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := newClientWithCookies()

	// Try to access authorize endpoint without being logged in
	authURL := env.server.URL + "/authorize?" + url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"state":         {"test-state"},
	}.Encode()

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to get authorize: %v", err)
	}
	defer resp.Body.Close()

	// Should redirect to login
	if resp.StatusCode != http.StatusFound {
		t.Errorf("Expected redirect to login, got status %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if !strings.HasPrefix(location, "/login") {
		t.Errorf("Expected redirect to /login, got '%s'", location)
	}
}

func TestIntegration_FullOIDCFlow_ConfidentialClient(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := newClientWithCookies()

	// Step 1: Get login page and CSRF token
	resp, _ := client.Get(env.server.URL + "/login")
	resp.Body.Close()

	csrfToken := ""
	for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
		if cookie.Name == "idp_csrf" {
			csrfToken = cookie.Value
			break
		}
	}

	// Step 2: Login
	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "password123")
	form.Set("csrf_token", csrfToken)

	resp, err := client.PostForm(env.server.URL+"/login", form)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	resp.Body.Close()

	// Step 3: Authorization request
	authURL := env.server.URL + "/authorize?" + url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile email"},
		"state":         {"test-state-123"},
	}.Encode()

	resp, err = client.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to get authorize: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected redirect with auth code, got status %d", resp.StatusCode)
	}

	// Step 4: Extract authorization code from redirect
	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	authCode := redirectURL.Query().Get("code")
	state := redirectURL.Query().Get("state")

	if authCode == "" {
		t.Fatal("Authorization code should not be empty")
	}
	if state != "test-state-123" {
		t.Errorf("State mismatch: expected 'test-state-123', got '%s'", state)
	}

	// Step 5: Exchange code for tokens
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", authCode)
	tokenForm.Set("redirect_uri", "http://localhost:3000/callback")
	tokenForm.Set("client_id", "test-client")
	tokenForm.Set("client_secret", "test-client-secret")

	resp, err = http.PostForm(env.server.URL+"/token", tokenForm)
	if err != nil {
		t.Fatalf("Failed to exchange token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 for token exchange, got %d", resp.StatusCode)
	}

	var tokenResponse oidc.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenResponse.AccessToken == "" {
		t.Error("Access token should not be empty")
	}
	if tokenResponse.IDToken == "" {
		t.Error("ID token should not be empty")
	}
	if tokenResponse.TokenType != "Bearer" {
		t.Errorf("Token type should be 'Bearer', got '%s'", tokenResponse.TokenType)
	}

	// Step 6: Use access token to get user info
	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to get userinfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 for userinfo, got %d", resp.StatusCode)
	}

	var userInfo oidc.UserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		t.Fatalf("Failed to decode userinfo: %v", err)
	}

	if userInfo.Sub != env.testUser.ID {
		t.Errorf("User ID mismatch: expected '%s', got '%s'", env.testUser.ID, userInfo.Sub)
	}
	if userInfo.Email != "test@example.com" {
		t.Errorf("Email mismatch: expected 'test@example.com', got '%s'", userInfo.Email)
	}
}

func TestIntegration_FullOIDCFlow_PublicClientWithPKCE(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := newClientWithCookies()

	// Step 1: Login
	resp, _ := client.Get(env.server.URL + "/login")
	resp.Body.Close()

	csrfToken := ""
	for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
		if cookie.Name == "idp_csrf" {
			csrfToken = cookie.Value
			break
		}
	}

	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "password123")
	form.Set("csrf_token", csrfToken)

	resp, _ = client.PostForm(env.server.URL+"/login", form)
	resp.Body.Close()

	// Step 2: Generate PKCE code verifier and challenge
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 test vector
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Step 3: Authorization request with PKCE
	authURL := env.server.URL + "/authorize?" + url.Values{
		"client_id":             {"public-client"},
		"redirect_uri":          {"http://localhost:3000/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"pkce-test-state"},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("Failed to get authorize: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected redirect with auth code, got status %d", resp.StatusCode)
	}

	// Step 4: Extract authorization code
	location := resp.Header.Get("Location")
	redirectURL, _ := url.Parse(location)
	authCode := redirectURL.Query().Get("code")

	if authCode == "" {
		t.Fatal("Authorization code should not be empty")
	}

	// Step 5: Exchange code for tokens with code_verifier
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", authCode)
	tokenForm.Set("redirect_uri", "http://localhost:3000/callback")
	tokenForm.Set("client_id", "public-client")
	tokenForm.Set("code_verifier", codeVerifier)

	resp, err = http.PostForm(env.server.URL+"/token", tokenForm)
	if err != nil {
		t.Fatalf("Failed to exchange token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected status 200 for token exchange, got %d", resp.StatusCode)
	}

	var tokenResponse oidc.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("Failed to decode token response: %v", err)
	}

	if tokenResponse.AccessToken == "" {
		t.Error("Access token should not be empty")
	}
	if tokenResponse.IDToken == "" {
		t.Error("ID token should not be empty")
	}
}

func TestIntegration_TokenEndpoint_InvalidGrant(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	// Try to exchange invalid code
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", "invalid-code")
	tokenForm.Set("redirect_uri", "http://localhost:3000/callback")
	tokenForm.Set("client_id", "test-client")
	tokenForm.Set("client_secret", "test-client-secret")

	resp, err := http.PostForm(env.server.URL+"/token", tokenForm)
	if err != nil {
		t.Fatalf("Failed to call token endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid code, got %d", resp.StatusCode)
	}

	var errResp map[string]string
	json.NewDecoder(resp.Body).Decode(&errResp)

	if errResp["error"] != "invalid_request" {
		t.Errorf("Expected error 'invalid_request', got '%s'", errResp["error"])
	}
}

func TestIntegration_TokenEndpoint_InvalidClientSecret(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	client := newClientWithCookies()

	// Login and get auth code
	resp, _ := client.Get(env.server.URL + "/login")
	resp.Body.Close()

	csrfToken := ""
	for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
		if cookie.Name == "idp_csrf" {
			csrfToken = cookie.Value
			break
		}
	}

	form := url.Values{}
	form.Set("email", "test@example.com")
	form.Set("password", "password123")
	form.Set("csrf_token", csrfToken)
	resp, _ = client.PostForm(env.server.URL+"/login", form)
	resp.Body.Close()

	authURL := env.server.URL + "/authorize?" + url.Values{
		"client_id":     {"test-client"},
		"redirect_uri":  {"http://localhost:3000/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"test"},
	}.Encode()

	resp, _ = client.Get(authURL)
	location := resp.Header.Get("Location")
	resp.Body.Close()

	redirectURL, _ := url.Parse(location)
	authCode := redirectURL.Query().Get("code")

	// Try to exchange with wrong secret
	tokenForm := url.Values{}
	tokenForm.Set("grant_type", "authorization_code")
	tokenForm.Set("code", authCode)
	tokenForm.Set("redirect_uri", "http://localhost:3000/callback")
	tokenForm.Set("client_id", "test-client")
	tokenForm.Set("client_secret", "wrong-secret")

	resp, _ = http.PostForm(env.server.URL+"/token", tokenForm)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for invalid client secret, got %d", resp.StatusCode)
	}
}

func TestIntegration_UserInfo_InvalidToken(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to call userinfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for invalid token, got %d", resp.StatusCode)
	}
}

func TestIntegration_UserInfo_MissingToken(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	req, _ := http.NewRequest(http.MethodGet, env.server.URL+"/userinfo", nil)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Failed to call userinfo: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for missing token, got %d", resp.StatusCode)
	}
}

func TestIntegration_AuthorizeErrors(t *testing.T) {
	env := setupTestEnv(t)
	defer env.cleanup()

	tests := []struct {
		name          string
		query         url.Values
		expectStatus  int
		expectInBody  string
	}{
		{
			name:         "missing client_id",
			query:        url.Values{"redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"openid"}},
			expectStatus: http.StatusBadRequest,
			expectInBody: "client_id",
		},
		{
			name:         "missing redirect_uri",
			query:        url.Values{"client_id": {"test-client"}, "response_type": {"code"}, "scope": {"openid"}},
			expectStatus: http.StatusBadRequest,
			expectInBody: "redirect_uri",
		},
		{
			name:         "invalid response_type",
			query:        url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"token"}, "scope": {"openid"}},
			expectStatus: http.StatusBadRequest,
			expectInBody: "response_type",
		},
		{
			name:         "missing openid scope",
			query:        url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"profile"}},
			expectStatus: http.StatusBadRequest,
			expectInBody: "openid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := http.Get(env.server.URL + "/authorize?" + tt.query.Encode())
			if err != nil {
				t.Fatalf("Failed to call authorize: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.expectStatus {
				t.Errorf("Expected status %d, got %d", tt.expectStatus, resp.StatusCode)
			}
		})
	}
}

func mustParseURL(rawURL string) *url.URL {
	u, _ := url.Parse(rawURL)
	return u
}
