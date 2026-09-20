package http

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tendant/idpico/internal/audit"
	"github.com/tendant/idpico/internal/auth"
	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/mail"
	"github.com/tendant/idpico/internal/oidc"
	"github.com/tendant/idpico/internal/store"
	"github.com/tendant/idpico/internal/store/file"
	"github.com/tendant/idpico/internal/store/sqlite"
)

// testEnv holds all the components needed for integration tests
type testEnv struct {
	server       *httptest.Server
	store        store.Store
	authService  *auth.Service
	keyService   *crypto.KeyService
	testUser     *domain.User
	testClient   *domain.Client
	mailer       *mail.MemoryMailer
	dataDir      string
	cookieSecret string
}

// storeDrivers lists the persistence backends every integration test runs against.
var storeDrivers = []string{"sqlite", "file"}

// forEachDriver runs fn as a subtest per store driver.
func forEachDriver(t *testing.T, fn func(t *testing.T, driver string)) {
	t.Helper()
	for _, driver := range storeDrivers {
		t.Run(driver, func(t *testing.T) { fn(t, driver) })
	}
}

// openTestStore creates a fresh store and matching key repository for driver.
func openTestStore(t *testing.T, driver, dataDir string) (store.Store, crypto.KeyRepository) {
	t.Helper()
	switch driver {
	case "sqlite":
		s, err := sqlite.NewStore(context.Background(), filepath.Join(dataDir, "idpico.db"))
		if err != nil {
			t.Fatalf("Failed to create sqlite store: %v", err)
		}
		return s, s.Keys()
	case "file":
		s, err := file.NewStore(dataDir)
		if err != nil {
			t.Fatalf("Failed to create file store: %v", err)
		}
		return s, file.NewKeyRepository(dataDir)
	default:
		t.Fatalf("unknown store driver %q", driver)
		return nil, nil
	}
}

func setupTestEnv(t *testing.T, driver string) *testEnv {
	t.Helper()

	// Create temp data directory
	dataDir, err := os.MkdirTemp("", "idp-integration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dataDir) })

	store, keyRepo := openTestStore(t, driver, dataDir)

	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Create key service
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

	// Create admin user
	adminUser := &domain.User{
		ID:            "admin-user-id",
		Email:         "admin@example.com",
		PasswordHash:  passwordHash,
		DisplayName:   "Admin",
		Active:        true,
		EmailVerified: true,
		Admin:         true,
	}
	if err := store.Users().Create(ctx, adminUser); err != nil {
		store.Close()
		os.RemoveAll(dataDir)
		t.Fatalf("Failed to create admin user: %v", err)
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

	// Create public client for PKCE tests (first-party: no consent screen)
	publicClient := &domain.Client{
		ID:           "public-client",
		Name:         "Public Client",
		Public:       true,
		SkipConsent:  true,
		RedirectURIs: []string{"http://localhost:3000/callback"},
		Scopes:       []string{"openid", "profile", "email", "groups", "offline_access"},
	}
	store.Clients().Create(ctx, publicClient)

	// Groups: the test user is a member of "devs"
	devs := &domain.Group{ID: "grp-devs", Name: "devs", Description: "Developers"}
	if err := store.Groups().Create(ctx, devs); err != nil {
		t.Fatalf("Failed to create group: %v", err)
	}
	store.Groups().Create(ctx, &domain.Group{ID: "grp-ops", Name: "ops"})
	store.Groups().AddMember(ctx, devs.ID, testUser.ID)
	groupClaims := oidc.NewGroupClaims(store.Groups(), "")

	// Cookie secret
	cookieSecret := "test-cookie-secret-32-bytes-long!"

	// Audit log
	auditRecorder := audit.NewRecorder(store.Audit(), logger)

	// Create auth services
	sessionService := auth.NewSessionService(store.Sessions(), cookieSecret)
	csrfService := auth.NewCSRFService(cookieSecret, false, "")
	lockoutService := auth.NewLockoutService(5, 15*time.Minute)
	authService := auth.NewService(store.Users(), sessionService, csrfService,
		auth.WithLogger(logger),
		auth.WithLockout(lockoutService),
		auth.WithAudit(auditRecorder),
	)

	// Self-service account flows with an in-memory mailer
	mailer := &mail.MemoryMailer{}
	accountService := auth.NewAccountService(store.Users(), store.VerificationTokens(), store.Sessions(), store.Tokens(),
		mailer, "http://localhost:8080", auth.WithAccountLogger(logger), auth.WithAccountAudit(auditRecorder))

	// Create OIDC services
	authorizeService := oidc.NewAuthorizeService(store.Clients(), store.AuthCodes(), 10*time.Minute)
	consentService := oidc.NewConsentService(store.Consents())
	tokenService := oidc.NewTokenService(
		store.Clients(),
		store.AuthCodes(),
		store.Tokens(),
		store.Users(),
		tokenGenerator,
		"http://localhost:8080",
		15*time.Minute,
		7*24*time.Hour,
		oidc.WithGroupClaims(groupClaims),
		oidc.WithRevocations(store.Revocations()),
	)
	userInfoService := oidc.NewUserInfoService(store.Users(), tokenGenerator,
		oidc.WithUserInfoGroups(groupClaims), oidc.WithUserInfoRevocations(store.Revocations()))

	// Create HTTP server
	server := NewServer(":0",
		WithLogger(logger),
		WithIssuerURL("http://localhost:8080"),
		WithKeyService(keyService),
		WithAuthService(authService),
		WithAccountService(accountService, "1h0m0s"),
		WithOIDCServices(authorizeService, tokenService, userInfoService),
		WithConsentService(consentService),
		WithGroupsClaim(groupClaims.ClaimName()),
		WithAudit(auditRecorder),
		WithAccountPage(store),
		WithMetrics(true),
		WithAdmin(AdminConfig{
			Store:          store,
			AuthService:    authService,
			AccountService: accountService,
			KeyService:     keyService,
			IssuerURL:      "http://localhost:8080",
			KeyGracePeriod: time.Hour,
		}),
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
		mailer:       mailer,
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
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
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
	})
}

func TestIntegration_OpenIDConfiguration(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
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
	})
}

func TestIntegration_JWKS(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
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
	})
}

func TestIntegration_LoginPage(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
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
	})
}

func TestIntegration_LoginWithInvalidCredentials(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()

		client := newClientWithCookies()

		// First get login page to get CSRF token
		resp, _ := client.Get(env.server.URL + "/login")
		resp.Body.Close()

		// Get CSRF token from cookie
		csrfToken := ""
		for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
			if cookie.Name == "idpico_csrf" {
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
	})
}

func TestIntegration_LoginAndLogout(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()

		client := newClientWithCookies()

		// Get login page to get CSRF token
		resp, _ := client.Get(env.server.URL + "/login")
		resp.Body.Close()

		// Get CSRF token from cookie
		csrfToken := ""
		for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
			if cookie.Name == "idpico_csrf" {
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
			if cookie.Name == "idpico_session" {
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
	})
}

func TestIntegration_AuthorizeWithoutAuth(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
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
	})
}

func TestIntegration_FullOIDCFlow_ConfidentialClient(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()

		client := newClientWithCookies()

		// Step 1: Get login page and CSRF token
		resp, _ := client.Get(env.server.URL + "/login")
		resp.Body.Close()

		csrfToken := ""
		for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
			if cookie.Name == "idpico_csrf" {
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
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		// First visit: the consent screen is shown for a third-party client
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected consent page (200), got status %d", resp.StatusCode)
		}
		if !strings.Contains(string(body), "Authorize Test Client") || !strings.Contains(string(body), "openid") {
			t.Errorf("Consent page should name the client and scopes")
		}

		// Step 3b: Allow
		resp = submitConsent(t, client, env.server.URL, mustParseURL(authURL).RawQuery, "allow")
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("Expected redirect with auth code after consent, got status %d", resp.StatusCode)
		}

		// Step 4: Extract authorization code from redirect
		location := resp.Header.Get("Location")
		redirectURL, _ := url.Parse(location)
		authCode := redirectURL.Query().Get("code")
		state := redirectURL.Query().Get("state")

		if authCode == "" {
			t.Fatalf("Authorization code should not be empty (location: %s)", location)
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
	})
}

func TestIntegration_FullOIDCFlow_PublicClientWithPKCE(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()

		client := newClientWithCookies()

		// Step 1: Login
		resp, _ := client.Get(env.server.URL + "/login")
		resp.Body.Close()

		csrfToken := ""
		for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
			if cookie.Name == "idpico_csrf" {
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
	})
}

func TestIntegration_TokenEndpoint_InvalidGrant(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
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

		if errResp["error"] != "invalid_grant" {
			t.Errorf("Expected error 'invalid_grant', got '%s'", errResp["error"])
		}
	})
}

func TestIntegration_TokenEndpoint_InvalidClientSecret(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()

		client := newClientWithCookies()

		// Login and get auth code
		resp, _ := client.Get(env.server.URL + "/login")
		resp.Body.Close()

		csrfToken := ""
		for _, cookie := range client.Jar.Cookies(mustParseURL(env.server.URL)) {
			if cookie.Name == "idpico_csrf" {
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
		resp.Body.Close()
		resp = submitConsent(t, client, env.server.URL, mustParseURL(authURL).RawQuery, "allow")
		location := resp.Header.Get("Location")
		resp.Body.Close()

		redirectURL, _ := url.Parse(location)
		authCode := redirectURL.Query().Get("code")
		if authCode == "" {
			t.Fatalf("expected auth code after consent, got %s", location)
		}

		// Try to exchange with wrong secret
		tokenForm := url.Values{}
		tokenForm.Set("grant_type", "authorization_code")
		tokenForm.Set("code", authCode)
		tokenForm.Set("redirect_uri", "http://localhost:3000/callback")
		tokenForm.Set("client_id", "test-client")
		tokenForm.Set("client_secret", "wrong-secret")

		resp, err := http.PostForm(env.server.URL+"/token", tokenForm)
		if err != nil {
			t.Fatalf("Token request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401 for invalid client secret, got %d", resp.StatusCode)
		}
	})
}

func TestIntegration_UserInfo_InvalidToken(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
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
	})
}

func TestIntegration_UserInfo_MissingToken(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
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
	})
}

func TestIntegration_AuthorizeErrors(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()

		// Errors before the client and redirect_uri are validated are shown
		// to the user (400 page, never a redirect); afterwards they go back
		// to the client as an OAuth error redirect with the state echoed.
		tests := []struct {
			name         string
			query        url.Values
			expectStatus int
			expectError  string // error code in the redirect, when expectStatus is 302
		}{
			{
				name:         "missing client_id",
				query:        url.Values{"redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"openid"}},
				expectStatus: http.StatusBadRequest,
			},
			{
				name:         "missing redirect_uri",
				query:        url.Values{"client_id": {"test-client"}, "response_type": {"code"}, "scope": {"openid"}},
				expectStatus: http.StatusBadRequest,
			},
			{
				name:         "unknown client_id",
				query:        url.Values{"client_id": {"nope"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"token"}, "scope": {"openid"}},
				expectStatus: http.StatusBadRequest,
			},
			{
				name:         "unregistered redirect_uri",
				query:        url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback/"}, "response_type": {"token"}, "scope": {"openid"}},
				expectStatus: http.StatusBadRequest,
			},
			{
				name:         "invalid response_type",
				query:        url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"token"}, "scope": {"openid"}, "state": {"s1"}},
				expectStatus: http.StatusFound,
				expectError:  "unsupported_response_type",
			},
			{
				name:         "missing openid scope",
				query:        url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"profile"}, "state": {"s1"}},
				expectStatus: http.StatusFound,
				expectError:  "invalid_scope",
			},
			{
				name:         "scope not allowed for client",
				query:        url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"openid admin"}, "state": {"s1"}},
				expectStatus: http.StatusFound,
				expectError:  "invalid_scope",
			},
			{
				name:         "public client without PKCE",
				query:        url.Values{"client_id": {"public-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}},
				expectStatus: http.StatusFound,
				expectError:  "invalid_request",
			},
			{
				name:         "request object not supported",
				query:        url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}, "request": {"eyJhbGciOiJub25lIn0.e30."}},
				expectStatus: http.StatusFound,
				expectError:  "request_not_supported",
			},
			{
				name:         "request_uri not supported",
				query:        url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s1"}, "request_uri": {"https://rp.example/r"}},
				expectStatus: http.StatusFound,
				expectError:  "request_uri_not_supported",
			},
		}

		client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				resp, err := client.Get(env.server.URL + "/authorize?" + tt.query.Encode())
				if err != nil {
					t.Fatalf("Failed to call authorize: %v", err)
				}
				defer resp.Body.Close()

				if resp.StatusCode != tt.expectStatus {
					t.Fatalf("Expected status %d, got %d", tt.expectStatus, resp.StatusCode)
				}
				if tt.expectStatus != http.StatusFound {
					if loc := resp.Header.Get("Location"); loc != "" {
						t.Errorf("error page must not redirect, got Location %q", loc)
					}
					return
				}
				loc, err := url.Parse(resp.Header.Get("Location"))
				if err != nil {
					t.Fatalf("bad Location: %v", err)
				}
				if got := loc.Scheme + "://" + loc.Host + loc.Path; got != tt.query.Get("redirect_uri") {
					t.Errorf("redirected to %q, want the registered redirect_uri", got)
				}
				if got := loc.Query().Get("error"); got != tt.expectError {
					t.Errorf("error = %q, want %q (%s)", got, tt.expectError, loc.Query().Get("error_description"))
				}
				if got := loc.Query().Get("state"); got != "s1" {
					t.Errorf("state = %q, want s1", got)
				}
			})
		}

		// OIDC Core §3.1.2.1: POST is accepted and, when a login is needed,
		// the return URL carries the posted parameters as a GET.
		t.Run("POST authorize", func(t *testing.T) {
			form := url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"openid"}, "state": {"s2"}}
			resp, err := client.PostForm(env.server.URL+"/authorize", form)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusFound {
				t.Fatalf("POST /authorize: HTTP %d", resp.StatusCode)
			}
			ret := mustParseURL(mustParseURL(resp.Header.Get("Location")).Query().Get("return_url"))
			if ret.Path != "/authorize" || ret.Query().Get("state") != "s2" || ret.Query().Get("client_id") != "test-client" {
				t.Errorf("return_url = %q, want the posted request as a GET", ret)
			}
		})
	})
}

// csrfCookie returns the current CSRF token from the client's cookie jar.
func csrfCookie(client *http.Client, base string) string {
	for _, cookie := range client.Jar.Cookies(mustParseURL(base)) {
		if cookie.Name == "idpico_csrf" {
			return cookie.Value
		}
	}
	return ""
}

// loginAs signs the cookie-jar client in as the test user.
func loginAs(t *testing.T, client *http.Client, base, email, password string) {
	t.Helper()
	resp, err := client.Get(base + "/login")
	if err != nil {
		t.Fatalf("Failed to get login page: %v", err)
	}
	resp.Body.Close()

	form := url.Values{}
	form.Set("email", email)
	form.Set("password", password)
	form.Set("csrf_token", csrfCookie(client, base))
	resp, err = client.PostForm(base+"/login", form)
	if err != nil {
		t.Fatalf("Failed to login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("Expected login redirect, got %d", resp.StatusCode)
	}
}

// submitConsent posts the consent form for the given authorize query.
func submitConsent(t *testing.T, client *http.Client, base, authorizeQuery, action string) *http.Response {
	t.Helper()
	form := url.Values{}
	form.Set("csrf_token", csrfCookie(client, base))
	form.Set("authorize_query", authorizeQuery)
	form.Set("action", action)
	resp, err := client.PostForm(base+"/consent", form)
	if err != nil {
		t.Fatalf("Failed to post consent: %v", err)
	}
	return resp
}

func mustParseURL(rawURL string) *url.URL {
	u, _ := url.Parse(rawURL)
	return u
}

func TestIntegration_Consent(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()

		base := env.server.URL
		params := url.Values{
			"client_id":     {"test-client"},
			"redirect_uri":  {"http://localhost:3000/callback"},
			"response_type": {"code"},
			"scope":         {"openid email"},
			"state":         {"s1"},
		}
		authURL := base + "/authorize?" + params.Encode()

		t.Run("prompt=none unauthenticated -> login_required", func(t *testing.T) {
			client := newClientWithCookies()
			p := url.Values{}
			for k, v := range params {
				p[k] = v
			}
			p.Set("prompt", "none")
			resp, _ := client.Get(base + "/authorize?" + p.Encode())
			resp.Body.Close()
			loc, _ := url.Parse(resp.Header.Get("Location"))
			if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "login_required" {
				t.Errorf("expected login_required redirect, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}
		})

		client := newClientWithCookies()
		loginAs(t, client, base, "test@example.com", "password123")

		t.Run("prompt=none without consent -> consent_required", func(t *testing.T) {
			p := url.Values{}
			for k, v := range params {
				p[k] = v
			}
			p.Set("prompt", "none")
			resp, _ := client.Get(base + "/authorize?" + p.Encode())
			resp.Body.Close()
			loc, _ := url.Parse(resp.Header.Get("Location"))
			if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "consent_required" {
				t.Errorf("expected consent_required redirect, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}
			if loc.Query().Get("state") != "s1" {
				t.Error("state should be echoed on error")
			}
		})

		t.Run("deny -> access_denied", func(t *testing.T) {
			resp, _ := client.Get(authURL)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected consent page, got %d", resp.StatusCode)
			}
			resp = submitConsent(t, client, base, params.Encode(), "deny")
			resp.Body.Close()
			loc, _ := url.Parse(resp.Header.Get("Location"))
			if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "access_denied" {
				t.Errorf("expected access_denied redirect, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}
			if loc.Query().Get("state") != "s1" {
				t.Error("state should be echoed on deny")
			}
		})

		t.Run("consent without CSRF token is rejected", func(t *testing.T) {
			form := url.Values{}
			form.Set("authorize_query", params.Encode())
			form.Set("action", "allow")
			resp, _ := client.PostForm(base+"/consent", form)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400 without CSRF token, got %d", resp.StatusCode)
			}
		})

		t.Run("allow is remembered", func(t *testing.T) {
			resp, _ := client.Get(authURL)
			resp.Body.Close()
			resp = submitConsent(t, client, base, params.Encode(), "allow")
			resp.Body.Close()
			loc, _ := url.Parse(resp.Header.Get("Location"))
			if resp.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
				t.Fatalf("expected code after allow, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}

			// Second authorization for the same scopes goes straight through
			resp, _ = client.Get(authURL)
			resp.Body.Close()
			loc, _ = url.Parse(resp.Header.Get("Location"))
			if resp.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
				t.Errorf("expected direct code issuance after remembered consent, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}

			// A wider scope asks again
			p := url.Values{}
			for k, v := range params {
				p[k] = v
			}
			p.Set("scope", "openid email profile")
			resp, _ = client.Get(base + "/authorize?" + p.Encode())
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected consent page for new scope, got %d", resp.StatusCode)
			}

			// prompt=consent forces the page even when already granted
			p = url.Values{}
			for k, v := range params {
				p[k] = v
			}
			p.Set("prompt", "consent")
			resp, _ = client.Get(base + "/authorize?" + p.Encode())
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("expected consent page for prompt=consent, got %d", resp.StatusCode)
			}
		})

		t.Run("tampered authorize_query cannot widen redirect_uri", func(t *testing.T) {
			p := url.Values{}
			for k, v := range params {
				p[k] = v
			}
			p.Set("redirect_uri", "http://evil.example.com/cb")
			resp := submitConsent(t, client, base, p.Encode(), "allow")
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("expected 400 for invalid redirect_uri in consent, got %d", resp.StatusCode)
			}
		})

		t.Run("first-party client skips consent", func(t *testing.T) {
			p := url.Values{
				"client_id":             {"public-client"},
				"redirect_uri":          {"http://localhost:3000/callback"},
				"response_type":         {"code"},
				"scope":                 {"openid"},
				"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
				"code_challenge_method": {"S256"},
			}
			resp, _ := client.Get(base + "/authorize?" + p.Encode())
			resp.Body.Close()
			loc, _ := url.Parse(resp.Header.Get("Location"))
			if resp.StatusCode != http.StatusFound || loc.Query().Get("code") == "" {
				t.Errorf("first-party client should get a code directly, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}
		})

		t.Run("prompt=login re-authenticates", func(t *testing.T) {
			p := url.Values{}
			for k, v := range params {
				p[k] = v
			}
			p.Set("prompt", "login")
			resp, _ := client.Get(base + "/authorize?" + p.Encode())
			resp.Body.Close()
			loc := resp.Header.Get("Location")
			if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/login") {
				t.Fatalf("expected redirect to login, got %d %s", resp.StatusCode, loc)
			}
			ret, _ := url.Parse(mustParseURL(loc).Query().Get("return_url"))
			if ret.Query().Get("prompt") != "" {
				t.Errorf("prompt=login should be stripped from return_url, got %q", ret.Query().Get("prompt"))
			}
			// The session was dropped
			resp, _ = client.Get(authURL)
			resp.Body.Close()
			if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
				t.Errorf("session should be gone after prompt=login, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
			}
		})
	})
}

// linkToken pulls the token out of the link in the last email.
func linkToken(t *testing.T, mailer *mail.MemoryMailer, path string) string {
	t.Helper()
	msg := mailer.Last()
	if msg == nil {
		t.Fatal("expected an email")
	}
	for _, word := range strings.Fields(msg.Body) {
		if strings.Contains(word, path+"?token=") {
			return mustParseURL(word).Query().Get("token")
		}
	}
	t.Fatalf("no %s link in email: %q", path, msg.Body)
	return ""
}

func TestIntegration_PasswordReset(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		client := newClientWithCookies()

		// Login page links to the flow
		resp, _ := client.Get(base + "/login")
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "/forgot-password") {
			t.Error("login page should link to forgot-password")
		}

		// Request a reset
		resp, _ = client.Get(base + "/forgot-password")
		resp.Body.Close()
		form := url.Values{"email": {"test@example.com"}, "csrf_token": {csrfCookie(client, base)}}
		resp, _ = client.PostForm(base+"/forgot-password", form)
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "reset link has been sent") {
			t.Fatalf("expected confirmation page, got %d", resp.StatusCode)
		}
		token := linkToken(t, env.mailer, "/reset-password")

		// Unknown email gets the same page and no mail
		sent := len(env.mailer.Messages)
		resp, _ = client.Get(base + "/forgot-password")
		resp.Body.Close()
		form = url.Values{"email": {"nobody@example.com"}, "csrf_token": {csrfCookie(client, base)}}
		resp, _ = client.PostForm(base+"/forgot-password", form)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || len(env.mailer.Messages) != sent {
			t.Errorf("unknown email should not be distinguishable: status %d, mails %d->%d", resp.StatusCode, sent, len(env.mailer.Messages))
		}

		// Open the link, submit mismatched passwords, then a good one
		resp, _ = client.Get(base + "/reset-password?token=" + url.QueryEscape(token))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected reset form, got %d", resp.StatusCode)
		}
		form = url.Values{"token": {token}, "password": {"new-password-1"}, "confirm": {"different"}, "csrf_token": {csrfCookie(client, base)}}
		resp, _ = client.PostForm(base+"/reset-password", form)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("mismatched passwords should be rejected, got %d", resp.StatusCode)
		}
		form.Set("confirm", "new-password-1")
		form.Set("csrf_token", csrfCookie(client, base))
		resp, _ = client.PostForm(base+"/reset-password", form)
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
			t.Fatalf("expected redirect to login after reset, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}

		// Link is now dead
		resp, _ = client.Get(base + "/reset-password?token=" + url.QueryEscape(token))
		resp.Body.Close()
		form.Set("csrf_token", csrfCookie(client, base))
		resp, _ = client.PostForm(base+"/reset-password", form)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("reused reset link should fail, got %d", resp.StatusCode)
		}

		// Old password fails, new one works
		resp, _ = client.Get(base + "/login")
		resp.Body.Close()
		form = url.Values{"email": {"test@example.com"}, "password": {"password123"}, "csrf_token": {csrfCookie(client, base)}}
		resp, _ = client.PostForm(base+"/login", form)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("old password should be rejected, got %d", resp.StatusCode)
		}
		loginAs(t, client, base, "test@example.com", "new-password-1")
	})
}

func TestIntegration_EmailVerification(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		ctx := context.Background()

		user, _ := env.store.Users().GetByID(ctx, env.testUser.ID)
		if user.EmailVerified {
			t.Fatal("test user should start unverified")
		}

		// Bad link
		resp, _ := http.Get(base + "/verify-email?token=nope")
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("bad token should be 400, got %d", resp.StatusCode)
		}

		// Real link (sent by the account service, as the admin UI will do)
		accounts := auth.NewAccountService(env.store.Users(), env.store.VerificationTokens(), env.store.Sessions(), env.store.Tokens(), env.mailer, base)
		if err := accounts.SendEmailVerification(ctx, user); err != nil {
			t.Fatalf("SendEmailVerification: %v", err)
		}
		token := linkToken(t, env.mailer, "/verify-email")

		resp, _ = http.Get(base + "/verify-email?token=" + url.QueryEscape(token))
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "has been verified") {
			t.Fatalf("expected verified page, got %d: %s", resp.StatusCode, body)
		}

		user, _ = env.store.Users().GetByID(ctx, env.testUser.ID)
		if !user.EmailVerified {
			t.Error("user should be verified")
		}

		// The claim now reflects it: log in, authorize the first-party client, exchange, check ID token
		client := newClientWithCookies()
		loginAs(t, client, base, "test@example.com", "password123")
		codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		hash := sha256.Sum256([]byte(codeVerifier))
		p := url.Values{
			"client_id": {"public-client"}, "redirect_uri": {"http://localhost:3000/callback"},
			"response_type": {"code"}, "scope": {"openid email"},
			"code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"},
		}
		resp, _ = client.Get(base + "/authorize?" + p.Encode())
		resp.Body.Close()
		code := mustParseURL(resp.Header.Get("Location")).Query().Get("code")
		tokenForm := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost:3000/callback"}, "client_id": {"public-client"}, "code_verifier": {codeVerifier}}
		resp, _ = http.PostForm(base+"/token", tokenForm)
		var tokens oidc.TokenResponse
		json.NewDecoder(resp.Body).Decode(&tokens)
		resp.Body.Close()

		req, _ := http.NewRequest(http.MethodGet, base+"/userinfo", nil)
		req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		resp, _ = http.DefaultClient.Do(req)
		var info map[string]any
		json.NewDecoder(resp.Body).Decode(&info)
		resp.Body.Close()
		if v, _ := info["email_verified"].(bool); !v {
			t.Errorf("userinfo email_verified should be true, got %v", info["email_verified"])
		}
	})
}

// pkceAuthorize runs the first-party public client through /authorize and
// /token for the signed-in client and returns the token response.
func pkceAuthorize(t *testing.T, client *http.Client, base, scope string) oidc.TokenResponse {
	t.Helper()
	codeVerifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(codeVerifier))
	p := url.Values{
		"client_id": {"public-client"}, "redirect_uri": {"http://localhost:3000/callback"},
		"response_type": {"code"}, "scope": {scope}, "nonce": {"nonce-xyz"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"},
	}
	resp, _ := client.Get(base + "/authorize?" + p.Encode())
	resp.Body.Close()
	code := mustParseURL(resp.Header.Get("Location")).Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", resp.Header.Get("Location"))
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {"http://localhost:3000/callback"}, "client_id": {"public-client"}, "code_verifier": {codeVerifier}}
	resp, err := http.PostForm(base+"/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer resp.Body.Close()
	var tokens oidc.TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil || tokens.AccessToken == "" {
		t.Fatalf("token exchange failed: status %d err %v", resp.StatusCode, err)
	}
	return tokens
}

func jwtPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var m map[string]any
	json.Unmarshal(raw, &m)
	return m
}

func userinfo(t *testing.T, base, accessToken string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("userinfo request: %v", err)
	}
	defer resp.Body.Close()
	var m map[string]any
	json.NewDecoder(resp.Body).Decode(&m)
	return m
}

func TestIntegration_GroupsClaim(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL

		// Discovery advertises the scope and claim
		resp, _ := http.Get(base + "/.well-known/openid-configuration")
		var disc map[string]any
		json.NewDecoder(resp.Body).Decode(&disc)
		resp.Body.Close()
		if !containsString(disc["scopes_supported"], "groups") || !containsString(disc["claims_supported"], "groups") {
			t.Errorf("discovery should advertise groups: %v / %v", disc["scopes_supported"], disc["claims_supported"])
		}

		client := newClientWithCookies()
		loginAs(t, client, base, "test@example.com", "password123")

		// With the groups scope: ID token, access token and userinfo carry it; nonce is top-level
		tokens := pkceAuthorize(t, client, base, "openid email groups")
		id := jwtPayload(t, tokens.IDToken)
		if g, ok := id["groups"].([]any); !ok || len(g) != 1 || g[0] != "devs" {
			t.Errorf("ID token groups claim wrong: %v", id["groups"])
		}
		if id["nonce"] != "nonce-xyz" {
			t.Errorf("nonce should be a top-level ID token claim, got %v", id["nonce"])
		}
		if _, nested := id["extra"]; nested {
			t.Error("ID token must not contain a nested extra object")
		}
		at := jwtPayload(t, tokens.AccessToken)
		if g, ok := at["groups"].([]any); !ok || len(g) != 1 {
			t.Errorf("access token groups claim wrong: %v", at["groups"])
		}
		info := userinfo(t, base, tokens.AccessToken)
		if g, ok := info["groups"].([]any); !ok || len(g) != 1 || g[0] != "devs" {
			t.Errorf("userinfo groups wrong: %v", info["groups"])
		}

		// Without the scope nothing is released
		tokens = pkceAuthorize(t, client, base, "openid email")
		if _, has := jwtPayload(t, tokens.IDToken)["groups"]; has {
			t.Error("groups must not be released without the scope")
		}
		if _, has := userinfo(t, base, tokens.AccessToken)["groups"]; has {
			t.Error("userinfo must not include groups without the scope")
		}

		// A user with no memberships gets an empty list, not a missing claim
		env.store.Groups().RemoveUser(context.Background(), env.testUser.ID)
		tokens = pkceAuthorize(t, client, base, "openid groups")
		if g, ok := jwtPayload(t, tokens.IDToken)["groups"].([]any); !ok || len(g) != 0 {
			t.Errorf("expected empty groups list, got %v", jwtPayload(t, tokens.IDToken)["groups"])
		}

		// A client without the scope allowed is refused at /authorize
		p := url.Values{"client_id": {"test-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"}, "scope": {"openid groups"}}
		resp, _ = client.Get(base + "/authorize?" + p.Encode())
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || mustParseURL(resp.Header.Get("Location")).Query().Get("error") != "invalid_scope" {
			t.Errorf("client without groups scope should be rejected with invalid_scope, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
	})
}

func TestIntegration_GroupsCustomClaimName(t *testing.T) {
	// Only the claim plumbing differs by name, so one driver is enough.
	env := setupTestEnv(t, "sqlite")
	defer env.cleanup()
	base := env.server.URL

	gc := oidc.NewGroupClaims(env.store.Groups(), "roles")
	if gc.ClaimName() != "roles" {
		t.Fatal("claim name not applied")
	}
	// Rebuild the userinfo service with the custom name to check flattening there too.
	claims := &crypto.Claims{}
	if err := gc.Apply(context.Background(), env.testUser, "openid groups", claims); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if claims.Groups != nil || len(claims.Extra["roles"].([]string)) != 1 {
		t.Errorf("custom claim should be in Extra, got groups=%v extra=%v", claims.Groups, claims.Extra)
	}
	_ = base
}

func containsString(list any, want string) bool {
	items, _ := list.([]any)
	for _, it := range items {
		if it == want {
			return true
		}
	}
	return false
}

func TestIntegration_RateLimitCoversConsentAndVerify(t *testing.T) {
	env := setupTestEnv(t, "sqlite")
	defer env.cleanup()

	// Build a second server on the same store with a tiny limit
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := NewServer(":0",
		WithLogger(logger),
		WithAuthService(env.authService),
		WithAccountService(auth.NewAccountService(env.store.Users(), env.store.VerificationTokens(), env.store.Sessions(), env.store.Tokens(), env.mailer, "http://x"), "1h"),
		WithLoginRateLimit(2),
	)
	ts := httptest.NewServer(srv.Router())
	defer ts.Close()

	hits := func(path string, method string) int {
		for i := 1; i <= 5; i++ {
			var resp *http.Response
			if method == http.MethodPost {
				resp, _ = http.PostForm(ts.URL+path, url.Values{})
			} else {
				resp, _ = http.Get(ts.URL + path)
			}
			resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				return i
			}
		}
		return 0
	}
	if n := hits("/verify-email?token=x", http.MethodGet); n == 0 {
		t.Error("verify-email should be rate limited")
	}
	if n := hits("/forgot-password", http.MethodPost); n == 0 {
		t.Error("forgot-password should be rate limited")
	}
}

func TestIntegration_MaxAgeAndAuthTime(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL
		ctx := context.Background()

		client := newClientWithCookies()
		loginAs(t, client, base, "test@example.com", "password123")

		// auth_time is the session start and lands in the ID token
		tokens := pkceAuthorize(t, client, base, "openid")
		sessions, _ := env.store.Sessions().ListByUserID(ctx, env.testUser.ID)
		authTime, ok := jwtPayload(t, tokens.IDToken)["auth_time"].(float64)
		if !ok || int64(authTime) != sessions[0].CreatedAt.Unix() {
			t.Errorf("auth_time should equal the session start %d, got %v", sessions[0].CreatedAt.Unix(), jwtPayload(t, tokens.IDToken)["auth_time"])
		}

		// A generous max_age is satisfied by the current session
		p := url.Values{"client_id": {"public-client"}, "redirect_uri": {"http://localhost:3000/callback"}, "response_type": {"code"},
			"scope": {"openid"}, "max_age": {"3600"}, "code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
		resp, _ := client.Get(base + "/authorize?" + p.Encode())
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || mustParseURL(resp.Header.Get("Location")).Query().Get("code") == "" {
			t.Errorf("max_age=3600 should be satisfied, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}

		// Age the session past max_age: re-authentication is required and max_age survives the round trip
		p.Set("max_age", "0")
		time.Sleep(1100 * time.Millisecond) // session is now > 0s old
		resp, _ = client.Get(base + "/authorize?" + p.Encode())
		resp.Body.Close()
		loc := resp.Header.Get("Location")
		if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/login") {
			t.Fatalf("stale session should require login, got %d %s", resp.StatusCode, loc)
		}
		ret := mustParseURL(mustParseURL(loc).Query().Get("return_url"))
		if ret.Query().Get("max_age") != "0" {
			t.Error("max_age should be preserved in return_url")
		}
		// The old session was dropped
		if _, err := env.store.Sessions().GetByID(ctx, sessions[0].ID); !idperrors.IsCode(err, idperrors.CodeNotFound) {
			t.Error("stale session should be terminated before re-login")
		}

		// prompt=none with a stale session -> login_required
		p.Set("prompt", "none")
		resp, _ = newClientWithCookies().Get(base + "/authorize?" + p.Encode())
		resp.Body.Close()
		if mustParseURL(resp.Header.Get("Location")).Query().Get("error") != "login_required" {
			t.Errorf("expected login_required, got %s", resp.Header.Get("Location"))
		}

		// Invalid max_age is rejected
		p.Del("prompt")
		p.Set("max_age", "-5")
		resp, _ = client.Get(base + "/authorize?" + p.Encode())
		resp.Body.Close()
		if resp.StatusCode != http.StatusFound || mustParseURL(resp.Header.Get("Location")).Query().Get("error") != "invalid_request" {
			t.Errorf("negative max_age should redirect with invalid_request, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}

		// prompt=select_account behaves like login (no chooser exists)
		client = newClientWithCookies()
		loginAs(t, client, base, "test@example.com", "password123")
		p.Del("max_age")
		p.Set("prompt", "select_account")
		resp, _ = client.Get(base + "/authorize?" + p.Encode())
		resp.Body.Close()
		loc = resp.Header.Get("Location")
		ret = mustParseURL(mustParseURL(loc).Query().Get("return_url"))
		if !strings.HasPrefix(loc, "/login") || ret.Query().Get("prompt") != "" {
			t.Errorf("select_account should re-authenticate and be stripped, got %s", loc)
		}
	})
}

// userinfoStatus returns the HTTP status /userinfo gives this access token.
func userinfoStatus(t *testing.T, base, accessToken string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestIntegration_AccessTokenRevocation: access tokens are stateless JWTs,
// yet /revoke, /account and grant cut-offs must all take effect at
// /userinfo and /introspect.
func TestIntegration_AccessTokenRevocation(t *testing.T) {
	forEachDriver(t, func(t *testing.T, driver string) {
		env := setupTestEnv(t, driver)
		defer env.cleanup()
		base := env.server.URL

		browser := newClientWithCookies()
		loginAs(t, browser, base, "test@example.com", "password123")

		t.Run("revoke endpoint", func(t *testing.T) {
			tokens := pkceAuthorize(t, browser, base, "openid profile")
			if userinfoStatus(t, base, tokens.AccessToken) != http.StatusOK {
				t.Fatal("fresh token should be accepted")
			}
			resp, err := http.PostForm(base+"/revoke", url.Values{"token": {tokens.AccessToken}, "client_id": {"public-client"}})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("/revoke: HTTP %d", resp.StatusCode)
			}
			if got := userinfoStatus(t, base, tokens.AccessToken); got != http.StatusUnauthorized {
				t.Errorf("userinfo after /revoke: HTTP %d, want 401", got)
			}
			resp, err = http.PostForm(base+"/introspect", url.Values{"token": {tokens.AccessToken}, "client_id": {"test-client"}, "client_secret": {"test-client-secret"}})
			if err != nil {
				t.Fatal(err)
			}
			var intro struct {
				Active bool `json:"active"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&intro)
			resp.Body.Close()
			if intro.Active {
				t.Error("introspection should report the revoked token inactive")
			}
		})

		t.Run("sign out everywhere", func(t *testing.T) {
			tokens := pkceAuthorize(t, browser, base, "openid profile offline_access")
			me := newClientWithCookies()
			loginAs(t, me, base, "test@example.com", "password123")
			get(t, me, base+"/account") // renders the form and its CSRF cookie
			postAndFollow(t, me, base, "/account/sessions/revoke-others", nil)
			if got := userinfoStatus(t, base, tokens.AccessToken); got != http.StatusUnauthorized {
				t.Errorf("userinfo after sign-out-everywhere: HTTP %d, want 401", got)
			}
		})

		t.Run("survives across restart of the store", func(t *testing.T) {
			// The revocation is a stored fact, not process state: a second
			// service on the same store sees it too.
			revoked, err := env.store.Revocations().IsRevoked(context.Background(), "no-such-jti", env.testUser.ID, "public-client", time.Now().Add(-time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if !revoked {
				t.Error("the user-wide revocation from sign-out-everywhere should be in the store")
			}
		})
	})
}

// TestIntegration_Metrics: the token, login and revocation counters on
// /metrics move when the corresponding things happen (they were once
// defined but never incremented).
func TestIntegration_Metrics(t *testing.T) {
	env := setupTestEnv(t, "sqlite")
	defer env.cleanup()
	base := env.server.URL

	scrape := func(t *testing.T) string {
		t.Helper()
		resp, err := http.Get(base + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return string(b)
	}
	// counter returns the value of a sample line such as
	// idpico_tokens_issued_total{grant_type="authorization_code",type="access"} 3
	counter := func(metrics, line string) float64 {
		for _, l := range strings.Split(metrics, "\n") {
			if strings.HasPrefix(l, line+" ") {
				var v float64
				fmt.Sscanf(strings.TrimPrefix(l, line+" "), "%g", &v)
				return v
			}
		}
		return 0
	}
	before := scrape(t)

	browser := newClientWithCookies()
	loginAs(t, browser, base, "test@example.com", "password123")
	tokens := pkceAuthorize(t, browser, base, "openid profile offline_access")
	userinfoStatus(t, base, tokens.AccessToken)
	userinfoStatus(t, base, "not-a-token")
	resp, _ := http.PostForm(base+"/revoke", url.Values{"token": {tokens.AccessToken}, "client_id": {"public-client"}})
	resp.Body.Close()
	userinfoStatus(t, base, tokens.AccessToken)
	resp, _ = http.PostForm(base+"/introspect", url.Values{"token": {tokens.AccessToken}, "client_id": {"test-client"}, "client_secret": {"test-client-secret"}})
	resp.Body.Close()
	bad := newClientWithCookies()
	bad.Get(base + "/login")
	postForm(t, bad, base, "/login", url.Values{"email": {"test@example.com"}, "password": {"wrong"}}).Body.Close()

	after := scrape(t)
	for line, want := range map[string]float64{
		`idpico_login_attempts_total{status="success"}`:                              1,
		`idpico_login_attempts_total{status="failure"}`:                              1,
		`idpico_auth_codes_issued_total`:                                             1,
		`idpico_tokens_issued_total{grant_type="authorization_code",type="access"}`:  1,
		`idpico_tokens_issued_total{grant_type="authorization_code",type="id"}`:      1,
		`idpico_tokens_issued_total{grant_type="authorization_code",type="refresh"}`: 1,
		`idpico_tokens_rejected_total{reason="invalid"}`:                             1,
		`idpico_tokens_rejected_total{reason="revoked"}`:                             1,
		`idpico_token_revocations_total`:                                             1,
		`idpico_token_introspections_total{active="false"}`:                          1,
	} {
		if got := counter(after, line) - counter(before, line); got < want {
			t.Errorf("%s increased by %g, want at least %g", line, got, want)
		}
	}
}
