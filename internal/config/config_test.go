package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Clear any existing IDP_ env vars
	clearIDPEnvVars()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Check defaults
	if cfg.Host != "0.0.0.0" {
		t.Errorf("Expected default host '0.0.0.0', got '%s'", cfg.Host)
	}
	if cfg.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", cfg.Port)
	}
	if cfg.IssuerURL != "http://localhost:8080" {
		t.Errorf("Expected default issuer URL, got '%s'", cfg.IssuerURL)
	}
	if cfg.DataDir != "./data" {
		t.Errorf("Expected default data dir './data', got '%s'", cfg.DataDir)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("Expected default log level 'info', got '%s'", cfg.LogLevel)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("Expected default log format 'json', got '%s'", cfg.LogFormat)
	}
	if cfg.LoginRateLimit != 5 {
		t.Errorf("Expected default login rate limit 5, got %d", cfg.LoginRateLimit)
	}
	if cfg.LockoutMaxAttempts != 5 {
		t.Errorf("Expected default lockout max attempts 5, got %d", cfg.LockoutMaxAttempts)
	}
}

func TestLoadFromEnv(t *testing.T) {
	clearIDPEnvVars()

	// Set custom values
	os.Setenv("IDP_HOST", "127.0.0.1")
	os.Setenv("IDP_PORT", "9090")
	os.Setenv("IDP_ISSUER_URL", "https://idp.example.com")
	os.Setenv("IDP_DATA_DIR", "/var/idp/data")
	os.Setenv("IDP_COOKIE_SECRET", "my-secret-key")
	os.Setenv("IDP_COOKIE_SECURE", "true")
	os.Setenv("IDP_LOG_LEVEL", "debug")
	os.Setenv("IDP_LOGIN_RATE_LIMIT", "10")
	defer clearIDPEnvVars()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected host '127.0.0.1', got '%s'", cfg.Host)
	}
	if cfg.Port != 9090 {
		t.Errorf("Expected port 9090, got %d", cfg.Port)
	}
	if cfg.IssuerURL != "https://idp.example.com" {
		t.Errorf("Expected issuer URL 'https://idp.example.com', got '%s'", cfg.IssuerURL)
	}
	if cfg.DataDir != "/var/idp/data" {
		t.Errorf("Expected data dir '/var/idp/data', got '%s'", cfg.DataDir)
	}
	if cfg.CookieSecret != "my-secret-key" {
		t.Errorf("Expected cookie secret 'my-secret-key', got '%s'", cfg.CookieSecret)
	}
	if !cfg.CookieSecure {
		t.Error("Expected cookie secure to be true")
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("Expected log level 'debug', got '%s'", cfg.LogLevel)
	}
	if cfg.LoginRateLimit != 10 {
		t.Errorf("Expected login rate limit 10, got %d", cfg.LoginRateLimit)
	}
}

func TestCookieSecretAutoGeneration(t *testing.T) {
	clearIDPEnvVars()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Should auto-generate a secret
	if cfg.CookieSecret == "" {
		t.Error("Cookie secret should be auto-generated")
	}
	if !cfg.CookieSecretGenerated {
		t.Error("CookieSecretGenerated flag should be true")
	}

	// Second load should generate different secret
	cfg2, _ := Load()
	if cfg.CookieSecret == cfg2.CookieSecret {
		t.Error("Different loads should generate different secrets")
	}
}

func TestAddr(t *testing.T) {
	cfg := &Config{
		Host: "0.0.0.0",
		Port: 8080,
	}

	if cfg.Addr() != "0.0.0.0:8080" {
		t.Errorf("Expected '0.0.0.0:8080', got '%s'", cfg.Addr())
	}

	cfg.Host = "localhost"
	cfg.Port = 3000
	if cfg.Addr() != "localhost:3000" {
		t.Errorf("Expected 'localhost:3000', got '%s'", cfg.Addr())
	}
}

func TestParseBootstrapUsers(t *testing.T) {
	tests := []struct {
		name           string
		bootstrapUsers string
		wantCount      int
		wantFirst      *BootstrapUser
	}{
		{
			name:           "empty",
			bootstrapUsers: "",
			wantCount:      0,
		},
		{
			name:           "single user with name",
			bootstrapUsers: "test@example.com:password123:Test User",
			wantCount:      1,
			wantFirst:      &BootstrapUser{Email: "test@example.com", Password: "password123", Name: "Test User"},
		},
		{
			name:           "single user without name",
			bootstrapUsers: "test@example.com:password123",
			wantCount:      1,
			wantFirst:      &BootstrapUser{Email: "test@example.com", Password: "password123", Name: ""},
		},
		{
			name:           "multiple users",
			bootstrapUsers: "user1@example.com:pass1:User One,user2@example.com:pass2:User Two",
			wantCount:      2,
			wantFirst:      &BootstrapUser{Email: "user1@example.com", Password: "pass1", Name: "User One"},
		},
		{
			name:           "with whitespace",
			bootstrapUsers: " user@example.com : password : Name , user2@example.com:pass2 ",
			wantCount:      2,
			wantFirst:      &BootstrapUser{Email: "user@example.com", Password: "password", Name: "Name"},
		},
		{
			name:           "invalid entries skipped",
			bootstrapUsers: "invalid,user@example.com:password:Name",
			wantCount:      1,
			wantFirst:      &BootstrapUser{Email: "user@example.com", Password: "password", Name: "Name"},
		},
		{
			name:           "password with colon",
			bootstrapUsers: "user@example.com:pass:word:Name",
			wantCount:      1,
			wantFirst:      &BootstrapUser{Email: "user@example.com", Password: "pass", Name: "word:Name"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{BootstrapUsers: tt.bootstrapUsers}
			users := cfg.ParseBootstrapUsers()

			if len(users) != tt.wantCount {
				t.Errorf("Expected %d users, got %d", tt.wantCount, len(users))
			}

			if tt.wantFirst != nil && len(users) > 0 {
				if users[0].Email != tt.wantFirst.Email {
					t.Errorf("Expected email '%s', got '%s'", tt.wantFirst.Email, users[0].Email)
				}
				if users[0].Password != tt.wantFirst.Password {
					t.Errorf("Expected password '%s', got '%s'", tt.wantFirst.Password, users[0].Password)
				}
				if users[0].Name != tt.wantFirst.Name {
					t.Errorf("Expected name '%s', got '%s'", tt.wantFirst.Name, users[0].Name)
				}
			}
		})
	}
}

func TestParseBootstrapClientsSimple(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		secret      string
		redirectURI string
		wantCount   int
		wantFirst   *BootstrapClient
	}{
		{
			name:      "no config",
			wantCount: 0,
		},
		{
			name:        "public client",
			clientID:    "public-app",
			secret:      "",
			redirectURI: "http://localhost:3000/callback",
			wantCount:   1,
			wantFirst: &BootstrapClient{
				ID:           "public-app",
				Secret:       "",
				RedirectURIs: []string{"http://localhost:3000/callback"},
				Public:       true,
			},
		},
		{
			name:        "confidential client",
			clientID:    "my-app",
			secret:      "super-secret",
			redirectURI: "https://app.example.com/callback",
			wantCount:   1,
			wantFirst: &BootstrapClient{
				ID:           "my-app",
				Secret:       "super-secret",
				RedirectURIs: []string{"https://app.example.com/callback"},
				Public:       false,
			},
		},
		{
			name:        "multiple redirect URIs",
			clientID:    "multi-uri-app",
			secret:      "secret",
			redirectURI: "http://localhost:3000/callback https://staging.example.com/callback",
			wantCount:   1,
			wantFirst: &BootstrapClient{
				ID:           "multi-uri-app",
				Secret:       "secret",
				RedirectURIs: []string{"http://localhost:3000/callback", "https://staging.example.com/callback"},
				Public:       false,
			},
		},
		{
			name:        "missing redirect URI",
			clientID:    "no-redirect",
			secret:      "secret",
			redirectURI: "",
			wantCount:   0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				ClientID:          tt.clientID,
				ClientSecret:      tt.secret,
				ClientRedirectURI: tt.redirectURI,
			}
			clients := cfg.ParseBootstrapClients()

			if len(clients) != tt.wantCount {
				t.Errorf("Expected %d clients, got %d", tt.wantCount, len(clients))
			}

			if tt.wantFirst != nil && len(clients) > 0 {
				if clients[0].ID != tt.wantFirst.ID {
					t.Errorf("Expected ID '%s', got '%s'", tt.wantFirst.ID, clients[0].ID)
				}
				if clients[0].Secret != tt.wantFirst.Secret {
					t.Errorf("Expected secret '%s', got '%s'", tt.wantFirst.Secret, clients[0].Secret)
				}
				if clients[0].Public != tt.wantFirst.Public {
					t.Errorf("Expected public %v, got %v", tt.wantFirst.Public, clients[0].Public)
				}
				if len(clients[0].RedirectURIs) != len(tt.wantFirst.RedirectURIs) {
					t.Errorf("Expected %d redirect URIs, got %d", len(tt.wantFirst.RedirectURIs), len(clients[0].RedirectURIs))
				}
				for i, uri := range tt.wantFirst.RedirectURIs {
					if i < len(clients[0].RedirectURIs) && clients[0].RedirectURIs[i] != uri {
						t.Errorf("Expected redirect URI '%s', got '%s'", uri, clients[0].RedirectURIs[i])
					}
				}
			}
		})
	}
}

func TestParseBootstrapClientsComplex(t *testing.T) {
	tests := []struct {
		name             string
		bootstrapClients string
		wantCount        int
		wantClients      []BootstrapClient
	}{
		{
			name:             "empty",
			bootstrapClients: "",
			wantCount:        0,
		},
		{
			name:             "single confidential client",
			bootstrapClients: "my-app|secret123|https://app.example.com/callback",
			wantCount:        1,
			wantClients: []BootstrapClient{
				{ID: "my-app", Secret: "secret123", RedirectURIs: []string{"https://app.example.com/callback"}, Public: false},
			},
		},
		{
			name:             "single public client (empty secret)",
			bootstrapClients: "public-spa||http://localhost:3000/callback",
			wantCount:        1,
			wantClients: []BootstrapClient{
				{ID: "public-spa", Secret: "", RedirectURIs: []string{"http://localhost:3000/callback"}, Public: true},
			},
		},
		{
			name:             "multiple clients",
			bootstrapClients: "app1|secret1|https://app1.com/callback,app2|secret2|https://app2.com/callback",
			wantCount:        2,
			wantClients: []BootstrapClient{
				{ID: "app1", Secret: "secret1", RedirectURIs: []string{"https://app1.com/callback"}, Public: false},
				{ID: "app2", Secret: "secret2", RedirectURIs: []string{"https://app2.com/callback"}, Public: false},
			},
		},
		{
			name:             "multiple redirect URIs",
			bootstrapClients: "multi-app|secret|http://localhost:3000/callback http://localhost:8080/callback",
			wantCount:        1,
			wantClients: []BootstrapClient{
				{ID: "multi-app", Secret: "secret", RedirectURIs: []string{"http://localhost:3000/callback", "http://localhost:8080/callback"}, Public: false},
			},
		},
		{
			name:             "invalid entries skipped",
			bootstrapClients: "invalid|only-two,valid-app|secret|https://valid.com/callback",
			wantCount:        1,
			wantClients: []BootstrapClient{
				{ID: "valid-app", Secret: "secret", RedirectURIs: []string{"https://valid.com/callback"}, Public: false},
			},
		},
		{
			name:             "with whitespace",
			bootstrapClients: " app1 | secret1 | https://app1.com/callback , app2|secret2|https://app2.com/callback ",
			wantCount:        2,
			wantClients: []BootstrapClient{
				{ID: "app1", Secret: "secret1", RedirectURIs: []string{"https://app1.com/callback"}, Public: false},
				{ID: "app2", Secret: "secret2", RedirectURIs: []string{"https://app2.com/callback"}, Public: false},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{BootstrapClients: tt.bootstrapClients}
			clients := cfg.ParseBootstrapClients()

			if len(clients) != tt.wantCount {
				t.Errorf("Expected %d clients, got %d", tt.wantCount, len(clients))
			}

			for i, want := range tt.wantClients {
				if i >= len(clients) {
					break
				}
				got := clients[i]
				if got.ID != want.ID {
					t.Errorf("Client %d: expected ID '%s', got '%s'", i, want.ID, got.ID)
				}
				if got.Secret != want.Secret {
					t.Errorf("Client %d: expected secret '%s', got '%s'", i, want.Secret, got.Secret)
				}
				if got.Public != want.Public {
					t.Errorf("Client %d: expected public %v, got %v", i, want.Public, got.Public)
				}
			}
		})
	}
}

func TestSimpleClientTakesPrecedence(t *testing.T) {
	cfg := &Config{
		// Simple client config
		ClientID:          "simple-app",
		ClientSecret:      "simple-secret",
		ClientRedirectURI: "http://localhost:3000/callback",
		// Complex client config (should still be included)
		BootstrapClients: "complex-app|complex-secret|https://complex.com/callback",
	}

	clients := cfg.ParseBootstrapClients()

	// Should have both clients
	if len(clients) != 2 {
		t.Errorf("Expected 2 clients, got %d", len(clients))
	}

	// Simple client should be first
	if clients[0].ID != "simple-app" {
		t.Errorf("First client should be simple-app, got %s", clients[0].ID)
	}
	if clients[1].ID != "complex-app" {
		t.Errorf("Second client should be complex-app, got %s", clients[1].ID)
	}
}

func TestTokenTTLDefaults(t *testing.T) {
	clearIDPEnvVars()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Access token: 15 minutes
	if cfg.AccessTokenTTL.Minutes() != 15 {
		t.Errorf("Expected access token TTL 15m, got %v", cfg.AccessTokenTTL)
	}

	// Refresh token: 7 days (168 hours)
	if cfg.RefreshTokenTTL.Hours() != 168 {
		t.Errorf("Expected refresh token TTL 168h, got %v", cfg.RefreshTokenTTL)
	}

	// Auth code: 10 minutes
	if cfg.AuthCodeTTL.Minutes() != 10 {
		t.Errorf("Expected auth code TTL 10m, got %v", cfg.AuthCodeTTL)
	}
}

func TestLockoutConfig(t *testing.T) {
	clearIDPEnvVars()

	os.Setenv("IDP_LOCKOUT_MAX_ATTEMPTS", "3")
	os.Setenv("IDP_LOCKOUT_DURATION", "30m")
	defer clearIDPEnvVars()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.LockoutMaxAttempts != 3 {
		t.Errorf("Expected lockout max attempts 3, got %d", cfg.LockoutMaxAttempts)
	}
	if cfg.LockoutDuration.Minutes() != 30 {
		t.Errorf("Expected lockout duration 30m, got %v", cfg.LockoutDuration)
	}
}

// Helper function to clear all IDP_ environment variables
func clearIDPEnvVars() {
	vars := []string{
		"IDP_HOST", "IDP_PORT", "IDP_ISSUER_URL", "IDP_DATA_DIR",
		"IDP_SESSION_DURATION", "IDP_COOKIE_SECRET", "IDP_COOKIE_SECURE", "IDP_COOKIE_DOMAIN",
		"IDP_ACCESS_TOKEN_TTL", "IDP_REFRESH_TOKEN_TTL", "IDP_AUTH_CODE_TTL",
		"IDP_SIGNING_KEY_ROTATION_DAYS", "IDP_LOGIN_RATE_LIMIT",
		"IDP_LOCKOUT_MAX_ATTEMPTS", "IDP_LOCKOUT_DURATION",
		"IDP_LOG_LEVEL", "IDP_LOG_FORMAT",
		"IDP_BOOTSTRAP_USERS", "IDP_BOOTSTRAP_CLIENTS",
		"IDP_CLIENT_ID", "IDP_CLIENT_SECRET", "IDP_CLIENT_REDIRECT_URI",
	}
	for _, v := range vars {
		os.Unsetenv(v)
	}
}
