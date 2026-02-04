// Package config handles application configuration via environment variables.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

// Config holds all configuration for the IdP.
type Config struct {
	// Server settings
	Host string `env:"IDP_HOST" env-default:"0.0.0.0"`
	Port int    `env:"IDP_PORT" env-default:"8080"`

	// Issuer URL (required for OIDC)
	IssuerURL string `env:"IDP_ISSUER_URL" env-default:"http://localhost:8080"`

	// Storage settings
	DataDir string `env:"IDP_DATA_DIR" env-default:"./data"`

	// Session settings
	SessionDuration   time.Duration `env:"IDP_SESSION_DURATION" env-default:"24h"`
	CookieSecret      string        `env:"IDP_COOKIE_SECRET"`
	CookieSecure      bool          `env:"IDP_COOKIE_SECURE" env-default:"false"`
	CookieDomain      string        `env:"IDP_COOKIE_DOMAIN" env-default:""`

	// Token settings
	AccessTokenTTL  time.Duration `env:"IDP_ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL time.Duration `env:"IDP_REFRESH_TOKEN_TTL" env-default:"168h"` // 7 days
	AuthCodeTTL     time.Duration `env:"IDP_AUTH_CODE_TTL" env-default:"10m"`

	// Key rotation
	SigningKeyRotationDays int `env:"IDP_SIGNING_KEY_ROTATION_DAYS" env-default:"30"`

	// Rate limiting
	LoginRateLimit int `env:"IDP_LOGIN_RATE_LIMIT" env-default:"5"` // attempts per minute

	// Account lockout
	LockoutMaxAttempts int           `env:"IDP_LOCKOUT_MAX_ATTEMPTS" env-default:"5"`  // 0 = disabled
	LockoutDuration    time.Duration `env:"IDP_LOCKOUT_DURATION" env-default:"15m"`

	// Logging
	LogLevel  string `env:"IDP_LOG_LEVEL" env-default:"info"`
	LogFormat string `env:"IDP_LOG_FORMAT" env-default:"json"` // json or text

	// CORS settings
	CORSAllowedOrigins string `env:"IDP_CORS_ALLOWED_ORIGINS" env-default:""` // Comma-separated origins, empty = disabled
	CORSAllowCredentials bool `env:"IDP_CORS_ALLOW_CREDENTIALS" env-default:"true"`

	// Security headers
	SecurityHeadersEnabled bool   `env:"IDP_SECURITY_HEADERS_ENABLED" env-default:"true"`
	ContentSecurityPolicy  string `env:"IDP_CONTENT_SECURITY_POLICY" env-default:"default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'"`
	HSTSMaxAge             int    `env:"IDP_HSTS_MAX_AGE" env-default:"0"` // 0 = disabled, recommended: 31536000 (1 year)

	// Metrics
	MetricsEnabled bool `env:"IDP_METRICS_ENABLED" env-default:"true"`

	// Bootstrap data (created on startup if not exists)
	// Format: "email:password:name,email2:password2:name2"
	BootstrapUsers string `env:"IDP_BOOTSTRAP_USERS"`

	// Simple single-client configuration (takes precedence if IDP_CLIENT_ID is set)
	ClientID          string `env:"IDP_CLIENT_ID"`
	ClientSecret      string `env:"IDP_CLIENT_SECRET"`      // Empty for public clients
	ClientRedirectURI string `env:"IDP_CLIENT_REDIRECT_URI"` // Space-separated for multiple URIs

	// Complex multi-client configuration
	// Format: "client_id|client_secret|redirect_uri" (use | as delimiter to avoid URL conflicts)
	// Multiple redirect URIs separated by space: "client_id|secret|http://uri1 http://uri2"
	// Multiple clients separated by comma: "client1|secret1|uri1,client2|secret2|uri2"
	// Empty secret for public clients: "public-app||http://localhost:3000/callback"
	BootstrapClients string `env:"IDP_BOOTSTRAP_CLIENTS"`

	// Internal flags (not from env)
	CookieSecretGenerated bool `env:"-"` // True if secret was auto-generated
}

// Load reads configuration from environment variables.
func Load() (*Config, error) {
	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Generate random cookie secret if not provided
	if cfg.CookieSecret == "" {
		secret, err := generateRandomSecret(32)
		if err != nil {
			return nil, fmt.Errorf("failed to generate cookie secret: %w", err)
		}
		cfg.CookieSecret = secret
		cfg.CookieSecretGenerated = true
	}

	return &cfg, nil
}

// Addr returns the server address in host:port format.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// generateRandomSecret generates a cryptographically secure random string.
func generateRandomSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// BootstrapUser represents a user to be created on startup.
type BootstrapUser struct {
	Email    string
	Password string
	Name     string
}

// BootstrapClient represents a client to be created on startup.
type BootstrapClient struct {
	ID           string
	Secret       string
	RedirectURIs []string
	Public       bool
}

// ParseBootstrapUsers parses the IDP_BOOTSTRAP_USERS environment variable.
// Format: "email:password:name,email2:password2:name2"
func (c *Config) ParseBootstrapUsers() []BootstrapUser {
	if c.BootstrapUsers == "" {
		return nil
	}

	var users []BootstrapUser
	for _, entry := range strings.Split(c.BootstrapUsers, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 3)
		if len(parts) < 2 {
			continue
		}

		user := BootstrapUser{
			Email:    strings.TrimSpace(parts[0]),
			Password: strings.TrimSpace(parts[1]),
		}
		if len(parts) >= 3 {
			user.Name = strings.TrimSpace(parts[2])
		}
		users = append(users, user)
	}
	return users
}

// ParseCORSAllowedOrigins parses the comma-separated CORS allowed origins.
func (c *Config) ParseCORSAllowedOrigins() []string {
	if c.CORSAllowedOrigins == "" {
		return nil
	}

	var origins []string
	for _, origin := range strings.Split(c.CORSAllowedOrigins, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			origins = append(origins, origin)
		}
	}
	return origins
}

// ParseBootstrapClients parses client configuration from environment variables.
// Simple single-client: IDP_CLIENT_ID, IDP_CLIENT_SECRET, IDP_CLIENT_REDIRECT_URI
// Complex multi-client: IDP_BOOTSTRAP_CLIENTS with format "client_id|client_secret|redirect_uri"
// Multiple redirect URIs separated by space: "client_id|secret|http://uri1 http://uri2"
func (c *Config) ParseBootstrapClients() []BootstrapClient {
	var clients []BootstrapClient

	// Simple single-client configuration (IDP_CLIENT_ID takes precedence)
	if c.ClientID != "" && c.ClientRedirectURI != "" {
		client := BootstrapClient{
			ID:           c.ClientID,
			Secret:       c.ClientSecret,
			RedirectURIs: strings.Fields(c.ClientRedirectURI), // Split by whitespace
			Public:       c.ClientSecret == "",
		}
		clients = append(clients, client)
	}

	// Complex multi-client configuration
	if c.BootstrapClients != "" {
		for _, entry := range strings.Split(c.BootstrapClients, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			parts := strings.SplitN(entry, "|", 3)
			if len(parts) < 3 {
				continue
			}

			secret := strings.TrimSpace(parts[1])
			client := BootstrapClient{
				ID:           strings.TrimSpace(parts[0]),
				Secret:       secret,
				RedirectURIs: strings.Fields(parts[2]), // Split by whitespace
				Public:       secret == "",
			}
			clients = append(clients, client)
		}
	}

	return clients
}
