// Package config handles application configuration via environment variables.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
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

	// Logging
	LogLevel  string `env:"IDP_LOG_LEVEL" env-default:"info"`
	LogFormat string `env:"IDP_LOG_FORMAT" env-default:"json"` // json or text

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
