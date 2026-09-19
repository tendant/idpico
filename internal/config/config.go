// Package config handles application configuration via environment variables.
package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

// Config holds all configuration for the IdP.
type Config struct {
	// Server settings
	Host string `env:"IDPICO_HOST" env-default:"0.0.0.0"`
	Port int    `env:"IDPICO_PORT" env-default:"8080"`

	// Issuer URL (required for OIDC)
	IssuerURL string `env:"IDPICO_ISSUER_URL" env-default:"http://localhost:8080"`

	// Storage settings
	// StoreDriver selects the persistence backend: "sqlite" (default) or "file" (JSON files).
	StoreDriver string `env:"IDPICO_STORE_DRIVER" env-default:"sqlite"`
	// DataDir holds the SQLite database (idpico.db) or the JSON files for the file driver.
	DataDir string `env:"IDPICO_DATA_DIR" env-default:"./data"`
	// StoreDSN overrides the SQLite database location. Defaults to <DataDir>/idpico.db.
	StoreDSN string `env:"IDPICO_STORE_DSN" env-default:""`

	// Session settings
	SessionDuration time.Duration `env:"IDPICO_SESSION_DURATION" env-default:"24h"`
	CookieSecret    string        `env:"IDPICO_COOKIE_SECRET"`
	CookieSecure    bool          `env:"IDPICO_COOKIE_SECURE" env-default:"false"` // unset: follows the issuer scheme (true for https)
	CookieDomain    string        `env:"IDPICO_COOKIE_DOMAIN" env-default:""`

	// Token settings
	AccessTokenTTL  time.Duration `env:"IDPICO_ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL time.Duration `env:"IDPICO_REFRESH_TOKEN_TTL" env-default:"168h"` // 7 days
	AuthCodeTTL     time.Duration `env:"IDPICO_AUTH_CODE_TTL" env-default:"10m"`

	// Account self-service (password reset, email verification)
	PasswordResetTTL      time.Duration `env:"IDPICO_PASSWORD_RESET_TTL" env-default:"1h"`
	PasswordResetInterval time.Duration `env:"IDPICO_PASSWORD_RESET_INTERVAL" env-default:"2m"` // min gap between reset emails to one address (0 = off)
	EmailVerifyTTL        time.Duration `env:"IDPICO_EMAIL_VERIFY_TTL" env-default:"24h"`

	// Outbound mail: "log" prints messages to the server log, "smtp" sends them
	MailDriver      string `env:"IDPICO_MAIL_DRIVER" env-default:"log"`
	SMTPHost        string `env:"IDPICO_SMTP_HOST" env-default:""`
	SMTPPort        int    `env:"IDPICO_SMTP_PORT" env-default:"587"`
	SMTPUsername    string `env:"IDPICO_SMTP_USERNAME" env-default:""`
	SMTPPassword    string `env:"IDPICO_SMTP_PASSWORD" env-default:""`
	SMTPFrom        string `env:"IDPICO_SMTP_FROM" env-default:""`
	SMTPImplicitTLS bool   `env:"IDPICO_SMTP_IMPLICIT_TLS" env-default:"false"` // TLS from the first byte (port 465)

	// Built-in OIDC relying party at /playground for trying the flow
	PlaygroundEnabled bool `env:"IDPICO_PLAYGROUND_ENABLED" env-default:"true"`

	// Consent
	RequireConsent bool `env:"IDPICO_REQUIRE_CONSENT" env-default:"true"` // Show the consent screen for clients without skip_consent

	// Key rotation
	SigningKeyRotationDays int           `env:"IDPICO_SIGNING_KEY_ROTATION_DAYS" env-default:"30"` // 0 = disabled
	SigningKeyGracePeriod  time.Duration `env:"IDPICO_SIGNING_KEY_GRACE_PERIOD" env-default:"24h"` // rotated keys stay valid for verification this long

	// Maintenance (expired session/code/token purge + key rotation)
	MaintenanceInterval time.Duration `env:"IDPICO_MAINTENANCE_INTERVAL" env-default:"10m"` // 0 = disabled

	// Audit log retention (0 = keep forever)
	AuditRetention time.Duration `env:"IDPICO_AUDIT_RETENTION" env-default:"2160h"` // 90 days

	// Rate limiting
	LoginRateLimit int `env:"IDPICO_LOGIN_RATE_LIMIT" env-default:"5"` // attempts per minute

	// Account lockout
	LockoutMaxAttempts int           `env:"IDPICO_LOCKOUT_MAX_ATTEMPTS" env-default:"5"` // 0 = disabled
	LockoutDuration    time.Duration `env:"IDPICO_LOCKOUT_DURATION" env-default:"15m"`

	// Logging
	LogLevel  string `env:"IDPICO_LOG_LEVEL" env-default:"info"`
	LogFormat string `env:"IDPICO_LOG_FORMAT" env-default:"json"` // json or text

	// CORS settings
	CORSAllowedOrigins   string `env:"IDPICO_CORS_ALLOWED_ORIGINS" env-default:""` // Comma-separated origins, empty = disabled
	CORSAllowCredentials bool   `env:"IDPICO_CORS_ALLOW_CREDENTIALS" env-default:"true"`

	// Reverse proxies whose X-Forwarded-For / X-Real-IP headers identify the
	// client for rate limiting and the audit log. "private" (default) trusts
	// loopback and private-network peers, "none" trusts nobody, otherwise a
	// comma-separated list of IPs or CIDRs.
	TrustedProxies string `env:"IDPICO_TRUSTED_PROXIES" env-default:"private"`

	// Security headers
	SecurityHeadersEnabled bool   `env:"IDPICO_SECURITY_HEADERS_ENABLED" env-default:"true"`
	ContentSecurityPolicy  string `env:"IDPICO_CONTENT_SECURITY_POLICY" env-default:"default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"`
	HSTSMaxAge             int    `env:"IDPICO_HSTS_MAX_AGE" env-default:"0"` // 0 = disabled, recommended: 31536000 (1 year)

	// Metrics
	MetricsEnabled bool `env:"IDPICO_METRICS_ENABLED" env-default:"true"`

	// Groups
	GroupsClaim string `env:"IDPICO_GROUPS_CLAIM" env-default:"groups"` // Claim name memberships are emitted under
	// BootstrapGroups creates groups and memberships on startup.
	// Format: "group:email1 email2,group2:email3" (members space-separated, groups comma-separated)
	BootstrapGroups string `env:"IDPICO_BOOTSTRAP_GROUPS" env-default:""`

	// AdminEmails lists users (comma-separated) granted access to the admin UI
	// on startup. Admins can promote further users from the UI.
	AdminEmails string `env:"IDPICO_ADMIN_EMAILS" env-default:""`

	// Bootstrap data (created on startup if not exists)
	// Format: "email:password:name,email2:password2:name2"
	BootstrapUsers string `env:"IDPICO_BOOTSTRAP_USERS"`

	// Simple single-client configuration (takes precedence if IDPICO_CLIENT_ID is set)
	ClientID          string `env:"IDPICO_CLIENT_ID"`
	ClientSecret      string `env:"IDPICO_CLIENT_SECRET"`       // Empty for public clients
	ClientRedirectURI string `env:"IDPICO_CLIENT_REDIRECT_URI"` // Space-separated for multiple URIs

	// Complex multi-client configuration
	// Format: "client_id|client_secret|redirect_uri" (use | as delimiter to avoid URL conflicts)
	// Multiple redirect URIs separated by space: "client_id|secret|http://uri1 http://uri2"
	// Multiple clients separated by comma: "client1|secret1|uri1,client2|secret2|uri2"
	// Empty secret for public clients: "public-app||http://localhost:3000/callback"
	BootstrapClients string `env:"IDPICO_BOOTSTRAP_CLIENTS"`

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

	// Cookies carry the session; over an https issuer they must be Secure
	// unless the operator deliberately says otherwise.
	if _, set := os.LookupEnv("IDPICO_COOKIE_SECURE"); !set && strings.HasPrefix(strings.ToLower(cfg.IssuerURL), "https://") {
		cfg.CookieSecure = true
	}

	if err := cfg.validateStore(); err != nil {
		return nil, err
	}
	if err := cfg.validateMail(); err != nil {
		return nil, err
	}
	if _, err := cfg.ParseTrustedProxies(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Store drivers.
const (
	StoreDriverSQLite = "sqlite"
	StoreDriverFile   = "file"
)

func (c *Config) validateStore() error {
	c.StoreDriver = strings.ToLower(strings.TrimSpace(c.StoreDriver))
	switch c.StoreDriver {
	case StoreDriverSQLite, StoreDriverFile:
		return nil
	default:
		return fmt.Errorf("invalid IDPICO_STORE_DRIVER %q (expected %q or %q)", c.StoreDriver, StoreDriverSQLite, StoreDriverFile)
	}
}

// Mail drivers.
const (
	MailDriverLog  = "log"
	MailDriverSMTP = "smtp"
)

func (c *Config) validateMail() error {
	c.MailDriver = strings.ToLower(strings.TrimSpace(c.MailDriver))
	switch c.MailDriver {
	case MailDriverLog:
		return nil
	case MailDriverSMTP:
		if c.SMTPHost == "" || c.SMTPFrom == "" {
			return fmt.Errorf("IDPICO_SMTP_HOST and IDPICO_SMTP_FROM are required when IDPICO_MAIL_DRIVER=smtp")
		}
		return nil
	default:
		return fmt.Errorf("invalid IDPICO_MAIL_DRIVER %q (expected %q or %q)", c.MailDriver, MailDriverLog, MailDriverSMTP)
	}
}

// SigningKeyMaxAge returns the age after which the signing key is rotated,
// or 0 when rotation is disabled.
func (c *Config) SigningKeyMaxAge() time.Duration {
	if c.SigningKeyRotationDays <= 0 {
		return 0
	}
	return time.Duration(c.SigningKeyRotationDays) * 24 * time.Hour
}

// SQLitePath returns the SQLite database path: IDPICO_STORE_DSN if set,
// otherwise <IDPICO_DATA_DIR>/idpico.db.
func (c *Config) SQLitePath() string {
	if c.StoreDSN != "" {
		return c.StoreDSN
	}
	return filepath.Join(c.DataDir, "idpico.db")
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

// ParseBootstrapUsers parses the IDPICO_BOOTSTRAP_USERS environment variable.
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

// BootstrapGroup is a group and its members to create on startup.
type BootstrapGroup struct {
	Name    string
	Members []string // emails
}

// ParseBootstrapGroups parses IDPICO_BOOTSTRAP_GROUPS.
// Format: "admins:alice@x.com bob@x.com,devs:carol@x.com"
func (c *Config) ParseBootstrapGroups() []BootstrapGroup {
	var groups []BootstrapGroup
	for _, entry := range splitList(c.BootstrapGroups) {
		name, members, _ := strings.Cut(entry, ":")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		groups = append(groups, BootstrapGroup{Name: name, Members: strings.Fields(members)})
	}
	return groups
}

// ParseAdminEmails parses the comma-separated IDPICO_ADMIN_EMAILS list.
func (c *Config) ParseAdminEmails() []string {
	return splitList(c.AdminEmails)
}

func splitList(v string) []string {
	if v == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// privateProxyPrefixes are the peers trusted by IDPICO_TRUSTED_PROXIES=private:
// loopback, RFC 1918, carrier-grade NAT, link-local and IPv6 ULA ranges.
var privateProxyPrefixes = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
}

// ParseTrustedProxies returns the peer networks whose forwarding headers are
// honoured. An empty result means the connecting address is always the client.
func (c *Config) ParseTrustedProxies() ([]netip.Prefix, error) {
	switch strings.ToLower(strings.TrimSpace(c.TrustedProxies)) {
	case "", "none":
		return nil, nil
	case "private":
		return privateProxyPrefixes, nil
	}
	var prefixes []netip.Prefix
	for _, item := range strings.Split(c.TrustedProxies, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, err := netip.ParsePrefix(item); err == nil {
			prefixes = append(prefixes, p)
			continue
		}
		addr, err := netip.ParseAddr(item)
		if err != nil {
			return nil, fmt.Errorf("IDPICO_TRUSTED_PROXIES: %q is not an IP or CIDR", item)
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return prefixes, nil
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
// Simple single-client: IDPICO_CLIENT_ID, IDPICO_CLIENT_SECRET, IDPICO_CLIENT_REDIRECT_URI
// Complex multi-client: IDPICO_BOOTSTRAP_CLIENTS with format "client_id|client_secret|redirect_uri"
// Multiple redirect URIs separated by space: "client_id|secret|http://uri1 http://uri2"
func (c *Config) ParseBootstrapClients() []BootstrapClient {
	var clients []BootstrapClient

	// Simple single-client configuration (IDPICO_CLIENT_ID takes precedence)
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
