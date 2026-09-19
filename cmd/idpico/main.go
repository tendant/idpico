// Package main is the entry point for the idpico Identity Provider.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/tendant/idpico/internal/audit"
	"github.com/tendant/idpico/internal/auth"
	"github.com/tendant/idpico/internal/config"
	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/domain"
	idphttp "github.com/tendant/idpico/internal/http"
	"github.com/tendant/idpico/internal/mail"
	"github.com/tendant/idpico/internal/maintenance"
	"github.com/tendant/idpico/internal/oidc"
	"github.com/tendant/idpico/internal/store"
	"github.com/tendant/idpico/internal/store/file"
	"github.com/tendant/idpico/internal/store/sqlite"
)

func main() {
	// Load .env file if present (ignore error if not found)
	_ = godotenv.Load()

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		slog.Error("failed to load config", "error", err)
		os.Exit(1)
	}

	// Setup logger
	var handler slog.Handler
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
			Level: parseLogLevel(cfg.LogLevel),
		})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: parseLogLevel(cfg.LogLevel),
		})
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Warn if using auto-generated cookie secret
	if cfg.CookieSecretGenerated {
		logger.Warn("using auto-generated cookie secret - sessions will not persist across restarts. Set IDPICO_COOKIE_SECRET for production.")
	}

	// Initialize persistence
	store, keyRepo, err := openStore(context.Background(), cfg, logger)
	if err != nil {
		logger.Error("failed to initialize store", "driver", cfg.StoreDriver, "error", err)
		os.Exit(1)
	}
	defer store.Close()

	// Bootstrap users and clients from environment variables
	bootstrapData(context.Background(), cfg, store, logger)
	bootstrapGroups(context.Background(), cfg, store, logger)
	grantAdmins(context.Background(), cfg, store, logger)

	// Initialize key service for JWT signing
	keyService := crypto.NewKeyService(keyRepo)

	// Ensure we have an active signing key
	activeKey, err := keyService.EnsureActiveKey(context.Background())
	if err != nil {
		logger.Error("failed to ensure active signing key", "error", err)
		os.Exit(1)
	}
	logger.Info("signing key ready", "kid", activeKey.Kid)

	// Initialize auth services
	sessionService := auth.NewSessionService(
		store.Sessions(),
		cfg.CookieSecret,
		auth.WithCookieSecure(cfg.CookieSecure),
		auth.WithCookieDomain(cfg.CookieDomain),
		auth.WithSessionTTL(cfg.SessionDuration),
	)

	csrfService := auth.NewCSRFService(cfg.CookieSecret, cfg.CookieSecure, cfg.CookieDomain)

	// Audit log
	auditRecorder := audit.NewRecorder(store.Audit(), logger)

	// Initialize lockout service for account lockout after failed attempts
	var lockoutService *auth.LockoutService
	if cfg.LockoutMaxAttempts > 0 {
		lockoutService = auth.NewLockoutService(cfg.LockoutMaxAttempts, cfg.LockoutDuration)
		logger.Info("account lockout enabled", "max_attempts", cfg.LockoutMaxAttempts, "duration", cfg.LockoutDuration)
	}

	authService := auth.NewService(
		store.Users(),
		sessionService,
		csrfService,
		auth.WithLogger(logger),
		auth.WithLockout(lockoutService),
		auth.WithAudit(auditRecorder),
	)

	// Outbound mail + self-service account flows
	mailer, err := newMailer(cfg, logger)
	if err != nil {
		logger.Error("failed to initialize mailer", "error", err)
		os.Exit(1)
	}
	accountService := auth.NewAccountService(
		store.Users(), store.VerificationTokens(), store.Sessions(), store.Tokens(),
		mailer, cfg.IssuerURL,
		auth.WithAccountLogger(logger),
		auth.WithResetTTL(cfg.PasswordResetTTL),
		auth.WithResetInterval(cfg.PasswordResetInterval),
		auth.WithVerifyTTL(cfg.EmailVerifyTTL),
		auth.WithAccountAudit(auditRecorder),
	)

	// Initialize token generator with KeyService for key rotation support
	tokenGenerator := crypto.NewTokenGeneratorWithKeyService(activeKey, keyService, cfg.IssuerURL, cfg.IssuerURL)

	// Initialize OIDC services
	authorizeService := oidc.NewAuthorizeService(
		store.Clients(),
		store.AuthCodes(),
		cfg.AuthCodeTTL,
	)

	groupClaims := oidc.NewGroupClaims(store.Groups(), cfg.GroupsClaim)

	tokenService := oidc.NewTokenService(
		store.Clients(),
		store.AuthCodes(),
		store.Tokens(),
		store.Users(),
		tokenGenerator,
		cfg.IssuerURL,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
		oidc.WithGroupClaims(groupClaims),
	)

	userInfoService := oidc.NewUserInfoService(store.Users(), tokenGenerator, oidc.WithUserInfoGroups(groupClaims))

	// Load() already validated the value; only the parsed form is needed here.
	trustedProxies, _ := cfg.ParseTrustedProxies()
	if len(trustedProxies) == 0 {
		logger.Warn("no trusted proxies (IDPICO_TRUSTED_PROXIES); forwarding headers are ignored and every request is attributed to its connecting address")
	}
	if !cfg.CookieSecure && strings.HasPrefix(strings.ToLower(cfg.IssuerURL), "https://") {
		logger.Warn("IDPICO_COOKIE_SECURE=false with an https issuer: session cookies can be sent over plain http")
	}

	// Build server options
	serverOpts := []idphttp.Option{
		idphttp.WithLogger(logger),
		idphttp.WithKeyService(keyService),
		idphttp.WithIssuerURL(cfg.IssuerURL),
		idphttp.WithAuthService(authService),
		idphttp.WithAccountService(accountService, cfg.PasswordResetTTL.String()),
		idphttp.WithOIDCServices(authorizeService, tokenService, userInfoService),
		idphttp.WithGroupsClaim(groupClaims.ClaimName()),
		idphttp.WithAudit(auditRecorder),
		idphttp.WithLoginRateLimit(cfg.LoginRateLimit),
		idphttp.WithTrustedProxies(trustedProxies),
	}

	// Admin UI
	serverOpts = append(serverOpts, idphttp.WithAdmin(idphttp.AdminConfig{
		Store:           store,
		AuthService:     authService,
		AccountService:  accountService,
		KeyService:      keyService,
		IssuerURL:       cfg.IssuerURL,
		KeyGracePeriod:  cfg.SigningKeyGracePeriod,
		AccessTokenTTL:  cfg.AccessTokenTTL,
		RefreshTokenTTL: cfg.RefreshTokenTTL,
		GroupsClaim:     groupClaims.ClaimName(),
	}))

	// OIDC playground
	if cfg.PlaygroundEnabled {
		serverOpts = append(serverOpts, idphttp.WithPlayground(store.Clients()))
	} else {
		logger.Info("OIDC playground disabled (IDPICO_PLAYGROUND_ENABLED, off by default for an https issuer)")
	}

	// Consent screen (per-client skip_consent still applies)
	if cfg.RequireConsent {
		serverOpts = append(serverOpts, idphttp.WithConsentService(oidc.NewConsentService(store.Consents())))
	} else {
		logger.Warn("consent screen disabled (IDPICO_REQUIRE_CONSENT=false)")
	}

	// Configure security headers
	if cfg.SecurityHeadersEnabled {
		securityConfig := idphttp.DefaultSecurityHeadersConfig()
		if cfg.ContentSecurityPolicy != "" {
			securityConfig.ContentSecurityPolicy = cfg.ContentSecurityPolicy
		}
		if cfg.HSTSMaxAge > 0 {
			securityConfig.StrictTransportSecurity = fmt.Sprintf("max-age=%d; includeSubDomains", cfg.HSTSMaxAge)
		}
		serverOpts = append(serverOpts, idphttp.WithSecurityHeaders(securityConfig))
	}

	// Configure CORS
	corsOrigins := cfg.ParseCORSAllowedOrigins()
	if len(corsOrigins) > 0 {
		corsConfig := idphttp.DefaultCORSConfig()
		corsConfig.AllowedOrigins = corsOrigins
		corsConfig.AllowCredentials = cfg.CORSAllowCredentials
		serverOpts = append(serverOpts, idphttp.WithCORS(corsConfig))
	}

	// Configure metrics
	if cfg.MetricsEnabled {
		serverOpts = append(serverOpts, idphttp.WithMetrics(true))
	}

	// Create HTTP server
	server := idphttp.NewServer(cfg.Addr(), serverOpts...)

	// Background maintenance: purge expired rows, rotate/clean signing keys
	maintCtx, stopMaintenance := context.WithCancel(context.Background())
	defer stopMaintenance()
	if cfg.MaintenanceInterval > 0 {
		runner := maintenance.NewRunner(store, keyService,
			maintenance.WithLogger(logger),
			maintenance.WithInterval(cfg.MaintenanceInterval),
			maintenance.WithKeyRotation(cfg.SigningKeyMaxAge(), cfg.SigningKeyGracePeriod),
			maintenance.WithAuditRetention(cfg.AuditRetention),
			maintenance.WithAudit(auditRecorder),
		)
		go runner.Run(maintCtx)
		logger.Info("maintenance enabled",
			"interval", cfg.MaintenanceInterval,
			"key_rotation_days", cfg.SigningKeyRotationDays,
			"key_grace_period", cfg.SigningKeyGracePeriod,
		)
	}

	// Start server in goroutine
	go func() {
		if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	logger.Info("server started", "addr", cfg.Addr(), "issuer", cfg.IssuerURL)

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info("shutting down server...")

	// Graceful shutdown with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}

// openStore opens the persistence backend selected by IDPICO_STORE_DRIVER and
// returns it together with the matching signing-key repository.
func openStore(ctx context.Context, cfg *config.Config, logger *slog.Logger) (store.Store, crypto.KeyRepository, error) {
	switch cfg.StoreDriver {
	case config.StoreDriverSQLite:
		path := cfg.SQLitePath()
		s, err := sqlite.NewStore(ctx, path)
		if err != nil {
			return nil, nil, err
		}
		logger.Info("initialized sqlite store", "path", path)
		return s, s.Keys(), nil

	case config.StoreDriverFile:
		s, err := file.NewStore(cfg.DataDir)
		if err != nil {
			return nil, nil, err
		}
		logger.Info("initialized file store", "data_dir", cfg.DataDir)
		return s, file.NewKeyRepository(cfg.DataDir), nil

	default:
		return nil, nil, fmt.Errorf("unsupported store driver %q", cfg.StoreDriver)
	}
}

// bootstrapGroups creates the groups and memberships from IDPICO_BOOTSTRAP_GROUPS,
// skipping anything that already exists.
func bootstrapGroups(ctx context.Context, cfg *config.Config, store store.Store, logger *slog.Logger) {
	for _, bg := range cfg.ParseBootstrapGroups() {
		group, err := store.Groups().GetByName(ctx, bg.Name)
		if err != nil {
			group = &domain.Group{ID: uuid.New().String(), Name: bg.Name}
			if err := store.Groups().Create(ctx, group); err != nil {
				logger.Error("failed to create bootstrap group", "group", bg.Name, "error", err)
				continue
			}
			logger.Info("created bootstrap group", "group", bg.Name)
		}
		for _, email := range bg.Members {
			user, err := store.Users().GetByEmail(ctx, email)
			if err != nil {
				logger.Warn("bootstrap group member not found", "group", bg.Name, "email", email)
				continue
			}
			if err := store.Groups().AddMember(ctx, group.ID, user.ID); err != nil {
				logger.Error("failed to add bootstrap group member", "group", bg.Name, "email", email, "error", err)
			}
		}
	}
}

// grantAdmins flags the users listed in IDPICO_ADMIN_EMAILS as administrators.
func grantAdmins(ctx context.Context, cfg *config.Config, store store.Store, logger *slog.Logger) {
	for _, email := range cfg.ParseAdminEmails() {
		user, err := store.Users().GetByEmail(ctx, email)
		if err != nil {
			logger.Warn("admin email not found; create the user first (IDPICO_BOOTSTRAP_USERS or the admin UI)", "email", email)
			continue
		}
		if user.Admin {
			continue
		}
		user.Admin = true
		if err := store.Users().Update(ctx, user); err != nil {
			logger.Error("failed to grant admin", "email", email, "error", err)
			continue
		}
		logger.Info("granted admin access", "email", email)
	}
}

// newMailer builds the outbound mailer selected by IDPICO_MAIL_DRIVER.
func newMailer(cfg *config.Config, logger *slog.Logger) (mail.Mailer, error) {
	switch cfg.MailDriver {
	case config.MailDriverSMTP:
		logger.Info("using smtp mailer", "host", cfg.SMTPHost, "port", cfg.SMTPPort, "from", cfg.SMTPFrom)
		return mail.NewSMTPMailer(mail.SMTPConfig{
			Host:        cfg.SMTPHost,
			Port:        cfg.SMTPPort,
			Username:    cfg.SMTPUsername,
			Password:    cfg.SMTPPassword,
			From:        cfg.SMTPFrom,
			ImplicitTLS: cfg.SMTPImplicitTLS,
		})
	default:
		logger.Info("using log mailer: emails are written to the server log, not sent")
		return mail.NewLogMailer(logger), nil
	}
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// bootstrapData creates users and clients from environment variables if they don't exist.
func bootstrapData(ctx context.Context, cfg *config.Config, store store.Store, logger *slog.Logger) {
	// Bootstrap users
	for _, u := range cfg.ParseBootstrapUsers() {
		// Check if user already exists
		if _, err := store.Users().GetByEmail(ctx, u.Email); err == nil {
			continue
		}

		hash, err := auth.HashPassword(u.Password)
		if err != nil {
			logger.Error("failed to hash password for bootstrap user", "email", u.Email, "error", err)
			continue
		}

		user := &domain.User{
			ID:            uuid.New().String(),
			Email:         u.Email,
			PasswordHash:  hash,
			DisplayName:   u.Name,
			Active:        true,
			EmailVerified: true, // provisioned by the operator
		}

		if err := store.Users().Create(ctx, user); err != nil {
			logger.Error("failed to create bootstrap user", "email", u.Email, "error", err)
		} else {
			logger.Info("created bootstrap user", "email", u.Email)
		}
	}

	// Bootstrap clients
	for _, c := range cfg.ParseBootstrapClients() {
		// Check if client already exists
		if _, err := store.Clients().GetByID(ctx, c.ID); err == nil {
			continue
		}

		secretHash := ""
		if c.Secret != "" {
			hash, err := oidc.HashClientSecret(c.Secret)
			if err != nil {
				logger.Error("failed to hash bootstrap client secret", "client_id", c.ID, "error", err)
				continue
			}
			secretHash = hash
		}

		client := &domain.Client{
			ID:           c.ID,
			Secret:       secretHash,
			Name:         c.ID,
			RedirectURIs: c.RedirectURIs,
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			Scopes:       []string{"openid", "profile", "email", "offline_access", "groups"},
			Public:       c.Public,
		}

		if err := store.Clients().Create(ctx, client); err != nil {
			logger.Error("failed to create bootstrap client", "client_id", c.ID, "error", err)
		} else {
			logger.Info("created bootstrap client", "client_id", c.ID, "public", c.Public)
		}
	}
}
