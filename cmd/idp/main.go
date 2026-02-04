// Package main is the entry point for the simple-idp Identity Provider.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"github.com/tendant/simple-idp/internal/auth"
	"github.com/tendant/simple-idp/internal/config"
	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/domain"
	idphttp "github.com/tendant/simple-idp/internal/http"
	"github.com/tendant/simple-idp/internal/oidc"
	"github.com/tendant/simple-idp/internal/store/file"
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
		logger.Warn("using auto-generated cookie secret - sessions will not persist across restarts. Set IDP_COOKIE_SECRET for production.")
	}

	// Initialize file store
	store, err := file.NewStore(cfg.DataDir)
	if err != nil {
		logger.Error("failed to initialize store", "error", err)
		os.Exit(1)
	}
	defer store.Close()

	logger.Info("initialized file store", "data_dir", cfg.DataDir)

	// Bootstrap users and clients from environment variables
	bootstrapData(context.Background(), cfg, store, logger)

	// Initialize key service for JWT signing
	keyRepo := file.NewKeyRepository(cfg.DataDir)
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
	)

	// Initialize token generator
	tokenGenerator := crypto.NewTokenGenerator(activeKey, cfg.IssuerURL, cfg.IssuerURL)

	// Initialize OIDC services
	authorizeService := oidc.NewAuthorizeService(
		store.Clients(),
		store.AuthCodes(),
		cfg.AuthCodeTTL,
	)

	tokenService := oidc.NewTokenService(
		store.Clients(),
		store.AuthCodes(),
		store.Tokens(),
		store.Users(),
		tokenGenerator,
		cfg.IssuerURL,
		cfg.AccessTokenTTL,
		cfg.RefreshTokenTTL,
	)

	userInfoService := oidc.NewUserInfoService(store.Users(), tokenGenerator)

	// Create HTTP server
	server := idphttp.NewServer(
		cfg.Addr(),
		idphttp.WithLogger(logger),
		idphttp.WithKeyService(keyService),
		idphttp.WithIssuerURL(cfg.IssuerURL),
		idphttp.WithAuthService(authService),
		idphttp.WithOIDCServices(authorizeService, tokenService, userInfoService),
		idphttp.WithLoginRateLimit(cfg.LoginRateLimit),
	)

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
func bootstrapData(ctx context.Context, cfg *config.Config, store *file.Store, logger *slog.Logger) {
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
			ID:           uuid.New().String(),
			Email:        u.Email,
			PasswordHash: hash,
			DisplayName:  u.Name,
			Active:       true,
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

		client := &domain.Client{
			ID:           c.ID,
			Secret:       c.Secret,
			Name:         c.ID,
			RedirectURIs: c.RedirectURIs,
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			Scopes:       []string{"openid", "profile", "email", "offline_access"},
			Public:       c.Public,
		}

		if err := store.Clients().Create(ctx, client); err != nil {
			logger.Error("failed to create bootstrap client", "client_id", c.ID, "error", err)
		} else {
			logger.Info("created bootstrap client", "client_id", c.ID, "public", c.Public)
		}
	}
}
