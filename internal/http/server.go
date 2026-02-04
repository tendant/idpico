package http

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/tendant/simple-idp/internal/auth"
	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/metrics"
	"github.com/tendant/simple-idp/internal/oidc"
)

// Server represents the HTTP server.
type Server struct {
	router                *chi.Mux
	server                *http.Server
	logger                *slog.Logger
	keyService            *crypto.KeyService
	authService           *auth.Service
	authorizeService      *oidc.AuthorizeService
	tokenService          *oidc.TokenService
	userInfoService       *oidc.UserInfoService
	issuerURL             string
	loginRateLimit        int // requests per minute, 0 = disabled
	corsConfig            *CORSConfig
	securityHeadersConfig *SecurityHeadersConfig
	metricsEnabled        bool
}

// Option configures the Server.
type Option func(*Server)

// WithLogger sets the logger for the server.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Server) {
		s.logger = logger
	}
}

// WithKeyService sets the key service for JWKS endpoint.
func WithKeyService(keyService *crypto.KeyService) Option {
	return func(s *Server) {
		s.keyService = keyService
	}
}

// WithIssuerURL sets the issuer URL for OIDC discovery.
func WithIssuerURL(issuerURL string) Option {
	return func(s *Server) {
		s.issuerURL = issuerURL
	}
}

// WithAuthService sets the auth service for login endpoints.
func WithAuthService(authService *auth.Service) Option {
	return func(s *Server) {
		s.authService = authService
	}
}

// WithOIDCServices sets the OIDC services.
func WithOIDCServices(authorizeService *oidc.AuthorizeService, tokenService *oidc.TokenService, userInfoService *oidc.UserInfoService) Option {
	return func(s *Server) {
		s.authorizeService = authorizeService
		s.tokenService = tokenService
		s.userInfoService = userInfoService
	}
}

// WithLoginRateLimit sets the login rate limit (requests per minute per IP).
func WithLoginRateLimit(limit int) Option {
	return func(s *Server) {
		s.loginRateLimit = limit
	}
}

// WithCORS sets the CORS configuration.
func WithCORS(config *CORSConfig) Option {
	return func(s *Server) {
		s.corsConfig = config
	}
}

// WithSecurityHeaders sets the security headers configuration.
func WithSecurityHeaders(config *SecurityHeadersConfig) Option {
	return func(s *Server) {
		s.securityHeadersConfig = config
	}
}

// WithMetrics enables Prometheus metrics.
func WithMetrics(enabled bool) Option {
	return func(s *Server) {
		s.metricsEnabled = enabled
	}
}

// NewServer creates a new HTTP server with default middleware.
func NewServer(addr string, opts ...Option) *Server {
	r := chi.NewRouter()

	s := &Server{
		router: r,
		logger: slog.Default(),
	}

	for _, opt := range opts {
		opt(s)
	}

	// Default middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Security headers middleware (applied to all routes)
	if s.securityHeadersConfig != nil {
		r.Use(SecurityHeadersMiddleware(s.securityHeadersConfig))
		s.logger.Info("security headers enabled")
	}

	// CORS middleware (applied to all routes)
	if s.corsConfig != nil && len(s.corsConfig.AllowedOrigins) > 0 {
		r.Use(CORSMiddleware(s.corsConfig))
		s.logger.Info("CORS enabled", "origins", s.corsConfig.AllowedOrigins)
	}

	// Metrics middleware (applied to all routes)
	if s.metricsEnabled {
		r.Use(metrics.Middleware)
		s.logger.Info("metrics enabled")
	}

	// Request logging middleware
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				s.logger.Info("request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.Status(),
					"duration", time.Since(start),
					"request_id", middleware.GetReqID(r.Context()),
				)
			}()
			next.ServeHTTP(ww, r)
		})
	})

	// Health endpoints
	health := NewHealthHandler()
	r.Get("/healthz", health.Healthz)
	r.Get("/readyz", health.Readyz)

	// Metrics endpoint
	if s.metricsEnabled {
		r.Handle("/metrics", metrics.Handler())
	}

	// OIDC discovery endpoint
	if s.issuerURL != "" {
		discovery := NewDiscoveryHandler(s.issuerURL)
		r.Get("/.well-known/openid-configuration", discovery.OpenIDConfiguration)
	}

	// JWKS endpoint
	if s.keyService != nil {
		jwks := NewJWKSHandler(s.keyService, s.logger)
		r.Get("/.well-known/jwks.json", jwks.JWKS)
		r.Get("/jwks", jwks.JWKS)
	}

	// Login endpoints
	if s.authService != nil {
		login := NewLoginHandler(s.authService, s.logger)
		r.Get("/login", login.LoginPage)

		// Apply rate limiting to login POST to prevent brute-force attacks
		if s.loginRateLimit > 0 {
			r.With(httprate.LimitByIP(s.loginRateLimit, time.Minute)).Post("/login", login.Login)
			s.logger.Info("login rate limiting enabled", "limit", s.loginRateLimit, "window", "1m")
		} else {
			r.Post("/login", login.Login)
		}

		r.Post("/logout", login.Logout)
		r.Get("/logout", login.Logout) // Also support GET for simple links
	}

	// OIDC endpoints
	if s.authorizeService != nil && s.tokenService != nil && s.userInfoService != nil && s.authService != nil {
		oidcHandler := NewOIDCHandler(s.authService, s.authorizeService, s.tokenService, s.userInfoService, s.logger)
		r.Get("/authorize", oidcHandler.Authorize)

		// Apply rate limiting to token endpoint to prevent brute-force attacks
		if s.loginRateLimit > 0 {
			// Token endpoint gets higher limit since legitimate apps make frequent requests
			r.With(httprate.LimitByIP(s.loginRateLimit*10, time.Minute)).Post("/token", oidcHandler.Token)
		} else {
			r.Post("/token", oidcHandler.Token)
		}

		r.Get("/userinfo", oidcHandler.UserInfo)
		r.Post("/userinfo", oidcHandler.UserInfo)

		// Token revocation endpoint (RFC 7009)
		r.Post("/revoke", oidcHandler.Revoke)

		// Token introspection endpoint (RFC 7662)
		r.Post("/introspect", oidcHandler.Introspect)
	}

	s.server = &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Router returns the chi router for adding routes.
func (s *Server) Router() *chi.Mux {
	return s.router
}

// Start starts the HTTP server.
func (s *Server) Start() error {
	s.logger.Info("starting server", "addr", s.server.Addr)
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down server")
	return s.server.Shutdown(ctx)
}
