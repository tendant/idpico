package http

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/tendant/simple-idp/internal/auth"
	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/oidc"
)

// Server represents the HTTP server.
type Server struct {
	router           *chi.Mux
	server           *http.Server
	logger           *slog.Logger
	keyService       *crypto.KeyService
	authService      *auth.Service
	authorizeService *oidc.AuthorizeService
	tokenService     *oidc.TokenService
	userInfoService  *oidc.UserInfoService
	issuerURL        string
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
		r.Post("/login", login.Login)
		r.Post("/logout", login.Logout)
		r.Get("/logout", login.Logout) // Also support GET for simple links
	}

	// OIDC endpoints
	if s.authorizeService != nil && s.tokenService != nil && s.userInfoService != nil && s.authService != nil {
		oidcHandler := NewOIDCHandler(s.authService, s.authorizeService, s.tokenService, s.userInfoService, s.logger)
		r.Get("/authorize", oidcHandler.Authorize)
		r.Post("/token", oidcHandler.Token)
		r.Get("/userinfo", oidcHandler.UserInfo)
		r.Post("/userinfo", oidcHandler.UserInfo)
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
