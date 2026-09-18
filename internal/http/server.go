package http

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/tendant/simple-idp/internal/audit"
	"github.com/tendant/simple-idp/internal/auth"
	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/metrics"
	"github.com/tendant/simple-idp/internal/oidc"
	"github.com/tendant/simple-idp/internal/store"
)

// Server represents the HTTP server.
type Server struct {
	router                *chi.Mux
	server                *http.Server
	logger                *slog.Logger
	keyService            *crypto.KeyService
	authService           *auth.Service
	accountService        *auth.AccountService
	accountResetTTL       string
	authorizeService      *oidc.AuthorizeService
	consentService        *oidc.ConsentService
	tokenService          *oidc.TokenService
	userInfoService       *oidc.UserInfoService
	issuerURL             string
	loginRateLimit        int // requests per minute, 0 = disabled
	corsConfig            *CORSConfig
	securityHeadersConfig *SecurityHeadersConfig
	metricsEnabled        bool
	adminConfig           *AdminConfig
	groupsClaim           string
	audit                 *audit.Recorder
	playground            bool
	playgroundClients     store.ClientRepository
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

// WithAccountService enables the password reset and email verification
// pages. resetTTL is shown to users as the link lifetime (e.g. "1 hour").
func WithAccountService(accountService *auth.AccountService, resetTTL string) Option {
	return func(s *Server) {
		s.accountService = accountService
		s.accountResetTTL = resetTTL
	}
}

// WithPlayground mounts the built-in OIDC relying party at /playground and
// registers its client in the given repository.
func WithPlayground(clients store.ClientRepository) Option {
	return func(s *Server) {
		s.playground = true
		s.playgroundClients = clients
	}
}

// WithAudit records consent decisions and admin actions.
func WithAudit(rec *audit.Recorder) Option {
	return func(s *Server) {
		s.audit = rec
	}
}

// WithGroupsClaim advertises the groups scope and claim in discovery.
func WithGroupsClaim(name string) Option {
	return func(s *Server) {
		s.groupsClaim = name
	}
}

// WithAdmin mounts the administration UI under /admin.
func WithAdmin(cfg AdminConfig) Option {
	return func(s *Server) {
		s.adminConfig = &cfg
	}
}

// WithConsentService enables the consent screen for clients that do not skip it.
func WithConsentService(consentService *oidc.ConsentService) Option {
	return func(s *Server) {
		s.consentService = consentService
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
		discovery := NewDiscoveryHandler(s.issuerURL, s.groupsClaim)
		r.Get("/.well-known/openid-configuration", discovery.OpenIDConfiguration)
	}

	// JWKS endpoint
	if s.keyService != nil {
		jwks := NewJWKSHandler(s.keyService, s.logger)
		r.Get("/.well-known/jwks.json", jwks.JWKS)
		r.Get("/jwks", jwks.JWKS)
	}

	templates := LoadTemplates(s.logger)

	// Rate limiters: "interactive" for anything a person submits (login-sized),
	// "api" for endpoints legitimate apps call frequently. Nil when disabled.
	var interactive, api func(http.Handler) http.Handler
	if s.loginRateLimit > 0 {
		interactive = httprate.LimitByIP(s.loginRateLimit, time.Minute)
		api = httprate.LimitByIP(s.loginRateLimit*10, time.Minute)
	}
	limited := func(limiter func(http.Handler) http.Handler) chi.Router {
		if limiter == nil {
			return r
		}
		return r.With(limiter)
	}

	// Login endpoints
	if s.authService != nil {
		login := NewLoginHandler(s.authService, templates, s.logger)
		r.Get("/login", login.LoginPage)

		// Apply rate limiting to login POST to prevent brute-force attacks
		limited(interactive).Post("/login", login.Login)
		if interactive != nil {
			s.logger.Info("rate limiting enabled", "interactive_per_min", s.loginRateLimit, "api_per_min", s.loginRateLimit*10)
		}

		r.Post("/logout", login.Logout)
		r.Get("/logout", login.Logout) // Also support GET for simple links

		// Self-service password reset and email verification
		if s.accountService != nil {
			login.EnableForgotPassword()
			account := NewAccountHandler(s.accountService, s.authService.CSRF(), templates, s.accountResetTTL, s.logger)
			r.Get("/forgot-password", account.ForgotPasswordPage)
			r.Get("/reset-password", account.ResetPasswordPage)
			limited(interactive).Get("/verify-email", account.VerifyEmail) // consumes a token: limit guessing
			limited(interactive).Post("/forgot-password", account.ForgotPassword)
			limited(interactive).Post("/reset-password", account.ResetPassword)
		}
	}

	// OIDC endpoints
	if s.authorizeService != nil && s.tokenService != nil && s.userInfoService != nil && s.authService != nil {
		oidcHandler := NewOIDCHandler(s.authService, s.authorizeService, s.consentService, s.tokenService, s.userInfoService, templates, s.logger)
		oidcHandler.audit = s.audit
		r.Get("/authorize", oidcHandler.Authorize)
		limited(interactive).Post("/consent", oidcHandler.Consent)

		// Endpoints apps call often get the higher "api" limit; it still
		// bounds client-secret and token guessing.
		limited(api).Post("/token", oidcHandler.Token)
		r.Get("/userinfo", oidcHandler.UserInfo)
		r.Post("/userinfo", oidcHandler.UserInfo)
		limited(api).Post("/revoke", oidcHandler.Revoke)         // RFC 7009
		limited(api).Post("/introspect", oidcHandler.Introspect) // RFC 7662
	}

	// Landing page: admins go to the admin UI, everyone else sees a status page
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		if s.authService != nil {
			if user, err := s.authService.GetCurrentUser(r.Context(), r); err == nil {
				if user.Admin && s.adminConfig != nil {
					http.Redirect(w, r, "/admin", http.StatusFound)
					return
				}
				templates.Render(w, http.StatusOK, "message", messagePageData{
					Title:     "Signed In",
					Message:   "You are signed in as " + user.Email + ".",
					BackURL:   "/logout",
					BackLabel: "Sign out",
				})
				return
			}
		}
		landing := messagePageData{
			Title:     "Simple IdP",
			Message:   "This is an OpenID Connect identity provider for local development.",
			BackURL:   "/login",
			BackLabel: "Sign in",
		}
		if s.playground {
			landing.BackURL, landing.BackLabel = "/playground", "Try the OIDC playground"
		}
		templates.Render(w, http.StatusOK, "message", landing)
	})

	// OIDC playground (built-in relying party)
	if s.playground && s.authService != nil && s.issuerURL != "" {
		pg, err := NewPlaygroundHandler(context.Background(), s.playgroundClients, s.authService.CSRF(), r, templates, s.issuerURL, s.logger)
		if err != nil {
			s.logger.Error("failed to enable playground", "error", err)
		} else {
			r.Route("/playground", pg.Routes)
			s.logger.Info("OIDC playground enabled at /playground")
		}
	}

	// Admin UI
	if s.adminConfig != nil && s.authService != nil {
		admin := NewAdminHandler(*s.adminConfig, templates, s.logger)
		admin.audit = s.audit
		r.Route("/admin", admin.Routes)
		s.logger.Info("admin UI enabled at /admin")
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
