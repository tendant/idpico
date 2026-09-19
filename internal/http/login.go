package http

import (
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/tendant/idpico/internal/auth"
	idperrors "github.com/tendant/idpico/internal/errors"
)

// LoginHandler handles login endpoints.
type LoginHandler struct {
	authService *auth.Service
	logger      *slog.Logger
	templates   *Templates
	// forgotPasswordURL is linked from the login form; empty hides the link.
	forgotPasswordURL string
}

// NewLoginHandler creates a new LoginHandler.
func NewLoginHandler(authService *auth.Service, templates *Templates, logger *slog.Logger) *LoginHandler {
	return &LoginHandler{
		authService: authService,
		logger:      logger,
		templates:   templates,
	}
}

// EnableForgotPassword shows the "Forgot your password?" link on the login page.
func (h *LoginHandler) EnableForgotPassword() {
	h.forgotPasswordURL = "/forgot-password"
}

// LoginPage handles GET /login - displays the login form.
func (h *LoginHandler) LoginPage(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	if h.authService.IsAuthenticated(r.Context(), r) {
		// Redirect to the return URL or home
		returnURL := r.URL.Query().Get("return_url")
		if returnURL == "" {
			returnURL = "/"
		}
		http.Redirect(w, r, returnURL, http.StatusFound)
		return
	}

	// Generate CSRF token
	csrfToken, err := h.authService.CSRF().GenerateToken(w)
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	h.templates.Render(w, http.StatusOK, "login", loginPageData{
		CSRFToken:         csrfToken,
		ReturnURL:         r.URL.Query().Get("return_url"),
		Message:           r.URL.Query().Get("message"),
		ForgotPasswordURL: h.forgotPasswordURL,
	})
}

// Login handles POST /login - processes the login form.
func (h *LoginHandler) Login(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderLoginError(w, "Invalid form data", r.FormValue("return_url"))
		return
	}

	email := r.FormValue("email")
	password := r.FormValue("password")
	returnURL := r.FormValue("return_url")

	if email == "" || password == "" {
		h.renderLoginError(w, "Email and password are required", returnURL)
		return
	}

	// Attempt login
	_, err := h.authService.Login(r.Context(), w, r, email, password)
	if err != nil {
		h.logger.Info("login failed", "email", email, "error", err)

		errMsg := "Invalid email or password"
		if idperrors.IsCode(err, idperrors.CodeForbidden) {
			// Check if it's a lockout error
			if e, ok := err.(*idperrors.Error); ok && e.Message == "account is temporarily locked" {
				errMsg = "Account is temporarily locked due to too many failed attempts. Please try again later."
			} else {
				errMsg = "Invalid request. Please try again."
			}
		}

		h.renderLoginError(w, errMsg, returnURL)
		return
	}

	// Redirect to return URL or home
	if returnURL == "" {
		returnURL = "/"
	}

	// Validate return URL to prevent open redirect
	if !isValidReturnURL(returnURL) {
		returnURL = "/"
	}

	http.Redirect(w, r, returnURL, http.StatusFound)
}

// Logout handles GET/POST /logout - terminates the session (OIDC end_session_endpoint).
// Supports the following parameters:
// - id_token_hint: Optional. The ID token previously issued to the client.
// - post_logout_redirect_uri: Optional. URL to redirect after logout (must be registered).
// - state: Optional. Opaque value to maintain state between logout request and callback.
func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.authService.Logout(r.Context(), w, r); err != nil {
		h.logger.Error("logout error", "error", err)
	}

	// Parse logout parameters
	idTokenHint := r.URL.Query().Get("id_token_hint")
	postLogoutRedirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	state := r.URL.Query().Get("state")

	// If post_logout_redirect_uri is provided, validate it
	if postLogoutRedirectURI != "" {
		// For security, we only allow redirect URIs that:
		// 1. Are relative paths (start with /)
		// 2. Or match a registered client's redirect URI (when id_token_hint is provided)
		valid := false

		// Check if it's a relative path
		if isValidReturnURL(postLogoutRedirectURI) {
			valid = true
		}

		// If id_token_hint is provided, we could validate against client's registered URIs
		// For now, we accept the hint but don't validate (development use)
		_ = idTokenHint

		if valid {
			redirectURL := postLogoutRedirectURI
			if state != "" {
				redirectURL += "?state=" + url.QueryEscape(state)
			}
			h.logger.Info("logout completed", "redirect", redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}

		h.logger.Warn("invalid post_logout_redirect_uri", "uri", postLogoutRedirectURI)
	}

	// Default: redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (h *LoginHandler) renderLoginError(w http.ResponseWriter, errMsg, returnURL string) {
	// Generate new CSRF token
	csrfToken, _ := h.authService.CSRF().GenerateToken(w)

	h.templates.Render(w, http.StatusUnauthorized, "login", loginPageData{
		CSRFToken:         csrfToken,
		ReturnURL:         returnURL,
		Error:             errMsg,
		ForgotPasswordURL: h.forgotPasswordURL,
	})
}

// isValidReturnURL validates the return URL to prevent open redirect: only
// an absolute path on this origin is accepted.
func isValidReturnURL(returnURL string) bool {
	// Must be a path, and not a scheme-relative URL ("//host") or its
	// backslash variant, which browsers also treat as leaving the origin
	// while url.Parse leaves it as a path.
	if len(returnURL) < 1 || returnURL[0] != '/' {
		return false
	}
	if len(returnURL) > 1 && (returnURL[1] == '/' || returnURL[1] == '\\') {
		return false
	}
	if strings.ContainsAny(returnURL, "\\\r\n") {
		return false
	}

	u, err := url.Parse(returnURL)
	if err != nil {
		return false
	}
	return u.Scheme == "" && u.Host == "" && u.User == nil
}

type loginPageData struct {
	CSRFToken         string
	ReturnURL         string
	Error             string
	Message           string
	ForgotPasswordURL string
}
