package http

import (
	"context"
	"errors"
	"fmt"
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
	// postLogoutRedirect resolves an absolute post_logout_redirect_uri for a
	// client (oidc.TokenService.PostLogoutRedirect); nil allows only
	// same-origin paths.
	postLogoutRedirect func(ctx context.Context, idTokenHint, clientID, redirectURI, state string) (string, error)
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
		if returnURL == "" || !isValidReturnURL(returnURL) {
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
	if errors.Is(err, auth.ErrSecondFactorRequired) {
		next := "/login/code"
		if returnURL != "" && isValidReturnURL(returnURL) {
			next += "?return_url=" + url.QueryEscape(returnURL)
		}
		http.Redirect(w, r, next, http.StatusFound)
		return
	}
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

// Logout handles GET/POST /logout - terminates the session (OIDC end_session_endpoint,
// RP-Initiated Logout 1.0). Parameters, from the query or a form body:
//   - id_token_hint: an ID token issued to the client; it may have expired.
//   - client_id: names the client when there is no id_token_hint.
//   - post_logout_redirect_uri: where to send the user afterwards: a path on
//     this server, or a redirect URI registered for the client named above.
//   - state: passed back to post_logout_redirect_uri.
func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.authService.Logout(r.Context(), w, r); err != nil {
		h.logger.Error("logout error", "error", err)
	}

	postLogoutRedirectURI := r.FormValue("post_logout_redirect_uri")
	state := r.FormValue("state")

	if postLogoutRedirectURI != "" {
		redirectURL, err := h.resolvePostLogoutRedirect(r, postLogoutRedirectURI, state)
		if err == nil {
			h.logger.Info("logout completed", "redirect", redirectURL)
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		h.logger.Warn("invalid post_logout_redirect_uri", "uri", postLogoutRedirectURI, "error", err)
	}

	// Default: redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}

// resolvePostLogoutRedirect accepts a same-origin path as is, and anything
// else only when it is registered for the client the request names.
func (h *LoginHandler) resolvePostLogoutRedirect(r *http.Request, uri, state string) (string, error) {
	if isValidReturnURL(uri) {
		if state != "" {
			u, err := url.Parse(uri)
			if err != nil {
				return "", err
			}
			q := u.Query()
			q.Set("state", state)
			u.RawQuery = q.Encode()
			uri = u.String()
		}
		return uri, nil
	}
	if h.postLogoutRedirect == nil {
		return "", fmt.Errorf("only same-origin paths are allowed")
	}
	return h.postLogoutRedirect(r.Context(), r.FormValue("id_token_hint"), r.FormValue("client_id"), uri, state)
}

// CodePage handles GET /login/code - the second step for a user with an
// authenticator, after the password was accepted.
func (h *LoginHandler) CodePage(w http.ResponseWriter, r *http.Request) {
	returnURL := r.URL.Query().Get("return_url")
	if !h.authService.HasPendingLogin(r) {
		h.restartLogin(w, r, returnURL)
		return
	}
	h.renderCodePage(w, http.StatusOK, returnURL, "")
}

// Code handles POST /login/code.
func (h *LoginHandler) Code(w http.ResponseWriter, r *http.Request) {
	returnURL := r.FormValue("return_url")
	user, err := h.authService.CompleteSecondFactor(r.Context(), w, r, r.FormValue("code"))
	switch {
	case errors.Is(err, auth.ErrInvalidCode):
		h.renderCodePage(w, http.StatusUnauthorized, returnURL, "That code is not valid. Check the time on your device, or use a recovery code.")
		return
	case errors.Is(err, auth.ErrPendingLoginExpired):
		h.restartLogin(w, r, returnURL)
		return
	case idperrors.IsCode(err, idperrors.CodeForbidden):
		msg := "Invalid request. Please try again."
		if e, ok := err.(*idperrors.Error); ok && e.Message == "account is temporarily locked" {
			msg = "Account is temporarily locked due to too many failed attempts. Please try again later."
		}
		h.renderCodePage(w, http.StatusForbidden, returnURL, msg)
		return
	case err != nil:
		h.logger.Error("second factor failed", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.logger.Info("second factor accepted", "user_id", user.ID)
	if returnURL == "" || !isValidReturnURL(returnURL) {
		returnURL = "/"
	}
	http.Redirect(w, r, returnURL, http.StatusFound)
}

// restartLogin sends the browser back to the password form when there is no
// pending login (expired, too many wrong codes, or a restart).
func (h *LoginHandler) restartLogin(w http.ResponseWriter, r *http.Request, returnURL string) {
	q := url.Values{"message": {"Your sign-in expired. Please enter your password again."}}
	if returnURL != "" && isValidReturnURL(returnURL) {
		q.Set("return_url", returnURL)
	}
	http.Redirect(w, r, "/login?"+q.Encode(), http.StatusFound)
}

func (h *LoginHandler) renderCodePage(w http.ResponseWriter, status int, returnURL, errMsg string) {
	csrfToken, err := h.authService.CSRF().GenerateToken(w)
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	h.templates.Render(w, status, "login_code", loginPageData{CSRFToken: csrfToken, ReturnURL: returnURL, Error: errMsg})
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
