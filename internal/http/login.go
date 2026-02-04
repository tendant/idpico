package http

import (
	"html/template"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/tendant/simple-idp/internal/auth"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

// LoginHandler handles login endpoints.
type LoginHandler struct {
	authService *auth.Service
	logger      *slog.Logger
	template    *template.Template
}

// NewLoginHandler creates a new LoginHandler.
func NewLoginHandler(authService *auth.Service, logger *slog.Logger) *LoginHandler {
	tmpl := template.Must(template.New("login").Parse(loginTemplate))
	return &LoginHandler{
		authService: authService,
		logger:      logger,
		template:    tmpl,
	}
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

	data := loginPageData{
		CSRFToken: csrfToken,
		ReturnURL: r.URL.Query().Get("return_url"),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.template.Execute(w, data); err != nil {
		h.logger.Error("failed to render login page", "error", err)
	}
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
			errMsg = "Invalid request. Please try again."
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

// Logout handles GET/POST /logout - terminates the session.
// Supports OIDC RP-initiated logout with post_logout_redirect_uri parameter.
func (h *LoginHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.authService.Logout(r.Context(), w, r); err != nil {
		h.logger.Error("logout error", "error", err)
	}

	// Check for OIDC RP-initiated logout parameters
	postLogoutRedirectURI := r.URL.Query().Get("post_logout_redirect_uri")
	if postLogoutRedirectURI == "" {
		postLogoutRedirectURI = r.FormValue("post_logout_redirect_uri")
	}

	// If post_logout_redirect_uri is provided, redirect there
	if postLogoutRedirectURI != "" {
		// Validate the redirect URI (basic validation - must be absolute URL)
		if isValidPostLogoutRedirectURI(postLogoutRedirectURI) {
			state := r.URL.Query().Get("state")
			if state == "" {
				state = r.FormValue("state")
			}
			redirectURL := postLogoutRedirectURI
			if state != "" {
				if u, err := url.Parse(redirectURL); err == nil {
					q := u.Query()
					q.Set("state", state)
					u.RawQuery = q.Encode()
					redirectURL = u.String()
				}
			}
			http.Redirect(w, r, redirectURL, http.StatusFound)
			return
		}
		h.logger.Warn("invalid post_logout_redirect_uri", "uri", postLogoutRedirectURI)
	}

	// Default: redirect to login page
	http.Redirect(w, r, "/login", http.StatusFound)
}

// isValidPostLogoutRedirectURI validates the post-logout redirect URI.
func isValidPostLogoutRedirectURI(uri string) bool {
	u, err := url.Parse(uri)
	if err != nil {
		return false
	}
	// Must be an absolute URL with https (or http for localhost)
	if u.Scheme != "https" && !(u.Scheme == "http" && (u.Host == "localhost" || u.Hostname() == "127.0.0.1")) {
		return false
	}
	return u.Host != ""
}

func (h *LoginHandler) renderLoginError(w http.ResponseWriter, errMsg, returnURL string) {
	// Generate new CSRF token
	csrfToken, _ := h.authService.CSRF().GenerateToken(w)

	data := loginPageData{
		CSRFToken: csrfToken,
		ReturnURL: returnURL,
		Error:     errMsg,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	if err := h.template.Execute(w, data); err != nil {
		h.logger.Error("failed to render login page", "error", err)
	}
}

// isValidReturnURL validates the return URL to prevent open redirect.
func isValidReturnURL(returnURL string) bool {
	if returnURL == "" {
		return false
	}

	u, err := url.Parse(returnURL)
	if err != nil {
		return false
	}

	// Only allow relative URLs (no scheme or host)
	return u.Scheme == "" && u.Host == ""
}

type loginPageData struct {
	CSRFToken string
	ReturnURL string
	Error     string
}

const loginTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Simple IdP</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #f5f5f5;
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }
        h1 {
            margin: 0 0 30px 0;
            font-size: 24px;
            font-weight: 600;
            text-align: center;
            color: #333;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #555;
        }
        input[type="email"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            transition: border-color 0.2s;
        }
        input[type="email"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #007bff;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: background 0.2s;
        }
        button:hover {
            background: #0056b3;
        }
        .error {
            background: #fee;
            color: #c00;
            padding: 12px;
            border-radius: 4px;
            margin-bottom: 20px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Sign In</h1>
        {{if .Error}}
        <div class="error">{{.Error}}</div>
        {{end}}
        <form method="POST" action="/login">
            <input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
            {{if .ReturnURL}}
            <input type="hidden" name="return_url" value="{{.ReturnURL}}">
            {{end}}
            <div class="form-group">
                <label for="email">Email</label>
                <input type="email" id="email" name="email" required autofocus>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit">Sign In</button>
        </form>
    </div>
</body>
</html>`
