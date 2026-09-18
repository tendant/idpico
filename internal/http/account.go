package http

import (
	"log/slog"
	"net/http"
	"net/url"

	"github.com/tendant/simple-idp/internal/auth"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

// AccountHandler serves the self-service password reset and email
// verification pages.
type AccountHandler struct {
	accounts  *auth.AccountService
	csrf      *auth.CSRFService
	templates *Templates
	logger    *slog.Logger
	resetTTL  string
}

// NewAccountHandler creates an AccountHandler.
func NewAccountHandler(accounts *auth.AccountService, csrf *auth.CSRFService, templates *Templates, resetTTL string, logger *slog.Logger) *AccountHandler {
	return &AccountHandler{
		accounts:  accounts,
		csrf:      csrf,
		templates: templates,
		logger:    logger,
		resetTTL:  resetTTL,
	}
}

type forgotPasswordData struct {
	CSRFToken string
	Email     string
	Error     string
	Sent      bool
	TTL       string
}

type resetPasswordData struct {
	CSRFToken string
	Token     string
	Error     string
	MinLength int
}

type messagePageData struct {
	Title     string
	Message   string
	Error     string
	BackURL   string
	BackLabel string
}

// ForgotPasswordPage handles GET /forgot-password.
func (h *AccountHandler) ForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	h.renderForgot(w, http.StatusOK, forgotPasswordData{})
}

// ForgotPassword handles POST /forgot-password.
func (h *AccountHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderForgot(w, http.StatusBadRequest, forgotPasswordData{Error: "Invalid form data"})
		return
	}
	email := r.FormValue("email")
	if err := h.csrf.ValidateToken(r); err != nil {
		h.renderForgot(w, http.StatusBadRequest, forgotPasswordData{Email: email, Error: "Invalid or expired form, please try again"})
		return
	}
	if email == "" {
		h.renderForgot(w, http.StatusBadRequest, forgotPasswordData{Error: "Email is required"})
		return
	}

	if err := h.accounts.RequestPasswordReset(r.Context(), email); err != nil {
		h.logger.Error("password reset request failed", "error", err)
		h.renderForgot(w, http.StatusInternalServerError, forgotPasswordData{Email: email, Error: "Something went wrong, please try again later"})
		return
	}

	h.csrf.ClearToken(w)
	h.templates.Render(w, http.StatusOK, "forgot_password", forgotPasswordData{Email: email, Sent: true, TTL: h.resetTTL})
}

// ResetPasswordPage handles GET /reset-password?token=...
func (h *AccountHandler) ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		h.renderInvalidLink(w)
		return
	}
	h.renderReset(w, http.StatusOK, resetPasswordData{Token: token})
}

// ResetPassword handles POST /reset-password.
func (h *AccountHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderReset(w, http.StatusBadRequest, resetPasswordData{Error: "Invalid form data"})
		return
	}
	token := r.FormValue("token")
	if err := h.csrf.ValidateToken(r); err != nil {
		h.renderReset(w, http.StatusBadRequest, resetPasswordData{Token: token, Error: "Invalid or expired form, please try again"})
		return
	}

	password, confirm := r.FormValue("password"), r.FormValue("confirm")
	if password != confirm {
		h.renderReset(w, http.StatusBadRequest, resetPasswordData{Token: token, Error: "Passwords do not match"})
		return
	}

	if _, err := h.accounts.ResetPassword(r.Context(), token, password); err != nil {
		switch {
		case idperrors.IsCode(err, idperrors.CodeInvalidInput):
			h.renderReset(w, http.StatusBadRequest, resetPasswordData{Token: token, Error: userMessage(err)})
		case idperrors.IsCode(err, idperrors.CodeTokenInvalid):
			h.renderInvalidLink(w)
		default:
			h.logger.Error("password reset failed", "error", err)
			h.renderReset(w, http.StatusInternalServerError, resetPasswordData{Token: token, Error: "Something went wrong, please try again later"})
		}
		return
	}

	h.csrf.ClearToken(w)
	http.Redirect(w, r, "/login?message="+url.QueryEscape("Your password has been updated. Please sign in."), http.StatusFound)
}

// VerifyEmail handles GET /verify-email?token=...
func (h *AccountHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	user, err := h.accounts.VerifyEmail(r.Context(), r.URL.Query().Get("token"))
	if err != nil {
		if !idperrors.IsCode(err, idperrors.CodeTokenInvalid) {
			h.logger.Error("email verification failed", "error", err)
		}
		h.templates.Render(w, http.StatusBadRequest, "message", messagePageData{
			Title:     "Verification Failed",
			Error:     "This verification link is invalid or has expired.",
			BackURL:   "/login",
			BackLabel: "Go to sign in",
		})
		return
	}

	h.templates.Render(w, http.StatusOK, "message", messagePageData{
		Title:     "Email Verified",
		Message:   user.Email + " has been verified.",
		BackURL:   "/login",
		BackLabel: "Go to sign in",
	})
}

func (h *AccountHandler) renderForgot(w http.ResponseWriter, status int, data forgotPasswordData) {
	data.CSRFToken, _ = h.csrf.GenerateToken(w)
	data.TTL = h.resetTTL
	h.templates.Render(w, status, "forgot_password", data)
}

func (h *AccountHandler) renderReset(w http.ResponseWriter, status int, data resetPasswordData) {
	data.CSRFToken, _ = h.csrf.GenerateToken(w)
	data.MinLength = auth.MinPasswordLength
	h.templates.Render(w, status, "reset_password", data)
}

func (h *AccountHandler) renderInvalidLink(w http.ResponseWriter) {
	h.templates.Render(w, http.StatusBadRequest, "message", messagePageData{
		Title:     "Link Invalid",
		Error:     "This password reset link is invalid or has expired. Please request a new one.",
		BackURL:   "/forgot-password",
		BackLabel: "Request a new link",
	})
}

// userMessage returns the message of a structured error, suitable for display.
func userMessage(err error) string {
	if e, ok := err.(*idperrors.Error); ok {
		return e.Message
	}
	return err.Error()
}
