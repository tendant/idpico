package http

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/idpico/internal/audit"
	"github.com/tendant/idpico/internal/auth"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/store"
)

// AccountPageHandler serves /account: the signed-in user's own sessions,
// refresh tokens and consents, with the same revoke actions an admin has on
// the user's page, plus a password change. Every action is scoped to the
// current user; nothing here takes a user id from the request.
type AccountPageHandler struct {
	store     store.Store
	auth      *auth.Service
	account   *auth.AccountService // nil: no password change form
	templates *Templates
	logger    *slog.Logger
	audit     *audit.Recorder
}

func NewAccountPageHandler(st store.Store, authService *auth.Service, account *auth.AccountService, templates *Templates, logger *slog.Logger, rec *audit.Recorder) *AccountPageHandler {
	return &AccountPageHandler{store: st, auth: authService, account: account, templates: templates, logger: logger, audit: rec}
}

// Routes mounts the page and its actions; every route requires a session.
func (h *AccountPageHandler) Routes(r chi.Router) {
	r.Group(func(r chi.Router) {
		r.Use(h.requireUser)
		r.Get("/account", h.Page)
		r.Post("/account/password", h.ChangePassword)
		r.Post("/account/sessions/{sessionID}/revoke", h.RevokeSession)
		r.Post("/account/sessions/revoke-others", h.RevokeOtherSessions)
		r.Post("/account/tokens/{tokenID}/revoke", h.RevokeToken)
		r.Post("/account/consents/{clientID}/revoke", h.RevokeConsent)
	})
}

type accountUserKey struct{}

func (h *AccountPageHandler) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := h.auth.GetCurrentUser(r.Context(), r)
		if err != nil {
			http.Redirect(w, r, "/login?return_url="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), accountUserKey{}, user)))
	})
}

func (h *AccountPageHandler) user(r *http.Request) *domain.User {
	u, _ := r.Context().Value(accountUserKey{}).(*domain.User)
	return u
}

// currentSessionID identifies the browser making the request so the page can
// mark it and "sign out everywhere else" can keep it.
func (h *AccountPageHandler) currentSessionID(r *http.Request) string {
	sess, err := h.auth.Sessions().GetSessionFromRequest(r.Context(), r)
	if err != nil {
		return ""
	}
	return sess.ID
}

// wideBase carries what the wide layout (playground, account) needs; page
// data structs embed it. CurrentUser is nil on anonymous pages.
type wideBase struct {
	Section     string
	CurrentUser *domain.User
	CSRFToken   string
	Flash       string
	Error       string
}

type accountSession struct {
	*domain.Session
	Current bool
}

type accountPageData struct {
	wideBase
	Sessions          []accountSession
	Tokens            []*domain.Token
	Consents          []*domain.Consent
	CanChangePassword bool
	MinPasswordLength int
}

func (h *AccountPageHandler) Page(w http.ResponseWriter, r *http.Request) {
	h.render(w, r, http.StatusOK, "")
}

func (h *AccountPageHandler) render(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	ctx := r.Context()
	user := h.user(r)
	current := h.currentSessionID(r)

	data := accountPageData{
		wideBase:          h.base(w, r),
		CanChangePassword: h.account != nil,
		MinPasswordLength: auth.MinPasswordLength,
	}
	data.Error = errMsg
	if sessions, err := h.store.Sessions().ListByUserID(ctx, user.ID); err == nil {
		for _, s := range sessions {
			data.Sessions = append(data.Sessions, accountSession{Session: s, Current: s.ID == current})
		}
	}
	if tokens, err := h.store.Tokens().ListByUserID(ctx, user.ID); err == nil {
		for _, t := range tokens {
			if !t.Revoked {
				data.Tokens = append(data.Tokens, t)
			}
		}
	}
	data.Consents, _ = h.store.Consents().ListByUserID(ctx, user.ID)
	h.templates.Render(w, status, "wide/account", data)
}

func (h *AccountPageHandler) base(w http.ResponseWriter, r *http.Request) wideBase {
	token, err := h.auth.CSRF().GenerateToken(w)
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
	}
	return wideBase{
		Section:     "account",
		CurrentUser: h.user(r),
		CSRFToken:   token,
		Flash:       r.URL.Query().Get("flash"),
	}
}

// checkCSRF validates the form token; on failure it re-renders the page with
// an error so the user can simply retry.
func (h *AccountPageHandler) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		h.render(w, r, http.StatusBadRequest, "Invalid form data")
		return false
	}
	if err := h.auth.CSRF().ValidateToken(r); err != nil {
		h.render(w, r, http.StatusBadRequest, "Invalid or expired form, please try again")
		return false
	}
	return true
}

func (h *AccountPageHandler) done(w http.ResponseWriter, r *http.Request, flash string) {
	http.Redirect(w, r, "/account?flash="+url.QueryEscape(flash), http.StatusFound)
}

func (h *AccountPageHandler) record(r *http.Request, action, detail string) {
	user := h.user(r)
	h.audit.Record(r.Context(), audit.Event{Actor: user, Action: action, TargetType: "user", TargetID: user.ID, Detail: detail, IP: audit.ClientIP(r)})
}

func (h *AccountPageHandler) RevokeSession(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	ctx := r.Context()
	user := h.user(r)
	id := chi.URLParam(r, "sessionID")
	sess, err := h.store.Sessions().GetByID(ctx, id)
	if err != nil || sess.UserID != user.ID {
		h.done(w, r, "Session not found")
		return
	}
	if err := h.store.Sessions().Delete(ctx, id); err != nil && !idperrors.IsCode(err, idperrors.CodeNotFound) {
		h.logger.Error("failed to revoke session", "error", err)
		h.render(w, r, http.StatusInternalServerError, "Failed to sign out that session")
		return
	}
	h.record(r, audit.UserSessionRevoked, "session "+id+" (self-service)")
	if id == h.currentSessionID(r) {
		// The user signed out this very browser: finish the job properly.
		_ = h.auth.Logout(ctx, w, r)
		http.Redirect(w, r, "/login?message="+url.QueryEscape("Signed out"), http.StatusFound)
		return
	}
	h.done(w, r, "Session signed out")
}

// RevokeOtherSessions signs the user out of every browser but this one and
// revokes all their refresh tokens.
func (h *AccountPageHandler) RevokeOtherSessions(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	ctx := r.Context()
	user := h.user(r)
	current := h.currentSessionID(r)
	sessions, err := h.store.Sessions().ListByUserID(ctx, user.ID)
	if err != nil {
		h.render(w, r, http.StatusInternalServerError, "Failed to list sessions")
		return
	}
	for _, s := range sessions {
		if s.ID == current {
			continue
		}
		if err := h.store.Sessions().Delete(ctx, s.ID); err != nil && !idperrors.IsCode(err, idperrors.CodeNotFound) {
			h.logger.Error("failed to revoke session", "error", err)
		}
	}
	if err := h.store.Tokens().RevokeByUserID(ctx, user.ID); err != nil {
		h.logger.Error("failed to revoke tokens", "error", err)
	}
	h.record(r, audit.UserSessionsRevoked, "all other sessions and refresh tokens (self-service)")
	h.done(w, r, "Signed out everywhere else; refresh tokens revoked")
}

func (h *AccountPageHandler) RevokeToken(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	ctx := r.Context()
	user := h.user(r)
	id := chi.URLParam(r, "tokenID")
	tok, err := h.store.Tokens().GetByID(ctx, id)
	if err != nil || tok.UserID != user.ID {
		h.done(w, r, "Token not found")
		return
	}
	if err := h.store.Tokens().Revoke(ctx, id); err != nil && !idperrors.IsCode(err, idperrors.CodeNotFound) {
		h.logger.Error("failed to revoke token", "error", err)
		h.render(w, r, http.StatusInternalServerError, "Failed to revoke token")
		return
	}
	h.record(r, audit.UserTokenRevoked, "token for "+tok.ClientID+" (self-service)")
	h.done(w, r, "Refresh token revoked")
}

// RevokeConsent withdraws consent for a client and revokes the refresh
// tokens it holds, so the withdrawal takes effect at once rather than at the
// next expiry.
func (h *AccountPageHandler) RevokeConsent(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	ctx := r.Context()
	user := h.user(r)
	clientID := chi.URLParam(r, "clientID")
	if err := h.store.Consents().Delete(ctx, user.ID, clientID); err != nil && !idperrors.IsCode(err, idperrors.CodeNotFound) {
		h.logger.Error("failed to revoke consent", "error", err)
		h.render(w, r, http.StatusInternalServerError, "Failed to revoke consent")
		return
	}
	if tokens, err := h.store.Tokens().ListByUserID(ctx, user.ID); err == nil {
		for _, t := range tokens {
			if t.ClientID == clientID && !t.Revoked {
				_ = h.store.Tokens().Revoke(ctx, t.ID)
			}
		}
	}
	h.record(r, audit.UserConsentRevoked, "client "+clientID+" (self-service)")
	h.done(w, r, "Access for "+clientID+" revoked")
}

// ChangePassword verifies the current password before setting the new one.
// SetPassword signs the user out everywhere, this browser included, so the
// user lands on the login page.
func (h *AccountPageHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	if h.account == nil {
		http.NotFound(w, r)
		return
	}
	if !h.checkCSRF(w, r) {
		return
	}
	ctx := r.Context()
	user := h.user(r)
	current, next, confirm := r.FormValue("current_password"), r.FormValue("new_password"), r.FormValue("confirm_password")

	if ok, err := auth.VerifyPassword(current, user.PasswordHash); err != nil || !ok {
		h.render(w, r, http.StatusBadRequest, "Current password is incorrect")
		return
	}
	if next != confirm {
		h.render(w, r, http.StatusBadRequest, "New passwords do not match")
		return
	}
	if err := h.account.SetPassword(ctx, user, next); err != nil {
		msg := "Failed to change password"
		if e, ok := err.(*idperrors.Error); ok && e.Code == idperrors.CodeInvalidInput {
			msg = e.Message
		}
		h.render(w, r, http.StatusBadRequest, msg)
		return
	}
	h.record(r, audit.PasswordChanged, "self-service")
	_ = h.auth.Logout(ctx, w, r)
	http.Redirect(w, r, "/login?message="+url.QueryEscape("Password changed; please sign in again"), http.StatusFound)
}
