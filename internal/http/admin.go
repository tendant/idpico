package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/tendant/idpico/internal/audit"
	"github.com/tendant/idpico/internal/auth"
	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/oidc"
	"github.com/tendant/idpico/internal/store"
)

// AdminConfig wires the admin UI.
type AdminConfig struct {
	Store          store.Store
	AuthService    *auth.Service
	AccountService *auth.AccountService
	KeyService     *crypto.KeyService
	IssuerURL      string
	KeyGracePeriod time.Duration
	GroupsClaim    string // claim name shown on the groups page
}

// AdminHandler serves the server-rendered administration UI under /admin.
// Every page requires an authenticated session whose user has the Admin flag.
type AdminHandler struct {
	cfg       AdminConfig
	templates *Templates
	logger    *slog.Logger
	audit     *audit.Recorder
}

// record logs an admin action and appends it to the audit log.
func (h *AdminHandler) record(r *http.Request, action, targetType, targetID, detail string) {
	actor := currentAdmin(r)
	h.logger.Info("admin action", "action", action, "admin", actor.Email, targetType, targetID, "detail", detail)
	h.audit.Record(r.Context(), audit.Event{
		Actor: actor, Action: action, TargetType: targetType, TargetID: targetID, Detail: detail, IP: audit.ClientIP(r),
	})
}

// NewAdminHandler creates an AdminHandler.
func NewAdminHandler(cfg AdminConfig, templates *Templates, logger *slog.Logger) *AdminHandler {
	if cfg.KeyGracePeriod == 0 {
		cfg.KeyGracePeriod = 24 * time.Hour
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	return &AdminHandler{cfg: cfg, templates: templates, logger: logger}
}

// Routes mounts the admin UI on r.
func (h *AdminHandler) Routes(r chi.Router) {
	r.Use(h.requireAdmin)

	r.Get("/", h.Dashboard)

	r.Get("/users", h.Users)
	r.Get("/users/new", h.NewUser)
	r.Post("/users", h.CreateUser)
	r.Get("/users/{id}", h.EditUser)
	r.Post("/users/{id}", h.UpdateUser)
	r.Post("/users/{id}/password", h.SetUserPassword)
	r.Post("/users/{id}/send-reset", h.SendUserReset)
	r.Post("/users/{id}/send-verification", h.SendUserVerification)
	r.Post("/users/{id}/revoke-sessions", h.RevokeUserSessions)
	r.Post("/users/{id}/sessions/{sessionID}/revoke", h.RevokeUserSession)
	r.Post("/users/{id}/tokens/{tokenID}/revoke", h.RevokeUserToken)
	r.Post("/users/{id}/consents/{clientID}/revoke", h.RevokeUserConsent)
	r.Post("/users/{id}/delete", h.DeleteUser)

	r.Post("/users/{id}/groups", h.SetUserGroups)

	r.Get("/groups", h.Groups)
	r.Get("/groups/new", h.NewGroup)
	r.Post("/groups", h.CreateGroup)
	r.Get("/groups/{id}", h.EditGroup)
	r.Post("/groups/{id}", h.UpdateGroup)
	r.Post("/groups/{id}/members", h.AddGroupMember)
	r.Post("/groups/{id}/members/{userID}/remove", h.RemoveGroupMember)
	r.Post("/groups/{id}/delete", h.DeleteGroup)

	r.Get("/clients", h.Clients)
	r.Get("/clients/new", h.NewClient)
	r.Post("/clients", h.CreateClient)
	r.Get("/clients/{id}", h.EditClient)
	r.Post("/clients/{id}", h.UpdateClient)
	r.Post("/clients/{id}/secret", h.RegenerateClientSecret)
	r.Post("/clients/{id}/revoke-tokens", h.RevokeClientTokens)
	r.Post("/clients/{id}/delete", h.DeleteClient)

	r.Get("/keys", h.Keys)
	r.Post("/keys/rotate", h.RotateKey)

	r.Get("/audit", h.Audit)
}

// Authorization

type adminUserKey struct{}

// requireAdmin redirects anonymous requests to the login page and rejects
// signed-in users who are not administrators.
func (h *AdminHandler) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, err := h.cfg.AuthService.GetCurrentUser(r.Context(), r)
		if err != nil {
			http.Redirect(w, r, "/login?return_url="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		if !user.Admin {
			h.templates.Render(w, http.StatusForbidden, "message", messagePageData{
				Title:     "Access Denied",
				Error:     "Your account (" + user.Email + ") is not an administrator.",
				BackURL:   "/logout",
				BackLabel: "Sign out",
			})
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), adminUserKey{}, user)))
	})
}

func currentAdmin(r *http.Request) *domain.User {
	u, _ := r.Context().Value(adminUserKey{}).(*domain.User)
	return u
}

// Page plumbing

// adminBase carries what the admin layout needs; page data structs embed it.
type adminBase struct {
	Section     string
	CurrentUser *domain.User
	CSRFToken   string
	Flash       string
	Error       string
}

func (h *AdminHandler) base(w http.ResponseWriter, r *http.Request, section string) adminBase {
	token, err := h.cfg.AuthService.CSRF().GenerateToken(w)
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
	}
	return adminBase{
		Section:     section,
		CurrentUser: currentAdmin(r),
		CSRFToken:   token,
		Flash:       r.URL.Query().Get("flash"),
	}
}

// checkCSRF validates the form token, rendering a generic error on failure.
func (h *AdminHandler) checkCSRF(w http.ResponseWriter, r *http.Request) bool {
	if err := r.ParseForm(); err != nil {
		h.fail(w, r, http.StatusBadRequest, "Invalid form data")
		return false
	}
	if err := h.cfg.AuthService.CSRF().ValidateToken(r); err != nil {
		h.fail(w, r, http.StatusBadRequest, "Invalid or expired form, please go back and try again")
		return false
	}
	return true
}

// redirect sends the browser to path with a flash message.
func (h *AdminHandler) redirect(w http.ResponseWriter, r *http.Request, path, flash string) {
	if flash != "" {
		path += "?flash=" + url.QueryEscape(flash)
	}
	http.Redirect(w, r, path, http.StatusFound)
}

func (h *AdminHandler) fail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	h.templates.Render(w, status, "message", messagePageData{
		Title:     "Error",
		Error:     msg,
		BackURL:   "/admin",
		BackLabel: "Back to admin",
	})
}

func (h *AdminHandler) notFound(w http.ResponseWriter, r *http.Request, what string) {
	h.fail(w, r, http.StatusNotFound, what+" not found")
}

// Dashboard

type dashboardData struct {
	adminBase
	UserCount   int
	GroupCount  int
	ClientCount int
	KeyCount    int
	IssuerURL   string
}

func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, _ := h.cfg.Store.Users().List(ctx)
	groups, _ := h.cfg.Store.Groups().List(ctx)
	clients, _ := h.cfg.Store.Clients().List(ctx)
	keyCount := 0
	if h.cfg.KeyService != nil {
		if keys, err := h.cfg.KeyService.ListKeys(ctx); err == nil {
			keyCount = len(keys)
		}
	}
	h.templates.Render(w, http.StatusOK, "admin/dashboard", dashboardData{
		adminBase:   h.base(w, r, ""),
		UserCount:   len(users),
		GroupCount:  len(groups),
		ClientCount: len(clients),
		KeyCount:    keyCount,
		IssuerURL:   h.cfg.IssuerURL,
	})
}

// Users

type usersData struct {
	adminBase
	Users []*domain.User
}

type userFormData struct {
	adminBase
	IsNew             bool
	IsSelf            bool
	User              *domain.User
	Consents          []*domain.Consent
	AllGroups         []groupMembership
	Sessions          []*domain.Session
	Tokens            []*domain.Token
	MinPasswordLength int
}

// groupMembership pairs a group with whether the user being edited belongs to it.
type groupMembership struct {
	Group  *domain.Group
	Member bool
}

func (h *AdminHandler) Users(w http.ResponseWriter, r *http.Request) {
	users, err := h.cfg.Store.Users().List(r.Context())
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, "Failed to list users")
		return
	}
	h.templates.Render(w, http.StatusOK, "admin/users", usersData{adminBase: h.base(w, r, "users"), Users: users})
}

func (h *AdminHandler) NewUser(w http.ResponseWriter, r *http.Request) {
	h.renderUserForm(w, r, http.StatusOK, userFormData{
		IsNew: true,
		User:  &domain.User{Active: true},
	})
}

func (h *AdminHandler) renderUserForm(w http.ResponseWriter, r *http.Request, status int, data userFormData) {
	data.adminBase = h.base(w, r, "users")
	data.MinPasswordLength = auth.MinPasswordLength
	if data.User != nil && currentAdmin(r) != nil {
		data.IsSelf = data.User.ID == currentAdmin(r).ID
	}
	h.templates.Render(w, status, "admin/user_form", data)
}

func (h *AdminHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	ctx := r.Context()

	user := &domain.User{
		ID:            uuid.New().String(),
		Email:         strings.TrimSpace(r.FormValue("email")),
		DisplayName:   strings.TrimSpace(r.FormValue("display_name")),
		Active:        r.FormValue("active") == "1",
		EmailVerified: r.FormValue("email_verified") == "1",
		Admin:         r.FormValue("admin") == "1",
	}
	password := r.FormValue("password")
	invite := password == ""

	renderErr := func(msg string) {
		data := userFormData{IsNew: true, User: user}
		data.Error = msg
		h.renderUserForm(w, r, http.StatusBadRequest, data)
	}

	if user.Email == "" {
		renderErr("Email is required")
		return
	}
	if invite {
		// Unusable placeholder; the invite email lets the user choose a password.
		random, err := randomSecret(32)
		if err != nil {
			renderErr("Failed to generate placeholder password")
			return
		}
		password = random
	} else if err := auth.ValidatePassword(password); err != nil {
		renderErr(userMessage(err))
		return
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		renderErr("Failed to hash password")
		return
	}
	user.PasswordHash = hash

	if err := h.cfg.Store.Users().Create(ctx, user); err != nil {
		if idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
			renderErr("A user with that email already exists")
			return
		}
		h.logger.Error("failed to create user", "error", err)
		renderErr("Failed to create user")
		return
	}
	h.record(r, audit.UserCreated, "user", user.ID, user.Email)

	flash := "User created"
	if invite {
		if err := h.cfg.AccountService.SendPasswordReset(ctx, user); err != nil {
			h.logger.Error("failed to send invite", "user_id", user.ID, "error", err)
			flash += ", but the invite email could not be sent"
		} else {
			h.record(r, audit.UserInvited, "user", user.ID, user.Email)
			flash += " and invite email sent"
		}
	}
	if r.FormValue("send_verification") == "1" && !user.EmailVerified {
		if err := h.cfg.AccountService.SendEmailVerification(ctx, user); err != nil {
			h.logger.Error("failed to send verification", "user_id", user.ID, "error", err)
			flash += ", but the verification email could not be sent"
		} else {
			flash += "; verification email sent"
		}
	}

	h.redirect(w, r, "/admin/users/"+user.ID, flash)
}

func (h *AdminHandler) loadUser(w http.ResponseWriter, r *http.Request) (*domain.User, bool) {
	user, err := h.cfg.Store.Users().GetByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			h.notFound(w, r, "User")
		} else {
			h.fail(w, r, http.StatusInternalServerError, "Failed to load user")
		}
		return nil, false
	}
	return user, true
}

func (h *AdminHandler) EditUser(w http.ResponseWriter, r *http.Request) {
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	consents, _ := h.cfg.Store.Consents().ListByUserID(ctx, user.ID)
	sessions, _ := h.cfg.Store.Sessions().ListByUserID(ctx, user.ID)
	tokens, _ := h.cfg.Store.Tokens().ListByUserID(ctx, user.ID)
	h.renderUserForm(w, r, http.StatusOK, userFormData{
		User:      user,
		Consents:  consents,
		AllGroups: h.groupMemberships(ctx, user.ID),
		Sessions:  sessions,
		Tokens:    tokens,
	})
}

// RevokeUserSession signs the user out of a single session.
func (h *AdminHandler) RevokeUserSession(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	sessionID := chi.URLParam(r, "sessionID")
	// Only touch sessions that belong to this user.
	if sess, err := h.cfg.Store.Sessions().GetByID(r.Context(), sessionID); err != nil || sess.UserID != user.ID {
		h.redirect(w, r, "/admin/users/"+user.ID, "Session not found")
		return
	}
	if err := h.cfg.Store.Sessions().Delete(r.Context(), sessionID); err != nil && !idperrors.IsCode(err, idperrors.CodeNotFound) {
		h.logger.Error("failed to revoke session", "error", err)
		h.redirect(w, r, "/admin/users/"+user.ID, "Failed to revoke session")
		return
	}
	h.record(r, audit.UserSessionRevoked, "user", user.ID, "session "+sessionID)
	h.redirect(w, r, "/admin/users/"+user.ID, "Session revoked")
}

// RevokeUserToken revokes a single refresh token.
func (h *AdminHandler) RevokeUserToken(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	tokenID := chi.URLParam(r, "tokenID")
	if tok, err := h.cfg.Store.Tokens().GetByID(r.Context(), tokenID); err != nil || tok.UserID != user.ID {
		h.redirect(w, r, "/admin/users/"+user.ID, "Token not found")
		return
	}
	if err := h.cfg.Store.Tokens().Revoke(r.Context(), tokenID); err != nil {
		h.logger.Error("failed to revoke token", "error", err)
		h.redirect(w, r, "/admin/users/"+user.ID, "Failed to revoke token")
		return
	}
	h.record(r, audit.UserTokenRevoked, "user", user.ID, "token "+tokenID)
	h.redirect(w, r, "/admin/users/"+user.ID, "Token revoked")
}

// groupMemberships lists every group flagged with the user's membership.
func (h *AdminHandler) groupMemberships(ctx context.Context, userID string) []groupMembership {
	all, err := h.cfg.Store.Groups().List(ctx)
	if err != nil {
		return nil
	}
	mine, _ := h.cfg.Store.Groups().GroupsForUser(ctx, userID)
	member := make(map[string]bool, len(mine))
	for _, g := range mine {
		member[g.ID] = true
	}
	out := make([]groupMembership, 0, len(all))
	for _, g := range all {
		out = append(out, groupMembership{Group: g, Member: member[g.ID]})
	}
	return out
}

// SetUserGroups replaces the user's memberships with the checked groups.
func (h *AdminHandler) SetUserGroups(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	ctx := r.Context()

	wanted := make(map[string]bool)
	for _, id := range r.Form["group"] {
		wanted[id] = true
	}
	for _, gm := range h.groupMemberships(ctx, user.ID) {
		switch {
		case wanted[gm.Group.ID] && !gm.Member:
			if err := h.cfg.Store.Groups().AddMember(ctx, gm.Group.ID, user.ID); err != nil {
				h.logger.Error("failed to add group member", "error", err)
			}
		case !wanted[gm.Group.ID] && gm.Member:
			if err := h.cfg.Store.Groups().RemoveMember(ctx, gm.Group.ID, user.ID); err != nil {
				h.logger.Error("failed to remove group member", "error", err)
			}
		}
	}
	h.record(r, audit.UserGroupsUpdated, "user", user.ID, user.Email)
	h.redirect(w, r, "/admin/users/"+user.ID, "Groups updated")
}

func (h *AdminHandler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}

	newEmail := strings.TrimSpace(r.FormValue("email"))
	if newEmail == "" {
		data := userFormData{User: user}
		data.Error = "Email is required"
		h.renderUserForm(w, r, http.StatusBadRequest, data)
		return
	}
	// Changing the address invalidates its verified status unless the admin
	// explicitly ticks the box.
	if !strings.EqualFold(newEmail, user.Email) {
		user.EmailVerified = false
	}
	user.Email = newEmail
	user.DisplayName = strings.TrimSpace(r.FormValue("display_name"))
	user.Active = r.FormValue("active") == "1"
	if r.FormValue("email_verified") == "1" {
		user.EmailVerified = true
	}

	self := user.ID == currentAdmin(r).ID
	if self {
		user.Admin = true // never let an admin lock themselves out
	} else {
		user.Admin = r.FormValue("admin") == "1"
	}
	if self && !user.Active {
		data := userFormData{User: user}
		data.Error = "You cannot disable your own account"
		user.Active = true
		h.renderUserForm(w, r, http.StatusBadRequest, data)
		return
	}

	if err := h.cfg.Store.Users().Update(r.Context(), user); err != nil {
		msg := "Failed to update user"
		if idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
			msg = "A user with that email already exists"
		} else {
			h.logger.Error("failed to update user", "error", err)
		}
		data := userFormData{User: user}
		data.Error = msg
		h.renderUserForm(w, r, http.StatusBadRequest, data)
		return
	}
	h.record(r, audit.UserUpdated, "user", user.ID, user.Email)
	h.redirect(w, r, "/admin/users/"+user.ID, "User updated")
}

func (h *AdminHandler) SetUserPassword(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	if err := h.cfg.AccountService.SetPassword(r.Context(), user, r.FormValue("password")); err != nil {
		if idperrors.IsCode(err, idperrors.CodeInvalidInput) {
			data := userFormData{User: user}
			data.Error = userMessage(err)
			h.renderUserForm(w, r, http.StatusBadRequest, data)
			return
		}
		h.logger.Error("failed to set password", "error", err)
		h.fail(w, r, http.StatusInternalServerError, "Failed to set password")
		return
	}
	h.record(r, audit.PasswordChanged, "user", user.ID, user.Email)
	h.redirect(w, r, "/admin/users/"+user.ID, "Password updated; the user has been signed out everywhere")
}

func (h *AdminHandler) SendUserReset(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	if err := h.cfg.AccountService.SendPasswordReset(r.Context(), user); err != nil {
		h.logger.Error("failed to send reset", "error", err)
		h.redirect(w, r, "/admin/users/"+user.ID, "Failed to send password reset email")
		return
	}
	h.redirect(w, r, "/admin/users/"+user.ID, "Password reset email sent to "+user.Email)
}

func (h *AdminHandler) SendUserVerification(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	if err := h.cfg.AccountService.SendEmailVerification(r.Context(), user); err != nil {
		h.logger.Error("failed to send verification", "error", err)
		h.redirect(w, r, "/admin/users/"+user.ID, "Failed to send verification email")
		return
	}
	h.redirect(w, r, "/admin/users/"+user.ID, "Verification email sent to "+user.Email)
}

func (h *AdminHandler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := h.cfg.Store.Sessions().DeleteByUserID(ctx, user.ID); err != nil {
		h.logger.Error("failed to revoke sessions", "error", err)
	}
	if err := h.cfg.Store.Tokens().RevokeByUserID(ctx, user.ID); err != nil {
		h.logger.Error("failed to revoke tokens", "error", err)
	}
	h.record(r, audit.UserSessionsRevoked, "user", user.ID, user.Email)
	h.redirect(w, r, "/admin/users/"+user.ID, "Sessions and tokens revoked")
}

func (h *AdminHandler) RevokeUserConsent(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	clientID := chi.URLParam(r, "clientID")
	if err := h.cfg.Store.Consents().Delete(r.Context(), user.ID, clientID); err != nil && !idperrors.IsCode(err, idperrors.CodeNotFound) {
		h.logger.Error("failed to revoke consent", "error", err)
		h.redirect(w, r, "/admin/users/"+user.ID, "Failed to revoke consent")
		return
	}
	h.record(r, audit.UserConsentRevoked, "user", user.ID, "client "+clientID)
	h.redirect(w, r, "/admin/users/"+user.ID, "Consent for "+clientID+" revoked")
}

func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	user, ok := h.loadUser(w, r)
	if !ok {
		return
	}
	if user.ID == currentAdmin(r).ID {
		h.fail(w, r, http.StatusBadRequest, "You cannot delete your own account")
		return
	}
	ctx := r.Context()
	// The SQLite backend cascades; the file backend does not, so clean up explicitly.
	_ = h.cfg.Store.Sessions().DeleteByUserID(ctx, user.ID)
	_ = h.cfg.Store.Tokens().RevokeByUserID(ctx, user.ID)
	_ = h.cfg.Store.Consents().DeleteByUserID(ctx, user.ID)
	_ = h.cfg.Store.VerificationTokens().DeleteByUserID(ctx, user.ID, "")
	_ = h.cfg.Store.Groups().RemoveUser(ctx, user.ID)
	if err := h.cfg.Store.Users().Delete(ctx, user.ID); err != nil {
		h.logger.Error("failed to delete user", "error", err)
		h.fail(w, r, http.StatusInternalServerError, "Failed to delete user")
		return
	}
	h.record(r, audit.UserDeleted, "user", user.ID, user.Email)
	h.redirect(w, r, "/admin/users", "User "+user.Email+" deleted")
}

// Groups

type groupRow struct {
	Group       *domain.Group
	MemberCount int
}

type groupsData struct {
	adminBase
	Groups    []groupRow
	ClaimName string
}

type groupFormData struct {
	adminBase
	IsNew   bool
	Group   *domain.Group
	Members []*domain.User
}

func (h *AdminHandler) Groups(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	groups, err := h.cfg.Store.Groups().List(ctx)
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, "Failed to list groups")
		return
	}
	rows := make([]groupRow, 0, len(groups))
	for _, g := range groups {
		ids, _ := h.cfg.Store.Groups().MemberIDs(ctx, g.ID)
		rows = append(rows, groupRow{Group: g, MemberCount: len(ids)})
	}
	h.templates.Render(w, http.StatusOK, "admin/groups", groupsData{
		adminBase: h.base(w, r, "groups"),
		Groups:    rows,
		ClaimName: h.cfg.GroupsClaim,
	})
}

func (h *AdminHandler) NewGroup(w http.ResponseWriter, r *http.Request) {
	h.renderGroupForm(w, r, http.StatusOK, groupFormData{IsNew: true, Group: &domain.Group{}})
}

func (h *AdminHandler) renderGroupForm(w http.ResponseWriter, r *http.Request, status int, data groupFormData) {
	data.adminBase = h.base(w, r, "groups")
	h.templates.Render(w, status, "admin/group_form", data)
}

func (h *AdminHandler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	group := &domain.Group{
		ID:          uuid.New().String(),
		Name:        strings.TrimSpace(r.FormValue("name")),
		Description: strings.TrimSpace(r.FormValue("description")),
	}
	if group.Name == "" {
		data := groupFormData{IsNew: true, Group: group}
		data.Error = "Name is required"
		h.renderGroupForm(w, r, http.StatusBadRequest, data)
		return
	}
	if err := h.cfg.Store.Groups().Create(r.Context(), group); err != nil {
		msg := "Failed to create group"
		if idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
			msg = "A group with that name already exists"
		} else {
			h.logger.Error("failed to create group", "error", err)
		}
		data := groupFormData{IsNew: true, Group: group}
		data.Error = msg
		h.renderGroupForm(w, r, http.StatusBadRequest, data)
		return
	}
	h.record(r, audit.GroupCreated, "group", group.ID, group.Name)
	h.redirect(w, r, "/admin/groups/"+group.ID, "Group created")
}

func (h *AdminHandler) loadGroup(w http.ResponseWriter, r *http.Request) (*domain.Group, bool) {
	group, err := h.cfg.Store.Groups().GetByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			h.notFound(w, r, "Group")
		} else {
			h.fail(w, r, http.StatusInternalServerError, "Failed to load group")
		}
		return nil, false
	}
	return group, true
}

func (h *AdminHandler) groupMembers(ctx context.Context, groupID string) []*domain.User {
	ids, _ := h.cfg.Store.Groups().MemberIDs(ctx, groupID)
	members := make([]*domain.User, 0, len(ids))
	for _, id := range ids {
		if u, err := h.cfg.Store.Users().GetByID(ctx, id); err == nil {
			members = append(members, u)
		}
	}
	return members
}

func (h *AdminHandler) EditGroup(w http.ResponseWriter, r *http.Request) {
	group, ok := h.loadGroup(w, r)
	if !ok {
		return
	}
	h.renderGroupForm(w, r, http.StatusOK, groupFormData{Group: group, Members: h.groupMembers(r.Context(), group.ID)})
}

func (h *AdminHandler) UpdateGroup(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	group, ok := h.loadGroup(w, r)
	if !ok {
		return
	}
	group.Name = strings.TrimSpace(r.FormValue("name"))
	group.Description = strings.TrimSpace(r.FormValue("description"))

	var msg string
	if group.Name == "" {
		msg = "Name is required"
	} else if err := h.cfg.Store.Groups().Update(r.Context(), group); err != nil {
		if idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
			msg = "A group with that name already exists"
		} else {
			h.logger.Error("failed to update group", "error", err)
			msg = "Failed to update group"
		}
	}
	if msg != "" {
		data := groupFormData{Group: group, Members: h.groupMembers(r.Context(), group.ID)}
		data.Error = msg
		h.renderGroupForm(w, r, http.StatusBadRequest, data)
		return
	}
	h.record(r, audit.GroupUpdated, "group", group.ID, group.Name)
	h.redirect(w, r, "/admin/groups/"+group.ID, "Group updated")
}

func (h *AdminHandler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	group, ok := h.loadGroup(w, r)
	if !ok {
		return
	}
	email := strings.TrimSpace(r.FormValue("email"))
	user, err := h.cfg.Store.Users().GetByEmail(r.Context(), email)
	if err != nil {
		h.redirect(w, r, "/admin/groups/"+group.ID, "No user with email "+email)
		return
	}
	if err := h.cfg.Store.Groups().AddMember(r.Context(), group.ID, user.ID); err != nil {
		h.logger.Error("failed to add group member", "error", err)
		h.redirect(w, r, "/admin/groups/"+group.ID, "Failed to add member")
		return
	}
	h.record(r, audit.GroupMemberAdded, "group", group.ID, group.Name+" += "+user.Email)
	h.redirect(w, r, "/admin/groups/"+group.ID, user.Email+" added to "+group.Name)
}

func (h *AdminHandler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	group, ok := h.loadGroup(w, r)
	if !ok {
		return
	}
	userID := chi.URLParam(r, "userID")
	if err := h.cfg.Store.Groups().RemoveMember(r.Context(), group.ID, userID); err != nil && !idperrors.IsCode(err, idperrors.CodeNotFound) {
		h.logger.Error("failed to remove group member", "error", err)
		h.redirect(w, r, "/admin/groups/"+group.ID, "Failed to remove member")
		return
	}
	h.record(r, audit.GroupMemberRemoved, "group", group.ID, group.Name+" -= "+userID)
	h.redirect(w, r, "/admin/groups/"+group.ID, "Member removed")
}

func (h *AdminHandler) DeleteGroup(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	group, ok := h.loadGroup(w, r)
	if !ok {
		return
	}
	if err := h.cfg.Store.Groups().Delete(r.Context(), group.ID); err != nil {
		h.logger.Error("failed to delete group", "error", err)
		h.fail(w, r, http.StatusInternalServerError, "Failed to delete group")
		return
	}
	h.record(r, audit.GroupDeleted, "group", group.ID, group.Name)
	h.redirect(w, r, "/admin/groups", "Group "+group.Name+" deleted")
}

// Clients

type clientsData struct {
	adminBase
	Clients []*domain.Client
}

type clientFormData struct {
	adminBase
	IsNew     bool
	Client    *domain.Client
	NewSecret string
}

var (
	defaultClientScopes     = []string{"openid", "profile", "email", "offline_access", "groups"}
	defaultClientGrantTypes = []string{"authorization_code", "refresh_token"}
	clientIDPattern         = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

func (h *AdminHandler) Clients(w http.ResponseWriter, r *http.Request) {
	clients, err := h.cfg.Store.Clients().List(r.Context())
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, "Failed to list clients")
		return
	}
	h.templates.Render(w, http.StatusOK, "admin/clients", clientsData{adminBase: h.base(w, r, "clients"), Clients: clients})
}

func (h *AdminHandler) NewClient(w http.ResponseWriter, r *http.Request) {
	h.renderClientForm(w, r, http.StatusOK, clientFormData{
		IsNew:  true,
		Client: &domain.Client{Scopes: defaultClientScopes, GrantTypes: defaultClientGrantTypes},
	})
}

func (h *AdminHandler) renderClientForm(w http.ResponseWriter, r *http.Request, status int, data clientFormData) {
	data.adminBase = h.base(w, r, "clients")
	h.templates.Render(w, status, "admin/client_form", data)
}

// applyClientForm copies the editable fields from the form onto client and
// returns a validation message, or "" when valid.
func applyClientForm(r *http.Request, client *domain.Client) string {
	client.Name = strings.TrimSpace(r.FormValue("name"))
	client.Public = r.FormValue("public") == "1"
	client.SkipConsent = r.FormValue("skip_consent") == "1"
	client.RedirectURIs = splitLines(r.FormValue("redirect_uris"))
	client.Scopes = strings.Fields(r.FormValue("scopes"))
	client.GrantTypes = strings.Fields(r.FormValue("grant_types"))

	if client.Name == "" {
		return "Name is required"
	}
	if len(client.RedirectURIs) == 0 {
		return "At least one redirect URI is required"
	}
	for _, uri := range client.RedirectURIs {
		u, err := url.Parse(uri)
		if err != nil || u.Scheme == "" || (u.Host == "" && u.Scheme != "urn") {
			return "Invalid redirect URI: " + uri
		}
	}
	if len(client.Scopes) == 0 {
		client.Scopes = append([]string(nil), defaultClientScopes...)
	}
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = append([]string(nil), defaultClientGrantTypes...)
	}
	if client.Public {
		client.Secret = ""
	}
	return ""
}

func (h *AdminHandler) CreateClient(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	client := &domain.Client{ID: strings.TrimSpace(r.FormValue("id"))}

	renderErr := func(msg string) {
		data := clientFormData{IsNew: true, Client: client}
		data.Error = msg
		h.renderClientForm(w, r, http.StatusBadRequest, data)
	}

	if msg := applyClientForm(r, client); msg != "" {
		renderErr(msg)
		return
	}
	if !clientIDPattern.MatchString(client.ID) {
		renderErr("Client ID may only contain letters, digits, '.', '_', ':' and '-'")
		return
	}

	var secret string
	if !client.Public {
		var err error
		if secret, err = newClientSecret(client); err != nil {
			renderErr("Failed to generate client secret")
			return
		}
	}

	if err := h.cfg.Store.Clients().Create(r.Context(), client); err != nil {
		if idperrors.IsCode(err, idperrors.CodeAlreadyExists) {
			renderErr("A client with that ID already exists")
			return
		}
		h.logger.Error("failed to create client", "error", err)
		renderErr("Failed to create client")
		return
	}
	h.record(r, audit.ClientCreated, "client", client.ID, client.Name)

	// Render directly (no redirect) so the secret is shown exactly once and
	// never appears in a URL.
	data := clientFormData{Client: client, NewSecret: secret}
	data.Flash = "Client created"
	h.renderClientForm(w, r, http.StatusOK, data)
}

func (h *AdminHandler) loadClient(w http.ResponseWriter, r *http.Request) (*domain.Client, bool) {
	client, err := h.cfg.Store.Clients().GetByID(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			h.notFound(w, r, "Client")
		} else {
			h.fail(w, r, http.StatusInternalServerError, "Failed to load client")
		}
		return nil, false
	}
	return client, true
}

func (h *AdminHandler) EditClient(w http.ResponseWriter, r *http.Request) {
	client, ok := h.loadClient(w, r)
	if !ok {
		return
	}
	h.renderClientForm(w, r, http.StatusOK, clientFormData{Client: client})
}

func (h *AdminHandler) UpdateClient(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	client, ok := h.loadClient(w, r)
	if !ok {
		return
	}

	wasPublic := client.Public
	if msg := applyClientForm(r, client); msg != "" {
		data := clientFormData{Client: client}
		data.Error = msg
		h.renderClientForm(w, r, http.StatusBadRequest, data)
		return
	}

	// Switching a public client to confidential needs a secret.
	var newSecret string
	if wasPublic && !client.Public {
		var err error
		if newSecret, err = newClientSecret(client); err != nil {
			h.fail(w, r, http.StatusInternalServerError, "Failed to generate client secret")
			return
		}
	}

	if err := h.cfg.Store.Clients().Update(r.Context(), client); err != nil {
		h.logger.Error("failed to update client", "error", err)
		data := clientFormData{Client: client}
		data.Error = "Failed to update client"
		h.renderClientForm(w, r, http.StatusBadRequest, data)
		return
	}
	h.record(r, audit.ClientUpdated, "client", client.ID, client.Name)

	if newSecret != "" {
		data := clientFormData{Client: client, NewSecret: newSecret}
		data.Flash = "Client updated and secret generated"
		h.renderClientForm(w, r, http.StatusOK, data)
		return
	}
	h.redirect(w, r, "/admin/clients/"+client.ID, "Client updated")
}

func (h *AdminHandler) RegenerateClientSecret(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	client, ok := h.loadClient(w, r)
	if !ok {
		return
	}
	if client.Public {
		h.fail(w, r, http.StatusBadRequest, "Public clients do not have a secret")
		return
	}
	secret, err := newClientSecret(client)
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, "Failed to generate client secret")
		return
	}
	if err := h.cfg.Store.Clients().Update(r.Context(), client); err != nil {
		h.logger.Error("failed to update client secret", "error", err)
		h.fail(w, r, http.StatusInternalServerError, "Failed to update client")
		return
	}
	h.record(r, audit.ClientSecretRotated, "client", client.ID, client.Name)

	data := clientFormData{Client: client, NewSecret: secret}
	data.Flash = "Secret regenerated; the previous secret no longer works"
	h.renderClientForm(w, r, http.StatusOK, data)
}

func (h *AdminHandler) RevokeClientTokens(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	client, ok := h.loadClient(w, r)
	if !ok {
		return
	}
	if err := h.cfg.Store.Tokens().RevokeByClientID(r.Context(), client.ID); err != nil {
		h.logger.Error("failed to revoke client tokens", "error", err)
		h.redirect(w, r, "/admin/clients/"+client.ID, "Failed to revoke tokens")
		return
	}
	h.record(r, audit.ClientTokensRevoked, "client", client.ID, client.Name)
	h.redirect(w, r, "/admin/clients/"+client.ID, "All tokens for "+client.ID+" revoked")
}

func (h *AdminHandler) DeleteClient(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	client, ok := h.loadClient(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	_ = h.cfg.Store.Tokens().RevokeByClientID(ctx, client.ID)
	if err := h.cfg.Store.Clients().Delete(ctx, client.ID); err != nil {
		h.logger.Error("failed to delete client", "error", err)
		h.fail(w, r, http.StatusInternalServerError, "Failed to delete client")
		return
	}
	h.record(r, audit.ClientDeleted, "client", client.ID, client.Name)
	h.redirect(w, r, "/admin/clients", "Client "+client.ID+" deleted")
}

// Audit log

type auditData struct {
	adminBase
	Events []*domain.AuditEvent
	Limit  int
}

func (h *AdminHandler) Audit(w http.ResponseWriter, r *http.Request) {
	const limit = 200
	events, err := h.cfg.Store.Audit().List(r.Context(), limit)
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, "Failed to load audit log")
		return
	}
	h.templates.Render(w, http.StatusOK, "admin/audit", auditData{
		adminBase: h.base(w, r, "audit"),
		Events:    events,
		Limit:     limit,
	})
}

// Signing keys

type keysData struct {
	adminBase
	Keys        []*crypto.KeyPair
	GracePeriod string
}

func (h *AdminHandler) Keys(w http.ResponseWriter, r *http.Request) {
	if h.cfg.KeyService == nil {
		h.fail(w, r, http.StatusNotFound, "Key management is not enabled")
		return
	}
	keys, err := h.cfg.KeyService.ListKeys(r.Context())
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, "Failed to list keys")
		return
	}
	h.templates.Render(w, http.StatusOK, "admin/keys", keysData{
		adminBase:   h.base(w, r, "keys"),
		Keys:        keys,
		GracePeriod: h.cfg.KeyGracePeriod.String(),
	})
}

func (h *AdminHandler) RotateKey(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	if h.cfg.KeyService == nil {
		h.fail(w, r, http.StatusNotFound, "Key management is not enabled")
		return
	}
	key, err := h.cfg.KeyService.RotateKey(r.Context(), h.cfg.KeyGracePeriod)
	if err != nil {
		h.logger.Error("failed to rotate key", "error", err)
		h.redirect(w, r, "/admin/keys", "Failed to rotate key")
		return
	}
	h.record(r, audit.KeyRotated, "key", key.Kid, "rotated from admin UI")
	h.redirect(w, r, "/admin/keys", "New signing key "+key.Kid+" is active")
}

// newClientSecret generates a client secret, stores its hash on client and
// returns the plaintext to show once.
func newClientSecret(client *domain.Client) (string, error) {
	secret, err := randomSecret(32)
	if err != nil {
		return "", err
	}
	hash, err := oidc.HashClientSecret(secret)
	if err != nil {
		return "", err
	}
	client.Secret = hash
	return secret, nil
}

// Helpers

func randomSecret(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func splitLines(s string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}
