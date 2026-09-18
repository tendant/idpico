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
	"github.com/tendant/simple-idp/internal/auth"
	"github.com/tendant/simple-idp/internal/crypto"
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
)

// AdminConfig wires the admin UI.
type AdminConfig struct {
	Store          store.Store
	AuthService    *auth.Service
	AccountService *auth.AccountService
	KeyService     *crypto.KeyService
	IssuerURL      string
	KeyGracePeriod time.Duration
}

// AdminHandler serves the server-rendered administration UI under /admin.
// Every page requires an authenticated session whose user has the Admin flag.
type AdminHandler struct {
	cfg       AdminConfig
	templates *Templates
	logger    *slog.Logger
}

// NewAdminHandler creates an AdminHandler.
func NewAdminHandler(cfg AdminConfig, templates *Templates, logger *slog.Logger) *AdminHandler {
	if cfg.KeyGracePeriod == 0 {
		cfg.KeyGracePeriod = 24 * time.Hour
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
	r.Post("/users/{id}/consents/{clientID}/revoke", h.RevokeUserConsent)
	r.Post("/users/{id}/delete", h.DeleteUser)

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
	ClientCount int
	KeyCount    int
	IssuerURL   string
}

func (h *AdminHandler) Dashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, _ := h.cfg.Store.Users().List(ctx)
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
	MinPasswordLength int
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
	h.logger.Info("admin created user", "admin", currentAdmin(r).Email, "user_id", user.ID, "email", user.Email)

	flash := "User created"
	if invite {
		if err := h.cfg.AccountService.SendPasswordReset(ctx, user); err != nil {
			h.logger.Error("failed to send invite", "user_id", user.ID, "error", err)
			flash += ", but the invite email could not be sent"
		} else {
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
	consents, _ := h.cfg.Store.Consents().ListByUserID(r.Context(), user.ID)
	h.renderUserForm(w, r, http.StatusOK, userFormData{User: user, Consents: consents})
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
	h.logger.Info("admin updated user", "admin", currentAdmin(r).Email, "user_id", user.ID)
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
	h.logger.Info("admin set user password", "admin", currentAdmin(r).Email, "user_id", user.ID)
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
	h.logger.Info("admin revoked user sessions", "admin", currentAdmin(r).Email, "user_id", user.ID)
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
	if err := h.cfg.Store.Users().Delete(ctx, user.ID); err != nil {
		h.logger.Error("failed to delete user", "error", err)
		h.fail(w, r, http.StatusInternalServerError, "Failed to delete user")
		return
	}
	h.logger.Info("admin deleted user", "admin", currentAdmin(r).Email, "user_id", user.ID, "email", user.Email)
	h.redirect(w, r, "/admin/users", "User "+user.Email+" deleted")
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
	defaultClientScopes     = []string{"openid", "profile", "email", "offline_access"}
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
		if secret, err = randomSecret(32); err != nil {
			renderErr("Failed to generate client secret")
			return
		}
		client.Secret = secret
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
	h.logger.Info("admin created client", "admin", currentAdmin(r).Email, "client_id", client.ID, "public", client.Public)

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
		if newSecret, err = randomSecret(32); err != nil {
			h.fail(w, r, http.StatusInternalServerError, "Failed to generate client secret")
			return
		}
		client.Secret = newSecret
	}

	if err := h.cfg.Store.Clients().Update(r.Context(), client); err != nil {
		h.logger.Error("failed to update client", "error", err)
		data := clientFormData{Client: client}
		data.Error = "Failed to update client"
		h.renderClientForm(w, r, http.StatusBadRequest, data)
		return
	}
	h.logger.Info("admin updated client", "admin", currentAdmin(r).Email, "client_id", client.ID)

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
	secret, err := randomSecret(32)
	if err != nil {
		h.fail(w, r, http.StatusInternalServerError, "Failed to generate client secret")
		return
	}
	client.Secret = secret
	if err := h.cfg.Store.Clients().Update(r.Context(), client); err != nil {
		h.logger.Error("failed to update client secret", "error", err)
		h.fail(w, r, http.StatusInternalServerError, "Failed to update client")
		return
	}
	h.logger.Info("admin regenerated client secret", "admin", currentAdmin(r).Email, "client_id", client.ID)

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
	h.logger.Info("admin revoked client tokens", "admin", currentAdmin(r).Email, "client_id", client.ID)
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
	h.logger.Info("admin deleted client", "admin", currentAdmin(r).Email, "client_id", client.ID)
	h.redirect(w, r, "/admin/clients", "Client "+client.ID+" deleted")
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
	h.logger.Info("admin rotated signing key", "admin", currentAdmin(r).Email, "kid", key.Kid)
	h.redirect(w, r, "/admin/keys", "New signing key "+key.Kid+" is active")
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
