package http

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tendant/idpico/internal/audit"
	"github.com/tendant/idpico/internal/auth"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
	"github.com/tendant/idpico/internal/oidc"
)

// OIDCHandler handles OIDC endpoints.
type OIDCHandler struct {
	authService      *auth.Service
	authorizeService *oidc.AuthorizeService
	consentService   *oidc.ConsentService
	tokenService     *oidc.TokenService
	userInfoService  *oidc.UserInfoService
	templates        *Templates
	logger           *slog.Logger
	audit            *audit.Recorder
}

// NewOIDCHandler creates a new OIDCHandler. consentService may be nil, in
// which case authorization never prompts for consent.
func NewOIDCHandler(
	authService *auth.Service,
	authorizeService *oidc.AuthorizeService,
	consentService *oidc.ConsentService,
	tokenService *oidc.TokenService,
	userInfoService *oidc.UserInfoService,
	templates *Templates,
	logger *slog.Logger,
) *OIDCHandler {
	return &OIDCHandler{
		authService:      authService,
		authorizeService: authorizeService,
		consentService:   consentService,
		tokenService:     tokenService,
		userInfoService:  userInfoService,
		templates:        templates,
		logger:           logger,
	}
}

// Authorize handles GET and POST /authorize - the OAuth 2.0 authorization
// endpoint. OIDC Core §3.1.2.1 requires both methods; a POST carries the
// parameters as a form body and is otherwise identical.
func (h *OIDCHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	params := r.URL.Query()
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			h.renderAuthError(w, r, "", "invalid form data", "", "")
			return
		}
		params = r.PostForm
	}
	// The request as a GET URL: what the login page returns to and what the
	// consent form re-submits.
	requestURL := &url.URL{Path: r.URL.Path, RawQuery: params.Encode()}

	// Parse authorization request
	authReq, err := h.authorizeService.ParseAuthorizeQuery(params)
	if err != nil {
		h.renderAuthError(w, r, "", err.Error(), "", "")
		return
	}

	// Validate client and redirect URI, then the rest of the request
	client, err := h.authorizeService.ValidateClient(ctx, authReq)
	if err != nil {
		h.authorizeFailed(w, r, authReq, err)
		return
	}

	// Check if user is authenticated. prompt=login / select_account and a
	// session older than max_age all force re-authentication.
	var authTime time.Time
	session, user, err := h.authService.CurrentSession(ctx, r)
	if err == nil {
		authTime = session.CreatedAt
	}
	if err != nil || authReq.RequiresFreshLogin(authTime) {
		if authReq.HasPrompt("none") {
			h.redirectError(w, r, authReq, "login_required", "user is not authenticated")
			return
		}
		if err == nil {
			// Drop the session and strip the prompt so the post-login
			// redirect does not loop back here (max_age is satisfied by the
			// fresh session and can stay).
			_ = h.authService.Logout(ctx, w, r)
		}
		loginURL := "/login?return_url=" + url.QueryEscape(withoutPrompt(requestURL, "login", "select_account"))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// Check consent
	if h.consentService != nil {
		granted, err := h.consentService.IsGranted(ctx, user.ID, client, authReq.Scopes())
		if err != nil {
			h.logger.Error("failed to check consent", "error", err)
			h.redirectError(w, r, authReq, "server_error", "failed to check consent")
			return
		}
		if !granted || authReq.HasPrompt("consent") {
			if authReq.HasPrompt("none") {
				h.redirectError(w, r, authReq, "consent_required", "user consent is required")
				return
			}
			h.renderConsent(w, r, authReq, requestURL.RawQuery, client, user.Email)
			return
		}
	}

	h.issueCode(w, r, authReq, user.ID, authTime)
}

// Consent handles POST /consent - the user allowed or denied the client.
func (h *OIDCHandler) Consent(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if err := r.ParseForm(); err != nil {
		h.renderAuthError(w, r, "", "invalid form data", "", "")
		return
	}
	if err := h.authService.CSRF().ValidateToken(r); err != nil {
		h.renderAuthError(w, r, "", "invalid or expired form, please try again", "", "")
		return
	}

	// Re-parse and re-validate the original authorization request so that
	// the hidden field cannot smuggle in anything the client is not allowed.
	query, err := url.ParseQuery(r.FormValue("authorize_query"))
	if err != nil {
		h.renderAuthError(w, r, "", "invalid authorization request", "", "")
		return
	}
	authReq, err := h.authorizeService.ParseAuthorizeQuery(query)
	if err != nil {
		h.renderAuthError(w, r, "", err.Error(), "", "")
		return
	}
	client, err := h.authorizeService.ValidateClient(ctx, authReq)
	if err != nil {
		h.authorizeFailed(w, r, authReq, err)
		return
	}

	session, user, err := h.authService.CurrentSession(ctx, r)
	if err != nil {
		loginURL := "/login?return_url=" + url.QueryEscape("/authorize?"+query.Encode())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	if r.FormValue("action") != "allow" {
		h.logger.Info("consent denied", "client_id", client.ID, "user_id", user.ID)
		h.audit.Record(ctx, audit.Event{Actor: user, Action: audit.ConsentDenied, TargetType: "client", TargetID: client.ID, Detail: authReq.Scope, IP: audit.ClientIP(r)})
		h.redirectError(w, r, authReq, "access_denied", "user denied the request")
		return
	}

	if h.consentService != nil {
		if err := h.consentService.Grant(ctx, user.ID, client.ID, authReq.Scopes()); err != nil {
			h.logger.Error("failed to record consent", "error", err)
			h.redirectError(w, r, authReq, "server_error", "failed to record consent")
			return
		}
	}
	h.logger.Info("consent granted", "client_id", client.ID, "user_id", user.ID, "scope", authReq.Scope)
	h.audit.Record(ctx, audit.Event{Actor: user, Action: audit.ConsentGranted, TargetType: "client", TargetID: client.ID, Detail: authReq.Scope, IP: audit.ClientIP(r)})

	h.issueCode(w, r, authReq, user.ID, session.CreatedAt)
}

// issueCode creates an authorization code and redirects back to the client.
func (h *OIDCHandler) issueCode(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthorizeRequest, userID string, authTime time.Time) {
	ctx := r.Context()

	authCode, err := h.authorizeService.CreateAuthCode(ctx, authReq, userID, authTime)
	if err != nil {
		h.logger.Error("failed to create auth code", "error", err)
		redirectURL := h.authorizeService.BuildErrorResponse(
			authReq.RedirectURI,
			"server_error",
			"failed to create authorization code",
			authReq.State,
		)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Redirect with authorization code
	redirectURL := h.authorizeService.BuildAuthorizationResponse(
		authReq.RedirectURI,
		authCode.Code,
		authReq.State,
	)

	h.logger.Info("authorization code issued",
		"client_id", authReq.ClientID,
		"user_id", userID,
	)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// authorizeFailed reports a ValidateClient error. Once the client and
// redirect_uri are known to be valid the error goes back to the client as
// an OAuth error redirect; before that there is nowhere safe to send it, so
// the user sees an error page (an unknown client or unregistered
// redirect_uri must never redirect). Anything else is a store failure.
func (h *OIDCHandler) authorizeFailed(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthorizeRequest, err error) {
	var re *oidc.RedirectError
	if errors.As(err, &re) {
		h.redirectError(w, r, authReq, re.Code, re.Description)
		return
	}
	if idperrors.IsCode(err, idperrors.CodeInvalidInput) {
		errMsg := "invalid request"
		if e, ok := err.(*idperrors.Error); ok {
			errMsg = e.Message
		}
		h.renderAuthError(w, r, "", errMsg, "", "")
		return
	}
	h.logger.Error("authorize failed", "error", err)
	h.templates.Render(w, http.StatusInternalServerError, "error", errorPageData{
		Title:   "Authorization Error",
		Message: "internal error",
	})
}

// redirectError sends an OAuth error back to the client's redirect URI.
func (h *OIDCHandler) redirectError(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthorizeRequest, code, desc string) {
	http.Redirect(w, r, h.authorizeService.BuildErrorResponse(authReq.RedirectURI, code, desc, authReq.State), http.StatusFound)
}

type consentScope struct {
	Name        string
	Description string
}

type consentPageData struct {
	CSRFToken      string
	AuthorizeQuery string
	ClientID       string
	ClientName     string
	UserEmail      string
	Scopes         []consentScope
}

func (h *OIDCHandler) renderConsent(w http.ResponseWriter, r *http.Request, authReq *oidc.AuthorizeRequest, authorizeQuery string, client *domain.Client, userEmail string) {
	csrfToken, err := h.authService.CSRF().GenerateToken(w)
	if err != nil {
		h.logger.Error("failed to generate CSRF token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	scopes := make([]consentScope, 0, len(authReq.Scopes()))
	for _, s := range authReq.Scopes() {
		scopes = append(scopes, consentScope{Name: s, Description: oidc.ScopeDescription(s)})
	}

	name := client.Name
	if name == "" {
		name = client.ID
	}

	h.templates.Render(w, http.StatusOK, "consent", consentPageData{
		CSRFToken:      csrfToken,
		AuthorizeQuery: authorizeQuery,
		ClientID:       client.ID,
		ClientName:     name,
		UserEmail:      userEmail,
		Scopes:         scopes,
	})
}

// withoutPrompt returns u's path and query with the given prompt values removed.
func withoutPrompt(u *url.URL, values ...string) string {
	q := u.Query()
	drop := make(map[string]bool, len(values))
	for _, v := range values {
		drop[v] = true
	}
	var kept []string
	for _, p := range strings.Fields(q.Get("prompt")) {
		if !drop[p] {
			kept = append(kept, p)
		}
	}
	if len(kept) == 0 {
		q.Del("prompt")
	} else {
		q.Set("prompt", strings.Join(kept, " "))
	}
	return u.Path + "?" + q.Encode()
}

// Token handles POST /token - the OAuth 2.0 token endpoint.
func (h *OIDCHandler) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeTokenError(w, "invalid_request", "method must be POST", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Parse token request
	tokenReq, err := h.tokenService.ParseTokenRequest(r)
	if err != nil {
		h.writeTokenError(w, "invalid_request", err.Error(), http.StatusBadRequest)
		return
	}

	var response *oidc.TokenResponse

	switch tokenReq.GrantType {
	case "authorization_code":
		response, err = h.tokenService.HandleAuthorizationCode(ctx, tokenReq)
	case "refresh_token":
		response, err = h.tokenService.HandleRefreshToken(ctx, tokenReq)
	default:
		h.writeTokenError(w, "unsupported_grant_type", "grant_type not supported", http.StatusBadRequest)
		return
	}

	if err != nil {
		h.logger.Info("token request failed", "grant_type", tokenReq.GrantType, "error", err)

		// RFC 6749 §5.2: malformed request vs. bad grant vs. bad scope vs.
		// failed client authentication. Clients key re-auth logic on these.
		errorCode := "invalid_request"
		status := http.StatusBadRequest
		switch {
		case idperrors.IsCode(err, idperrors.CodeUnauthorized):
			errorCode = "invalid_client"
			status = http.StatusUnauthorized
		case idperrors.IsCode(err, idperrors.CodeInvalidGrant):
			errorCode = "invalid_grant"
		case idperrors.IsCode(err, idperrors.CodeInvalidScope):
			errorCode = "invalid_scope"
		}

		errMsg := "request failed"
		if e, ok := err.(*idperrors.Error); ok {
			errMsg = e.Message
		}

		h.writeTokenError(w, errorCode, errMsg, status)
		return
	}

	h.logger.Info("tokens issued", "grant_type", tokenReq.GrantType, "client_id", tokenReq.ClientID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// UserInfo handles GET /userinfo - the OIDC userinfo endpoint.
func (h *OIDCHandler) UserInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract bearer token: the Authorization header (RFC 6750 §2.1) or,
	// for a form-encoded POST without one, the access_token body parameter
	// (§2.2). A request that sends neither gets a bare challenge (§3).
	token, err := oidc.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil && r.Header.Get("Authorization") == "" && r.Method == http.MethodPost &&
		strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		if perr := r.ParseForm(); perr == nil && r.PostForm.Get("access_token") != "" {
			token, err = r.PostForm.Get("access_token"), nil
		}
	}
	if err != nil {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user info
	userInfo, err := h.userInfoService.GetUserInfo(r.Context(), token)
	if err != nil {
		h.logger.Info("userinfo request failed", "error", err)
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

func (h *OIDCHandler) renderAuthError(w http.ResponseWriter, r *http.Request, redirectURI, errorDesc, errorCode, state string) {
	// If we have a valid redirect URI, redirect with error
	if redirectURI != "" {
		if errorCode == "" {
			errorCode = "invalid_request"
		}
		redirectURL := h.authorizeService.BuildErrorResponse(redirectURI, errorCode, errorDesc, state)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Otherwise show error page (template escapes the description)
	h.templates.Render(w, http.StatusBadRequest, "error", errorPageData{
		Title:   "Authorization Error",
		Message: errorDesc,
	})
}

func (h *OIDCHandler) writeTokenError(w http.ResponseWriter, errorCode, errorDesc string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": errorDesc,
	})
}

// Revoke handles POST /revoke - token revocation endpoint (RFC 7009).
func (h *OIDCHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeTokenError(w, "invalid_request", "method must be POST", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Parse revocation request
	req, err := h.tokenService.ParseRevocationRequest(r)
	if err != nil {
		h.writeTokenError(w, "invalid_request", err.Error(), http.StatusBadRequest)
		return
	}

	// Handle revocation
	if err := h.tokenService.HandleRevocation(ctx, req); err != nil {
		if idperrors.IsCode(err, idperrors.CodeUnauthorized) {
			h.writeTokenError(w, "invalid_client", "invalid client credentials", http.StatusUnauthorized)
			return
		}
		// Per RFC 7009, return 200 OK even on errors (except auth errors)
	}

	h.logger.Info("token revocation processed", "client_id", req.ClientID)

	// RFC 7009: Always return 200 OK with empty body on success
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(http.StatusOK)
}

// Introspect handles POST /introspect - token introspection endpoint (RFC 7662).
func (h *OIDCHandler) Introspect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeTokenError(w, "invalid_request", "method must be POST", http.StatusMethodNotAllowed)
		return
	}

	ctx := r.Context()

	// Parse introspection request
	req, err := h.tokenService.ParseIntrospectionRequest(r)
	if err != nil {
		h.writeTokenError(w, "invalid_request", err.Error(), http.StatusBadRequest)
		return
	}

	// Handle introspection
	response, err := h.tokenService.HandleIntrospection(ctx, req)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeUnauthorized) {
			h.writeTokenError(w, "invalid_client", "client authentication required", http.StatusUnauthorized)
			return
		}
		h.logger.Error("introspection failed", "error", err)
		h.writeTokenError(w, "server_error", "introspection failed", http.StatusInternalServerError)
		return
	}

	h.logger.Info("token introspection processed", "client_id", req.ClientID, "active", response.Active)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}
