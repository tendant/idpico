package http

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/tendant/simple-idp/internal/auth"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/oidc"
)

// OIDCHandler handles OIDC endpoints.
type OIDCHandler struct {
	authService      *auth.Service
	authorizeService *oidc.AuthorizeService
	tokenService     *oidc.TokenService
	userInfoService  *oidc.UserInfoService
	logger           *slog.Logger
}

// NewOIDCHandler creates a new OIDCHandler.
func NewOIDCHandler(
	authService *auth.Service,
	authorizeService *oidc.AuthorizeService,
	tokenService *oidc.TokenService,
	userInfoService *oidc.UserInfoService,
	logger *slog.Logger,
) *OIDCHandler {
	return &OIDCHandler{
		authService:      authService,
		authorizeService: authorizeService,
		tokenService:     tokenService,
		userInfoService:  userInfoService,
		logger:           logger,
	}
}

// Authorize handles GET /authorize - the OAuth 2.0 authorization endpoint.
func (h *OIDCHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse authorization request
	authReq, err := h.authorizeService.ParseAuthorizeRequest(r)
	if err != nil {
		h.renderAuthError(w, r, "", err.Error(), "", "")
		return
	}

	// Validate client and redirect URI
	_, err = h.authorizeService.ValidateClient(ctx, authReq)
	if err != nil {
		// If redirect URI is invalid, we can't redirect - show error page
		if idperrors.IsCode(err, idperrors.CodeInvalidInput) {
			errMsg := "invalid request"
			if e, ok := err.(*idperrors.Error); ok {
				errMsg = e.Message
			}
			h.renderAuthError(w, r, "", errMsg, "", "")
			return
		}
		// For other errors, redirect with error
		redirectURL := h.authorizeService.BuildErrorResponse(
			authReq.RedirectURI,
			"invalid_request",
			err.Error(),
			authReq.State,
		)
		http.Redirect(w, r, redirectURL, http.StatusFound)
		return
	}

	// Check if user is authenticated
	user, err := h.authService.GetCurrentUser(ctx, r)
	if err != nil {
		// Not authenticated - redirect to login with return URL
		loginURL := "/login?return_url=" + url.QueryEscape(r.URL.String())
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	// User is authenticated - create authorization code
	authCode, err := h.authorizeService.CreateAuthCode(ctx, authReq, user.ID)
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
		"user_id", user.ID,
	)

	http.Redirect(w, r, redirectURL, http.StatusFound)
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

		errorCode := "invalid_request"
		status := http.StatusBadRequest

		if idperrors.IsCode(err, idperrors.CodeUnauthorized) {
			errorCode = "invalid_client"
			status = http.StatusUnauthorized
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

	// Extract bearer token
	token, err := oidc.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
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

	// Otherwise show error page
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	w.Write([]byte(`<!DOCTYPE html>
<html>
<head><title>Authorization Error</title></head>
<body>
<h1>Authorization Error</h1>
<p>` + errorDesc + `</p>
</body>
</html>`))
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
