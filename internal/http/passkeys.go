package http

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"

	"github.com/go-chi/chi/v5"

	"github.com/tendant/idpico/internal/auth"
	idperrors "github.com/tendant/idpico/internal/errors"
)

// Passkey endpoints. The browser side is static/passkeys.js: it posts form
// fields (CSRF token included) and gets JSON back, with the WebAuthn
// options to hand to navigator.credentials and, at the end, where to go.

// maxPasskeyResponse bounds the credential JSON the browser posts.
const maxPasskeyResponse = 64 << 10

// isLockedError reports the account-lockout refusal (as opposed to a CSRF
// failure, which shares CodeForbidden).
func isLockedError(err error) bool {
	var e *idperrors.Error
	return errors.As(err, &e) && e.Code == idperrors.CodeForbidden && e.Message == "account is temporarily locked"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func passkeyError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// passkeyFailure maps service errors to a status and a message for the page.
func passkeyFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, auth.ErrInvalidPassword):
		passkeyError(w, http.StatusBadRequest, "Your current password is incorrect.")
	case errors.Is(err, auth.ErrAccountLocked):
		passkeyError(w, http.StatusForbidden, lockedMessage)
	case errors.Is(err, auth.ErrPasskeyCeremony):
		passkeyError(w, http.StatusBadRequest, "That took too long. Please try again.")
	case errors.Is(err, auth.ErrPasskeysUnavailable):
		passkeyError(w, http.StatusNotFound, "Passkeys are not available on this server.")
	case idperrors.IsCode(err, idperrors.CodeForbidden):
		passkeyError(w, http.StatusForbidden, "This page has expired. Reload it and try again.")
	case idperrors.IsCode(err, idperrors.CodeInvalidInput), idperrors.IsCode(err, idperrors.CodeAlreadyExists):
		msg := "The passkey could not be added."
		if e, ok := err.(*idperrors.Error); ok && idperrors.IsCode(err, idperrors.CodeInvalidInput) {
			msg = "The passkey could not be added: " + e.Message + "."
		}
		passkeyError(w, http.StatusBadRequest, msg)
	default:
		passkeyError(w, http.StatusInternalServerError, "Something went wrong. Please try again.")
	}
}

// --- /account -------------------------------------------------------------

func (h *AccountPageHandler) jsonCSRF(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxPasskeyResponse)
	if err := r.ParseForm(); err != nil {
		passkeyError(w, http.StatusBadRequest, "Invalid request.")
		return false
	}
	if err := h.auth.CSRF().ValidateToken(r); err != nil {
		passkeyError(w, http.StatusBadRequest, "This page has expired. Reload it and try again.")
		return false
	}
	return true
}

// PasskeyRegisterBegin checks the current password and returns the
// options for navigator.credentials.create.
func (h *AccountPageHandler) PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if !h.jsonCSRF(w, r) {
		return
	}
	creation, err := h.auth.BeginPasskeyRegistration(r.Context(), h.user(r), r.FormValue("current_password"))
	if err != nil {
		passkeyFailure(w, err)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

// PasskeyRegisterFinish stores the new passkey. The reply says where to go
// next, or carries recovery codes to show (first second step).
func (h *AccountPageHandler) PasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if !h.jsonCSRF(w, r) {
		return
	}
	codes, err := h.auth.FinishPasskeyRegistration(r.Context(), r, h.user(r), r.FormValue("name"), []byte(r.FormValue("credential")))
	if err != nil {
		h.logger.Info("passkey registration failed", "error", err)
		passkeyFailure(w, err)
		return
	}
	if len(codes) > 0 {
		writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/account?flash=" + url.QueryEscape("Passkey added")})
}

// PasskeyRemove deletes a passkey (plain form; the current password is required).
func (h *AccountPageHandler) PasskeyRemove(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	err := h.auth.RemovePasskey(r.Context(), r, h.user(r), chi.URLParam(r, "passkeyID"), r.FormValue("current_password"))
	switch {
	case errors.Is(err, auth.ErrInvalidPassword):
		h.render(w, r, http.StatusBadRequest, "Your current password is incorrect.")
	case errors.Is(err, auth.ErrAccountLocked):
		h.render(w, r, http.StatusForbidden, lockedMessage)
	case idperrors.IsCode(err, idperrors.CodeNotFound):
		h.done(w, r, "Passkey not found")
	case err != nil:
		h.logger.Error("failed to remove passkey", "error", err)
		h.render(w, r, http.StatusInternalServerError, "Failed to remove the passkey")
	default:
		h.done(w, r, "Passkey removed")
	}
}

// --- /login/passkey -------------------------------------------------------

// PasskeyBegin returns the options for navigator.credentials.get for the
// pending login.
func (h *LoginHandler) PasskeyBegin(w http.ResponseWriter, r *http.Request) {
	assertion, err := h.authService.BeginPasskeyLogin(r.Context(), r)
	switch {
	case errors.Is(err, auth.ErrPendingLoginExpired):
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Your sign-in expired.", "redirect": "/login"})
	case err != nil:
		h.logger.Info("passkey login could not start", "error", err)
		passkeyFailure(w, err)
	default:
		writeJSON(w, http.StatusOK, assertion)
	}
}

// PasskeyFinish verifies the assertion and finishes the sign-in.
func (h *LoginHandler) PasskeyFinish(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPasskeyResponse)
	if err := r.ParseForm(); err != nil {
		passkeyError(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	returnURL := r.FormValue("return_url")
	user, err := h.authService.CompletePasskeyLogin(r.Context(), w, r, []byte(r.FormValue("credential")))
	switch {
	case errors.Is(err, auth.ErrInvalidCode):
		passkeyError(w, http.StatusUnauthorized, "That passkey was not accepted. Try again, or use a code.")
	case errors.Is(err, auth.ErrPendingLoginExpired):
		q := url.Values{"message": {"Your sign-in expired. Please enter your password again."}}
		if returnURL != "" && isValidReturnURL(returnURL) {
			q.Set("return_url", returnURL)
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Your sign-in expired.", "redirect": "/login?" + q.Encode()})
	case isLockedError(err):
		passkeyError(w, http.StatusForbidden, "Account is temporarily locked due to too many failed attempts. Please try again later.")
	case err != nil:
		h.logger.Info("passkey login failed", "error", err)
		passkeyFailure(w, err)
	default:
		h.logger.Info("passkey accepted", "user_id", user.ID)
		if returnURL == "" || !isValidReturnURL(returnURL) {
			returnURL = "/"
		}
		writeJSON(w, http.StatusOK, map[string]string{"redirect": returnURL})
	}
}
