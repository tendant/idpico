package http

import (
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"strings"

	"rsc.io/qr"

	"github.com/tendant/idpico/internal/auth"
)

// Two-step sign-in on /account: set up an authenticator (QR code + one code
// to prove it works), see recovery codes once, renew them, turn it off.

type twoStepPageData struct {
	wideBase
	Secret        string
	SecretDisplay string       // the secret in groups of four, for typing
	QRDataURI     template.URL // built here from our own PNG bytes, so trusted
	RecoveryCodes []string     // set only right after they were generated
}

// TwoStepSetup shows a fresh secret as a QR code. Nothing is stored until
// the user proves the app holds it; the secret travels in the form.
func (h *AccountPageHandler) TwoStepSetup(w http.ResponseWriter, r *http.Request) {
	if h.user(r).TOTPEnabled() {
		h.done(w, r, "Two-step sign-in is already on")
		return
	}
	secret, err := auth.NewTOTPSecret()
	if err != nil {
		h.logger.Error("failed to generate TOTP secret", "error", err)
		h.render(w, r, http.StatusInternalServerError, "Failed to start setup")
		return
	}
	h.renderTwoStepSetup(w, r, http.StatusOK, secret, "")
}

func (h *AccountPageHandler) renderTwoStepSetup(w http.ResponseWriter, r *http.Request, status int, secret, errMsg string) {
	data := twoStepPageData{wideBase: h.base(w, r), Secret: secret, SecretDisplay: groupsOf4(secret)}
	data.Error = errMsg
	w.Header().Set("Cache-Control", "no-store") // the page carries the secret
	code, err := qr.Encode(auth.TOTPURI("IDPico", h.user(r).Email, secret), qr.M)
	if err != nil {
		h.logger.Error("failed to render QR code", "error", err)
	} else {
		code.Scale = 5
		data.QRDataURI = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG()))
	}
	h.templates.Render(w, status, "wide/two_step", data)
}

func (h *AccountPageHandler) TwoStepEnable(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	secret := r.FormValue("secret")
	codes, err := h.auth.EnableTOTP(r.Context(), r, h.user(r), r.FormValue("current_password"), secret, r.FormValue("code"))
	switch {
	case errors.Is(err, auth.ErrInvalidPassword):
		h.renderTwoStepSetup(w, r, http.StatusBadRequest, secret, "Your current password is incorrect.")
		return
	case errors.Is(err, auth.ErrAccountLocked):
		h.renderTwoStepSetup(w, r, http.StatusForbidden, secret, lockedMessage)
		return
	case errors.Is(err, auth.ErrInvalidCode):
		h.renderTwoStepSetup(w, r, http.StatusBadRequest, secret, "That code did not match. Check that the app added the account and that your phone's clock is right, then try the current code.")
		return
	case err != nil:
		h.logger.Error("failed to enable TOTP", "error", err)
		h.render(w, r, http.StatusInternalServerError, "Failed to turn on two-step sign-in")
		return
	}
	h.renderRecoveryCodes(w, r, codes, "Two-step sign-in is on.")
}

func (h *AccountPageHandler) TwoStepDisable(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	if err := h.auth.DisableTOTP(r.Context(), r, h.user(r), r.FormValue("code")); err != nil {
		h.twoStepError(w, r, err)
		return
	}
	h.done(w, r, "Two-step sign-in is off")
}

func (h *AccountPageHandler) TwoStepRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	if !h.checkCSRF(w, r) {
		return
	}
	codes, err := h.auth.RenewRecoveryCodes(r.Context(), r, h.user(r), r.FormValue("code"))
	if err != nil {
		h.twoStepError(w, r, err)
		return
	}
	h.renderRecoveryCodes(w, r, codes, "New recovery codes; the old ones no longer work.")
}

func (h *AccountPageHandler) twoStepError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, auth.ErrInvalidCode) {
		h.render(w, r, http.StatusBadRequest, "That code is not valid. Use the current code from your app, or a recovery code.")
		return
	}
	if errors.Is(err, auth.ErrAccountLocked) {
		h.render(w, r, http.StatusForbidden, lockedMessage)
		return
	}
	h.logger.Error("two-step sign-in change failed", "error", err)
	h.render(w, r, http.StatusInternalServerError, "Failed to change two-step sign-in")
}

func (h *AccountPageHandler) renderRecoveryCodes(w http.ResponseWriter, r *http.Request, codes []string, flash string) {
	data := twoStepPageData{wideBase: h.base(w, r), RecoveryCodes: codes}
	data.Flash = flash
	w.Header().Set("Cache-Control", "no-store")
	h.templates.Render(w, http.StatusOK, "wide/two_step", data)
}

const lockedMessage = "Too many failed attempts. Please try again later."

func groupsOf4(s string) string {
	var parts []string
	for len(s) > 4 {
		parts = append(parts, s[:4])
		s = s[4:]
	}
	return strings.Join(append(parts, s), " ")
}
