package http

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/tendant/simple-idp/internal/auth"
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/oidc"
	"github.com/tendant/simple-idp/internal/store"
)

// PlaygroundClientID is the built-in relying party the playground signs in as.
const PlaygroundClientID = "playground"

const (
	playgroundCookie     = "idp_playground"
	playgroundPendingTTL = 10 * time.Minute
	playgroundSessionTTL = 24 * time.Hour
)

// PlaygroundHandler is a built-in OIDC relying party. It drives this IdP's
// own endpoints the way an external application would (through the router,
// not by calling services directly) and renders what comes back.
type PlaygroundHandler struct {
	clients   store.ClientRepository
	csrf      *auth.CSRFService
	router    http.Handler // the IdP itself; token/userinfo calls are served in-process
	templates *Templates
	logger    *slog.Logger
	issuer    string
	secret    string // plaintext client secret, regenerated on every start

	mu       sync.Mutex
	pending  map[string]*playgroundPending // keyed by state
	sessions map[string]*playgroundSession // keyed by cookie value
}

type playgroundPending struct {
	nonce, verifier string
	created         time.Time
}

type playgroundSession struct {
	tokens    oidc.TokenResponse
	nonce     string
	nonceOK   bool
	obtained  string
	at        time.Time
	lastCall  string
	lastError string
	touched   time.Time
}

// NewPlaygroundHandler creates the playground and registers (or updates)
// its client in the store so the flow works out of the box.
func NewPlaygroundHandler(ctx context.Context, clients store.ClientRepository, csrf *auth.CSRFService, router http.Handler, templates *Templates, issuer string, logger *slog.Logger) (*PlaygroundHandler, error) {
	secret, err := randomSecret(32)
	if err != nil {
		return nil, err
	}
	hash, err := oidc.HashClientSecret(secret)
	if err != nil {
		return nil, err
	}

	h := &PlaygroundHandler{
		clients:   clients,
		csrf:      csrf,
		router:    router,
		templates: templates,
		logger:    logger,
		issuer:    strings.TrimRight(issuer, "/"),
		secret:    secret,
		pending:   map[string]*playgroundPending{},
		sessions:  map[string]*playgroundSession{},
	}

	client := &domain.Client{
		ID:           PlaygroundClientID,
		Secret:       hash,
		Name:         "OIDC Playground",
		RedirectURIs: []string{h.redirectURI()},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email", "offline_access", "groups"},
	}
	existing, err := clients.GetByID(ctx, PlaygroundClientID)
	switch {
	case err == nil:
		// Keep the operator's consent choice, refresh everything else.
		client.SkipConsent = existing.SkipConsent
		client.CreatedAt = existing.CreatedAt
		err = clients.Update(ctx, client)
	case idperrors.IsCode(err, idperrors.CodeNotFound):
		err = clients.Create(ctx, client)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to register playground client: %w", err)
	}
	return h, nil
}

func (h *PlaygroundHandler) redirectURI() string { return h.issuer + "/playground/callback" }

// Routes mounts the playground on r.
func (h *PlaygroundHandler) Routes(r chi.Router) {
	r.Get("/", h.Page)
	r.Post("/start", h.Start)
	r.Get("/callback", h.Callback)
	r.Post("/userinfo", h.action(h.callUserInfo))
	r.Post("/introspect", h.action(h.callIntrospect))
	r.Post("/refresh", h.action(h.callRefresh))
	r.Post("/revoke", h.action(h.callRevoke))
	r.Post("/logout", h.Logout)
	r.Post("/clear", h.Clear)
}

// Page data

type playgroundScope struct {
	Name    string
	Checked bool
}

type playgroundResult struct {
	ObtainedVia       string
	At                string
	IDTokenHeader     string
	IDTokenClaims     string
	AccessTokenClaims string
	UserInfo          string
	Raw               string
	ExpiresIn         int
	Scope             string
	RefreshToken      string
	NonceOK           bool
	Extra             string
}

type playgroundData struct {
	CSRFToken   string
	Flash       string
	Error       string
	ClientID    string
	RedirectURI string
	Issuer      string
	Scopes      []playgroundScope
	Result      *playgroundResult
	LastError   string
}

// Page handles GET /playground.
func (h *PlaygroundHandler) Page(w http.ResponseWriter, r *http.Request) {
	token, _ := h.csrf.GenerateToken(w)
	data := playgroundData{
		CSRFToken:   token,
		Flash:       r.URL.Query().Get("flash"),
		Error:       r.URL.Query().Get("error"),
		ClientID:    PlaygroundClientID,
		RedirectURI: h.redirectURI(),
		Issuer:      h.issuer,
		Scopes: []playgroundScope{
			{"profile", true}, {"email", true}, {"groups", true}, {"offline_access", false},
		},
	}
	if sess := h.session(r); sess != nil {
		data.Result = h.render(r.Context(), sess)
		data.LastError = sess.lastError
	}
	h.templates.Render(w, http.StatusOK, "wide/playground", data)
}

// Start handles POST /playground/start: builds the authorization request.
func (h *PlaygroundHandler) Start(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || h.csrf.ValidateToken(r) != nil {
		h.redirect(w, r, "", "Invalid or expired form, please try again")
		return
	}

	state, _ := randomSecret(16)
	nonce, _ := randomSecret(16)
	verifier, _ := randomSecret(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	h.mu.Lock()
	h.prune()
	h.pending[state] = &playgroundPending{nonce: nonce, verifier: verifier, created: time.Now()}
	h.mu.Unlock()

	scopes := append([]string{"openid"}, r.Form["scope"]...)
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {PlaygroundClientID},
		"redirect_uri":          {h.redirectURI()},
		"scope":                 {strings.Join(scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if p := r.FormValue("prompt"); p != "" {
		q.Set("prompt", p)
	}
	if m := strings.TrimSpace(r.FormValue("max_age")); m != "" {
		q.Set("max_age", m)
	}
	http.Redirect(w, r, "/authorize?"+q.Encode(), http.StatusFound)
}

// Callback handles GET /playground/callback: exchanges the code.
func (h *PlaygroundHandler) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		h.redirect(w, r, "", "Authorization failed: "+e+" — "+q.Get("error_description"))
		return
	}

	h.mu.Lock()
	p, ok := h.pending[q.Get("state")]
	delete(h.pending, q.Get("state"))
	h.mu.Unlock()
	if !ok || time.Since(p.created) > playgroundPendingTTL {
		h.redirect(w, r, "", "Unknown or expired state — start again")
		return
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {q.Get("code")},
		"redirect_uri":  {h.redirectURI()},
		"client_id":     {PlaygroundClientID},
		"client_secret": {h.secret},
		"code_verifier": {p.verifier},
	}
	var tokens oidc.TokenResponse
	if status, body, err := h.post("/token", form, &tokens); err != nil || status != http.StatusOK {
		h.redirect(w, r, "", fmt.Sprintf("Token exchange failed (%d): %s", status, body))
		return
	}

	sess := &playgroundSession{tokens: tokens, nonce: p.nonce, obtained: "authorization_code", at: time.Now(), touched: time.Now()}
	if claims := decodeJWTClaims(tokens.IDToken); claims != nil {
		sess.nonceOK = claims["nonce"] == p.nonce
	}

	id, _ := randomSecret(24)
	h.mu.Lock()
	h.sessions[id] = sess
	h.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: playgroundCookie, Value: id, Path: "/playground", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: int(playgroundSessionTTL.Seconds())})

	h.redirect(w, r, "Signed in: tokens received from /token", "")
}

// action wraps a token-using operation with CSRF and session lookup.
func (h *PlaygroundHandler) action(fn func(ctx context.Context, s *playgroundSession) (string, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || h.csrf.ValidateToken(r) != nil {
			h.redirect(w, r, "", "Invalid or expired form, please try again")
			return
		}
		sess := h.session(r)
		if sess == nil {
			h.redirect(w, r, "", "No tokens yet — sign in first")
			return
		}
		out, err := fn(r.Context(), sess)
		h.mu.Lock()
		sess.touched = time.Now()
		if err != nil {
			sess.lastCall = ""
			sess.lastError = err.Error()
		} else {
			sess.lastCall = out
			sess.lastError = ""
		}
		h.mu.Unlock()
		if err != nil {
			h.redirect(w, r, "", err.Error())
			return
		}
		h.redirect(w, r, "Done — see \"Last call\"", "")
	}
}

func (h *PlaygroundHandler) callUserInfo(_ context.Context, s *playgroundSession) (string, error) {
	status, body, err := h.get("/userinfo", s.tokens.AccessToken)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("GET /userinfo → %d\n%s", status, prettyJSON(body)), nil
}

func (h *PlaygroundHandler) callIntrospect(_ context.Context, s *playgroundSession) (string, error) {
	form := url.Values{"token": {s.tokens.AccessToken}, "token_type_hint": {"access_token"}, "client_id": {PlaygroundClientID}, "client_secret": {h.secret}}
	status, body, err := h.post("/introspect", form, nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("POST /introspect → %d\n%s", status, prettyJSON(body)), nil
}

func (h *PlaygroundHandler) callRefresh(_ context.Context, s *playgroundSession) (string, error) {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {s.tokens.RefreshToken}, "client_id": {PlaygroundClientID}, "client_secret": {h.secret}}
	var tokens oidc.TokenResponse
	status, body, err := h.post("/token", form, &tokens)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("refresh failed (%d): %s", status, body)
	}
	s.tokens = tokens
	s.obtained = "refresh_token"
	s.at = time.Now()
	return fmt.Sprintf("POST /token (refresh_token) → %d\n%s", status, prettyJSON(body)), nil
}

func (h *PlaygroundHandler) callRevoke(_ context.Context, s *playgroundSession) (string, error) {
	form := url.Values{"token": {s.tokens.RefreshToken}, "token_type_hint": {"refresh_token"}, "client_id": {PlaygroundClientID}, "client_secret": {h.secret}}
	status, body, err := h.post("/revoke", form, nil)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("POST /revoke → %d\n%s\n(the refresh token is now unusable; try \"Refresh tokens\")", status, body), nil
}

// Logout handles POST /playground/logout: RP-initiated logout at the IdP.
func (h *PlaygroundHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || h.csrf.ValidateToken(r) != nil {
		h.redirect(w, r, "", "Invalid or expired form, please try again")
		return
	}
	q := url.Values{"post_logout_redirect_uri": {"/playground"}, "state": {"logged-out"}}
	if sess := h.session(r); sess != nil {
		q.Set("id_token_hint", sess.tokens.IDToken)
	}
	h.forget(w, r)
	http.Redirect(w, r, "/logout?"+q.Encode(), http.StatusFound)
}

// Clear handles POST /playground/clear: drops the stored tokens.
func (h *PlaygroundHandler) Clear(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || h.csrf.ValidateToken(r) != nil {
		h.redirect(w, r, "", "Invalid or expired form, please try again")
		return
	}
	h.forget(w, r)
	h.redirect(w, r, "Tokens forgotten (the IdP session is still signed in)", "")
}

// In-process HTTP against the IdP

func (h *PlaygroundHandler) post(path string, form url.Values, out any) (int, string, error) {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:0"
	return h.do(req, out)
}

func (h *PlaygroundHandler) get(path, bearer string) (int, string, error) {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.RemoteAddr = "127.0.0.1:0"
	return h.do(req, nil)
}

func (h *PlaygroundHandler) do(req *http.Request, out any) (int, string, error) {
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Body)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(body, out); err != nil {
			return rec.Code, string(body), fmt.Errorf("invalid JSON from %s: %w", req.URL.Path, err)
		}
	}
	return rec.Code, string(body), nil
}

// Session helpers

func (h *PlaygroundHandler) session(r *http.Request) *playgroundSession {
	c, err := r.Cookie(playgroundCookie)
	if err != nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sessions[c.Value]
}

func (h *PlaygroundHandler) forget(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(playgroundCookie); err == nil {
		h.mu.Lock()
		delete(h.sessions, c.Value)
		h.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: playgroundCookie, Value: "", Path: "/playground", MaxAge: -1})
}

// prune drops stale pending states and sessions. Caller holds mu.
func (h *PlaygroundHandler) prune() {
	now := time.Now()
	for k, p := range h.pending {
		if now.Sub(p.created) > playgroundPendingTTL {
			delete(h.pending, k)
		}
	}
	for k, s := range h.sessions {
		if now.Sub(s.touched) > playgroundSessionTTL {
			delete(h.sessions, k)
		}
	}
}

func (h *PlaygroundHandler) redirect(w http.ResponseWriter, r *http.Request, flash, errMsg string) {
	q := url.Values{}
	if flash != "" {
		q.Set("flash", flash)
	}
	if errMsg != "" {
		q.Set("error", errMsg)
	}
	target := "/playground"
	if len(q) > 0 {
		target += "?" + q.Encode()
	}
	http.Redirect(w, r, target, http.StatusFound)
}

func (h *PlaygroundHandler) render(_ context.Context, s *playgroundSession) *playgroundResult {
	h.mu.Lock()
	defer h.mu.Unlock()

	res := &playgroundResult{
		ObtainedVia:  s.obtained,
		At:           s.at.Format("15:04:05"),
		ExpiresIn:    s.tokens.ExpiresIn,
		Scope:        s.tokens.Scope,
		RefreshToken: s.tokens.RefreshToken,
		NonceOK:      s.nonceOK,
		Extra:        s.lastCall,
	}
	raw, _ := json.MarshalIndent(s.tokens, "", "  ")
	res.Raw = string(raw)
	res.IDTokenHeader = decodeJWTPart(s.tokens.IDToken, 0)
	res.IDTokenClaims = prettyJSON(decodeJWTPart(s.tokens.IDToken, 1))
	res.AccessTokenClaims = prettyJSON(decodeJWTPart(s.tokens.AccessToken, 1))

	if _, body, err := h.get("/userinfo", s.tokens.AccessToken); err == nil {
		res.UserInfo = prettyJSON(body)
	}
	return res
}

// JWT helpers (decode only; the IdP already verified these tokens)

func decodeJWTPart(token string, idx int) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[idx])
	if err != nil {
		return ""
	}
	return string(b)
}

func decodeJWTClaims(token string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(decodeJWTPart(token, 1)), &m); err != nil {
		return nil
	}
	return m
}

func prettyJSON(s string) string {
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return s
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return s
	}
	return string(b)
}
