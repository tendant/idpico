// Command oidc-client is a minimal relying party built on the mainstream Go
// OIDC libraries (coreos/go-oidc and golang.org/x/oauth2). It knows nothing
// about IDPico: point it at any OpenID Connect provider with the four
// standard settings and it does discovery, Authorization Code + PKCE, ID
// token verification and a UserInfo call.
//
//	OIDC_ISSUER=http://localhost:8080 \
//	OIDC_CLIENT_ID=my-client \
//	OIDC_CLIENT_SECRET=...            # empty = public client
//	OIDC_REDIRECT_URI=http://localhost:18081/callback \
//	LISTEN=:18081 go run .
//
// Then open http://localhost:18081/ and click "Sign in".
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type app struct {
	provider *oidc.Provider
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	public   bool
}

func main() {
	issuer := must("OIDC_ISSUER")
	clientID := must("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirectURI := envOr("OIDC_REDIRECT_URI", "http://localhost:8080/callback")
	listen := envOr("LISTEN", ":8080")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("discovery failed for %s: %v", issuer, err)
	}

	a := &app{
		provider: provider,
		oauth: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  redirectURI,
			Scopes:       strings.Fields(envOr("OIDC_SCOPES", "openid profile email")),
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: clientID}),
		public:   clientSecret == "",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", a.index)
	mux.HandleFunc("/login", a.login)
	mux.HandleFunc(mustPath(redirectURI), a.callback)
	log.Printf("oidc-client listening on %s (issuer %s, client %s, public=%v)", listen, issuer, clientID, a.public)
	log.Fatal(http.ListenAndServe(listen, mux))
}

const cookieName = "oidc_client_flow"

// flow is what the client must remember between /login and /callback.
type flow struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
}

func (a *app) index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	pageTmpl.Execute(w, map[string]any{"Issuer": a.provider.Endpoint().AuthURL})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	f := flow{State: random(), Nonce: random(), Verifier: oauth2.GenerateVerifier()}
	b, _ := json.Marshal(f)
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: base64.RawURLEncoding.EncodeToString(b),
		Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
	opts := []oauth2.AuthCodeOption{oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier)}
	http.Redirect(w, r, a.oauth.AuthCodeURL(f.State, opts...), http.StatusFound)
}

func (a *app) callback(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		http.Error(w, "no login in progress", http.StatusBadRequest)
		return
	}
	var f flow
	if b, err := base64.RawURLEncoding.DecodeString(c.Value); err != nil || json.Unmarshal(b, &f) != nil {
		http.Error(w, "bad flow cookie", http.StatusBadRequest)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})

	q := r.URL.Query()
	if q.Get("state") != f.State {
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	if e := q.Get("error"); e != "" {
		http.Error(w, "authorization failed: "+e+": "+q.Get("error_description"), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	token, err := a.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		http.Error(w, "code exchange failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "token response has no id_token", http.StatusBadGateway)
		return
	}
	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		http.Error(w, "id_token verification failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if idToken.Nonce != f.Nonce {
		http.Error(w, "nonce mismatch", http.StatusBadGateway)
		return
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	var userinfo map[string]any
	if ui, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(token)); err != nil {
		userinfo = map[string]any{"error": err.Error()}
	} else if err := ui.Claims(&userinfo); err != nil {
		userinfo = map[string]any{"error": err.Error()}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"sub":      idToken.Subject,
		"issuer":   idToken.Issuer,
		"audience": idToken.Audience,
		"expires":  idToken.Expiry,
		"claims":   claims,
		"userinfo": userinfo,
	})
}

var pageTmpl = template.Must(template.New("").Parse(`<!doctype html>
<title>oidc-client</title>
<h1>oidc-client</h1>
<p>A relying party built on go-oidc. Authorization endpoint: <code>{{.Issuer}}</code></p>
<p><a href="/login">Sign in</a></p>
`))

func must(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s is required", key)
	}
	return v
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func mustPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Path == "" {
		log.Fatalf("OIDC_REDIRECT_URI %q must be an absolute URL with a path", rawURL)
	}
	return u.Path
}

func random() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
