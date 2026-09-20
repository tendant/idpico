//go:build conformance

package conformance

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// ---- HTTP -------------------------------------------------------------

// provider is the client-side view of one OpenID provider: its issuer, the
// transport to reach it (nil for a direct connection; a proxyTransport to
// simulate a reverse proxy) and its cached discovery document. The
// package-level free functions below act on def, the default server, so
// tests that only ever talk to one provider read naturally; operational
// tests hold several providers and call the methods.
type provider struct {
	issuer    string
	transport http.RoundTripper
	client    *http.Client // no cookie jar: discovery, JWKS, token, userinfo

	discOnce sync.Once
	disc     *discoveryDoc
	discErr  error
}

func newProvider(issuer string, transport http.RoundTripper) *provider {
	return &provider{
		issuer:    strings.TrimSuffix(issuer, "/"),
		transport: transport,
		client:    &http.Client{Transport: transport, Timeout: 10 * time.Second},
	}
}

// newHTTPClient returns a client that keeps cookies (the CSRF cookie is
// SameSite=Strict, so it must round-trip between GET and POST /login) and
// never follows redirects: every 302 is inspected by the test.
func newHTTPClient(t *testing.T) *http.Client { return def.newHTTPClient(t) }

func (p *provider) newHTTPClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar:       jar,
		Transport: p.transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// send performs the request and returns the response with its body already
// read (and closed). In verbose mode the exchange is logged, redacted.
func send(t *testing.T, c *http.Client, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	var reqBody []byte
	if req.GetBody != nil {
		rc, _ := req.GetBody()
		reqBody, _ = io.ReadAll(rc)
		rc.Close()
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("%s %s: read body: %v", req.Method, req.URL, err)
	}
	if cfg.Verbose {
		var sb strings.Builder
		fmt.Fprintf(&sb, "> %s %s\n", req.Method, req.URL)
		for k, v := range req.Header {
			fmt.Fprintf(&sb, "> %s: %s\n", k, strings.Join(v, ", "))
		}
		if len(reqBody) > 0 {
			fmt.Fprintf(&sb, ">\n> %s\n", reqBody)
		}
		fmt.Fprintf(&sb, "< %s\n", resp.Status)
		for k, v := range resp.Header {
			fmt.Fprintf(&sb, "< %s: %s\n", k, strings.Join(v, ", "))
		}
		if len(body) > 0 {
			b := body
			if len(b) > 2000 {
				b = append(b[:2000:2000], []byte("...")...)
			}
			fmt.Fprintf(&sb, "<\n< %s\n", b)
		}
		t.Log(redact(sb.String()))
	}
	return resp, body
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		t.Fatal(err)
	}
	return send(t, c, req)
}

func postForm(t *testing.T, c *http.Client, u string, form url.Values) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return send(t, c, req)
}

// ---- redaction --------------------------------------------------------

var (
	jwtRe    = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`)
	formRe   = regexp.MustCompile(`(?i)((?:password|client_secret|code_verifier|code|refresh_token|access_token|id_token)=)[^&\s"]+`)
	jsonRe   = regexp.MustCompile(`("(?:access_token|id_token|refresh_token|code|client_secret|password)"\s*:\s*")[^"]*`)
	cookieRe = regexp.MustCompile(`(idpico_[a-z_]+=)[^;\s,]+`)
	authRe   = regexp.MustCompile(`(?i)(Authorization: (?:Bearer|Basic) )\S+`)
)

// redact removes credentials, tokens, codes and cookies from diagnostic
// output. Anything printed by the suite goes through here.
func redact(s string) string {
	for _, secret := range []string{cfg.ClientSecret, cfg.OtherClientSecret, cfg.StrictClientSecret, cfg.UserPassword} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
			s = strings.ReplaceAll(s, url.QueryEscape(secret), "[redacted]")
		}
	}
	s = authRe.ReplaceAllString(s, "${1}[redacted]")
	s = cookieRe.ReplaceAllString(s, "${1}[redacted]")
	s = jsonRe.ReplaceAllString(s, "${1}[redacted]")
	s = formRe.ReplaceAllString(s, "${1}[redacted]")
	s = jwtRe.ReplaceAllString(s, "[jwt redacted]")
	return s
}

// ---- discovery and JWKS ----------------------------------------------

type discoveryDoc struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`

	raw map[string]any
}

// discovery fetches and caches the provider metadata. Every endpoint the
// suite talks to comes from here, never from a hard-coded path.
func discovery(t *testing.T) *discoveryDoc { return def.discovery(t) }

func (p *provider) discovery(t *testing.T) *discoveryDoc {
	t.Helper()
	p.discOnce.Do(func() {
		resp, err := p.client.Get(p.issuer + "/.well-known/openid-configuration")
		if err != nil {
			p.discErr = err
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			p.discErr = fmt.Errorf("discovery: HTTP %d", resp.StatusCode)
			return
		}
		var d discoveryDoc
		if err := json.Unmarshal(body, &d); err != nil {
			p.discErr = fmt.Errorf("discovery: invalid JSON: %w", err)
			return
		}
		_ = json.Unmarshal(body, &d.raw)
		p.disc = &d
	})
	if p.discErr != nil {
		t.Fatal(p.discErr)
	}
	return p.disc
}

// fetchJWKS returns the raw JWK Set document and its parsed form.
func fetchJWKS(t *testing.T) ([]byte, *jose.JSONWebKeySet) { return def.fetchJWKS(t) }

func (p *provider) fetchJWKS(t *testing.T) ([]byte, *jose.JSONWebKeySet) {
	t.Helper()
	resp, body := get(t, p.client, p.discovery(t).JWKSURI)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("jwks_uri: HTTP %d", resp.StatusCode)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatalf("jwks_uri: invalid JWK Set: %v", err)
	}
	return body, &set
}

// ---- authorization flow -----------------------------------------------

func randomString(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// pkce returns a fresh RFC 7636 verifier and its S256 challenge.
func pkce(t *testing.T) (verifier, challenge string) {
	t.Helper()
	verifier = randomString(t, 32)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// authzParams builds a standard authorization request. challenge may be
// empty for confidential clients.
func authzParams(clientID, redirectURI, scope, state, nonce, challenge string) url.Values {
	p := url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {scope},
	}
	if state != "" {
		p.Set("state", state)
	}
	if nonce != "" {
		p.Set("nonce", nonce)
	}
	if challenge != "" {
		p.Set("code_challenge", challenge)
		p.Set("code_challenge_method", "S256")
	}
	return p
}

var hiddenInputRe = regexp.MustCompile(`name="([^"]+)"\s+value="([^"]*)"`)

// formValue extracts a hidden input's value from a rendered form.
func formValue(body []byte, name string) string {
	for _, m := range hiddenInputRe.FindAllSubmatch(body, -1) {
		if string(m[1]) == name {
			return html.UnescapeString(string(m[2]))
		}
	}
	return ""
}

// login signs the test user in through the login page reached at loginURL
// (as sent by /authorize) and returns the URL the server sends the browser
// to afterwards.
func login(t *testing.T, c *http.Client, loginURL string) string {
	t.Helper()
	resp, body := get(t, c, loginURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET login page: HTTP %d", resp.StatusCode)
	}
	form := url.Values{
		"email":    {cfg.UserEmail},
		"password": {cfg.UserPassword},
	}
	for _, name := range []string{"csrf_token", "return_url"} {
		if v := formValue(body, name); v != "" {
			form.Set(name, v)
		}
	}
	resp, body = postForm(t, c, loginURL, form)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("POST login: HTTP %d: %s", resp.StatusCode, redact(string(body)))
	}
	return resolve(t, loginURL, resp.Header.Get("Location"))
}

// resolve turns a possibly relative Location into an absolute URL.
func resolve(t *testing.T, base, loc string) string {
	t.Helper()
	b, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	l, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("bad Location %q: %v", loc, err)
	}
	return b.ResolveReference(l).String()
}

// authorize sends the authorization request and drives whatever the
// provider puts in front of the user (login page, consent page) until it
// answers the request: a 302 to the client's redirect_uri or an error page.
func authorize(t *testing.T, c *http.Client, params url.Values) (*http.Response, []byte) {
	return def.authorize(t, c, params)
}

func (p *provider) authorize(t *testing.T, c *http.Client, params url.Values) (*http.Response, []byte) {
	t.Helper()
	authURL := p.discovery(t).AuthorizationEndpoint + "?" + params.Encode()
	resp, body := get(t, c, authURL)

	for i := 0; i < 5; i++ {
		switch {
		case resp.StatusCode == http.StatusFound && strings.Contains(resp.Header.Get("Location"), "/login"):
			next := login(t, c, resolve(t, authURL, resp.Header.Get("Location")))
			resp, body = get(t, c, next)
		case resp.StatusCode == http.StatusOK && strings.Contains(string(body), `action="/consent"`):
			form := url.Values{
				"csrf_token":      {formValue(body, "csrf_token")},
				"authorize_query": {formValue(body, "authorize_query")},
				"action":          {"allow"},
			}
			resp, body = postForm(t, c, resolve(t, authURL, "/consent"), form)
		default:
			return resp, body
		}
	}
	t.Fatalf("authorization did not settle after login and consent (last: HTTP %d)", resp.StatusCode)
	return nil, nil
}

// callback asserts that resp redirects to exactly the registered
// redirect_uri and returns its query parameters.
func callback(t *testing.T, resp *http.Response, body []byte, redirectURI string) url.Values {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 to %s, got HTTP %d: %s", redirectURI, resp.StatusCode, redact(snippet(body)))
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("bad Location: %v", err)
	}
	q := loc.Query()
	loc.RawQuery, loc.Fragment = "", ""
	if loc.String() != redirectURI {
		t.Fatalf("redirected to %q, want exactly %q", loc.String(), redirectURI)
	}
	return q
}

// obtainCode runs a complete authorization for a fresh browser session and
// returns the code and the callback parameters.
func obtainCode(t *testing.T, params url.Values, redirectURI string) (string, url.Values) {
	return def.obtainCode(t, params, redirectURI)
}

func (p *provider) obtainCode(t *testing.T, params url.Values, redirectURI string) (string, url.Values) {
	t.Helper()
	resp, body := p.authorize(t, p.newHTTPClient(t), params)
	q := callback(t, resp, body, redirectURI)
	if q.Get("error") != "" {
		t.Fatalf("authorization error: %s (%s)", q.Get("error"), q.Get("error_description"))
	}
	if q.Get("code") == "" {
		t.Fatalf("callback has no code: %v", q)
	}
	return q.Get("code"), q
}

// ---- token endpoint ---------------------------------------------------

// tokenResponse is what /token answered: status, headers and the decoded
// JSON body (error responses included).
type tokenResponse struct {
	Status int
	Header http.Header
	Body   map[string]any
	Raw    []byte
}

func (r tokenResponse) str(k string) string {
	s, _ := r.Body[k].(string)
	return s
}

// tokenRequest posts form to the token endpoint. When basic is non-nil the
// client authenticates with client_secret_basic; otherwise whatever is in
// form (client_secret_post or nothing for public clients).
func tokenRequest(t *testing.T, form url.Values, basic *[2]string) tokenResponse {
	return def.tokenRequest(t, form, basic)
}

func (p *provider) tokenRequest(t *testing.T, form url.Values, basic *[2]string) tokenResponse {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, p.discovery(t).TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic != nil {
		req.SetBasicAuth(basic[0], basic[1])
	}
	resp, body := send(t, p.client, req)
	tr := tokenResponse{Status: resp.StatusCode, Header: resp.Header, Raw: body}
	if err := json.Unmarshal(body, &tr.Body); err != nil {
		t.Fatalf("token endpoint returned HTTP %d with non-JSON body: %s", resp.StatusCode, redact(snippet(body)))
	}
	return tr
}

// exchange redeems an authorization code. secret == "" means a public
// client (no client authentication); verifier == "" omits code_verifier.
func exchange(t *testing.T, code, verifier, clientID, secret, redirectURI string) tokenResponse {
	return def.exchange(t, code, verifier, clientID, secret, redirectURI)
}

func (p *provider) exchange(t *testing.T, code, verifier, clientID, secret, redirectURI string) tokenResponse {
	t.Helper()
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	var basic *[2]string
	if secret != "" {
		basic = &[2]string{clientID, secret}
	}
	return p.tokenRequest(t, form, basic)
}

// expectTokenError asserts an RFC 6749 §5.2 error response.
func expectTokenError(t *testing.T, tr tokenResponse, status int, code string) {
	t.Helper()
	if tr.Status != status || tr.str("error") != code {
		t.Errorf("want HTTP %d error=%q, got HTTP %d %s", status, code, tr.Status, redact(string(tr.Raw)))
	}
	if ct := tr.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("error response Content-Type = %q, want application/json", ct)
	}
}

// ---- tokens (independent of the provider's implementation) ------------

var allowedAlgs = []jose.SignatureAlgorithm{jose.RS256, jose.EdDSA}

// claimsOf decodes a JWT payload without verifying anything. Only for
// reading values the test then compares against verified ones.
func claimsOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS compact serialization (%d parts)", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("payload is not base64url: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	return m
}

// idTokenExpectation is what the relying party knows and must check.
type idTokenExpectation struct {
	Issuer   string
	ClientID string
	Nonce    string
}

// errTokenInvalid is returned by verifyIDToken when a check fails.
var errTokenInvalid = errors.New("id token invalid")

// verifyIDToken validates an ID token the way an independent relying party
// must (OIDC Core §3.1.3.7), using go-jose and the published JWK Set only:
// signature by a key from jwks_uri that matches kid and alg, iss, aud, exp,
// iat sanity and nonce. It never consults the provider's own code.
func verifyIDToken(t *testing.T, raw string, set *jose.JSONWebKeySet, want idTokenExpectation) (map[string]any, error) {
	t.Helper()
	sig, err := jose.ParseSigned(raw, allowedAlgs)
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", errTokenInvalid, err)
	}
	if len(sig.Signatures) != 1 {
		return nil, fmt.Errorf("%w: %d signatures", errTokenInvalid, len(sig.Signatures))
	}
	hdr := sig.Signatures[0].Header
	if hdr.KeyID == "" {
		return nil, fmt.Errorf("%w: no kid header", errTokenInvalid)
	}
	keys := set.Key(hdr.KeyID)
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: kid %q not in JWKS", errTokenInvalid, hdr.KeyID)
	}
	key := keys[0]
	if key.Algorithm != "" && key.Algorithm != hdr.Algorithm {
		return nil, fmt.Errorf("%w: token alg %s but key alg %s", errTokenInvalid, hdr.Algorithm, key.Algorithm)
	}
	payload, err := sig.Verify(key.Public().Key)
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", errTokenInvalid, err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("%w: claims: %v", errTokenInvalid, err)
	}

	if iss, _ := claims["iss"].(string); iss != want.Issuer {
		return nil, fmt.Errorf("%w: iss %q, want %q", errTokenInvalid, iss, want.Issuer)
	}
	if !audienceContains(claims["aud"], want.ClientID) {
		return nil, fmt.Errorf("%w: aud %v does not contain %q", errTokenInvalid, claims["aud"], want.ClientID)
	}
	now := time.Now()
	exp, ok := numericDate(claims["exp"])
	if !ok {
		return nil, fmt.Errorf("%w: exp missing", errTokenInvalid)
	}
	if !now.Before(exp) {
		return nil, fmt.Errorf("%w: expired at %s", errTokenInvalid, exp)
	}
	iat, ok := numericDate(claims["iat"])
	if !ok {
		return nil, fmt.Errorf("%w: iat missing", errTokenInvalid)
	}
	if iat.After(now.Add(2*time.Minute)) || now.Sub(iat) > 24*time.Hour {
		return nil, fmt.Errorf("%w: iat %s is not plausible", errTokenInvalid, iat)
	}
	if nonce, _ := claims["nonce"].(string); nonce != want.Nonce {
		return nil, fmt.Errorf("%w: nonce %q, want %q", errTokenInvalid, nonce, want.Nonce)
	}
	if sub, _ := claims["sub"].(string); sub == "" {
		return nil, fmt.Errorf("%w: sub missing", errTokenInvalid)
	}
	return claims, nil
}

func audienceContains(aud any, clientID string) bool {
	switch v := aud.(type) {
	case string:
		return v == clientID
	case []any:
		for _, a := range v {
			if s, _ := a.(string); s == clientID {
				return true
			}
		}
	}
	return false
}

func numericDate(v any) (time.Time, bool) {
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

// mustVerifyIDToken is verifyIDToken for the positive path.
func mustVerifyIDToken(t *testing.T, raw string, want idTokenExpectation) map[string]any {
	return def.mustVerifyIDToken(t, raw, want)
}

func (p *provider) mustVerifyIDToken(t *testing.T, raw string, want idTokenExpectation) map[string]any {
	t.Helper()
	_, set := p.fetchJWKS(t)
	claims, err := verifyIDToken(t, raw, set, want)
	if err != nil {
		t.Fatalf("ID token failed independent validation: %v", err)
	}
	return claims
}

// mintToken signs claims with a key the provider does not know, imitating a
// forged token. kid and alg are placed in the header verbatim.
func mintToken(t *testing.T, alg jose.SignatureAlgorithm, key any, kid string, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid != "" {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(claims)
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// unsignedToken builds an alg=none token (RFC 7518 §3.6) from claims.
func unsignedToken(claims map[string]any) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	return hdr + "." + base64.RawURLEncoding.EncodeToString(payload) + "."
}

// withClaim re-encodes the payload of raw with one claim changed, keeping
// the original header and signature (which therefore no longer matches).
func withClaim(t *testing.T, raw, name string, value any) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	claims := claimsOf(t, raw)
	claims[name] = value
	payload, _ := json.Marshal(claims)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	return strings.Join(parts, ".")
}

// flipSignature corrupts the signature segment of raw.
func flipSignature(raw string) string {
	parts := strings.Split(raw, ".")
	sig := []byte(parts[2])
	i := len(sig) / 2
	if sig[i] == 'A' {
		sig[i] = 'B'
	} else {
		sig[i] = 'A'
	}
	parts[2] = string(sig)
	return strings.Join(parts, ".")
}

// ---- userinfo ---------------------------------------------------------

// userinfo calls the UserInfo endpoint with the given Authorization header
// value ("" sends none).
func userinfo(t *testing.T, authorization string) (*http.Response, []byte) {
	return def.userinfo(t, authorization)
}

func (p *provider) userinfo(t *testing.T, authorization string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, p.discovery(t).UserinfoEndpoint, nil)
	if err != nil {
		t.Fatal(err)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return send(t, p.client, req)
}

// expectUnauthorized asserts an RFC 6750 §3 rejection.
func expectUnauthorized(t *testing.T, resp *http.Response, body []byte) {
	t.Helper()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("want HTTP 401, got %d: %s", resp.StatusCode, redact(snippet(body)))
	}
	if h := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(h, "Bearer") {
		t.Errorf("want WWW-Authenticate: Bearer ..., got %q", h)
	}
}

// ---- misc -------------------------------------------------------------

func snippet(b []byte) string {
	s := string(b)
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// assertNoSecrets fails when body leaks any credential or token the suite
// knows about.
func assertNoSecrets(t *testing.T, what string, body []byte, tokens ...string) {
	t.Helper()
	s := string(body)
	for _, secret := range append([]string{cfg.ClientSecret, cfg.OtherClientSecret, cfg.StrictClientSecret, cfg.UserPassword}, tokens...) {
		if secret != "" && strings.Contains(s, secret) {
			t.Errorf("%s leaks a secret", what)
		}
	}
	for _, marker := range []string{"goroutine ", "runtime/panic", ".go:"} {
		if strings.Contains(s, marker) {
			t.Errorf("%s looks like it contains a stack trace (%q)", what, marker)
		}
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func formValues(m map[string]string) url.Values {
	v := url.Values{}
	for k, s := range m {
		v.Set(k, s)
	}
	return v
}

// afterRevocation lets a few milliseconds pass. A grant revocation covers
// every token issued up to that instant; the issue time is taken from the
// UUIDv7 jti (millisecond resolution), so a token minted immediately
// afterwards for the same user and client is only safe once the clock has
// moved on.
func afterRevocation() { time.Sleep(5 * time.Millisecond) }
