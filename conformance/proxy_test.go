//go:build conformance

package conformance

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// proxyTransport plays a TLS-terminating reverse proxy in front of an
// instance: the client believes it is talking to https://<public host>,
// while each request actually goes to the instance's loopback listener with
// the original Host and X-Forwarded-Proto: https (and X-Forwarded-For when
// set), exactly what an ingress sends. Keeping the client-side URLs https
// lets the standard cookie jar handle Secure cookies.
type proxyTransport struct {
	target       string // host:port of the instance
	forwardedFor string
	noProto      bool // omit X-Forwarded-Proto (a plain-HTTP hop)
}

func (p *proxyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Host = req.URL.Host
	r.URL.Scheme = "http"
	r.URL.Host = p.target
	if !p.noProto {
		r.Header.Set("X-Forwarded-Proto", "https")
	}
	if p.forwardedFor != "" {
		r.Header.Set("X-Forwarded-For", p.forwardedFor)
	}
	return http.DefaultTransport.RoundTrip(r)
}

const publicIssuer = "https://idp.example.test"

// TestOperationalReverseProxy: behind a TLS-terminating proxy the issuer is
// what was configured (never the Host header), cookies are Secure, HSTS is
// sent, a login completes, and forwarding headers are believed only from
// trusted proxies.
func TestOperationalReverseProxy(t *testing.T) {
	inst := startInstance(t, "", map[string]string{
		"IDPICO_ISSUER_URL":       publicIssuer,
		"IDPICO_HSTS_MAX_AGE":     "300",
		"IDPICO_LOGIN_RATE_LIMIT": "3",
	})
	target := "127.0.0.1:" + strconv.Itoa(inst.port)
	viaProxy := &proxyTransport{target: target}
	p := newProvider(publicIssuer, viaProxy)

	t.Run("issuer_is_configuration", func(t *testing.T) {
		d := p.discovery(t)
		if d.Issuer != publicIssuer {
			t.Fatalf("issuer = %q, want %q", d.Issuer, publicIssuer)
		}
		for name, ep := range map[string]string{"authorization": d.AuthorizationEndpoint, "token": d.TokenEndpoint, "userinfo": d.UserinfoEndpoint, "jwks": d.JWKSURI} {
			if !strings.HasPrefix(ep, publicIssuer+"/") {
				t.Errorf("%s endpoint = %q, not under the public issuer", name, ep)
			}
		}
		// An internal hop reaching the pod by another name must not change it.
		internal := newProvider("https://idpico.default.svc.cluster.local:8080", viaProxy)
		if got := internal.discovery(t).Issuer; got != publicIssuer {
			t.Errorf("issuer follows the Host header: %q", got)
		}
		direct := newProvider("http://"+target, nil)
		if got := direct.discovery(t).Issuer; got != publicIssuer {
			t.Errorf("issuer differs when reached directly: %q", got)
		}
	})

	t.Run("secure_cookies_and_hsts", func(t *testing.T) {
		resp, _ := get(t, p.client, publicIssuer+"/login")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET /login: HTTP %d", resp.StatusCode)
		}
		if hsts := resp.Header.Get("Strict-Transport-Security"); !strings.Contains(hsts, "max-age=300") {
			t.Errorf("Strict-Transport-Security = %q, want max-age=300", hsts)
		}
		var csrf *http.Cookie
		for _, c := range resp.Cookies() {
			if c.Name == "idpico_csrf" {
				csrf = c
			}
		}
		if csrf == nil {
			t.Fatal("no idpico_csrf cookie")
		}
		if !csrf.Secure || !csrf.HttpOnly && csrf.Name == "idpico_session" {
			t.Errorf("csrf cookie flags: Secure=%v", csrf.Secure)
		}

		plain := newProvider(publicIssuer, &proxyTransport{target: target, noProto: true})
		resp, _ = get(t, plain.client, publicIssuer+"/healthz")
		if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
			t.Errorf("HSTS sent on a request that did not arrive over TLS: %q", hsts)
		}
	})

	var g grant
	t.Run("login_through_proxy", func(t *testing.T) {
		g = loginAndExchange(t, p)
		if iss := claimsOf(t, g.idToken)["iss"]; iss != publicIssuer {
			t.Errorf("iss = %v, want %q", iss, publicIssuer)
		}
		var session *http.Cookie
		for _, c := range g.client.Jar.Cookies(mustURL(t, publicIssuer)) {
			if c.Name == "idpico_session" {
				session = c
			}
		}
		if session == nil {
			t.Fatal("no idpico_session cookie after login")
		}
		expectUserinfo(t, p, g.access, true)
	})

	// The rate limiter is keyed by client IP, so it shows who the server
	// believes it is talking to: distinct X-Forwarded-For values from a
	// trusted proxy are distinct clients; from anyone else they are ignored.
	failLogin := func(t *testing.T, forwardedFor string) int {
		t.Helper()
		pp := newProvider(publicIssuer, &proxyTransport{target: target, forwardedFor: forwardedFor})
		c := pp.newHTTPClient(t)
		resp, body := get(t, c, publicIssuer+"/login")
		form := url.Values{"csrf_token": {formValue(body, "csrf_token")}, "email": {cfg.UserEmail}, "password": {"wrong"}}
		resp, _ = postForm(t, c, publicIssuer+"/login", form)
		return resp.StatusCode
	}
	t.Run("forwarded_for_from_trusted_proxy", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			if code := failLogin(t, "203.0.113."+strconv.Itoa(10+i)); code == http.StatusTooManyRequests {
				t.Fatalf("attempt %d from a distinct forwarded address was rate limited: proxy not trusted", i+1)
			}
		}
	})

	inst.restart(t, map[string]string{"IDPICO_TRUSTED_PROXIES": "none"})
	t.Run("forwarded_headers_from_untrusted_peer", func(t *testing.T) {
		limited := false
		for i := 0; i < 5; i++ {
			if failLogin(t, "203.0.113."+strconv.Itoa(20+i)) == http.StatusTooManyRequests {
				limited = true
				break
			}
		}
		if !limited {
			t.Error("with no trusted proxies, forwarded addresses were still believed (no rate limit after 5 attempts)")
		}
		resp, _ := get(t, p.client, publicIssuer+"/healthz")
		if hsts := resp.Header.Get("Strict-Transport-Security"); hsts != "" {
			t.Errorf("HSTS sent on X-Forwarded-Proto from an untrusted peer: %q", hsts)
		}
	})
}

func mustURL(t *testing.T, s string) *url.URL {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
