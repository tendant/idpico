#!/usr/bin/env bash
# Interoperability check with oauth2-proxy, a widely deployed OIDC relying
# party that idpico has no code in common with: it must discover idpico,
# log a user in, pass the identity to an upstream application, refresh the
# session with a refresh token, and sign out — with nothing but standard
# configuration.
#
# Topology (docker is only used for oauth2-proxy itself):
#
#   curl (browser) --> oauth2-proxy (container, :4180)
#                         |   ^ OIDC over host.docker.internal
#                         v   |
#                     idpico (host, :28140)         upstream echo (host, :28142)
#
# Usage: make validate-interop-proxy   (or scripts/interop-oauth2-proxy.sh)
# Requires: docker, go, curl, python3. Not run in CI.
set -euo pipefail

cd "$(dirname "$0")/.."
IMAGE="${OAUTH2_PROXY_IMAGE:-quay.io/oauth2-proxy/oauth2-proxy:v7.14.2}"
IDP_PORT=28140 UP_PORT=28142 PROXY_PORT=4180
IDP_HOST=host.docker.internal            # how the container reaches the host
ISSUER="http://$IDP_HOST:$IDP_PORT"       # must be the same string for both sides
PROXY="http://localhost:$PROXY_PORT"
USER_EMAIL=alice@example.com USER_PASSWORD=test-password
CLIENT_ID=oauth2-proxy CLIENT_SECRET=oauth2-proxy-secret

for tool in docker go curl python3; do
	command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

tmp=$(mktemp -d)
cleanup() {
	docker rm -f idpico-interop-oauth2-proxy >/dev/null 2>&1 || true
	kill "${idp:-}" "${up:-}" 2>/dev/null; wait "${idp:-}" "${up:-}" 2>/dev/null
	rm -rf "$tmp"
}
trap cleanup EXIT

step() { printf '\n==> %s\n' "$*"; }
ok()   { printf '    ok: %s\n' "$*"; }
fail() { printf '    FAIL: %s\n' "$*" >&2; [ -f "$tmp/proxy.log" ] && { echo "--- oauth2-proxy log ---" >&2; tail -30 "$tmp/proxy.log" >&2; }; exit 1; }

# --- idpico on the host, reachable from the container ------------------------
step "idpico on 0.0.0.0:$IDP_PORT (issuer $ISSUER)"
go build -o "$tmp/idpico" ./cmd/idpico
IDPICO_HOST=0.0.0.0 IDPICO_PORT=$IDP_PORT IDPICO_ISSUER_URL=$ISSUER IDPICO_DATA_DIR="$tmp/data" \
IDPICO_LOG_FORMAT=text IDPICO_LOG_LEVEL=warn IDPICO_PLAYGROUND_ENABLED=false IDPICO_LOGIN_RATE_LIMIT=0 \
IDPICO_ACCESS_TOKEN_TTL=3s \
IDPICO_BOOTSTRAP_USERS="$USER_EMAIL:$USER_PASSWORD:Alice Example" \
IDPICO_BOOTSTRAP_GROUPS="admins:$USER_EMAIL" \
IDPICO_BOOTSTRAP_CLIENTS="$CLIENT_ID|$CLIENT_SECRET|$PROXY/oauth2/callback" \
"$tmp/idpico" > "$tmp/idpico.log" 2>&1 &
idp=$!
for i in $(seq 1 50); do curl -sf -o /dev/null "http://127.0.0.1:$IDP_PORT/healthz" && break; sleep 0.1; done
curl -sf -o /dev/null "http://127.0.0.1:$IDP_PORT/readyz" || { cat "$tmp/idpico.log"; fail "idpico did not start"; }
docker run --rm curlimages/curl -sf -o /dev/null "$ISSUER/.well-known/openid-configuration" \
	|| fail "containers cannot reach idpico at $ISSUER"

# --- the protected application: echoes the request headers as JSON ---------
step "upstream echo application on :$UP_PORT"
python3 - "$UP_PORT" > "$tmp/upstream.log" 2>&1 <<'PY' &
import sys, json
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "headers": dict(self.headers)}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(("0.0.0.0", int(sys.argv[1])), H).serve_forever()
PY
up=$!
for i in $(seq 1 50); do curl -sf -o /dev/null "http://127.0.0.1:$UP_PORT/" && break; sleep 0.1; done

# --- oauth2-proxy with nothing but standard settings ---------------------------
step "oauth2-proxy ($IMAGE)"
docker run -d --name idpico-interop-oauth2-proxy -p "$PROXY_PORT:$PROXY_PORT" "$IMAGE" \
	--provider=oidc --provider-display-name=IDPico \
	--oidc-issuer-url="$ISSUER" \
	--client-id="$CLIENT_ID" --client-secret="$CLIENT_SECRET" \
	--redirect-url="$PROXY/oauth2/callback" \
	--scope="openid profile email offline_access groups" --oidc-groups-claim=groups \
	--code-challenge-method=S256 \
	--email-domain='*' \
	--cookie-secret="$(head -c 32 /dev/urandom | base64 | tr -d '\n' | head -c 32)" \
	--cookie-secure=false --cookie-refresh=2s \
	--http-address="0.0.0.0:$PROXY_PORT" \
	--upstream="http://$IDP_HOST:$UP_PORT" \
	--pass-user-headers --set-xauthrequest --pass-access-token \
	--skip-provider-button --reverse-proxy --show-debug-on-error \
	>/dev/null
for i in $(seq 1 100); do curl -sf -o /dev/null "$PROXY/ping" && break; sleep 0.1; done
docker logs idpico-interop-oauth2-proxy > "$tmp/proxy.log" 2>&1
curl -sf -o /dev/null "$PROXY/ping" || fail "oauth2-proxy did not start (discovery against $ISSUER failed?)"
ok "started; discovered $ISSUER"

# --- the login, as a browser would do it ----------------------------------------
# curl on the host has to reach idpico under the same name the proxy used,
# so that cookies and redirects line up.
jar="$tmp/cookies"
resolve=(--resolve "$IDP_HOST:$IDP_PORT:127.0.0.1")
form_value() { sed -n "s/.*name=\"$2\" value=\"\([^\"]*\)\".*/\1/p" "$1" | head -1 | python3 -c 'import sys,html; print(html.unescape(sys.stdin.read().strip()))'; }
req() { # req <out> <curl args...>; sets STATUS and LOCATION
	local out=$1; shift
	STATUS=$(curl -sS "${resolve[@]}" -o "$out" -D "$tmp/hdr" -w '%{http_code}' -b "$jar" -c "$jar" "$@")
	LOCATION=$(sed -n 's/^[Ll]ocation: *//p' "$tmp/hdr" | tr -d '\r' | head -1)
}
json_get() { python3 -c 'import sys,json; d=json.load(open(sys.argv[1]))
for k in sys.argv[2].split("."): d=d.get(k,"") if isinstance(d,dict) else ""
print(d)' "$1" "$2"; }

step "Unauthenticated request is sent to idpico"
req "$tmp/start.html" "$PROXY/app/page?x=1"
[ "$STATUS" = 302 ] || fail "expected a redirect to the provider, got HTTP $STATUS"
case "$LOCATION" in "$ISSUER/authorize?"*) ok "redirected to $ISSUER/authorize" ;; *) fail "redirected to $LOCATION" ;; esac
case "$LOCATION" in *code_challenge_method=S256*) ok "PKCE S256 in the request" ;; *) fail "no PKCE in the request" ;; esac

step "Log in at idpico"
req "$tmp/authz.html" "$LOCATION"
[ "$STATUS" = 302 ] || fail "/authorize returned HTTP $STATUS"
loc=$LOCATION; case "$loc" in /*) loc="$ISSUER$loc" ;; esac
req "$tmp/login.html" "$loc"
[ "$STATUS" = 200 ] || fail "login page returned HTTP $STATUS"
req "$tmp/post.html" -X POST "$ISSUER/login" \
	--data-urlencode "csrf_token=$(form_value "$tmp/login.html" csrf_token)" \
	--data-urlencode "return_url=$(form_value "$tmp/login.html" return_url)" \
	--data-urlencode "email=$USER_EMAIL" --data-urlencode "password=$USER_PASSWORD"
[ "$STATUS" = 302 ] || fail "login POST returned HTTP $STATUS"
loc=$LOCATION; case "$loc" in /*) loc="$ISSUER$loc" ;; esac
req "$tmp/resume.html" "$loc"
if [ "$STATUS" = 200 ] && grep -q 'action="/consent"' "$tmp/resume.html"; then
	req "$tmp/consent.html" -X POST "$ISSUER/consent" \
		--data-urlencode "csrf_token=$(form_value "$tmp/resume.html" csrf_token)" \
		--data-urlencode "authorize_query=$(form_value "$tmp/resume.html" authorize_query)" \
		--data-urlencode "action=allow"
	ok "consent granted"
fi
[ "$STATUS" = 302 ] || fail "expected the callback redirect, got HTTP $STATUS"
case "$LOCATION" in "$PROXY/oauth2/callback?"*code=*) ok "back to the proxy with a code" ;; *) fail "unexpected redirect $LOCATION" ;; esac

step "oauth2-proxy exchanges the code and starts a session"
req "$tmp/cb.html" "$LOCATION"
[ "$STATUS" = 302 ] || fail "callback returned HTTP $STATUS: $(head -c 300 "$tmp/cb.html")"
[ "$LOCATION" = "/app/page?x=1" ] || fail "expected to land on the original URL, got $LOCATION"
grep -q "_oauth2_proxy" "$jar" || fail "no session cookie set"
ok "session cookie set, returning to /app/page?x=1"

step "The upstream application receives the identity"
req "$tmp/app.json" "$PROXY/app/page?x=1"
[ "$STATUS" = 200 ] || fail "proxied request returned HTTP $STATUS"
[ "$(json_get "$tmp/app.json" path)" = "/app/page?x=1" ] || fail "upstream saw path $(json_get "$tmp/app.json" path)"
[ "$(json_get "$tmp/app.json" headers.X-Forwarded-Email)" = "$USER_EMAIL" ] || fail "X-Forwarded-Email = '$(json_get "$tmp/app.json" headers.X-Forwarded-Email)'"
sub=$(json_get "$tmp/app.json" headers.X-Forwarded-User)
[ -n "$sub" ] || fail "no X-Forwarded-User"
ok "X-Forwarded-Email=$USER_EMAIL X-Forwarded-User=$sub"
groups=$(json_get "$tmp/app.json" headers.X-Forwarded-Groups)
case "$groups" in *admins*) ok "X-Forwarded-Groups=$groups (from the groups claim)" ;; *) fail "groups claim not passed through (X-Forwarded-Groups='$groups')" ;; esac
at=$(json_get "$tmp/app.json" headers.X-Forwarded-Access-Token)
[ -n "$at" ] || fail "no access token forwarded"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $at" "http://127.0.0.1:$IDP_PORT/userinfo")" = 200 ] || fail "forwarded access token rejected by idpico /userinfo"
ok "forwarded access token is accepted by idpico's /userinfo"

step "oauth2-proxy's own userinfo endpoint"
req "$tmp/ui.json" "$PROXY/oauth2/userinfo"
[ "$STATUS" = 200 ] && [ "$(json_get "$tmp/ui.json" email)" = "$USER_EMAIL" ] || fail "/oauth2/userinfo: HTTP $STATUS $(cat "$tmp/ui.json")"
ok "email=$(json_get "$tmp/ui.json" email)"

step "Session refresh with the refresh token (cookie-refresh=2s, access token TTL 3s)"
sleep 3.5
req "$tmp/app2.json" "$PROXY/app/page?x=2"
[ "$STATUS" = 200 ] || fail "request after the refresh window returned HTTP $STATUS"
at2=$(json_get "$tmp/app2.json" headers.X-Forwarded-Access-Token)
[ -n "$at2" ] && [ "$at2" != "$at" ] || fail "access token was not renewed via refresh_token"
[ "$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $at2" "http://127.0.0.1:$IDP_PORT/userinfo")" = 200 ] || fail "renewed access token rejected"
refreshes=$(curl -s "http://127.0.0.1:$IDP_PORT/metrics" | sed -n 's/^idpico_tokens_issued_total{grant_type="refresh_token",type="access"} //p')
[ "${refreshes:-0}" -ge 1 ] || fail "idpico issued no tokens via refresh_token grant"
ok "new access token via refresh_token grant ($refreshes refresh grant(s) at idpico)"

step "Sign out"
req "$tmp/out.html" "$PROXY/oauth2/sign_out"
[ "$STATUS" = 302 ] || fail "sign_out returned HTTP $STATUS"
req "$tmp/after.html" "$PROXY/app/page"
[ "$STATUS" = 302 ] || fail "after sign-out, expected a redirect to log in again, got HTTP $STATUS"
ok "session ended; next request goes back to the provider"

printf '\noauth2-proxy interop passed against %s (%s)\n' "$ISSUER" "$IMAGE"
