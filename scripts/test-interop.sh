#!/usr/bin/env bash
# Drive the independent reference client (examples/oidc-client) through a
# complete login against a running IDPico, with curl acting as the browser:
#   client /login -> issuer /authorize -> /login -> /consent ->
#   client /callback (code exchange, ID token verification, userinfo)
# and check that the client rendered verified claims. The client is built on
# go-oidc and x/oauth2, so a pass means a mainstream OIDC library needs no
# IDPico-specific workaround. Requires: bash, curl, python3.
#
# Usage: scripts/test-interop.sh   (both servers must be running; see `make validate-interop`)
#
#   IDPICO_URL      issuer base URL          (default http://localhost:8080)
#   CLIENT_URL      oidc-client base URL     (default http://localhost:18081)
#   USER_EMAIL      login email              (default test@example.com)
#   USER_PASSWORD   login password           (default password123)
set -euo pipefail

IDPICO_URL="${IDPICO_URL:-http://localhost:8080}"
CLIENT_URL="${CLIENT_URL:-http://localhost:18081}"
USER_EMAIL="${USER_EMAIL:-test@example.com}"
USER_PASSWORD="${USER_PASSWORD:-password123}"

for tool in curl python3; do
	command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
JAR="$WORK/cookies"

step() { printf '\n==> %s\n' "$*"; }
ok()   { printf '    ok: %s\n' "$*"; }
fail() { printf '    FAIL: %s\n' "$*" >&2; exit 1; }

form_value() { sed -n "s/.*name=\"$2\" value=\"\([^\"]*\)\".*/\1/p" "$1" | head -1 | python3 -c 'import sys,html; print(html.unescape(sys.stdin.read().strip()))'; }
json_get() { python3 -c 'import sys,json; d=json.load(open(sys.argv[1])); v=d
for k in sys.argv[2].split("."):
    v=v.get(k,"") if isinstance(v,dict) else ""
print(v if not isinstance(v,(list,dict)) else json.dumps(v))' "$1" "$2"; }

# request <out-file> <base-url-for-relative-location> <curl args...>
request() {
	local out=$1 base=$2; shift 2
	local hdr="$WORK/headers"
	STATUS=$(curl -sS -o "$out" -D "$hdr" -w '%{http_code}' -b "$JAR" -c "$JAR" "$@")
	LOCATION=$(sed -n 's/^[Ll]ocation: *//p' "$hdr" | tr -d '\r' | head -1)
	case "$LOCATION" in /*) LOCATION="$base$LOCATION" ;; esac
}
redirected() { [ "$STATUS" = 302 ] || [ "$STATUS" = 303 ]; }

step "Start login at the reference client $CLIENT_URL/login"
request "$WORK/start.html" "$CLIENT_URL" "$CLIENT_URL/login"
redirected || fail "client /login returned HTTP $STATUS"
case "$LOCATION" in "$IDPICO_URL"/*) ;; *) fail "client redirected to $LOCATION, not the issuer" ;; esac
case "$LOCATION" in *code_challenge_method=S256*) ok "client uses PKCE S256" ;; *) fail "client did not send a PKCE challenge" ;; esac
case "$LOCATION" in *nonce=*) ok "client sends a nonce" ;; *) fail "client did not send a nonce" ;; esac

step "Issuer authorization endpoint"
request "$WORK/authz.html" "$IDPICO_URL" "$LOCATION"
redirected || fail "/authorize returned HTTP $STATUS"
case "$LOCATION" in */login*) ok "sent to the login page" ;; *) fail "unexpected redirect to $LOCATION" ;; esac

step "Log in as $USER_EMAIL"
request "$WORK/login.html" "$IDPICO_URL" "$LOCATION"
[ "$STATUS" = 200 ] || fail "login page returned HTTP $STATUS"
CSRF=$(form_value "$WORK/login.html" csrf_token)
RETURN_URL=$(form_value "$WORK/login.html" return_url)
request "$WORK/login-post.html" "$IDPICO_URL" -X POST "$IDPICO_URL/login" \
	--data-urlencode "csrf_token=$CSRF" --data-urlencode "return_url=$RETURN_URL" \
	--data-urlencode "email=$USER_EMAIL" --data-urlencode "password=$USER_PASSWORD"
redirected || fail "login POST returned HTTP $STATUS"
ok "logged in"

request "$WORK/after-login.html" "$IDPICO_URL" "$LOCATION"
if [ "$STATUS" = 200 ] && grep -q 'action="/consent"' "$WORK/after-login.html"; then
	step "Consent"
	request "$WORK/consent.html" "$IDPICO_URL" -X POST "$IDPICO_URL/consent" \
		--data-urlencode "csrf_token=$(form_value "$WORK/after-login.html" csrf_token)" \
		--data-urlencode "authorize_query=$(form_value "$WORK/after-login.html" authorize_query)" \
		--data-urlencode "action=allow"
	ok "consent granted"
fi
redirected || fail "expected a redirect back to the client, got HTTP $STATUS"
case "$LOCATION" in "$CLIENT_URL"/*) ;; *) fail "issuer redirected to $LOCATION, not the client" ;; esac
case "$LOCATION" in *code=*) ok "callback carries a code" ;; *) fail "callback has no code: $LOCATION" ;; esac

step "Client callback: code exchange, ID token verification, userinfo"
request "$WORK/callback.json" "$CLIENT_URL" "$LOCATION"
[ "$STATUS" = 200 ] || fail "client callback returned HTTP $STATUS: $(head -c 300 "$WORK/callback.json")"
SUB=$(json_get "$WORK/callback.json" sub)
[ -n "$SUB" ] || fail "client did not report a verified subject: $(cat "$WORK/callback.json")"
ok "verified id_token for sub=$SUB from $(json_get "$WORK/callback.json" issuer)"
UI_SUB=$(json_get "$WORK/callback.json" userinfo.sub)
[ "$UI_SUB" = "$SUB" ] || fail "userinfo sub '$UI_SUB' != id_token sub '$SUB': $(json_get "$WORK/callback.json" userinfo)"
ok "userinfo agrees (email=$(json_get "$WORK/callback.json" userinfo.email))"

step "Forged state is rejected by the client"
request "$WORK/forged.html" "$CLIENT_URL" "$CLIENT_URL/login" >/dev/null
request "$WORK/forged.html" "$CLIENT_URL" "$CLIENT_URL/callback?code=x&state=forged"
[ "$STATUS" = 400 ] || fail "client accepted a callback with a forged state (HTTP $STATUS)"
ok "rejected (HTTP $STATUS)"

printf '\nInterop check passed: %s <-> %s\n' "$CLIENT_URL" "$IDPICO_URL"
