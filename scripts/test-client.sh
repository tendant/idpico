#!/usr/bin/env bash
# Exercise IDPico as an external OIDC relying party, end to end, with curl only.
#
# Walks the Authorization Code + PKCE flow the way a real client would:
#   /.well-known/openid-configuration -> /authorize -> /login -> /consent ->
#   redirect_uri?code=... -> /token -> /userinfo -> (refresh_token grant)
# and checks the refusals a client must be able to rely on: exchange without
# code_verifier, replayed code, wrong client secret, reused refresh token, and
# (for public clients) /authorize without PKCE.
#
# The redirect back to the client is never followed, so nothing has to listen
# on REDIRECT_URI. Requires: bash, curl, openssl, python3.
#
# Usage: scripts/test-client.sh   (server must already be running; see `make test-flow`)
#
#   IDPICO_URL      issuer base URL          (default http://localhost:8080)
#   CLIENT_ID       registered client id     (default test-app)
#   CLIENT_SECRET   client secret; empty = public client (default test-secret)
#   REDIRECT_URI    registered redirect URI  (default http://localhost:3000/callback)
#   USER_EMAIL      login email              (default test@example.com)
#   USER_PASSWORD   login password           (default password123)
#   SCOPE           requested scopes         (default "openid profile email offline_access")
set -euo pipefail

IDPICO_URL="${IDPICO_URL:-http://localhost:8080}"
CLIENT_ID="${CLIENT_ID:-test-app}"
CLIENT_SECRET="${CLIENT_SECRET-test-secret}"
REDIRECT_URI="${REDIRECT_URI:-http://localhost:3000/callback}"
USER_EMAIL="${USER_EMAIL:-test@example.com}"
USER_PASSWORD="${USER_PASSWORD:-password123}"
SCOPE="${SCOPE:-openid profile email offline_access}"

for tool in curl openssl python3; do
	command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
JAR="$WORK/cookies"

step() { printf '\n==> %s\n' "$*"; }
ok()   { printf '    ok: %s\n' "$*"; }
fail() { printf '    FAIL: %s\n' "$*" >&2; exit 1; }

urlencode() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
# form_value <html-file> <input-name>: value of a hidden <input> in a rendered
# form, with HTML entities decoded (html/template escapes & in URLs as &amp;).
form_value() { sed -n "s/.*name=\"$2\" value=\"\([^\"]*\)\".*/\1/p" "$1" | head -1 | python3 -c 'import sys,html; print(html.unescape(sys.stdin.read().strip()))'; }
# query_param <url> <name>
query_param() { python3 -c 'import sys,urllib.parse; q=urllib.parse.urlparse(sys.argv[1]).query; print(urllib.parse.parse_qs(q).get(sys.argv[2],[""])[0])' "$1" "$2"; }
json_get() { python3 -c 'import sys,json; d=json.load(open(sys.argv[1])); v=d
for k in sys.argv[2].split("."):
    v=v.get(k,"") if isinstance(v,dict) else ""
print(v if not isinstance(v,(list,dict)) else json.dumps(v))' "$1" "$2"; }
jwt_claims() { python3 -c 'import sys,json,base64; p=sys.argv[1].split(".")[1]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4))), indent=2, sort_keys=True))' "$1"; }
jwt_header() { python3 -c 'import sys,json,base64; p=sys.argv[1].split(".")[0]; print(json.dumps(json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)))))' "$1"; }

# request <out-file> <curl args...>: runs curl with the cookie jar and leaves
# the HTTP status in $STATUS and the Location header (if any) in $LOCATION.
request() {
	local out=$1; shift
	local hdr="$WORK/headers"
	STATUS=$(curl -sS -o "$out" -D "$hdr" -w '%{http_code}' -b "$JAR" -c "$JAR" "$@")
	LOCATION=$(sed -n 's/^[Ll]ocation: *//p' "$hdr" | tr -d '\r' | head -1)
	# Resolve a relative Location against the issuer.
	case "$LOCATION" in /*) LOCATION="$IDPICO_URL$LOCATION" ;; esac
}
redirected() { [ "$STATUS" = 302 ] || [ "$STATUS" = 303 ]; }

# --- 1. Discovery ------------------------------------------------------------
step "Discovery $IDPICO_URL/.well-known/openid-configuration"
request "$WORK/disc.json" "$IDPICO_URL/.well-known/openid-configuration"
[ "$STATUS" = 200 ] || fail "discovery returned HTTP $STATUS"
ISSUER=$(json_get "$WORK/disc.json" issuer)
AUTHZ=$(json_get "$WORK/disc.json" authorization_endpoint)
TOKEN=$(json_get "$WORK/disc.json" token_endpoint)
USERINFO=$(json_get "$WORK/disc.json" userinfo_endpoint)
JWKS=$(json_get "$WORK/disc.json" jwks_uri)
[ -n "$ISSUER" ] && [ -n "$AUTHZ" ] && [ -n "$TOKEN" ] || fail "discovery document is missing endpoints"
ok "issuer=$ISSUER"
request "$WORK/jwks.json" "$JWKS"
[ "$STATUS" = 200 ] || fail "jwks returned HTTP $STATUS"
ok "jwks has $(python3 -c 'import sys,json; print(len(json.load(open(sys.argv[1]))["keys"]))' "$WORK/jwks.json") key(s)"

# --- 2. /authorize with PKCE -------------------------------------------------
VERIFIER=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)
CHALLENGE=$(printf '%s' "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '=')
STATE=$(openssl rand -hex 12)
NONCE=$(openssl rand -hex 12)
AUTHZ_URL="$AUTHZ?response_type=code&client_id=$(urlencode "$CLIENT_ID")&redirect_uri=$(urlencode "$REDIRECT_URI")&scope=$(urlencode "$SCOPE")&state=$STATE&nonce=$NONCE&code_challenge=$CHALLENGE&code_challenge_method=S256"

if [ -z "$CLIENT_SECRET" ]; then
	step "GET /authorize as public client '$CLIENT_ID' without PKCE (must be rejected)"
	request "$WORK/nopkce.html" "$AUTHZ?response_type=code&client_id=$(urlencode "$CLIENT_ID")&redirect_uri=$(urlencode "$REDIRECT_URI")&scope=openid&state=$STATE"
	case "$STATUS:$LOCATION" in
		400:*|*:"$REDIRECT_URI"*error=*) ok "rejected (HTTP $STATUS)" ;;
		*) fail "/authorize without code_challenge returned HTTP $STATUS -> $LOCATION" ;;
	esac
fi

step "GET /authorize as client '$CLIENT_ID' (PKCE S256)"
request "$WORK/authz.html" "$AUTHZ_URL"
redirected || fail "/authorize returned HTTP $STATUS (expected redirect to /login)"
case "$LOCATION" in
	*/login*) ok "redirected to login" ;;
	*) fail "unexpected redirect: $LOCATION" ;;
esac

# --- 3. Login ----------------------------------------------------------------
step "Login as $USER_EMAIL"
request "$WORK/login.html" "$LOCATION"
[ "$STATUS" = 200 ] || fail "GET /login returned HTTP $STATUS"
CSRF=$(form_value "$WORK/login.html" csrf_token)
RETURN_URL=$(form_value "$WORK/login.html" return_url)
[ -n "$CSRF" ] || fail "no csrf_token in login form"
request "$WORK/login-post.html" -X POST "$IDPICO_URL/login" \
	--data-urlencode "csrf_token=$CSRF" \
	--data-urlencode "return_url=$RETURN_URL" \
	--data-urlencode "email=$USER_EMAIL" \
	--data-urlencode "password=$USER_PASSWORD"
redirected || fail "POST /login returned HTTP $STATUS (bad credentials?)"
ok "session established"

# --- 4. Back to /authorize; consent if asked ---------------------------------
step "Resume /authorize with session"
request "$WORK/authz2.html" "$LOCATION"
if [ "$STATUS" = 200 ] && grep -q 'action="/consent"' "$WORK/authz2.html"; then
	# /authorize renders the consent form inline; approving it issues the code.
	step "Consent screen shown; approving"
	CSRF=$(form_value "$WORK/authz2.html" csrf_token)
	AQ=$(form_value "$WORK/authz2.html" authorize_query)
	[ -n "$CSRF" ] && [ -n "$AQ" ] || fail "consent form is missing csrf_token/authorize_query"
	request "$WORK/consent-post.html" -X POST "$IDPICO_URL/consent" \
		--data-urlencode "csrf_token=$CSRF" \
		--data-urlencode "authorize_query=$AQ" \
		--data-urlencode "action=allow"
	redirected || fail "POST /consent returned HTTP $STATUS"
elif redirected; then
	ok "consent not required for this client"
else
	fail "/authorize (authenticated) returned HTTP $STATUS"
fi

case "$LOCATION" in
	"$REDIRECT_URI"*) ;;
	*) fail "expected redirect to $REDIRECT_URI, got: $LOCATION" ;;
esac
CODE=$(query_param "$LOCATION" code)
GOT_STATE=$(query_param "$LOCATION" state)
[ -n "$CODE" ] || fail "no code in redirect: $LOCATION"
[ "$GOT_STATE" = "$STATE" ] || fail "state mismatch: sent $STATE, got $GOT_STATE"
ok "authorization code received, state verified"

# --- 5. /token ---------------------------------------------------------------
auth=()
[ -n "$CLIENT_SECRET" ] && auth=(-u "$CLIENT_ID:$CLIENT_SECRET")

step "POST /token without code_verifier (must be rejected; code stays valid)"
request "$WORK/noverifier.json" "${auth[@]}" -X POST "$TOKEN" \
	-d grant_type=authorization_code -d "client_id=$CLIENT_ID" \
	--data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT_URI"
[ "$STATUS" = 400 ] || fail "exchange without code_verifier returned HTTP $STATUS, expected 400"
[ "$(json_get "$WORK/noverifier.json" error)" = invalid_grant ] || fail "expected error=invalid_grant, got $(cat "$WORK/noverifier.json")"
ok "rejected (invalid_grant): $(json_get "$WORK/noverifier.json" error_description)"

step "POST /token (authorization_code + code_verifier)"
request "$WORK/token.json" "${auth[@]}" -X POST "$TOKEN" \
	-d grant_type=authorization_code \
	-d "client_id=$CLIENT_ID" \
	--data-urlencode "code=$CODE" \
	--data-urlencode "redirect_uri=$REDIRECT_URI" \
	--data-urlencode "code_verifier=$VERIFIER"
[ "$STATUS" = 200 ] || fail "/token returned HTTP $STATUS: $(cat "$WORK/token.json")"
ACCESS_TOKEN=$(json_get "$WORK/token.json" access_token)
ID_TOKEN=$(json_get "$WORK/token.json" id_token)
REFRESH_TOKEN=$(json_get "$WORK/token.json" refresh_token)
[ -n "$ACCESS_TOKEN" ] && [ -n "$ID_TOKEN" ] || fail "token response missing access_token/id_token"
ok "token_type=$(json_get "$WORK/token.json" token_type) expires_in=$(json_get "$WORK/token.json" expires_in) scope=\"$(json_get "$WORK/token.json" scope)\""

echo "    id_token header: $(jwt_header "$ID_TOKEN")"
jwt_claims "$ID_TOKEN" | sed 's/^/    /' > "$WORK/claims.txt"; cat "$WORK/claims.txt"
python3 - "$ID_TOKEN" "$ISSUER" "$CLIENT_ID" "$NONCE" <<'EOF' || fail "id_token claim check failed"
import sys, json, base64
tok, iss, cid, nonce = sys.argv[1:]
p = tok.split(".")[1]
c = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
aud = c.get("aud"); aud = aud if isinstance(aud, list) else [aud]
problems = []
if c.get("iss") != iss: problems.append(f"iss={c.get('iss')!r} != {iss!r}")
if cid not in aud: problems.append(f"aud={aud!r} lacks {cid!r}")
if c.get("nonce") != nonce: problems.append("nonce mismatch")
if not c.get("sub"): problems.append("missing sub")
if problems: print("    " + "; ".join(problems)); sys.exit(1)
EOF
ok "id_token iss/aud/nonce/sub verified"

# --- 6. /userinfo ------------------------------------------------------------
step "GET /userinfo"
request "$WORK/userinfo.json" -H "Authorization: Bearer $ACCESS_TOKEN" "$USERINFO"
[ "$STATUS" = 200 ] || fail "/userinfo returned HTTP $STATUS"
sed 's/^/    /' "$WORK/userinfo.json"; echo
[ "$(json_get "$WORK/userinfo.json" email)" = "$USER_EMAIL" ] || fail "userinfo email != $USER_EMAIL"
ok "userinfo matches $USER_EMAIL"

# --- 7. Negative checks ------------------------------------------------------
step "Replay the authorization code (must be rejected)"
request "$WORK/replay.json" "${auth[@]}" -X POST "$TOKEN" \
	-d grant_type=authorization_code -d "client_id=$CLIENT_ID" \
	--data-urlencode "code=$CODE" --data-urlencode "redirect_uri=$REDIRECT_URI" \
	--data-urlencode "code_verifier=$VERIFIER"
[ "$STATUS" = 400 ] || fail "code replay returned HTTP $STATUS, expected 400"
[ "$(json_get "$WORK/replay.json" error)" = invalid_grant ] || fail "expected error=invalid_grant, got $(cat "$WORK/replay.json")"
ok "rejected (invalid_grant): $(json_get "$WORK/replay.json" error_description)"

if [ -n "$CLIENT_SECRET" ]; then
	step "Wrong client secret (must be rejected)"
	request "$WORK/badsecret.json" -u "$CLIENT_ID:not-the-secret" -X POST "$TOKEN" \
		-d grant_type=authorization_code -d "code=x" --data-urlencode "redirect_uri=$REDIRECT_URI"
	[ "$STATUS" = 401 ] || fail "bad secret returned HTTP $STATUS, expected 401"
	[ "$(json_get "$WORK/badsecret.json" error)" = invalid_client ] || fail "expected error=invalid_client, got $(cat "$WORK/badsecret.json")"
	ok "rejected (invalid_client, HTTP 401)"
fi

# --- 8. Refresh --------------------------------------------------------------
if [ -n "$REFRESH_TOKEN" ]; then
	step "POST /token (refresh_token)"
	request "$WORK/refresh.json" "${auth[@]}" -X POST "$TOKEN" \
		-d grant_type=refresh_token -d "client_id=$CLIENT_ID" \
		--data-urlencode "refresh_token=$REFRESH_TOKEN"
	[ "$STATUS" = 200 ] || fail "refresh returned HTTP $STATUS: $(cat "$WORK/refresh.json")"
	NEW_REFRESH=$(json_get "$WORK/refresh.json" refresh_token)
	[ -n "$(json_get "$WORK/refresh.json" access_token)" ] || fail "refresh response has no access_token"
	[ "$NEW_REFRESH" != "$REFRESH_TOKEN" ] || fail "refresh token was not rotated"
	ok "new access token issued, refresh token rotated"

	step "Refresh with a wider scope than granted (must be rejected)"
	request "$WORK/refresh3.json" "${auth[@]}" -X POST "$TOKEN" \
		-d grant_type=refresh_token -d "client_id=$CLIENT_ID" \
		--data-urlencode "refresh_token=$NEW_REFRESH" \
		--data-urlencode "scope=$SCOPE admin:everything"
	[ "$STATUS" = 400 ] || fail "widened refresh returned HTTP $STATUS, expected 400"
	[ "$(json_get "$WORK/refresh3.json" error)" = invalid_scope ] || fail "expected error=invalid_scope, got $(cat "$WORK/refresh3.json")"
	ok "rejected (invalid_scope)"

	step "Reuse the old refresh token (must be rejected)"
	request "$WORK/refresh2.json" "${auth[@]}" -X POST "$TOKEN" \
		-d grant_type=refresh_token -d "client_id=$CLIENT_ID" \
		--data-urlencode "refresh_token=$REFRESH_TOKEN"
	[ "$STATUS" = 400 ] || fail "old refresh token returned HTTP $STATUS, expected 400"
	[ "$(json_get "$WORK/refresh2.json" error)" = invalid_grant ] || fail "expected error=invalid_grant, got $(cat "$WORK/refresh2.json")"
	ok "rejected (invalid_grant): $(json_get "$WORK/refresh2.json" error_description)"

else
	step "No refresh_token issued (scope lacks offline_access); skipping refresh checks"
fi

printf '\nAll client checks passed against %s as %s\n' "$ISSUER" "$CLIENT_ID"
