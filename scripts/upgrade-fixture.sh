#!/usr/bin/env bash
# Build a data directory with a previous IDPico release, for the upgrade test
# in conformance/ (TestOperationalUpgrade): the current release must start
# on it, apply its migrations, and keep the signing key, users, clients and
# consents that the old release wrote.
#
#   scripts/upgrade-fixture.sh v0.0.3
#
# writes conformance/testdata/upgrade/<tag>/idpico.db and fixture.json. The
# instance is bootstrapped with the same user and clients the conformance
# suite uses (see conformance/config.go), then one login + consent + token
# exchange is performed so sessions, consents and a refresh token exist.
# Re-run this for the previous release whenever a new one is cut.
# Requires: git (with the tag), go, curl, python3.
set -euo pipefail

tag="${1:?usage: scripts/upgrade-fixture.sh <git tag>}"
cd "$(dirname "$0")/.."
out="conformance/testdata/upgrade/$tag"
port=28120
issuer="http://127.0.0.1:$port"

USER_EMAIL=alice@example.com
USER_PASSWORD=test-password
CLIENT_ID=conformance-client
CLIENT_SECRET=conformance-secret
REDIRECT_URI=http://127.0.0.1:18081/callback

tmp=$(mktemp -d)
trap 'kill $pid 2>/dev/null; wait $pid 2>/dev/null; rm -rf "$tmp"' EXIT

echo "==> building idpico $tag"
mkdir -p "$tmp/src"
git archive "$tag" | tar -x -C "$tmp/src"
(cd "$tmp/src" && go build -o "$tmp/idpico" ./cmd/idpico)

echo "==> starting it on $issuer"
mkdir -p "$tmp/data"
IDPICO_HOST=127.0.0.1 IDPICO_PORT=$port IDPICO_ISSUER_URL=$issuer IDPICO_DATA_DIR="$tmp/data" \
IDPICO_LOG_FORMAT=text IDPICO_LOG_LEVEL=warn IDPICO_PLAYGROUND_ENABLED=false IDPICO_LOGIN_RATE_LIMIT=0 \
IDPICO_BOOTSTRAP_USERS="$USER_EMAIL:$USER_PASSWORD:Alice Conformance" \
IDPICO_BOOTSTRAP_CLIENTS="$CLIENT_ID|$CLIENT_SECRET|$REDIRECT_URI,conformance-public||$REDIRECT_URI,conformance-other|conformance-other-secret|http://127.0.0.1:18082/callback,conformance-strict|conformance-strict-secret|https://app.example.com/callback" \
"$tmp/idpico" > "$tmp/server.log" 2>&1 &
pid=$!
for i in $(seq 1 50); do curl -sf -o /dev/null "$issuer/healthz" && break; sleep 0.1; done
curl -sf -o /dev/null "$issuer/healthz" || { cat "$tmp/server.log"; echo "server did not start" >&2; exit 1; }

echo "==> one login, consent and token exchange"
jar="$tmp/cookies"
form_value() { sed -n "s/.*name=\"$2\" value=\"\([^\"]*\)\".*/\1/p" "$1" | head -1 | python3 -c 'import sys,html; print(html.unescape(sys.stdin.read().strip()))'; }
location() { sed -n 's/^[Ll]ocation: *//p' "$1" | tr -d '\r' | head -1; }
req() { curl -sS -o "$1" -D "$tmp/hdr" -b "$jar" -c "$jar" "${@:2}"; }

authz="$issuer/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$(python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$REDIRECT_URI")&scope=openid%20profile%20email%20offline_access&state=fixture&nonce=fixture"
req "$tmp/a.html" "$authz"
loc=$(location "$tmp/hdr"); case "$loc" in /*) loc="$issuer$loc";; esac
req "$tmp/login.html" "$loc"
req "$tmp/post.html" -X POST "$issuer/login" --data-urlencode "csrf_token=$(form_value "$tmp/login.html" csrf_token)" \
	--data-urlencode "return_url=$(form_value "$tmp/login.html" return_url)" --data-urlencode "email=$USER_EMAIL" --data-urlencode "password=$USER_PASSWORD"
loc=$(location "$tmp/hdr"); case "$loc" in /*) loc="$issuer$loc";; esac
req "$tmp/resume.html" "$loc"
if grep -q 'action="/consent"' "$tmp/resume.html"; then
	req "$tmp/consent.html" -X POST "$issuer/consent" --data-urlencode "csrf_token=$(form_value "$tmp/resume.html" csrf_token)" \
		--data-urlencode "authorize_query=$(form_value "$tmp/resume.html" authorize_query)" --data-urlencode "action=allow"
fi
cb=$(location "$tmp/hdr")
code=$(python3 -c 'import sys,urllib.parse; print(urllib.parse.parse_qs(urllib.parse.urlparse(sys.argv[1]).query).get("code",[""])[0])' "$cb")
[ -n "$code" ] || { echo "no code in callback: $cb" >&2; exit 1; }
curl -sf -u "$CLIENT_ID:$CLIENT_SECRET" -X POST "$issuer/token" -d grant_type=authorization_code -d "code=$code" --data-urlencode "redirect_uri=$REDIRECT_URI" -o "$tmp/token.json"
python3 -c 'import sys,json; d=json.load(open(sys.argv[1])); assert d.get("id_token") and d.get("refresh_token"), d' "$tmp/token.json"
kid=$(curl -sf "$issuer/.well-known/jwks.json" | python3 -c 'import sys,json; ks=json.load(sys.stdin)["keys"]; assert len(ks)==1, ks; print(ks[0]["kid"])')

echo "==> stopping cleanly and collecting $out"
kill "$pid"; wait "$pid" 2>/dev/null || true
if ls "$tmp/data"/idpico.db-wal "$tmp/data"/idpico.db-shm >/dev/null 2>&1; then
	echo "WAL/SHM files left after clean stop" >&2; exit 1
fi
mkdir -p "$out"
cp "$tmp/data/idpico.db" "$out/idpico.db"
python3 - "$out/fixture.json" "$tag" "$kid" <<'PY'
import sys, json
json.dump({
    "version": sys.argv[2], "kid": sys.argv[3],
    "user_email": "alice@example.com", "user_password": "test-password",
    "client_id": "conformance-client", "client_secret": "conformance-secret",
    "redirect_uri": "http://127.0.0.1:18081/callback",
    "note": "sqlite data dir written by this release after one login + consent + token exchange; see scripts/upgrade-fixture.sh",
}, open(sys.argv[1], "w"), indent=2)
open(sys.argv[1], "a").write("\n")
PY
ls -la "$out"
