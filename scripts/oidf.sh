#!/usr/bin/env bash
# Run the OpenID Foundation conformance suite (OpenID Connect Core, Basic OP
# profile) against a throwaway IDPico, non-interactively.
#
# The suite runs from its prebuilt images via docker compose and is driven
# with its own scripts/run-test-plan.py. IDPico runs on the host and is
# reached from the containers as host.docker.internal, so it is started with
# that as its issuer. Expected warnings and skips (documented in
# CONFORMANCE.md) live in conformance/oidf/; anything else fails the run.
#
# Requires: docker (with compose), git, python3, go. First run downloads the
# suite (~1.3 GB of images) into OIDF_CACHE.
#
#   scripts/oidf.sh                 # run the Basic OP plan, exit 0 on success
#   KEEP_SUITE=1 scripts/oidf.sh    # leave the suite running afterwards
#                                   # (https://localhost.emobix.co.uk:8443)
#   OIDF_PLAN=... scripts/oidf.sh   # another plan, e.g. oidcc-config-certification-test-plan
#
#   OIDF_CACHE   where the suite checkout, venv and mongo data live
#                (default ~/.cache/idpico-oidf)
#   OIDF_REF     conformance-suite git ref to check out (pinned below)
#   OIDF_PORT    host port IDPico listens on (default 28100; must match the
#                URLs in conformance/oidf/idpico-oidcc.json)
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT=$PWD
OIDF_CACHE="${OIDF_CACHE:-$HOME/.cache/idpico-oidf}"
OIDF_REF="${OIDF_REF:-440eec8bac7b12b7389d7ca9cbc459b53507a443}" # 2026-09-20
OIDF_PORT="${OIDF_PORT:-28100}"
OIDF_PLAN="${OIDF_PLAN:-oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]}"
SUITE_URL=https://localhost.emobix.co.uk:8443/
SUITE="$OIDF_CACHE/conformance-suite"
CONFIG="$ROOT/conformance/oidf/idpico-oidcc.json"

for tool in docker git python3 go curl; do
	command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

step() { printf '\n==> %s\n' "$*"; }

# --- the suite -----------------------------------------------------------
step "OpenID conformance suite at $SUITE ($OIDF_REF)"
mkdir -p "$OIDF_CACHE"
if [ ! -d "$SUITE/.git" ]; then
	git clone -q https://gitlab.com/openid/conformance-suite.git "$SUITE"
fi
git -C "$SUITE" fetch -q origin "$OIDF_REF" 2>/dev/null || git -C "$SUITE" fetch -q origin
git -C "$SUITE" checkout -q "$OIDF_REF"

if [ ! -x "$OIDF_CACHE/venv/bin/python" ]; then
	python3 -m venv "$OIDF_CACHE/venv"
	"$OIDF_CACHE/venv/bin/pip" -q install -r "$SUITE/scripts/requirements.txt"
fi

(cd "$SUITE" && docker compose -f docker-compose-prebuilt.yml up -d --quiet-pull 2>&1 | grep -v "^$" | sed 's/^/    /')
for i in $(seq 1 120); do
	curl -sk -o /dev/null -w '%{http_code}' "${SUITE_URL}api/runner/available" 2>/dev/null | grep -q 200 && break
	sleep 2
	[ "$i" = 120 ] && { echo "conformance suite did not come up" >&2; exit 1; }
done
echo "    suite ready: $SUITE_URL"

# --- IDPico --------------------------------------------------------------
step "IDPico on 0.0.0.0:$OIDF_PORT (issuer http://host.docker.internal:$OIDF_PORT)"
go build -o "$OIDF_CACHE/idpico" ./cmd/idpico
tmp=$(mktemp -d)
cleanup() {
	kill "$idp" 2>/dev/null; wait "$idp" 2>/dev/null
	rm -rf "$tmp"
	if [ -z "${KEEP_SUITE:-}" ]; then
		(cd "$SUITE" && docker compose -f docker-compose-prebuilt.yml down >/dev/null 2>&1) || true
	fi
}
# The two static clients and the user in conformance/oidf/idpico-oidcc.json.
# Consent is off so the suite's scripted browser only fills the login form;
# rate limiting is off because every module logs in from one address.
IDPICO_HOST=0.0.0.0 IDPICO_PORT="$OIDF_PORT" IDPICO_ISSUER_URL="http://host.docker.internal:$OIDF_PORT" \
IDPICO_DATA_DIR="$tmp" IDPICO_LOG_FORMAT=text IDPICO_LOG_LEVEL=warn IDPICO_PLAYGROUND_ENABLED=false \
IDPICO_LOGIN_RATE_LIMIT=0 IDPICO_LOCKOUT_MAX_ATTEMPTS=0 IDPICO_REQUIRE_CONSENT=false \
IDPICO_BOOTSTRAP_USERS="alice@example.com:test-password:Alice Example" \
IDPICO_BOOTSTRAP_CLIENTS="oidf-client-1|oidf-secret-1|https://localhost.emobix.co.uk:8443/test/a/idpico/callback,oidf-client-2|oidf-secret-2|https://localhost.emobix.co.uk:8443/test/a/idpico/callback" \
"$OIDF_CACHE/idpico" > "$tmp/idpico.log" 2>&1 &
idp=$!
trap cleanup EXIT
for i in $(seq 1 50); do curl -sf -o /dev/null "http://127.0.0.1:$OIDF_PORT/healthz" && break; sleep 0.1; done
docker run --rm curlimages/curl -sf -o /dev/null "http://host.docker.internal:$OIDF_PORT/healthz" \
	|| { echo "containers cannot reach IDPico at host.docker.internal:$OIDF_PORT" >&2; exit 1; }

# --- run -----------------------------------------------------------------
step "Running $OIDF_PLAN"
cd "$SUITE"
CONFORMANCE_SERVER="$SUITE_URL" CONFORMANCE_DEV_MODE=1 \
"$OIDF_CACHE/venv/bin/python" scripts/run-test-plan.py --no-parallel --verbose \
	--expected-failures-file "$ROOT/conformance/oidf/expected-warnings.json" \
	--expected-skips-file "$ROOT/conformance/oidf/expected-skips.json" \
	"$OIDF_PLAN" "$CONFIG"
