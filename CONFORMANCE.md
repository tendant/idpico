# IDPico conformance

How IDPico's OpenID Connect behaviour is validated, what the declared profile is, and what is known
not to be covered. The design behind this is in [idpico-validation-design.md](idpico-validation-design.md).

The principle: **unit tests verify the implementation; black-box tests and independent clients verify the
protocol contract.** Everything under `conformance/` treats IDPico as a remote provider — it knows only
an issuer URL and test credentials, talks HTTP, and verifies tokens with [go-jose](https://github.com/go-jose/go-jose),
not with the `golang-jwt` library IDPico signs with. It cannot import `internal/` (a test enforces this).

## Declared profile (v0.1)

| | |
|---|---|
| **Required, tested** | Discovery, Authorization Code flow, PKCE `S256`, JWKS, signed ID tokens (`RS256`, `EdDSA`), UserInfo, `state`, `nonce`, client authentication `client_secret_basic` / `client_secret_post` / `none` |
| **Implemented, not yet in the conformance contract** | Refresh tokens (rotation, reuse detection — covered by `scripts/test-client.sh` and unit tests), RP-initiated logout (`end_session_endpoint`), token revocation, token introspection, `prompt`, `max_age` / `auth_time`, `groups` claim |
| **Not supported** | Implicit and hybrid flows, Resource Owner Password Credentials, client credentials, device authorization, dynamic client registration, request objects, encrypted tokens, federation, SAML, SCIM |

Unsupported response types and grant types are refused with `unsupported_response_type` /
`unsupported_grant_type`; the suite checks that they are refused, not that they work.

## Validation levels

| Level | What | Status |
|---|---|---|
| 0 Development | `go test ./...`, `go vet`, gofmt | ✅ CI |
| 1 Functional | discovery, JWKS, authorization code, token exchange, independent ID token validation, UserInfo | ✅ `make validate-conformance`, CI |
| 2 Security | PKCE S256, redirect URI enforcement, code replay, client/code binding, state/nonce, forged and damaged JWTs | ✅ `make validate-security`, CI |
| 3 Interoperability | independent go-oidc client (`examples/oidc-client`) | ✅ `make validate-interop`, CI · other real applications: see below |
| 4 Standards | OpenID Foundation conformance suite, Basic OP profile | ✅ `make validate-oidf`: 36 modules, 0 failures (results below) |
| Operational | restart, key rotation, backup/restore, upgrade, reverse proxy | ✅ `make validate-operational`, CI (section below) |

A release states the level it reached rather than claiming "OIDC compatible".

## Running it

```bash
make validate               # unit tests + conformance suite (~10 s)
make validate-conformance   # conformance suite only, verbose
make validate-security      # only the Security* tests (level 2)
make validate-interop       # login through examples/oidc-client
make validate-all           # everything incl. -race
make validate-operational   # restart, key rotation, backup/restore, upgrade, reverse proxy (~12 s)
make validate-oidf          # OpenID Foundation suite, Basic OP profile (docker; ~90 s after first pull)
```

`validate-conformance` builds `./cmd/idpico`, starts it on a free loopback port with a temporary data
directory and deterministic bootstrap data, runs the suite, and removes everything — also on failure and
on Ctrl-C. The server's environment is built from scratch, so `IDPICO_*` variables or a `.env` in the
working tree do not reach it. The instance runs with rate limiting and lockout off and 4-second
auth-code / access-token lifetimes (so expiry is observable); nothing else deviates from defaults.

The suite is behind the `conformance` build tag so that `go test ./...` stays a pure unit run:

```bash
go test -tags conformance -count=1 -v ./conformance/
go test -tags conformance -count=1 -v -run 'TestPKCE|TestSecurityToken' ./conformance/
```

### Against a running instance

Set `CONFORMANCE_ISSUER` and the suite skips starting a server. The instance must have these provisioned
(names are overridable with the matching `CONFORMANCE_*` variables):

| Variable | Default | Must be |
|---|---|---|
| `CONFORMANCE_CLIENT_ID` / `_SECRET` / `_REDIRECT_URI` | `conformance-client` / `conformance-secret` / `http://127.0.0.1:18081/callback` | confidential client, scopes `openid profile email` |
| `CONFORMANCE_PUBLIC_CLIENT_ID` | `conformance-public` | public client, same redirect URI |
| `CONFORMANCE_OTHER_CLIENT_ID` / `_SECRET` / `_REDIRECT_URI` | `conformance-other` / … / `http://127.0.0.1:18082/callback` | second confidential client |
| `CONFORMANCE_STRICT_CLIENT_ID` / `_SECRET` / `_REDIRECT_URI` | `conformance-strict` / … / `https://app.example.com/callback` | confidential client whose only redirect URI is `https://` (never followed) |
| `CONFORMANCE_USER_EMAIL` / `_PASSWORD` | `alice@example.com` / `test-password` | active user, email verified |

For an IDPico started by hand the matching bootstrap is:

```bash
IDPICO_BOOTSTRAP_USERS="alice@example.com:test-password:Alice" \
IDPICO_BOOTSTRAP_CLIENTS="conformance-client|conformance-secret|http://127.0.0.1:18081/callback,conformance-public||http://127.0.0.1:18081/callback,conformance-other|conformance-other-secret|http://127.0.0.1:18082/callback,conformance-strict|conformance-strict-secret|https://app.example.com/callback" \
IDPICO_LOGIN_RATE_LIMIT=0 IDPICO_LOCKOUT_MAX_ATTEMPTS=0 ./idpico

CONFORMANCE_ISSUER=http://localhost:8080 go test -tags conformance -count=1 -v ./conformance/
```

The two tests that wait for expiry skip themselves in this mode. Leave the rate limiter on and the suite
will hit 429s: the security tests deliberately make dozens of requests a minute from one address.

### Diagnostics

`CONFORMANCE_VERBOSE=1` logs every request and response through `t.Log`. Output is redacted before it is
written: passwords, client secrets, cookies, `Authorization` headers, authorization codes, verifiers,
and anything that looks like a JWT become `[redacted]`. The throwaway server's own log is printed
(redacted) only if it fails to start.

## What the suite checks

| Test | Covers |
|---|---|
| `TestDiscovery` | metadata document: exact `issuer`, endpoints under the issuer, `code` response type, `S256`, `none` auth method, no `alg=none` |
| `TestJWKS` | reachable via `jwks_uri`, valid public keys with stable unique `kid`, RSA/RS256 or OKP/EdDSA, no private members |
| `TestAuthorizationCode` | full flow for a confidential (basic and post auth) and a public client; `state` round-trip; token response shape and `Cache-Control: no-store`; single-use code; UserInfo `sub` equals ID token `sub` |
| `TestIDToken` | OIDC Core §3.1.3.7 step by step with go-jose: `kid` → JWKS key with matching `alg`, signature, `iss`, `aud` (+`azp` rule), `exp`/`iat`, `nonce`, opaque `sub`, `email` for scope `email` |
| `TestPKCE` | correct verifier passes; wrong / missing verifier and replay are `invalid_grant`; a public client that omits the challenge, uses `plain` or an unknown method gets `error=invalid_request` at its redirect URI |
| `TestUserInfo` | claims by scope, GET and POST, `sub` consistency, 401 + `WWW-Authenticate: Bearer` for missing / Basic / empty / junk / altered tokens |
| `TestSecurityRedirectURI` | exact matching: trailing slash, sub-path, suffix domain, other host, scheme, port, case, query, userinfo — none redirect; exchange `redirect_uri` must match |
| `TestSecurityToken` | code bound to client (other confidential client, public client), to `redirect_uri`, single use, expiry; wrong / missing / unknown client credentials are 401 `invalid_client`; other grant types `unsupported_grant_type`; error bodies are JSON, `no-store`, leak nothing |
| `TestSecurityJWT` | `/userinfo` refuses: altered payload, altered signature, tokens signed by unknown RSA/Ed25519 keys (even with the real `kid`), unknown `kid`, `alg=none`, HMAC, truncated, garbage, expired. The independent verifier refuses wrong `iss`, `aud`, `nonce`, alg |
| `TestSecurityAuthorize` | before client + `redirect_uri` are validated: error page, never a redirect; after: `unsupported_response_type` / `invalid_scope` redirected with `state`; `scope=openidx` is not `openid`; `prompt=none` → `login_required`; login form requires its CSRF token |
| `TestNoInternalImports` | the suite imports nothing from this module |

Error responses are additionally checked never to contain a client secret, the password, a token, or a
stack trace.

## Reference client

[`examples/oidc-client`](examples/oidc-client/) is a separate Go module built on `coreos/go-oidc` and
`golang.org/x/oauth2`, configured with only `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET` and
`OIDC_REDIRECT_URI`. `make validate-interop` starts a throwaway IDPico and the client and drives a login
through both with `scripts/test-interop.sh` (curl as the browser), checking that the client sent PKCE and
a nonce, verified the ID token, agreed with UserInfo on `sub`, and rejects a forged `state`.

A workaround needed by a standard client is an IDPico bug, not a client configuration problem.

### Other applications

Tried so far: none recorded. When adding one, note the configuration used, whether discovery, login,
callback, token verification and logout worked, and any workaround — two or three genuinely independent
implementations are worth more than many clients sharing a library.

## Known limitations and deviations

Found while writing the suite; none affects the declared profile.

- **`plain` PKCE is accepted from confidential clients** while discovery advertises only `S256`. Public
  clients are held to `S256`. RFC 7636 permits `plain`; a future release may refuse it everywhere.
- **No `at_hash` in the ID token.** Not required for the code flow (OIDC Core §3.1.3.6), but clients that
  validate access tokens through it will not be able to.
- **Scope claims are in the ID token.** For the code flow OIDC Core §5.4 says the `profile`/`email`
  claims belong in the UserInfo response; IDPico also puts `email`, `email_verified` and `name` (and a
  non-standard `client_id`) in the ID token so that relying parties that only read the ID token —
  Kubernetes, most auth proxies — get them without a UserInfo call. Deliberate; the OIDF suite warns.
- **Only `name` for scope `profile`**: no `given_name`, `family_name`, `picture`, `locale`, … .
- **`acr_values` is ignored** and no `acr` claim is returned (a SHOULD); there are no authentication
  context classes.
- **The `claims` request parameter is not supported** (`claims_parameter_supported: false`).
- **Access tokens are JWTs; revocation is checked at `/userinfo` and `/introspect` only.** A resource
  server that validates the signature itself will not learn that a token was revoked — use
  introspection there, or keep `IDPICO_ACCESS_TOKEN_TTL` short.
- **`grant_types` on a client is stored but not enforced** at `/token`; every client can use both
  `authorization_code` and `refresh_token`.
- **Refresh tokens, logout, revocation and introspection** have unit, `scripts/test-client.sh` and (for
  refresh) OIDF coverage but are not yet part of the black-box conformance contract.

Fixed while writing the suite and running the OIDF tests (v0.0.4):

- `/authorize` showed a 400 page for an unsupported `response_type`, a `scope` without `openid`, a
  disallowed scope or a public client without PKCE even when the client and `redirect_uri` were valid;
  RFC 6749 §4.1.2.1 requires these to go to the redirect URI. `openid` was matched as a substring.
- `/authorize` only accepted GET; OIDC Core §3.1.2.1 requires POST too.
- A `request`, `request_uri` or `registration` parameter was silently ignored and the request processed
  from the query parameters; §6.1/§6.2/§7.2.1 require `request_not_supported` /
  `request_uri_not_supported` / `registration_not_supported`. Discovery now states
  `request_parameter_supported`, `request_uri_parameter_supported` (whose default is *true*) and
  `claims_parameter_supported` as `false`.
- Reusing an authorization code did not revoke anything; it now revokes the grant's refresh tokens.
- `/userinfo` did not accept `access_token` in a form-encoded POST body (RFC 6750 §2.2), and answered a
  request with no credentials with `error="invalid_token"` instead of a bare `Bearer` challenge (§3.1).

## OpenID Foundation conformance (level 4)

`make validate-oidf` runs the official [conformance suite](https://gitlab.com/openid/conformance-suite)
(prebuilt images, pinned commit in `scripts/oidf.sh`) with docker compose, starts a throwaway IDPico
that the containers reach as `host.docker.internal`, and drives the **OpenID Connect Core: Basic OP**
plan (`oidcc-basic-certification-test-plan`, discovery, static clients) with the suite's own
`run-test-plan.py`. The test configuration, including the scripted-browser steps that fill IDPico's login
form, is `conformance/oidf/idpico-oidcc.json`; `expected-warnings.json` and `expected-skips.json` list
what is accepted, with a reason each. Anything else — a failure, a new warning, a new skip — makes the
run exit non-zero. `KEEP_SUITE=1` leaves the suite up at <https://localhost.emobix.co.uk:8443/> to browse
the logs and screenshots. It is not run in CI (docker, ~1.3 GB of images, ~90 s).

### Results — 2026-09-20, suite `440eec8b`, Basic OP profile

36 modules, 1712 conditions: **0 failures**, 14 warnings, 4 skips, 4 screenshots for review.

| Result | Modules | Classification |
|---|---|---|
| PASSED (21) | server, response-type-missing, userinfo-get/-post-header/-post-body, request-without-nonce, display-page/-popup, prompt-none-not-logged-in/-logged-in, max-age-10000, unknown-parameter, id-token-hint, login-hint, ui-locales, claims-locales, codereuse, codereuse-30seconds, ensure-post-request, server-client-secret-post, refresh-token, valid-pkce | — |
| REVIEW (4) | prompt-login, max-age-1, ensure-registered-redirect-uri, ensure-request-object-with-redirect-uri | Pass with a screenshot the suite captured automatically (second login page; `invalid redirect_uri` error page). A human checks them in a certification submission. |
| WARNING (6) | server, scope-email, alternate-happy-flow, claims-essential | SPEC INTERPRETATION: scope claims in the ID token (see above) |
| | scope-profile | UNSUPPORTED: only `name` of the profile claims |
| | ensure-request-with-acr-values | UNSUPPORTED: no `acr` |
| SKIPPED (4) | scope-address, scope-phone, scope-all, unsigned-request-object | UNSUPPORTED: scopes not in `scopes_supported`; request objects not supported |

The failures the first run found — POST `/authorize` unsupported, request objects silently ignored — were
bugs in the declared profile and are fixed above. Formal certification (submitting these results to the
OpenID Foundation) is a separate decision; the profile would need the ID-token-claims interpretation
accepted or changed, and the screenshots reviewed.

## Operational validation

Protocol conformance says nothing about what happens to identity state over time. `make
validate-operational` (`go test -tags conformance -run Operational ./conformance/`, in CI) starts its own
idpico instances — several per test, restarted on the same data directory so the issuer and every
`iss` stay the same — and pins the following policies. Each runs against the SQLite and the file
driver.

| Test | Proves | Policy it pins |
|---|---|---|
| `TestOperationalRestart` | After a restart: same `kid`, an access token issued before still passes `/userinfo`, the refresh token refreshes, the browser session completes `/authorize` without a login or consent page, the user's password and the client's secret still work | **Sessions survive restarts.** They are opaque server-side records; `IDPICO_COOKIE_SECRET` only signs CSRF tokens, so an auto-generated secret costs only the login/consent/admin forms that were open at the moment of the restart |
| `TestOperationalBackupRestore` | A `cp -a` of the data directory taken after a clean stop, started elsewhere on the same port, has the signing key, users, clients, sessions and live tokens | **A backup is a file copy of `IDPICO_DATA_DIR` after a clean stop.** SQLite is checkpointed on close (no `-wal`/`-shm` left behind); copying a running instance is not tested and not recommended |
| `TestOperationalKeyRotation` | `idpicoctl key rotate -grace 6s`, restart: JWKS lists old and new key (public members only), new tokens carry the new `kid`, old tokens still verify. After the grace: old tokens are refused and the old key is no longer published; after the next maintenance run it is deleted. `IDPICO_SIGNING_ALGORITHM=EdDSA` on restart rotates likewise, keeping the RS256 key verifiable | **Rotated keys verify until `IDPICO_SIGNING_KEY_GRACE_PERIOD` ends and are published only until then.** Rotate ≥ one access-token lifetime before the old key must be gone |
| `TestOperationalReverseProxy` | Behind a simulated TLS-terminating proxy (`Host` + `X-Forwarded-Proto: https` to the loopback listener): discovery and `iss` are the configured `https://` issuer whatever `Host` says; cookies are `Secure`; HSTS is sent only for requests that arrived over TLS; a login completes; `X-Forwarded-For` is believed from a trusted proxy (`IDPICO_TRUSTED_PROXIES`, default private ranges) and ignored — together with `X-Forwarded-Proto` — from anyone else | **The issuer is configuration, never the request.** Forwarding headers from untrusted peers are stripped |
| `TestOperationalUpgrade` | The current build starts on `conformance/testdata/upgrade/<previous tag>/idpico.db`, `goose_db_version` reaches the newest migration, the previous release's `kid`, user password, client secret and recorded consent all work | **Upgrades are forward-only**: migrations apply at startup; running an older release on a migrated directory is unsupported. Restore the pre-upgrade backup instead |

Every instance start also requires `/readyz` to answer 200, which now checks the backend (a SQLite
ping, or the data directory for the file driver).

The upgrade fixture is produced by `scripts/upgrade-fixture.sh <tag>`: it builds that tag from git,
bootstraps the conformance user and clients, performs one login + consent + token exchange, stops
cleanly and copies the database. Re-run it for the release just cut whenever a new one is made, so
"previous release" stays current; CI's shallow checkout has no tags and relies on the committed file.

Access-token revocation (after v0.0.4) removed the last `SHOULD` warning: a replayed code now also
invalidates the access token it issued (`oidcc-codereuse-30seconds` passes).

Found and fixed while writing the suite (after v0.0.4): the JWKS kept publishing keys whose grace
period had ended (verification already refused them); `X-Forwarded-Proto` from an untrusted peer
could switch HSTS on; the startup warning and README said sessions die with an auto-generated cookie
secret; `/readyz` never looked at the database.
