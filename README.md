# IDPico

**A tiny, self-contained identity provider.** One static binary that speaks OAuth 2.0 and
OpenID Connect, stores everything in a single SQLite file, and ships with an admin console,
a test client, groups, consent, and email flows — so you can develop and test against a real
IdP without standing up Keycloak.

> **⚠️ Development Use Only**
>
> IDPico is designed for **local testing and development**. It is deliberately small and is
> not intended for production use. For production environments, use a battle-tested identity
> provider.

## Features

- **OIDC Authorization Code + PKCE** flow
- **JWT tokens** (ID token and access token) signed with RS256 or EdDSA (Ed25519)
- **Refresh token rotation**
- **Token revocation** (RFC 7009)
- **Token introspection** (RFC 7662)
- **OIDC logout** (end_session_endpoint)
- **Argon2id password hashing**
- **Secure session cookies** (HttpOnly, Secure, SameSite)
- **CSRF protection** on login forms
- **CORS support** with configurable origins
- **Security headers** (CSP, X-Frame-Options, HSTS, etc.)
- **Rate limiting** on login and token endpoints
- **Account lockout** after failed login attempts
- **Prometheus metrics** for observability
- **File-based JSON storage** (no database required)
- **Bootstrap users and clients** via environment variables

## Quick Start

### Docker

```bash
docker run -p 8080:8080 wang/idpico:latest
```

That is a working identity provider at `http://localhost:8080` — but with no users, so `/` shows
what to do next. Give it a first user, an admin and your application in a three-line file:

```bash
cat > idpico.env <<'EOF'
IDPICO_BOOTSTRAP_USERS=you@example.com:change-me:Your Name
IDPICO_ADMIN_EMAILS=you@example.com
IDPICO_BOOTSTRAP_CLIENTS=my-app|my-app-secret|http://localhost:3000/callback
EOF
docker run -p 8080:8080 --env-file idpico.env -v idpico-data:/app/data wang/idpico:latest
```

Sign in at `http://localhost:8080/login`, open `/playground` to run an OIDC login end to end, and
`/admin` to manage users, groups, clients and signing keys. The named volume keeps the database
(`/app/data/idpico.db`) across restarts, so the env file is only needed the first time. If `8080` is
taken, change the port mapping *and* tell idpico its public address — that URL is the OIDC issuer:

```bash
docker run -p 8090:8080 -e IDPICO_ISSUER_URL=http://localhost:8090 --env-file idpico.env -v idpico-data:/app/data wang/idpico:latest
```

Images are multi-arch (amd64, arm64); pin a version (`wang/idpico:v0.0.7`) for anything you keep.

### From source

```bash
make build && ./idpico          # same server, SQLite in ./data
```

The same three lines go in a `.env` next to the binary (`cp .env.example .env`, edit, restart);
`idpicoctl user add` / `client add` do the same without a restart. For a developer sandbox with
ready-made accounts, `make seed && make run` (`test@example.com` / `password123`) or
`docker compose up` (`admin@example.com` / `password123`).

Kubernetes manifests are in [`deploy/k8s/`](deploy/k8s/) (kustomize; see
[docs/k3s-headlamp-setup.md](docs/k3s-headlamp-setup.md) for a full walkthrough).
`make docker-build` builds your own image.

## Configuration

Everything is an `IDPICO_*` environment variable with a working default; IDPico also reads a
`.env` file from its working directory. A first run needs nothing, a deployment needs the
handful under [Running it on a shared host](#running-it-on-a-shared-host), and the full list —
storage, sessions, token lifetimes, signing algorithm and key rotation, mail, rate limiting,
lockout, CORS, security headers, logging, bootstrap formats — is in
[docs/configuration.md](docs/configuration.md).

## Endpoints

### OIDC / OAuth 2.0
| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC discovery document |
| `GET /.well-known/jwks.json` | Public keys for JWT verification |
| `GET /authorize` | Authorization endpoint (start OIDC flow) |
| `POST /token` | Token endpoint (exchange code for tokens) |
| `GET /userinfo` | User info endpoint (requires access token) |
| `POST /revoke` | Token revocation endpoint (RFC 7009) |
| `POST /introspect` | Token introspection endpoint (RFC 7662) |

### Authentication & Consent
| Endpoint | Description |
|----------|-------------|
| `GET /login` | Login page |
| `POST /login` | Process login |
| `GET /logout` | Logout |
| `POST /consent` | Records the user's allow/deny decision from the consent screen |
| `GET/POST /forgot-password` | Request a password reset link by email |
| `GET/POST /reset-password` | Choose a new password from an emailed link |
| `GET /verify-email` | Confirm an email address from an emailed link |
| `GET /account` | The signed-in user's own sessions, refresh tokens, consents and password change |

### Playground

| Endpoint | Description |
|----------|-------------|
| `GET /playground` | Built-in relying party that runs the full flow against this IdP (see [OIDC Playground](#oidc-playground)) |

### Admin UI

| Endpoint | Description |
|----------|-------------|
| `GET /admin` | Dashboard (requires a signed-in user with the admin flag) |
| `/admin/users` | List, create, edit, invite, set password, revoke sessions/consents, delete |
| `/admin/groups` | List, create, edit, add/remove members, delete |
| `/admin/clients` | List, create, edit, regenerate secret, revoke tokens, delete |
| `/admin/keys` | List signing keys, rotate now |
| `/admin/audit` | Audit log: sign-ins, consent, password changes, key rotations, admin actions |

### Operations

| Endpoint | Description |
|----------|-------------|
| `GET /healthz` | Liveness check |
| `GET /readyz` | Readiness check |
| `GET /metrics` | Prometheus metrics (if enabled) |

## OIDC Flow Example

1. **Redirect user to authorize:**
   ```
   GET /authorize?client_id=my-app
     &redirect_uri=http://localhost:3000/callback
     &response_type=code
     &scope=openid profile email
     &state=random-state
     &code_challenge=<S256-challenge>
     &code_challenge_method=S256
   ```

2. **User logs in** at `/login`

3. **IdP redirects back** with authorization code:
   ```
   http://localhost:3000/callback?code=<auth-code>&state=random-state
   ```

4. **Exchange code for tokens:**
   ```bash
   curl -X POST http://localhost:8080/token \
     -d "grant_type=authorization_code" \
     -d "client_id=my-app" \
     -d "client_secret=my-secret" \
     -d "code=<auth-code>" \
     -d "redirect_uri=http://localhost:3000/callback" \
     -d "code_verifier=<original-verifier>"
   ```

5. **Response includes tokens:**
   ```json
   {
     "access_token": "eyJ...",
     "token_type": "Bearer",
     "expires_in": 900,
     "id_token": "eyJ...",
     "scope": "openid profile email"
   }
   ```

## OIDC Playground

Open `http://localhost:8080/playground` to try the whole flow without writing a client. It is a
built-in relying party (client id `playground`, registered automatically with a fresh secret
on every start) that runs Authorization Code + PKCE against this IdP through the same HTTP
endpoints an external app would use, then shows:

- the decoded ID token and access token claims (with nonce verification)
- the `/userinfo` response
- buttons to call `/userinfo`, `/introspect`, refresh, `/revoke`, and RP-initiated logout

Pick scopes (`groups`, `offline_access`, …) and `prompt`/`max_age` values to see how the IdP
reacts. Open it at the configured `IDPICO_ISSUER_URL` host, since the callback is an absolute
URL under the issuer. It is on by default for an `http://` issuer and off for `https://` (a shared host); `IDPICO_PLAYGROUND_ENABLED` overrides either way.

## idpicoctl

`idpicoctl` manages the same store from the shell, for Makefiles, CI and scripts:

```bash
make build                          # builds ./idpico and ./idpicoctl
./idpicoctl user add alice@example.com -name Alice -password s3cret-pass -admin -verified
./idpicoctl group add admins && ./idpicoctl group add-member admins alice@example.com
./idpicoctl client add my-app -redirect http://localhost:3000/callback   # prints the secret once
./idpicoctl client add spa -public -redirect http://localhost:5173/callback
./idpicoctl client add cli -redirect http://127.0.0.1/cb -access-ttl 5m -refresh-ttl 720h   # per-client lifetimes
./idpicoctl key rotate -grace 24h
./idpicoctl user list | group list | client list | key list
```

It takes `-driver`, `-data-dir` and `-dsn` like the server. With the SQLite driver it can run
while the server is up; with the JSON file driver stop the server first.

## Admin UI

A server-rendered admin console lives at `/admin`. Sign in with a user that has the admin
flag — grant it with `IDPICO_ADMIN_EMAILS` (applied on startup to existing or bootstrap users)
or from the Users page once you have one admin. `make seed` creates `test@example.com` (admin,
groups `admins` + `devs`) and `alice@example.com` (groups `devs`), both with password
`password123`, plus `test-client` / `test-public-client`.

- **Users**: create (with a password, or leave it blank to send an invite link), edit email /
  name / active / verified / admin, set a password (signs the user out everywhere), send reset
  or verification emails, see and revoke individual sessions and refresh tokens (or all at
  once), revoke consents, delete.
  You cannot delete or disable your own account or drop your own admin flag.
- **Groups**: create groups, add members by email, or tick group checkboxes on a user's page.
- **Clients**: create confidential or public (PKCE) clients; the secret is generated and shown
  exactly once — only an Argon2id hash is stored (plaintext secrets from older data files are
  upgraded to a hash the first time they authenticate). Edit redirect URIs, scopes, grant types, first-party (skip consent);
  regenerate the secret; revoke all tokens; delete.
- **Signing keys**: see active / retiring keys and rotate immediately.

The UI follows the system light/dark preference. Every form is CSRF-protected. Every mutation — along with sign-ins (including failures and
lockouts), sign-outs, consent decisions, password resets and key rotations — is written to the
audit log (`/admin/audit`, pruned after `IDPICO_AUDIT_RETENTION`, default 90 days).

## Data Storage

Two persistence backends are available, selected with `IDPICO_STORE_DRIVER`:

### SQLite (default)

A single-file database at `./data/idpico.db` (configurable via `IDPICO_DATA_DIR`, or point
`IDPICO_STORE_DSN` at any path). No external services or cgo required — the driver is
pure Go (`modernc.org/sqlite`), so the static Docker image works unchanged.

- Schema is created and migrated automatically on startup (embedded [goose](https://github.com/pressly/goose) migrations under `internal/store/migrations/`)
- WAL journaling with a 5s busy timeout
- Tables: `users`, `clients`, `sessions`, `auth_codes`, `tokens`, `signing_keys`
- Foreign keys are enforced: deleting a user or client cascades to its sessions, auth codes and tokens
- Emails are unique case-insensitively (`LOWER(email)` index); the JSON backend applies the same rule

Inspect it with any SQLite client, e.g. `sqlite3 data/idpico.db '.tables'`.

### JSON files (`IDPICO_STORE_DRIVER=file`)

The original backend: one JSON file per collection in `IDPICO_DATA_DIR`:

- `users.json` - User accounts with Argon2id password hashes
- `clients.json` - OAuth 2.0 client configurations
- `sessions.json` - Active user sessions
- `auth_codes.json` - Authorization codes
- `tokens.json` - Refresh tokens
- `signing_keys.json` - RSA signing keys

Every write rewrites the whole file, so it is best suited to tiny single-user setups
or when you want to hand-edit the data. There is no automatic migration between
backends; switching drivers starts from an empty store (bootstrap users/clients are
re-created from the environment).

## Security

### Running it on a shared host

The defaults suit a laptop. For anything reachable by other people, set:

```bash
IDPICO_ISSUER_URL=https://idp.example.com   # https: cookies become Secure automatically
IDPICO_COOKIE_SECRET=<random 32+ bytes>      # otherwise forms open during a restart fail their CSRF check (sessions persist regardless)
IDPICO_HSTS_MAX_AGE=31536000                 # once the host is https-only
IDPICO_PLAYGROUND_ENABLED=false              # already the default for an https issuer; the test client is one more signed-in surface
IDPICO_TRUSTED_PROXIES=private               # or your load balancer's CIDRs; "none" if reached directly
IDPICO_ADMIN_EMAILS=you@example.com          # keep the admin list short
```

`deploy/k8s/deployment.yaml` sets all of these. Also check the startup log: it warns about an
auto-generated cookie secret, an https issuer with `IDPICO_COOKIE_SECURE=false`, and an empty
trusted-proxy list.

### Rate Limiting

Per-IP limits guard every endpoint that accepts a guessable secret. `IDPICO_LOGIN_RATE_LIMIT`
(default 5) sets the interactive limit; API endpoints get 10× that. Set to `0` to disable.

The client IP is taken from `X-Forwarded-For` / `X-Real-IP` only when the connection comes from
a trusted proxy (`IDPICO_TRUSTED_PROXIES`, default `private`: loopback and private-network
peers, which covers an ingress or sidecar in front of the pod). Set it to your load balancer's
addresses or CIDRs when it has a public IP, or `none` when IDPico is reached directly; otherwise
a client could spoof a fresh address on every request and sidestep the limit.

| Endpoints | Default Limit | Window |
|-----------|---------------|--------|
| `POST /login`, `POST /consent`, `POST /forgot-password`, `POST /reset-password`, `GET /verify-email` | 5 requests | 1 minute |
| `POST /token`, `POST /revoke`, `POST /introspect` | 50 requests | 1 minute |

When the limit is exceeded, the server returns HTTP 429 (Too Many Requests).

Self-service password reset is additionally throttled per address: at most one email per
`IDPICO_PASSWORD_RESET_INTERVAL` (default 2m) to the same mailbox, regardless of source IP.
Admin-triggered sends are not throttled.

### Account Lockout

Accounts are temporarily locked after too many failed login attempts:

| Setting | Default | Description |
|---------|---------|-------------|
| `IDPICO_LOCKOUT_MAX_ATTEMPTS` | 5 | Failed attempts before lockout |
| `IDPICO_LOCKOUT_DURATION` | 15m | How long account stays locked |

Set `IDPICO_LOCKOUT_MAX_ATTEMPTS=0` to disable account lockout.

### CORS

Cross-Origin Resource Sharing can be enabled for specific origins:

```bash
IDPICO_CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
IDPICO_CORS_ALLOW_CREDENTIALS=true
```

Leave `IDPICO_CORS_ALLOWED_ORIGINS` empty to disable CORS (default).

### Security Headers

Security headers are enabled by default and include:

| Header | Default Value |
|--------|---------------|
| Content-Security-Policy | `default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'` |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| X-XSS-Protection | `0` (the legacy auditor is disabled; CSP is the defence) |
| Permissions-Policy | `geolocation=(), microphone=(), camera=()` |
| Strict-Transport-Security | Disabled by default (set `IDPICO_HSTS_MAX_AGE` to enable). Sent when TLS terminates here or a proxy reports `X-Forwarded-Proto: https` |

Configure via environment variables:

```bash
IDPICO_SECURITY_HEADERS_ENABLED=true
IDPICO_CONTENT_SECURITY_POLICY="default-src 'self'"
IDPICO_HSTS_MAX_AGE=31536000  # Enable HSTS with 1-year max-age
```

### Token Revocation (RFC 7009)

Revoke a refresh token or an access token:

```bash
curl -X POST http://localhost:8080/revoke \
  -u "my-app:my-secret" \
  -d "token=<refresh-token or access-token>"
```

A token can only be revoked by the client it was issued to. Per RFC 7009 the endpoint always returns
200 OK (except for authentication errors), so an unknown, foreign or already revoked token looks the
same as a successful revocation.

Access tokens are JWTs and nothing is stored when one is issued; revocation records what is no longer
valid in `token_revocations` and `/userinfo` and `/introspect` check it. A resource server that only
verifies the signature will not see a revocation — introspect, or keep `IDPICO_ACCESS_TOKEN_TTL`
short. Revoking a refresh token also revokes the access tokens of the same user and client issued up
to that moment (RFC 7009 §2.1), as does everything else that cuts off a grant: a replayed
authorization code or refresh token, **Sign out everywhere** and a password change on `/account`,
the admin console's revoke actions, `idpicoctl user passwd`. If the user has the same app open on a
second device, that device's access token is revoked too for at most one token lifetime; its refresh
token still works, so a well-behaved app recovers silently. Revocation rows are purged by maintenance
seven days after they can no longer matter.

### Token Introspection (RFC 7662)

Check if a token is active and get its metadata:

```bash
curl -X POST http://localhost:8080/introspect \
  -u "my-app:my-secret" \
  -d "token=<token>" \
  -d "token_type_hint=access_token"
```

Response for an active token:
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "my-app",
  "username": "user@example.com",
  "token_type": "Bearer",
  "exp": 1234567890,
  "iat": 1234567000,
  "sub": "user-id"
}
```

Response for an inactive/invalid token:
```json
{
  "active": false
}
```

### OIDC Logout (end_session_endpoint)

The `/logout` endpoint supports OIDC RP-Initiated Logout:

```
GET /logout?id_token_hint=<id-token>&post_logout_redirect_uri=/callback&state=abc123
```

Parameters:
- `id_token_hint`: Optional. The ID token previously issued.
- `post_logout_redirect_uri`: Optional. URL to redirect after logout (must be a relative path).
- `state`: Optional. Opaque value passed through to the redirect.

### Consent Screen

The first time a user authorizes a client, `/authorize` shows a consent page listing the
requested scopes. Allowing is remembered per user and client; a later request for a wider
scope prompts again, and `prompt=consent` always prompts. Standard OIDC `prompt` handling:

- `prompt=none` — never interact; returns `login_required` or `consent_required` to the client
- `prompt=login` / `prompt=select_account` — drop the current session and re-authenticate
  (there is no account chooser, so `select_account` re-authenticates)
- `prompt=consent` — re-show the consent page even if already granted
- `max_age=N` — re-authenticate if the session is older than N seconds; ID tokens carry
  `auth_time` (the session start) so clients can check it themselves

Clients marked `skip_consent` (first-party apps) never prompt. Set `IDPICO_REQUIRE_CONSENT=false`
to disable the screen globally.

### Groups

Users can belong to groups, and a client that is granted the `groups` scope receives the
member group names in the ID token, the access token, and `/userinfo`:

```json
{ "sub": "…", "email": "alice@example.com", "groups": ["cluster-admins", "devs"] }
```

A user with no memberships gets `"groups": []`; without the scope the claim is absent. Clients
must have `groups` in their allowed scopes (bootstrap and admin-created clients do by default).
`IDPICO_GROUPS_CLAIM` renames the claim (e.g. `roles`) for applications that expect a different
name — there is no separate role model; a "role" is a group.

Manage groups in the admin UI or seed them at startup:

```bash
IDPICO_BOOTSTRAP_GROUPS="cluster-admins:admin@example.com,viewers:alice@example.com bob@example.com"
```

Kubernetes: `--oidc-groups-claim=groups` lets you bind ClusterRoles to `Group` subjects named
after idpico groups — see [docs/k3s-headlamp-setup.md](docs/k3s-headlamp-setup.md).

### Password Reset & Email Verification

Users can request a reset link from the login page (`/forgot-password`). Links are random,
single-use, expire after `IDPICO_PASSWORD_RESET_TTL` (default 1h), and only their hash is stored.
Completing a reset revokes all of the user's sessions and refresh tokens. The response never
reveals whether an address exists.

Email verification works the same way (`/verify-email`, `IDPICO_EMAIL_VERIFY_TTL`, default 24h)
and sets the `email_verified` claim returned in ID tokens and `/userinfo`. Bootstrap users are
created verified; verification mail is sent from the admin UI.

With the default `IDPICO_MAIL_DRIVER=log`, emails are written to the server log instead of being
sent — the link is right there when you're testing locally. Set `IDPICO_MAIL_DRIVER=smtp` with
`IDPICO_SMTP_HOST`, `IDPICO_SMTP_FROM` and optional `IDPICO_SMTP_USERNAME`/`IDPICO_SMTP_PASSWORD` to
deliver real mail (STARTTLS when offered; `IDPICO_SMTP_IMPLICIT_TLS=true` for port 465).

### Signing Algorithm

Keys are RSA-2048 / `RS256` by default, which every relying party understands. Set
`IDPICO_SIGNING_ALGORITHM=EdDSA` for Ed25519: smaller keys and tokens, faster verification,
supported by current libraries (go-oidc, jose, Auth.js, oauth2-proxy) but not by everything.
Changing the setting rotates the signing key at the next start; the previous key keeps
verifying tokens it issued for `IDPICO_SIGNING_KEY_GRACE_PERIOD`, and the JWKS lists both
(`kty: RSA` and `kty: OKP, crv: Ed25519`). `idpicoctl key rotate -alg EdDSA` does the same
by hand. Discovery advertises `id_token_signing_alg_values_supported: ["RS256", "EdDSA"]`.

### Signing Key Rotation & Maintenance

A background maintenance loop runs every `IDPICO_MAINTENANCE_INTERVAL` (default 10m, `0` disables it) and:

- Deletes expired sessions, authorization codes and refresh tokens
- Rotates the RS256 signing key once it is older than `IDPICO_SIGNING_KEY_ROTATION_DAYS` (default 30, `0` disables rotation). New tokens are signed with the new key immediately; the previous key stays in `/.well-known/jwks.json` and keeps verifying tokens for `IDPICO_SIGNING_KEY_GRACE_PERIOD` (default 24h), then is deleted
- The grace period only needs to cover the access/ID token TTL — refresh tokens are opaque and unaffected by rotation

### Prometheus Metrics

Metrics are enabled by default. Disable with:

```bash
IDPICO_METRICS_ENABLED=false
```

Available metrics at `/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `idpico_http_requests_total` | Counter | Total HTTP requests by method, path, status |
| `idpico_http_request_duration_seconds` | Histogram | Request duration |
| `idpico_login_attempts_total` | Counter | Login attempts by status (success/failure/locked) |
| `idpico_tokens_issued_total` | Counter | Tokens issued by `type` (access, id, refresh) and `grant_type` |
| `idpico_tokens_rejected_total` | Counter | Access tokens refused at `/userinfo` by `reason` (invalid, revoked) |
| `idpico_token_introspections_total` | Counter | Introspection requests by `active` |
| `idpico_token_revocations_total` | Counter | Tokens actually revoked via `/revoke` |
| `idpico_auth_codes_issued_total` | Counter | Authorization codes issued |
| `idpico_rate_limit_exceeded_total` | Counter | Rate limit exceeded events |
| `idpico_account_lockouts_total` | Counter | Account lockout events |

## Guides

- [k3s + Headlamp OIDC Setup](docs/k3s-headlamp-setup.md) - Complete guide for setting up OIDC authentication with Kubernetes

## Development

```bash
make build        # Build ./idpico and ./idpicoctl
make run          # Build and run
make run-dev      # Run with debug logging
make seed         # Dev users, groups and clients
make test         # Run tests
make ci           # gofmt check, vet, race tests, OIDC flow, conformance, interop, static build (same as GitHub Actions)
make test-flow    # Full OIDC flow as an external client against a throwaway server
make validate     # Unit tests + black-box OIDC conformance suite (see below)
make docker-build # Build wang/idpico:<git tag> and :latest (IMAGE=/TAG= to override)
make docker-push  # Build linux/amd64 + linux/arm64 and push both tags as one manifest
make fmt          # Format code
make vet          # Run go vet
make clean        # Clean build artifacts
```

`scripts/test-client.sh` is the relying party behind `make test-flow`: it walks
discovery → `/authorize` (PKCE) → login → consent → `/token` → `/userinfo` →
refresh with nothing but `curl`, and checks that a replayed code, a wrong client
secret and a rotated-out refresh token are rejected. Point it at any running
IDPico, for example a container:

```bash
IDPICO_URL=http://localhost:8090 CLIENT_ID=my-app CLIENT_SECRET=... \
  USER_EMAIL=alice@example.com USER_PASSWORD=... scripts/test-client.sh
```

### Validation

`make validate` runs the unit tests and then the black-box conformance suite in
[`conformance/`](conformance/): it builds and starts an isolated IDPico, drives the
Authorization Code + PKCE flow over HTTP as a foreign relying party, verifies the
ID token with an independent JOSE library, and checks the refusals a client relies
on — wrong redirect URIs, PKCE downgrades, replayed codes, forged tokens.
`make validate-operational` restarts servers, rotates keys, restores a backup, upgrades a
data directory written by the previous release and drives a login through a simulated
TLS-terminating proxy. `make validate-interop` logs in through [`examples/oidc-client`](examples/oidc-client/),
a relying party built on go-oidc with no IDPico-specific code, and `make validate-oidf` runs the
OpenID Foundation conformance suite (Basic OP profile) in docker — v0.0.4 passes it with no
failures. The declared
profile, how to run the suite against a deployed instance, and known limitations
are in [CONFORMANCE.md](CONFORMANCE.md).

## License

MIT
