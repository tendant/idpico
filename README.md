# simple-idp

A lightweight Identity Provider (IdP) implementing OAuth 2.0 and OpenID Connect (OIDC).

> **⚠️ Development Use Only**
>
> This IdP is designed for **local testing and development** purposes. It uses file-based JSON storage and is not intended for production use. For production environments, use a battle-tested identity provider.

## Features

- **OIDC Authorization Code + PKCE** flow
- **JWT tokens** (ID token and access token) with RS256 signing
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

```bash
# Build
make build

# Run with default settings
make run

# Run with debug logging
make run-dev
```

The server starts at `http://localhost:8080` by default.

## Configuration

Configuration is via environment variables with `IDP_` prefix:

```bash
# Server
IDP_HOST=0.0.0.0
IDP_PORT=8080
IDP_ISSUER_URL=http://localhost:8080

# Storage
IDP_STORE_DRIVER=sqlite      # sqlite (default) or file
IDP_DATA_DIR=./data          # Holds idp.db (sqlite) or the JSON files (file)
IDP_STORE_DSN=               # Optional: explicit SQLite path, overrides <IDP_DATA_DIR>/idp.db

# Session
IDP_SESSION_DURATION=24h
IDP_COOKIE_SECRET=           # Auto-generated if empty
IDP_COOKIE_SECURE=false      # Set true for HTTPS

# Tokens
IDP_ACCESS_TOKEN_TTL=15m
IDP_REFRESH_TOKEN_TTL=168h   # 7 days
IDP_AUTH_CODE_TTL=10m

# Groups
IDP_GROUPS_CLAIM=groups            # claim name for memberships
IDP_BOOTSTRAP_GROUPS=              # "admins:alice@x.com bob@x.com,devs:carol@x.com"

# Admin UI
IDP_ADMIN_EMAILS=admin@example.com # who may open /admin (comma-separated)

# Consent
IDP_REQUIRE_CONSENT=true           # consent screen for third-party clients

# Email (password reset / verification links)
IDP_MAIL_DRIVER=log                # log = print to server log, smtp = send
IDP_SMTP_HOST=                     # required for smtp, with IDP_SMTP_FROM
IDP_PASSWORD_RESET_TTL=1h
IDP_EMAIL_VERIFY_TTL=24h

# Key rotation & maintenance
IDP_SIGNING_KEY_ROTATION_DAYS=30   # 0 = disabled
IDP_SIGNING_KEY_GRACE_PERIOD=24h   # rotated keys remain valid for verification
IDP_MAINTENANCE_INTERVAL=10m       # expired-row purge + key rotation (0 = disabled)

# Logging
IDP_LOG_LEVEL=info           # debug, info, warn, error
IDP_LOG_FORMAT=json          # json or text

# Rate limiting
IDP_LOGIN_RATE_LIMIT=5       # requests per minute per IP (0 = disabled)

# Account lockout
IDP_LOCKOUT_MAX_ATTEMPTS=5   # failed attempts before lockout (0 = disabled)
IDP_LOCKOUT_DURATION=15m     # how long account stays locked

# CORS (empty = disabled)
IDP_CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
IDP_CORS_ALLOW_CREDENTIALS=true

# Security headers
IDP_SECURITY_HEADERS_ENABLED=true
IDP_CONTENT_SECURITY_POLICY=default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'
IDP_HSTS_MAX_AGE=31536000    # 1 year, 0 = disabled

# Bootstrap a single client
IDP_CLIENT_ID=my-app
IDP_CLIENT_SECRET=my-secret
IDP_CLIENT_REDIRECT_URI=http://localhost:3000/callback

# Bootstrap users (email:password:name, comma-separated)
IDP_BOOTSTRAP_USERS=admin@example.com:password123:Admin User
```

You can also use a `.env` file (copy from `.env.example`).

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

### Admin UI
| Endpoint | Description |
|----------|-------------|
| `GET /admin` | Dashboard (requires a signed-in user with the admin flag) |
| `/admin/users` | List, create, edit, invite, set password, revoke sessions/consents, delete |
| `/admin/groups` | List, create, edit, add/remove members, delete |
| `/admin/clients` | List, create, edit, regenerate secret, revoke tokens, delete |
| `/admin/keys` | List signing keys, rotate now |

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

## Admin UI

A server-rendered admin console lives at `/admin`. Sign in with a user that has the admin
flag — grant it with `IDP_ADMIN_EMAILS` (applied on startup to existing or bootstrap users)
or from the Users page once you have one admin. `make seed` makes `test@example.com` an admin.

- **Users**: create (with a password, or leave it blank to send an invite link), edit email /
  name / active / verified / admin, set a password (signs the user out everywhere), send reset
  or verification emails, revoke sessions and refresh tokens, revoke consents, delete.
  You cannot delete or disable your own account or drop your own admin flag.
- **Groups**: create groups, add members by email, or tick group checkboxes on a user's page.
- **Clients**: create confidential or public (PKCE) clients; the secret is generated and shown
  exactly once. Edit redirect URIs, scopes, grant types, first-party (skip consent);
  regenerate the secret; revoke all tokens; delete.
- **Signing keys**: see active / retiring keys and rotate immediately.

Every form is CSRF-protected and every mutation is logged with the acting admin.

## Data Storage

Two persistence backends are available, selected with `IDP_STORE_DRIVER`:

### SQLite (default)

A single-file database at `./data/idp.db` (configurable via `IDP_DATA_DIR`, or point
`IDP_STORE_DSN` at any path). No external services or cgo required — the driver is
pure Go (`modernc.org/sqlite`), so the static Docker image works unchanged.

- Schema is created and migrated automatically on startup (embedded [goose](https://github.com/pressly/goose) migrations under `internal/store/migrations/`)
- WAL journaling with a 5s busy timeout
- Tables: `users`, `clients`, `sessions`, `auth_codes`, `tokens`, `signing_keys`
- Foreign keys are enforced: deleting a user or client cascades to its sessions, auth codes and tokens
- Emails are unique case-insensitively (`LOWER(email)` index); the JSON backend applies the same rule

Inspect it with any SQLite client, e.g. `sqlite3 data/idp.db '.tables'`.

### JSON files (`IDP_STORE_DRIVER=file`)

The original backend: one JSON file per collection in `IDP_DATA_DIR`:

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

### Rate Limiting

The IdP includes rate limiting to prevent brute-force attacks:

| Endpoint | Default Limit | Window |
|----------|---------------|--------|
| `POST /login` | 5 requests | 1 minute |
| `POST /token` | 50 requests | 1 minute |

When the limit is exceeded, the server returns HTTP 429 (Too Many Requests).

Configure via `IDP_LOGIN_RATE_LIMIT` environment variable. Set to `0` to disable.

### Account Lockout

Accounts are temporarily locked after too many failed login attempts:

| Setting | Default | Description |
|---------|---------|-------------|
| `IDP_LOCKOUT_MAX_ATTEMPTS` | 5 | Failed attempts before lockout |
| `IDP_LOCKOUT_DURATION` | 15m | How long account stays locked |

Set `IDP_LOCKOUT_MAX_ATTEMPTS=0` to disable account lockout.

### CORS

Cross-Origin Resource Sharing can be enabled for specific origins:

```bash
IDP_CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
IDP_CORS_ALLOW_CREDENTIALS=true
```

Leave `IDP_CORS_ALLOWED_ORIGINS` empty to disable CORS (default).

### Security Headers

Security headers are enabled by default and include:

| Header | Default Value |
|--------|---------------|
| Content-Security-Policy | `default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'` |
| X-Frame-Options | `DENY` |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| X-XSS-Protection | `1; mode=block` |
| Permissions-Policy | `geolocation=(), microphone=(), camera=()` |
| Strict-Transport-Security | Disabled by default (set `IDP_HSTS_MAX_AGE` to enable) |

Configure via environment variables:

```bash
IDP_SECURITY_HEADERS_ENABLED=true
IDP_CONTENT_SECURITY_POLICY="default-src 'self'"
IDP_HSTS_MAX_AGE=31536000  # Enable HSTS with 1-year max-age
```

### Token Revocation (RFC 7009)

Revoke refresh tokens:

```bash
curl -X POST http://localhost:8080/revoke \
  -u "my-app:my-secret" \
  -d "token=<refresh-token>" \
  -d "token_type_hint=refresh_token"
```

Per RFC 7009, the endpoint always returns 200 OK (except for authentication errors) to prevent token enumeration.

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
- `prompt=login` — drop the current session and re-authenticate
- `prompt=consent` — re-show the consent page even if already granted

Clients marked `skip_consent` (first-party apps) never prompt. Set `IDP_REQUIRE_CONSENT=false`
to disable the screen globally.

### Groups

Users can belong to groups, and a client that is granted the `groups` scope receives the
member group names in the ID token, the access token, and `/userinfo`:

```json
{ "sub": "…", "email": "alice@example.com", "groups": ["cluster-admins", "devs"] }
```

A user with no memberships gets `"groups": []`; without the scope the claim is absent. Clients
must have `groups` in their allowed scopes (bootstrap and admin-created clients do by default).
`IDP_GROUPS_CLAIM` renames the claim (e.g. `roles`) for applications that expect a different
name — there is no separate role model; a "role" is a group.

Manage groups in the admin UI or seed them at startup:

```bash
IDP_BOOTSTRAP_GROUPS="cluster-admins:admin@example.com,viewers:alice@example.com bob@example.com"
```

Kubernetes: `--oidc-groups-claim=groups` lets you bind ClusterRoles to `Group` subjects named
after simple-idp groups — see [docs/k3s-headlamp-setup.md](docs/k3s-headlamp-setup.md).

### Password Reset & Email Verification

Users can request a reset link from the login page (`/forgot-password`). Links are random,
single-use, expire after `IDP_PASSWORD_RESET_TTL` (default 1h), and only their hash is stored.
Completing a reset revokes all of the user's sessions and refresh tokens. The response never
reveals whether an address exists.

Email verification works the same way (`/verify-email`, `IDP_EMAIL_VERIFY_TTL`, default 24h)
and sets the `email_verified` claim returned in ID tokens and `/userinfo`. Bootstrap users are
created verified; verification mail is sent from the admin UI.

With the default `IDP_MAIL_DRIVER=log`, emails are written to the server log instead of being
sent — the link is right there when you're testing locally. Set `IDP_MAIL_DRIVER=smtp` with
`IDP_SMTP_HOST`, `IDP_SMTP_FROM` and optional `IDP_SMTP_USERNAME`/`IDP_SMTP_PASSWORD` to
deliver real mail (STARTTLS when offered; `IDP_SMTP_IMPLICIT_TLS=true` for port 465).

### Signing Key Rotation & Maintenance

A background maintenance loop runs every `IDP_MAINTENANCE_INTERVAL` (default 10m, `0` disables it) and:

- Deletes expired sessions, authorization codes and refresh tokens
- Rotates the RS256 signing key once it is older than `IDP_SIGNING_KEY_ROTATION_DAYS` (default 30, `0` disables rotation). New tokens are signed with the new key immediately; the previous key stays in `/.well-known/jwks.json` and keeps verifying tokens for `IDP_SIGNING_KEY_GRACE_PERIOD` (default 24h), then is deleted
- The grace period only needs to cover the access/ID token TTL — refresh tokens are opaque and unaffected by rotation

### Prometheus Metrics

Metrics are enabled by default. Disable with:

```bash
IDP_METRICS_ENABLED=false
```

Available metrics at `/metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `idp_http_requests_total` | Counter | Total HTTP requests by method, path, status |
| `idp_http_request_duration_seconds` | Histogram | Request duration |
| `idp_login_attempts_total` | Counter | Login attempts by status (success/failure/locked) |
| `idp_active_sessions` | Gauge | Number of active sessions |
| `idp_tokens_issued_total` | Counter | Tokens issued by type and grant type |
| `idp_token_introspections_total` | Counter | Token introspection requests |
| `idp_token_revocations_total` | Counter | Token revocation requests |
| `idp_auth_codes_issued_total` | Counter | Authorization codes issued |
| `idp_rate_limit_exceeded_total` | Counter | Rate limit exceeded events |
| `idp_account_lockouts_total` | Counter | Account lockout events |

## Guides

- [k3s + Headlamp OIDC Setup](docs/k3s-headlamp-setup.md) - Complete guide for setting up OIDC authentication with Kubernetes

## Development

```bash
make build        # Build binary
make run          # Build and run
make run-dev      # Run with debug logging
make test         # Run tests
make test-flow    # Test full OIDC flow
make fmt          # Format code
make vet          # Run go vet
make clean        # Clean build artifacts
```

## License

MIT
