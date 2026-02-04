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
IDP_DATA_DIR=./data

# Session
IDP_SESSION_DURATION=24h
IDP_COOKIE_SECRET=           # Auto-generated if empty
IDP_COOKIE_SECURE=false      # Set true for HTTPS

# Tokens
IDP_ACCESS_TOKEN_TTL=15m
IDP_REFRESH_TOKEN_TTL=168h   # 7 days
IDP_AUTH_CODE_TTL=10m

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

### Authentication
| Endpoint | Description |
|----------|-------------|
| `GET /login` | Login page |
| `POST /login` | Process login |
| `GET /logout` | Logout |

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

## Data Storage

Data is stored as JSON files in `./data/` (configurable via `IDP_DATA_DIR`):

- `users.json` - User accounts with Argon2id password hashes
- `clients.json` - OAuth 2.0 client configurations
- `sessions.json` - Active user sessions
- `auth_codes.json` - Authorization codes
- `tokens.json` - Refresh tokens
- `signing_keys.json` - RSA signing keys

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
