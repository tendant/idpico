# simple-idp

A lightweight Identity Provider (IdP) implementing OAuth 2.0 and OpenID Connect (OIDC).

> **⚠️ Development Use Only**
>
> This IdP is designed for **local testing and development** purposes. It uses file-based JSON storage and is not intended for production use. For production environments, use a battle-tested identity provider.

## Features

- **OIDC Authorization Code + PKCE** flow
- **JWT tokens** (ID token and access token) with RS256 signing
- **Refresh token rotation**
- **Argon2id password hashing**
- **Secure session cookies** (HttpOnly, Secure, SameSite)
- **CSRF protection** on login forms
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
