# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

**simple-idp** is a lightweight Identity Provider (IdP) for **local testing and development**. Phase 1 (File Storage) and the SQLite backend are complete. The IdP is fully functional with:

- Complete OIDC Authorization Code + PKCE flow
- JWT ID tokens and access tokens (RS256)
- Refresh token rotation
- SQLite storage by default (`IDP_STORE_DRIVER=sqlite`), JSON file storage as an alternative (`file`)
- Bootstrap users and clients via environment variables

See DESIGN.md for the complete architectural specification.

## Reference Project

The **simple-idm** project (`../simple-idm`) serves as a reference for coding patterns and conventions. Key patterns to follow:

- **Package structure**: `pkg/<feature>/` with `service.go`, `repository.go`, `api/` subdirectory
- **Service pattern**: Constructor with options (`NewServiceWithOptions`, `WithDependency()` functional options)
- **Repository pattern**: Interface + multiple implementations (postgres, inmem, file)
- **Error handling**: Structured errors with codes in `pkg/errors/`
- **Logging**: `log/slog` structured logging
- **HTTP**: chi router with middleware pattern
- **Testing**: TestContainers for integration tests
- **JWT/JWKS**: See `pkg/tokengenerator/` and `pkg/jwks/` for token generation and key handling patterns

**Note**: simple-idp remains independent of simple-idm at runtime and build-time, but follows the same architectural patterns.

## Implementation Strategy

Implementation proceeds in phases to enable faster iteration:

1. **Phase 1 - File Storage**: ✅ **COMPLETE**
   - Local file storage (JSON files) for all persistence
   - Full OIDC Authorization Code + PKCE flow
   - JWT tokens with RS256 signing
   - User authentication with Argon2id password hashing
   - Session management with secure cookies

2. **Phase 1.5 - SQLite**: ✅ **COMPLETE** (default backend)
   - `internal/store/sqlite/` using `modernc.org/sqlite` (pure Go, keeps `CGO_ENABLED=0` builds)
   - Embedded goose migrations in `internal/store/migrations/<dialect>/`
   - `internal/store/storetest/` conformance suite — run it against every backend

3. **Phase 2 - PostgreSQL**: Planned
   - Implement postgres repository implementations (same schema; add `migrations/postgres/`)
   - Production-ready persistence

## Build Commands

```bash
make build              # Build the binary
make run                # Build and run the server
make run-dev            # Run with debug logging
make test               # Run all tests
make test-flow          # Test full OIDC flow
go vet ./...            # Lint
go fmt ./...            # Format code
```

## Architecture Overview

### Core Design Principles
- **Stateless application servers** - all persistent state externalized (file or Postgres)
- **OIDC-first** - Authorization Code + PKCE as primary flow
- **Security by default** - Argon2id passwords, secure cookies, strict redirect URI validation, PKCE required for public clients
- **Independent of simple-idm** - no runtime or build-time coupling (patterns are shared, code is not)

### Directory Structure
```
cmd/idp/main.go           # Entry point
internal/
  config/                 # Configuration loading/validation
  http/                   # Router + middleware
  auth/                   # Login/session, cookies, CSRF
  oidc/                   # OAuth 2.0/OIDC flows
  crypto/                 # JWKS, key rotation, JWT signing
  maintenance/            # Background purge of expired rows + key rotation
  store/                  # Persistence interfaces
    file/                 #   JSON file backend
    sqlite/               #   SQLite backend (default)
    migrations/           #   Embedded goose migrations per dialect
    storetest/            #   Conformance suite shared by all backends
  domain/                 # Core types (User, Client, Token, etc.)
data/                     # idp.db (SQLite) or JSON files, auto-created
```

All production code goes under `internal/` to prevent accidental coupling.

### Key Technical Decisions
- **Signing keys**: RSA 2048 / RS256 (implemented). Ed25519/EdDSA is a possible future addition; the `signing_keys.algorithm` column already carries the alg
- **Tokens**: JWT for both ID and access tokens with short TTL + refresh token rotation
- **Database**: SQLite (default) or JSON files today; Postgres planned. Tables: users, clients, sessions, auth_codes, tokens, signing_keys
- **Migrations**: goose, embedded via `embed.FS` and applied at startup. Keep SQL portable; dialect-specific DDL lives in its own directory
- **Dependency versions**: `go.mod` targets Go 1.24 (matches the Dockerfile). Newer goose/modernc releases require Go 1.25+; check a dependency's `go` directive before bumping
- **Config**: Environment variables with `IDP_` prefix (e.g., `IDP_ISSUER_URL`, `IDP_STORE_DRIVER`, `IDP_COOKIE_SECRET`)

### OIDC Flow
1. App redirects to `/authorize` with PKCE challenge
2. IdP checks session, redirects to `/login` if needed
3. After login, IdP creates auth_code and redirects back
4. App exchanges code at `/token` with code_verifier
5. IdP returns id_token (JWT), access_token (JWT), optional refresh_token

### Public Endpoints
- OIDC: `/.well-known/openid-configuration`, `/authorize`, `/token`, `/userinfo`, `/.well-known/jwks.json`
- Auth UI: `/login`, `/logout`
- Ops: `/healthz`, `/readyz`, `/metrics`

## Security Requirements

- Argon2id password hashing
- HttpOnly/Secure/SameSite cookies with session ID rotation on login
- CSRF protection on login forms
- Exact redirect URI matching (no wildcards)
- Token signing key rotation with grace period for old keys (`internal/maintenance`, driven by `IDP_SIGNING_KEY_ROTATION_DAYS` / `IDP_SIGNING_KEY_GRACE_PERIOD`)
- Rate limiting on login attempts
