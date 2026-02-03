# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Status

**simple-idp** is a standalone Identity Provider (IdP) currently in design phase with no implementation yet. See DESIGN.md for the complete architectural specification.

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

1. **Phase 1 - File Storage**: Local file storage (JSON files) for all persistence
   - Enables rapid development and testing without database setup
   - Repository interfaces allow easy swap to database later

2. **Phase 2 - PostgreSQL**: Full database implementation
   - Implement postgres repository implementations
   - Add migrations
   - Production-ready persistence

## Expected Build Commands

Once implemented (Go project):
```bash
go build ./cmd/idp      # Build the IdP server
go test ./...           # Run all tests
go vet ./...            # Lint
go fmt ./...            # Format code
```

## Architecture Overview

### Core Design Principles
- **Stateless application servers** - all persistent state externalized (file or Postgres)
- **OIDC-first** - Authorization Code + PKCE as primary flow
- **Security by default** - Argon2id passwords, secure cookies, strict redirect URI validation, PKCE required for public clients
- **Independent of simple-idm** - no runtime or build-time coupling (patterns are shared, code is not)

### Planned Directory Structure
```
cmd/idp/main.go           # Entry point
internal/
  config/                 # Configuration loading/validation
  http/                   # Router + middleware
  auth/                   # Login/session, cookies, CSRF
  oidc/                   # OAuth 2.0/OIDC flows
  crypto/                 # JWKS, key rotation, JWT signing
  store/                  # Persistence interfaces + SQL implementation
  domain/                 # Core types (User, Client, Token, etc.)
  audit/                  # Event logging (optional)
migrations/               # Database migrations
```

All production code goes under `internal/` to prevent accidental coupling.

### Key Technical Decisions
- **Signing keys**: Ed25519 recommended (or RSA)
- **Tokens**: JWT for both ID and access tokens with short TTL + refresh token rotation
- **Database**: Postgres with tables for users, credentials, sessions, oauth_clients, auth_codes, tokens, signing_keys
- **Config**: Environment variables with `IDP_` prefix (e.g., `IDP_ISSUER_URL`, `IDP_DB_DSN`, `IDP_COOKIE_SECRET`)

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
- Token signing key rotation with grace period for old keys
- Rate limiting on login attempts
