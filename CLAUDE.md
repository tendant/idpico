# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Naming

Write **IDPico** in prose and headings, `idpico` for anything machine-facing (module path, binaries, env vars, cookies, `idpico.db`, k8s names, metrics prefix `idpico_`). Never `IdPico`. The project was called simple-idp before v0.0.2; there is no compatibility shim for the old `IDP_*` variables.

## Project Status

**IDPico** (module `github.com/tendant/idpico`, binaries `idpico` / `idpicoctl`, env prefix `IDPICO_`) is a tiny, self-contained Identity Provider for **local testing and development**. Phase 1 (File Storage) and the SQLite backend are complete. The IdP is fully functional with:

- Complete OIDC Authorization Code + PKCE flow
- JWT ID tokens and access tokens (RS256)
- Refresh token rotation
- SQLite storage by default (`IDPICO_STORE_DRIVER=sqlite`), JSON file storage as an alternative (`file`)
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

**Note**: IDPico remains independent of simple-idm at runtime and build-time, but follows the same architectural patterns.

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
make build              # Build ./idpico and ./idpicoctl
make run                # Build and run the server
make run-dev            # Run with debug logging
make seed               # Dev users/groups/clients in ./data
make test               # Run all tests
make ci                 # Exactly what GitHub Actions runs: gofmt, vet, -race tests, test-flow, static build
make test-flow          # scripts/test-client.sh: curl-only external-client OIDC flow against a throwaway server
make docker-build       # Container image wang/idpico:<git tag> and :latest (IMAGE=/TAG= to override)
make docker-push        # buildx linux/amd64 + linux/arm64 manifest for both tags, pushed to Docker Hub
make compose-up         # docker compose up --build
```

CI (`.github/workflows/ci.yml`) runs `make ci`'s steps plus a throwaway `docker build` on every push/PR. **Nothing is released or published from GitHub**: images are built with `make docker-build` and pushed to a registry by hand. Releases: update CHANGELOG.md, tag `vX.Y.Z`.

## Architecture Overview

### Core Design Principles
- **Stateless application servers** - all persistent state externalized (file or Postgres)
- **OIDC-first** - Authorization Code + PKCE as primary flow
- **Security by default** - Argon2id passwords, secure cookies, strict redirect URI validation, PKCE required for public clients
- **Independent of simple-idm** - no runtime or build-time coupling (patterns are shared, code is not)

### Directory Structure
```
cmd/idpico/main.go           # Server entry point
cmd/idpicoctl/               # CLI for users, groups, clients, keys (same store)
cmd/seed/                 # Dev seed data
internal/
  config/                 # Configuration loading/validation
  http/                   # Router, middleware, handlers, embedded templates (templates/{,admin,wide}/) and static/style.css
  auth/                   # Login/session, cookies, CSRF
  oidc/                   # OAuth 2.0/OIDC flows
  crypto/                 # JWKS, key rotation, JWT signing
  maintenance/            # Background purge of expired rows + key rotation
  mail/                   # Outbound email (log mailer for dev, SMTP)
  store/                  # Persistence interfaces
    file/                 #   JSON file backend
    sqlite/               #   SQLite backend (default)
    migrations/           #   Embedded goose migrations per dialect
    storetest/            #   Conformance suite shared by all backends
  domain/                 # Core types (User, Client, Token, etc.)
data/                     # idpico.db (SQLite) or JSON files, auto-created
```

All production code goes under `internal/` to prevent accidental coupling.

### Key Technical Decisions
- **Signing keys**: RSA 2048 / RS256 (implemented). Ed25519/EdDSA is a possible future addition; the `signing_keys.algorithm` column already carries the alg
- **Tokens**: JWT for both ID and access tokens with short TTL + refresh token rotation
- **Database**: SQLite (default) or JSON files today; Postgres planned. Tables: users, clients, sessions, auth_codes, tokens, signing_keys
- **Migrations**: goose, embedded via `embed.FS` and applied at startup. Keep SQL portable; dialect-specific DDL lives in its own directory. **Shipped migrations are frozen** (`00001_init.sql` as of v0.0.2): every schema change is a new `0000N_<name>.sql`, never an edit of an existing file
- **Dependency versions**: `go.mod` targets Go 1.24 (matches the Dockerfile). Newer goose/modernc releases require Go 1.25+; check a dependency's `go` directive before bumping
- **Config**: Environment variables with `IDPICO_` prefix (e.g., `IDPICO_ISSUER_URL`, `IDPICO_STORE_DRIVER`, `IDPICO_COOKIE_SECRET`)

### OIDC Flow
1. App redirects to `/authorize` with PKCE challenge
2. IdP checks session, redirects to `/login` if needed
3. After login, IdP creates auth_code and redirects back
4. App exchanges code at `/token` with code_verifier
5. IdP returns id_token (JWT), access_token (JWT), optional refresh_token

### Public Endpoints
- OIDC: `/.well-known/openid-configuration`, `/authorize`, `/token`, `/userinfo`, `/.well-known/jwks.json`
- Auth UI: `/login`, `/logout`, `/consent`, `/forgot-password`, `/reset-password`, `/verify-email`
- Admin UI: `/admin` (users, groups, clients, signing keys; requires `User.Admin`, granted via `IDPICO_ADMIN_EMAILS`)
- Playground: `/playground` is a built-in relying party (client `playground`) that drives the IdP's own endpoints in-process via the router; disable with `IDPICO_PLAYGROUND_ENABLED=false`
- Groups: `groups` scope releases memberships as the `groups` claim (`IDPICO_GROUPS_CLAIM` renames it). No separate role model — a role is a group.
- Ops: `/healthz`, `/readyz`, `/metrics`

## UI Conventions

- Server-rendered `html/template`, no JavaScript, no build step. Three layouts: `templates/layout.html` (centered card: login, consent, reset), `templates/admin/layout.html` (admin console), `templates/wide/layout.html` (playground)
- All styling is in `internal/http/static/style.css`, served at `/static/style.css`. Colors are CSS custom properties on `:root` with a `prefers-color-scheme: dark` override — add tokens there, never hard-code colors in templates
- Forms are plain POST + redirect with a `csrf_token` hidden field and a `?flash=` message

## Security Requirements

- Argon2id password hashing
- HttpOnly/Secure/SameSite cookies with session ID rotation on login
- CSRF protection on login forms
- Exact redirect URI matching (no wildcards)
- Token signing key rotation with grace period for old keys (`internal/maintenance`, driven by `IDPICO_SIGNING_KEY_ROTATION_DAYS` / `IDPICO_SIGNING_KEY_GRACE_PERIOD`)
- Rate limiting on login attempts
