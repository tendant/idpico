# simple-idp — Design Document

**Status:** Draft (v0.1)  
**Owner:** Wei Labs / tendant  
**Last updated:** 2026-02-03

## 1. Purpose

`simple-idp` is a standalone Identity Provider (IdP) that offers:

- First-party user authentication (local users)
- OAuth 2.0 + OpenID Connect (OIDC) provider endpoints
- Token issuance + verification primitives (JWKS, key rotation)
- Minimal, dependable operational footprint (Go + Postgres, optional Redis later)

`simple-idp` is explicitly **not dependent** on `simple-idm` at runtime or build time.

## 2. Goals

### Product goals
- Provide a self-hostable, production-oriented OIDC issuer for internal tools and early SaaS.
- Support **Authorization Code + PKCE** as the primary flow.
- Provide stable subject identifiers: `sub` is immutable for a given user.
- Keep the architecture modular and easy to extend (connectors, MFA, SCIM later).

### Engineering goals
- Small, understandable codebase.
- Stateless app servers; persistent state in Postgres.
- Clear migration path from existing `simple-idm` auth logic (if desired).
- Strong security defaults (Argon2, secure cookies, strict redirect URI validation).

## 3. Non-goals (v0 / v1)

- Social login connectors (Google/GitHub/etc.) — later.
- Enterprise features (SAML, advanced MFA policies, device posture) — later.
- Full admin console with complex org/tenant modeling — keep IdP tenant-agnostic in v1.
- Fine-grained authorization model (RBAC/ABAC) — belongs to apps (e.g., `simple-idm`).

## 4. High-level architecture

### Components
1. **Auth UI & Session Layer**
   - `/login`, `/logout`
   - Secure session cookies for browser login (used by `/authorize`)

2. **OIDC Provider**
   - Discovery: `/.well-known/openid-configuration`
   - Authorization: `/authorize` (auth code + PKCE)
   - Token: `/token`
   - UserInfo: `/userinfo` (optional but recommended)
   - JWKS: `/.well-known/jwks.json` or `/jwks.json`

3. **Core Stores (Postgres)**
   - Users and credentials (Argon2)
   - OAuth clients
   - Authorization codes
   - Tokens (refresh + access) and revocation
   - Consents (optional; can start “trusted clients” only)
   - Signing keys + rotation metadata
   - Audit events (lightweight; v1 optional)

4. **Crypto & Key Management**
   - RSA or Ed25519 signing keys (recommend **Ed25519** for simplicity/perf)
   - Key rotation strategy and JWKS publication

### Request flows

#### Login + OIDC Authorization Code + PKCE
1. App redirects user to:
   - `GET /authorize?client_id=...&redirect_uri=...&response_type=code&scope=openid...&code_challenge=...`
2. `simple-idp` checks session:
   - If not logged in → redirect to `/login`
3. After login, IdP creates `auth_code` record and redirects back:
   - `302 Location: {redirect_uri}?code=...&state=...`
4. App exchanges code:
   - `POST /token` with `code_verifier`
5. IdP returns tokens:
   - `id_token` (JWT), `access_token` (JWT or opaque), optional `refresh_token`
6. App verifies `id_token` via JWKS.

## 5. Repo layout

Recommended layout:

```
simple-idp/
  cmd/idp/
    main.go
  internal/
    config/          # config loading, validation
    http/            # router + middleware
    auth/            # login/session, cookie, csrf
    oidc/            # authorize/token/userinfo flows
    crypto/          # jwks, key rotation, jwt signing
    store/           # persistence interfaces + sql implementation
    domain/          # types: User, Client, Consent, Token, etc.
    audit/           # optional
  migrations/
  docs/
  Dockerfile
  docker-compose.yml
  go.mod
```

**Rule:** all production code under `internal/` to avoid accidental coupling.

## 6. Public endpoints

### OIDC / OAuth
- `GET /.well-known/openid-configuration`
- `GET /authorize`
- `POST /token`
- `GET /userinfo` *(optional in v1, recommended)*
- `GET /.well-known/jwks.json` *(or `/jwks.json`)*
- `POST /revoke` *(optional v1)*
- `POST /introspect` *(optional v1; only if using opaque tokens)*
- `GET /logout` *(basic RP-initiated logout optional)*

### Auth UI
- `GET /login`
- `POST /login`
- `POST /logout` *(preferred over GET in production)*

### Ops
- `GET /healthz`
- `GET /readyz`
- `GET /metrics` *(optional; Prometheus)*

## 7. Token strategy

### ID Token
- Always JWT signed by IdP key.
- Contains:
  - `iss`, `sub`, `aud`, `exp`, `iat`
  - `nonce` (if provided)
  - `email`, `email_verified` (if scope allows)
  - `name`, `preferred_username` (if profile scope allows)

### Access token
Choose one for v1:

**Option A (simplest): JWT access token**
- Pros: no introspection required; stateless validation for resource servers.
- Cons: revocation is hard; shorter expiry recommended.

**Option B: Opaque access token + introspection**
- Pros: revocable; better control.
- Cons: requires introspection endpoint and server-side checks.

**Recommendation:** v1 use **JWT access tokens** with short TTL (e.g., 10–15 min) + refresh tokens.

### Refresh token
- Stored server-side (hashed) with rotation (recommended).
- Offline session model:
  - user_id + client_id + scopes
- Support revocation.

## 8. Data model (Postgres)

Below is a suggested baseline schema (snake_case). Adjust to your conventions.

### users
- `id` (uuid, pk)
- `email` (text, unique)
- `email_verified` (bool, default false)
- `name` (text, nullable)
- `preferred_username` (text, nullable, unique optional)
- `created_at`, `updated_at`
- `disabled_at` (timestamp, nullable)

### user_credentials
- `id` (uuid, pk)
- `user_id` (uuid, fk users)
- `type` (text) — `password` in v1
- `password_hash` (text) — Argon2id hash string
- `created_at`, `updated_at`
- `disabled_at` (timestamp, nullable)

### sessions
- `id` (uuid, pk)
- `user_id` (uuid, fk)
- `session_token_hash` (text, unique) — hash of cookie token
- `created_at`, `expires_at`
- `last_seen_at`
- `revoked_at` (timestamp, nullable)

### oauth_clients
- `id` (text, pk) — client_id
- `name` (text)
- `type` (text) — `public` | `confidential`
- `client_secret_hash` (text, nullable)
- `redirect_uris` (text[]) — validated
- `allowed_scopes` (text[])
- `grant_types` (text[]) — include `authorization_code`, `refresh_token`
- `response_types` (text[]) — include `code`
- `created_at`, `updated_at`
- `disabled_at` (timestamp, nullable)

### oauth_consents (optional v1)
- `id` (uuid, pk)
- `user_id` (uuid)
- `client_id` (text)
- `scopes` (text[])
- `created_at`, `updated_at`
- unique(user_id, client_id)

### oauth_auth_codes
- `id` (uuid, pk)
- `code_hash` (text, unique)
- `user_id` (uuid)
- `client_id` (text)
- `redirect_uri` (text)
- `scopes` (text[])
- `nonce` (text, nullable)
- `code_challenge` (text)
- `code_challenge_method` (text) — `S256`
- `created_at`, `expires_at`
- `consumed_at` (timestamp, nullable)

### oauth_tokens
- `id` (uuid, pk)
- `user_id` (uuid)
- `client_id` (text)
- `kind` (text) — `refresh` | `access`
- `token_hash` (text, unique)
- `scopes` (text[])
- `created_at`, `expires_at`
- `revoked_at` (timestamp, nullable)
- `rotated_from_token_id` (uuid, nullable)

### signing_keys
- `id` (uuid, pk)
- `kid` (text, unique)
- `alg` (text) — `EdDSA` or `RS256`
- `public_jwk` (jsonb)
- `private_key_enc` (bytea) — encrypted at rest (envelope) or KMS ref
- `created_at`
- `not_before` (timestamp, nullable)
- `expires_at` (timestamp, nullable)
- `rotated_at` (timestamp, nullable)

### audit_events (optional v1)
- `id` (uuid, pk)
- `type` (text) — `login_success`, `login_failure`, `token_issued`, etc.
- `actor_user_id` (uuid, nullable)
- `client_id` (text, nullable)
- `ip` (inet, nullable)
- `user_agent` (text, nullable)
- `created_at`
- `data` (jsonb, nullable)

## 9. Configuration

Config sources:
- environment variables (default)
- optional YAML file for local dev

Key config:
- `IDP_ISSUER_URL` (e.g., https://auth.example.com)
- `IDP_HTTP_ADDR` (e.g., :8080)
- `IDP_PUBLIC_BASE_URL` (if behind proxy)
- `IDP_DB_DSN`
- `IDP_COOKIE_SECRET` (32+ bytes)
- `IDP_SESSION_TTL`
- `IDP_ID_TOKEN_TTL`
- `IDP_ACCESS_TOKEN_TTL`
- `IDP_REFRESH_TOKEN_TTL`
- `IDP_ALLOWED_ORIGINS` (CORS, if needed)
- `IDP_TRUSTED_PROXIES`

Client bootstrap options:
- v1: static clients in config
- v1.1: DB-managed clients with admin endpoint

## 10. Security requirements

- Password hashing: **Argon2id** with sensible parameters.
- Session cookies:
  - `HttpOnly`, `Secure`, `SameSite=Lax` (or `None` if cross-site required)
  - rotate session IDs on login
- CSRF protection for login form.
- Redirect URI validation:
  - exact match against registered `redirect_uris`
  - reject wildcards by default
- PKCE required for public clients.
- Token signing key rotation:
  - keep old keys in JWKS until all tokens expire
- Rate limit login attempts (per IP + per account) — can be in-memory first.
- Audit logs for auth events.

## 11. Deployment

### Docker/Kubernetes
- Stateless `simple-idp` pods
- Postgres (CloudNativePG or managed)
- Ingress terminates TLS; forward `X-Forwarded-*` headers.

### Suggested K8s objects
- Deployment + HPA
- Service
- Ingress
- Secret (cookie secret, DB creds)
- ConfigMap (issuer url, token TTL)
- PodDisruptionBudget (optional)

## 12. Integrating with applications (e.g., simple-idm)

Apps should treat `simple-idp` as the identity source.

**Identity key:** `(issuer, sub)`

Apps typically:
1. Redirect to `/authorize`
2. Exchange code at `/token`
3. Verify `id_token` using JWKS
4. Map `(issuer, sub)` to an internal account row
5. Manage authorization (roles/tenants) locally

## 13. Migration plan from simple-idm (optional)

Two strategies:

### Strategy A: Fresh start
- Stand up `simple-idp` with new DB
- Apps re-login; new `sub` values are generated
- Simplest operationally

### Strategy B: Preserve user identities
- Export `users` and `password_hashes` from `simple-idm`
- Import into `simple-idp` `users` + `user_credentials`
- Ensure `sub` = existing stable user ID (recommended)
- Keep email verification flags

## 14. Testing & validation

### Unit tests
- Redirect URI validation
- PKCE verification
- Token claim correctness
- Session cookie lifecycle

### Integration tests
- Full auth code + PKCE flow using a test RP
- JWKS fetch + token verification
- Refresh token rotation and revocation

### Interop tests (optional)
- Use a simple OIDC client library to validate standard compliance.

## 15. Roadmap

### v0.1 (bootstrap)
- Local users (email + password)
- Auth code + PKCE
- JWT id_token + access token
- JWKS publication
- Static client config
- Minimal login UI

### v0.2
- Refresh tokens + rotation
- Client management stored in DB
- `/userinfo`
- Basic audit events

### v0.3
- Password reset + email verification
- Consent UI (optional)
- Rate limiting improvements

### v1.0
- Hardening, docs, k8s manifests, upgrade guide

---

## Appendix A: Minimal OIDC discovery example

Issuer: `https://auth.example.com`

- `/.well-known/openid-configuration`
  - `authorization_endpoint`: `https://auth.example.com/authorize`
  - `token_endpoint`: `https://auth.example.com/token`
  - `jwks_uri`: `https://auth.example.com/.well-known/jwks.json`
  - `userinfo_endpoint`: `https://auth.example.com/userinfo`

