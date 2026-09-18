# Changelog

All notable changes to simple-idp. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.0.2] - 2026-09-18

This release turns the file-backed prototype into a complete development IdP: SQLite
storage, consent, self-service account flows, groups, an admin console, a built-in test
client, and an audit trail.

### Behaviour changes to be aware of

- **Storage defaults to SQLite** (`IDP_STORE_DRIVER=sqlite`, database at `<IDP_DATA_DIR>/idp.db`).
  The JSON file backend remains available with `IDP_STORE_DRIVER=file`. There is no migration
  between backends; bootstrap users/clients are re-created from the environment.
- **A consent screen is shown** the first time a user authorizes a third-party client. Mark
  first-party clients `skip_consent` (admin UI / `idpctl`) or set `IDP_REQUIRE_CONSENT=false`.
- **Client secrets are stored hashed.** Plaintext secrets in existing data are upgraded on
  first use; new secrets are shown exactly once.
- **`email_verified` is now a real flag** (bootstrap users are verified) instead of always `true`.
- Requires clients to list `groups` in their allowed scopes to receive the claim (bootstrap and
  admin-created clients do).

### Added

- SQLite backend with embedded goose migrations, foreign keys and case-insensitive email uniqueness
- Store conformance suite run against every backend; HTTP integration tests run on both drivers
- Consent screen with remembered grants; OIDC `prompt=none|login|consent|select_account`,
  `max_age`, `auth_time`
- Password reset and email verification with log (default) or SMTP delivery
- Groups: `groups` scope/claim in ID token, access token and userinfo; `IDP_GROUPS_CLAIM`;
  `IDP_BOOTSTRAP_GROUPS`
- Admin UI at `/admin`: users (invite, password, sessions, tokens, consents, groups), groups,
  clients (secret shown once, regenerate), signing keys (rotate), audit log
- `IDP_ADMIN_EMAILS` to grant admin access on startup
- OIDC playground at `/playground`: built-in relying party showing decoded tokens, userinfo,
  refresh, introspection, revocation and RP-initiated logout (`IDP_PLAYGROUND_ENABLED`)
- `idpctl` CLI for users, groups, clients and keys against the same store
- Background maintenance: expired-row purge, signing key rotation with grace period,
  audit retention (`IDP_MAINTENANCE_INTERVAL`, `IDP_SIGNING_KEY_ROTATION_DAYS`,
  `IDP_SIGNING_KEY_GRACE_PERIOD`, `IDP_AUDIT_RETENTION`)
- Audit log of sign-ins, consent, password changes, key rotations and admin actions
- Rate limits on every secret-accepting endpoint; per-address password reset throttle
- Shared stylesheet with dark mode; `docker-compose.yml`, `deploy/k8s/`, GitHub Actions CI
  (verification only — images are built locally with `make docker-build`)

### Fixed

- The ID token `nonce` was emitted nested under an `extra` object instead of as a top-level
  claim; strict OIDC clients would have rejected ID tokens
- Tokens issued after a key rotation were still signed with the retired key
- `go vet` failure in the integration tests

## [0.0.1]

- Initial file-backed IdP: Authorization Code + PKCE, RS256 JWTs, refresh token rotation,
  revocation, introspection, RP-initiated logout, rate limiting, lockout, CORS, metrics.

[Unreleased]: https://github.com/tendant/simple-idp/compare/v0.0.2...HEAD
[0.0.2]: https://github.com/tendant/simple-idp/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/tendant/simple-idp/releases/tag/v0.0.1
