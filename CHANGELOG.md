# Changelog

All notable changes to idpico. The format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- Black-box conformance suite in `conformance/` (`make validate`, `make validate-security`): builds and starts an isolated IDPico, then tests it over HTTP only — discovery, JWKS, Authorization Code + PKCE for confidential and public clients, independent ID-token validation with go-jose, UserInfo, and the security negatives (redirect URI matching, PKCE downgrades, code replay and client binding, forged/altered/expired JWTs, error-page vs redirect rules). `CONFORMANCE_ISSUER` points it at a running instance; diagnostics are redacted. CI runs it on every push.
- `examples/oidc-client`: an independent relying party on coreos/go-oidc + x/oauth2 with no IDPico-specific code; `make validate-interop` drives a login through it. `CONFORMANCE.md` records the declared v0.1 profile, validation levels, known limitations and the OpenID Foundation test plan.
- EdDSA (Ed25519) signing: `IDPICO_SIGNING_ALGORITHM=EdDSA` (default stays `RS256`). Changing it rotates the key at startup with the usual grace period, so RS256 tokens already issued keep verifying; the JWKS publishes `OKP`/`Ed25519` keys alongside RSA ones and discovery lists both algorithms. `idpicoctl key rotate -alg EdDSA`. Token verification binds the token's `alg` to the key's, so a token cannot name a key of the other kind.
- Per-client token lifetimes: each client can override `IDPICO_ACCESS_TOKEN_TTL` (which also bounds the ID token) and `IDPICO_REFRESH_TOKEN_TTL`. Set them on the client's admin page (`15m`, `12h`, `30d`; blank = server default) or with `idpicoctl client add -access-ttl 5m -refresh-ttl 720h`. Migration `00002` adds the two columns; existing clients keep the defaults.

- `/account`: every signed-in user can see and sign out their own sessions (the current one is marked), revoke the refresh tokens apps hold for them and the consents they granted, sign out everywhere else in one click, and change their password (current password required; signs out everywhere). Linked from the admin header and the playground nav; `/` sends signed-in non-admins there.

### Changed

- `/authorize` errors follow RFC 6749 §4.1.2.1: once the client and `redirect_uri` are valid, an unsupported `response_type`, a `scope` without `openid` or not allowed for the client, a bad `max_age`/`prompt`, and a public client without PKCE (or with `plain`) are sent back to the redirect URI as `unsupported_response_type` / `invalid_scope` / `invalid_request` with the `state`; before that point (unknown client, unregistered `redirect_uri`) the user still sees an error page and nothing is redirected. `openid` must now be a whole scope token (`openidx` no longer passes).
- Session IP addresses are stored without the port.
- `/token` errors follow RFC 6749 §5.2: a used, expired, revoked or mismatched code or refresh token is `invalid_grant`; a widened refresh scope is `invalid_scope`; an unknown client id or bad secret is `invalid_client` with HTTP 401. Malformed requests stay `invalid_request`. Client libraries use these codes to decide between retrying and re-authenticating.
- The playground is off by default when the issuer is `https://` (a shared host) and on for `http://`; `IDPICO_PLAYGROUND_ENABLED` still overrides either way.

## [0.0.3] - 2026-09-19

Hardening and operability: refresh-token reuse detection, trusted-proxy handling, secure
cookie and HSTS defaults that work behind an ingress, multi-arch images, cache-safe static
assets, and a curl-only client test that CI runs.

### Security

- Refresh tokens: a replayed (already rotated) refresh token now revokes every token the user holds for that client, since a replay means the token leaked; the grant can only be narrowed on refresh (`scope` wider than the original is `invalid_request`), and a disabled user can no longer refresh.
- Forwarding headers (`X-Forwarded-For`, `X-Real-IP`) are honoured only from trusted proxies (`IDPICO_TRUSTED_PROXIES`, default `private`), so a direct client cannot spoof its address to bypass the login rate limit or forge audit-log IPs. Previously any peer's headers were trusted.
- `IDPICO_COOKIE_SECURE` defaults to `true` when the issuer is `https://`; a startup warning is logged if it is explicitly turned off there.
- `return_url` accepts only absolute paths on this origin; `/\evil.com` (which browsers treat as `//evil.com`) and CR/LF are rejected.
- Headers: CSP adds `base-uri 'none'; object-src 'none'`; `X-XSS-Protection` is `0` per current guidance.
- HSTS (`IDPICO_HSTS_MAX_AGE`) is now actually sent behind a TLS-terminating proxy (`X-Forwarded-Proto: https`); before, it was only emitted when the Go listener itself did TLS, i.e. never in a typical ingress deployment. The Kubernetes manifest enables it and sets `IDPICO_TRUSTED_PROXIES`.

### Fixed

- Static assets are linked as `/static/<file>?v=<content hash>` and served `immutable`, so a browser that cached the previous build's stylesheet never applies it to the new build's pages (the stale-CSS symptom: an oversized header icon and a collapsed nav right after a deploy). Unversioned URLs such as `/favicon.ico` keep their one-hour cache.
- `make docker-push` builds a linux/amd64 + linux/arm64 manifest list with `docker buildx` (the Dockerfile cross-compiles from the build host). Images pushed before this were built with plain `docker build` and only ran on the architecture of the machine that built them.

### Added

- Icon: the IDPico shield as favicon (`/favicon.ico`, `/static/icon.png`), in the admin and playground header, and above the sign-in, consent and password pages. Shipped as a 128px quantized PNG (6 KB) and a favicon with PNG-compressed 48/32/16 frames (5 KB); `scripts/icons.sh <source.png>` regenerates both.
- Admin → Clients: each client page now has an **Endpoints** card listing the issuer, discovery, authorization, token, userinfo, JWKS, end-session and revocation URLs plus the client ID, auth method and scopes — everything to paste into a relying party, whether it does OIDC discovery or takes each URL by hand.
- `scripts/test-client.sh`: curl-only external relying party that runs the full Authorization Code + PKCE flow (login, consent, token, userinfo, refresh rotation, replay/bad-secret rejection) against any running IDPico. `make test-flow` now starts a throwaway server and runs it for both a confidential (`test-app`) and a public PKCE-only (`test-spa`) client; `make ci` and GitHub Actions run it.

## [0.0.2] - 2026-09-18

This release turns the file-backed prototype into a complete development IdP: SQLite
storage, consent, self-service account flows, groups, an admin console, a built-in test
client, and an audit trail.

### Renamed: simple-idp is now IDPico

- Go module `github.com/tendant/idpico`; binaries `idpico` and `idpicoctl` (was `idp`, `idpctl`)
- **Environment variables are `IDPICO_*`** — the old `IDP_*` names are no longer read
- Cookies `idpico_session` / `idpico_csrf`, database file `idpico.db`, metrics prefix `idpico_`,
  Kubernetes namespace and resource names `idpico`

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

[Unreleased]: https://github.com/tendant/idpico/compare/v0.0.3...HEAD
[0.0.3]: https://github.com/tendant/idpico/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/tendant/idpico/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/tendant/idpico/releases/tag/v0.0.1
