# Configuration reference

Every setting is an environment variable with the `IDPICO_` prefix. All have defaults; a first run
needs none of them (see the README's Quick Start), and a real deployment needs the handful under
**Settings that matter**. IDPico also reads a `.env` file from the directory it is started in —
the same `NAME=value` lines — so a file is the simplest way to configure it without a shell or a
manifest. Real environment variables take precedence over `.env`.

## Settings that matter

| Variable | Default | Set it when |
|---|---|---|
| `IDPICO_ISSUER_URL` | `http://localhost:8080` | Anyone but you talks to it. Must be the exact public URL — it is the `iss` in every token and the base of every endpoint in discovery. `https://` makes cookies `Secure` and turns the playground off. |
| `IDPICO_BOOTSTRAP_USERS` | — | You want the first user without the CLI: `email:password:Name`, comma-separated for several. Existing users are left alone. |
| `IDPICO_ADMIN_EMAILS` | — | Who may open `/admin` (comma-separated; the users must exist). |
| `IDPICO_BOOTSTRAP_CLIENTS` | — | Your application: `id|secret|redirect_uri` (`id||redirect_uri` for a public/PKCE client; several redirect URIs separated by spaces, several clients by commas). Or `IDPICO_CLIENT_ID` / `_SECRET` / `_REDIRECT_URI` for exactly one. |
| `IDPICO_COOKIE_SECRET` | random per start | Production. It signs CSRF tokens; with a random one, forms open across a restart fail. Sessions persist regardless. |
| `IDPICO_DATA_DIR` | `./data` | You want the database somewhere specific. Everything lives here (`idpico.db`); a backup is a copy of it after a clean stop. |
| `IDPICO_TRUSTED_PROXIES` | `private` | Behind an ingress on a public address: the proxy's IPs/CIDRs, or `none` when reached directly. Forwarding headers from anyone else are ignored. |
| `IDPICO_HSTS_MAX_AGE` | `0` | The host is https-only. |

## Everything

```bash
# Server
IDPICO_HOST=0.0.0.0
IDPICO_PORT=8080
IDPICO_ISSUER_URL=http://localhost:8080

# Storage
IDPICO_STORE_DRIVER=sqlite      # sqlite (default) or file
IDPICO_DATA_DIR=./data          # Holds idpico.db (sqlite) or the JSON files (file)
IDPICO_STORE_DSN=               # Optional: explicit SQLite path, overrides <IDPICO_DATA_DIR>/idpico.db

# Session
IDPICO_SESSION_DURATION=24h
IDPICO_COOKIE_SECRET=           # Auto-generated if empty
IDPICO_COOKIE_SECURE=           # Unset: true when IDPICO_ISSUER_URL is https://, else false

# Tokens (server defaults; each client can override both on its admin page)
IDPICO_SIGNING_ALGORITHM=RS256  # or EdDSA (Ed25519); changing it rotates the key at the next start
IDPICO_ACCESS_TOKEN_TTL=15m
IDPICO_REFRESH_TOKEN_TTL=168h   # 7 days
IDPICO_AUTH_CODE_TTL=10m

# Groups
IDPICO_GROUPS_CLAIM=groups            # claim name for memberships
IDPICO_BOOTSTRAP_GROUPS=              # "admins:alice@x.com bob@x.com,devs:carol@x.com"

# Admin UI & playground
IDPICO_ADMIN_EMAILS=admin@example.com # who may open /admin (comma-separated)
IDPICO_PLAYGROUND_ENABLED=            # built-in test client at /playground; unset: on for http://, off for https:// issuers

# Consent
IDPICO_REQUIRE_CONSENT=true           # consent screen for third-party clients

# Email (password reset / verification links)
IDPICO_MAIL_DRIVER=log                # log = print to server log, smtp = send
IDPICO_SMTP_HOST=                     # required for smtp, with IDPICO_SMTP_FROM
IDPICO_PASSWORD_RESET_TTL=1h
IDPICO_EMAIL_VERIFY_TTL=24h

# Key rotation & maintenance
IDPICO_SIGNING_KEY_ROTATION_DAYS=30   # 0 = disabled
IDPICO_SIGNING_KEY_GRACE_PERIOD=24h   # rotated keys remain valid for verification
IDPICO_MAINTENANCE_INTERVAL=10m       # expired-row purge + key rotation (0 = disabled)

# Logging
IDPICO_LOG_LEVEL=info           # debug, info, warn, error
IDPICO_LOG_FORMAT=json          # json or text

# Rate limiting
IDPICO_LOGIN_RATE_LIMIT=5       # requests per minute per IP (0 = disabled)
IDPICO_TRUSTED_PROXIES=private  # peers whose X-Forwarded-For/X-Real-IP name the client: private | none | IPs/CIDRs

# Account lockout
IDPICO_LOCKOUT_MAX_ATTEMPTS=5   # failed attempts before lockout (0 = disabled)
IDPICO_LOCKOUT_DURATION=15m     # how long account stays locked

# CORS (empty = disabled)
IDPICO_CORS_ALLOWED_ORIGINS=https://app.example.com,https://admin.example.com
IDPICO_CORS_ALLOW_CREDENTIALS=true

# Security headers
IDPICO_SECURITY_HEADERS_ENABLED=true
IDPICO_CONTENT_SECURITY_POLICY=default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'
IDPICO_HSTS_MAX_AGE=31536000    # 1 year, 0 = disabled

# Bootstrap a single client
IDPICO_CLIENT_ID=my-app
IDPICO_CLIENT_SECRET=my-secret
IDPICO_CLIENT_REDIRECT_URI=http://localhost:3000/callback

# Bootstrap users (email:password:name, comma-separated)
IDPICO_BOOTSTRAP_USERS=admin@example.com:password123:Admin User
```

## Bootstrap formats

- **Users** — `IDPICO_BOOTSTRAP_USERS="email:password:Display Name,other@x:pw:Name"`. The name is
  optional. Bootstrap users are active with a verified email. A user that already exists is skipped,
  so the variable can stay set across restarts without resetting passwords.
- **Groups** — `IDPICO_BOOTSTRAP_GROUPS="admins:alice@x bob@x,devs:carol@x"` (members separated by
  spaces). Released as the `groups` claim when a client requests the `groups` scope.
- **Clients** — `IDPICO_BOOTSTRAP_CLIENTS="my-app|secret|http://localhost:3000/callback http://localhost:3000/alt,spa||http://localhost:5173/callback"`.
  An empty secret makes a public client (PKCE required). Bootstrap clients may request every scope
  (`openid profile email offline_access groups`) and show the consent screen unless marked first-party
  in the admin console. `IDPICO_CLIENT_ID`, `IDPICO_CLIENT_SECRET` and `IDPICO_CLIENT_REDIRECT_URI`
  (space-separated URIs) describe one client the same way.

Everything bootstrap creates can also be created and changed later in the admin console (`/admin`)
or with `idpicoctl`, which works on the same data directory.
