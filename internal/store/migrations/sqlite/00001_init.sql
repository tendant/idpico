-- +goose Up
CREATE TABLE users (
    id            TEXT PRIMARY KEY,
    email         TEXT NOT NULL,
    password_hash TEXT NOT NULL DEFAULT '',
    display_name  TEXT NOT NULL DEFAULT '',
    active         BOOLEAN NOT NULL DEFAULT TRUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    admin          BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMP NOT NULL,
    updated_at     TIMESTAMP NOT NULL
);
-- Emails are unique case-insensitively; lookups use LOWER(email) to hit this index.
CREATE UNIQUE INDEX users_email_idx ON users (LOWER(email));

CREATE TABLE clients (
    id            TEXT PRIMARY KEY,
    secret        TEXT NOT NULL DEFAULT '',   -- empty for public clients
    name          TEXT NOT NULL DEFAULT '',
    redirect_uris TEXT NOT NULL DEFAULT '[]', -- JSON array
    grant_types   TEXT NOT NULL DEFAULT '[]', -- JSON array
    scopes        TEXT NOT NULL DEFAULT '[]', -- JSON array
    public        BOOLEAN NOT NULL DEFAULT FALSE,
    skip_consent  BOOLEAN NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMP NOT NULL,
    updated_at    TIMESTAMP NOT NULL
);

CREATE TABLE sessions (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    user_agent TEXT NOT NULL DEFAULT '',
    ip_address TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_user_id_idx    ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE auth_codes (
    code                  TEXT PRIMARY KEY,
    client_id             TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    user_id               TEXT NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    redirect_uri          TEXT NOT NULL DEFAULT '',
    scope                 TEXT NOT NULL DEFAULT '',
    code_challenge        TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    nonce                 TEXT NOT NULL DEFAULT '',
    auth_time             TIMESTAMP NOT NULL,
    created_at            TIMESTAMP NOT NULL,
    expires_at            TIMESTAMP NOT NULL,
    used                  BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX auth_codes_client_id_idx  ON auth_codes (client_id);
CREATE INDEX auth_codes_user_id_idx    ON auth_codes (user_id);
CREATE INDEX auth_codes_expires_at_idx ON auth_codes (expires_at);

CREATE TABLE tokens (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scope      TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX tokens_user_id_idx    ON tokens (user_id);
CREATE INDEX tokens_client_id_idx  ON tokens (client_id);
CREATE INDEX tokens_expires_at_idx ON tokens (expires_at);

CREATE TABLE consents (
    id         TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    client_id  TEXT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    scopes     TEXT NOT NULL DEFAULT '[]', -- JSON array
    granted_at TIMESTAMP NOT NULL,
    UNIQUE (user_id, client_id)
);

CREATE TABLE verification_tokens (
    token_hash TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used       BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE INDEX verification_tokens_user_id_idx    ON verification_tokens (user_id, purpose);
CREATE INDEX verification_tokens_expires_at_idx ON verification_tokens (expires_at);

CREATE TABLE groups (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMP NOT NULL,
    updated_at  TIMESTAMP NOT NULL
);
CREATE UNIQUE INDEX groups_name_idx ON groups (LOWER(name));

CREATE TABLE user_groups (
    user_id  TEXT NOT NULL REFERENCES users(id)  ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);
CREATE INDEX user_groups_group_id_idx ON user_groups (group_id);

CREATE TABLE audit_events (
    id          TEXT PRIMARY KEY,
    at          TIMESTAMP NOT NULL,
    actor_id    TEXT NOT NULL DEFAULT '',
    actor_email TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    target_type TEXT NOT NULL DEFAULT '',
    target_id   TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',
    ip          TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_events_at_idx ON audit_events (at);

-- Serves both store.SigningKeyRepository (domain.SigningKey) and
-- crypto.KeyRepository (crypto.KeyPair); keys are stored PEM-encoded.
CREATE TABLE signing_keys (
    id          TEXT PRIMARY KEY, -- kid
    algorithm   TEXT NOT NULL DEFAULT '',
    private_key BLOB NOT NULL,
    public_key  BLOB NOT NULL,
    active      BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP NOT NULL,
    expires_at  TIMESTAMP NOT NULL
);
-- At most one active key
CREATE UNIQUE INDEX signing_keys_active_idx ON signing_keys (active) WHERE active = TRUE;

-- +goose Down
DROP TABLE signing_keys;
DROP TABLE audit_events;
DROP TABLE user_groups;
DROP TABLE groups;
DROP TABLE verification_tokens;
DROP TABLE consents;
DROP TABLE tokens;
DROP TABLE auth_codes;
DROP TABLE sessions;
DROP TABLE clients;
DROP TABLE users;
