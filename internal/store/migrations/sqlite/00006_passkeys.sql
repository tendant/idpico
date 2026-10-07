-- Passkeys (WebAuthn credentials) as a second sign-in step. credential is the
-- WebAuthn library's record as JSON (public key, sign counter, flags).

-- +goose Up
CREATE TABLE passkeys (
    id           TEXT PRIMARY KEY, -- credential ID, base64url
    user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT NOT NULL DEFAULT '',
    credential   TEXT NOT NULL,
    created_at   TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP
);
CREATE INDEX idx_passkeys_user_id ON passkeys(user_id);

-- +goose Down
DROP TABLE passkeys;
