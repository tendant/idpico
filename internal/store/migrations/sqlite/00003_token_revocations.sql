-- Access-token revocation. Access tokens are stateless JWTs and are not
-- stored; this table records what is no longer valid: one token by its jti,
-- or every token of a user / user+client / client issued at or before
-- not_before (kind in jti, user, user_client, client). Rows are purged once
-- expires_at passes.

-- +goose Up
CREATE TABLE token_revocations (
    kind       TEXT      NOT NULL,
    key        TEXT      NOT NULL,
    not_before TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    PRIMARY KEY (kind, key)
);
CREATE INDEX token_revocations_expires_at_idx ON token_revocations (expires_at);

-- +goose Down
DROP TABLE token_revocations;
