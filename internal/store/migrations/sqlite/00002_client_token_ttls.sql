-- Per-client token lifetimes, in seconds; 0 means "use the server default"
-- (IDPICO_ACCESS_TOKEN_TTL / IDPICO_REFRESH_TOKEN_TTL).

-- +goose Up
ALTER TABLE clients ADD COLUMN access_token_ttl  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE clients ADD COLUMN refresh_token_ttl INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE clients DROP COLUMN access_token_ttl;
ALTER TABLE clients DROP COLUMN refresh_token_ttl;
