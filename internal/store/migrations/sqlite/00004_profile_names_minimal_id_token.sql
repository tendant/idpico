-- given_name / family_name for the profile scope, and a per-client switch
-- for spec-pure ID tokens (no scope claims; they stay at /userinfo).

-- +goose Up
ALTER TABLE users   ADD COLUMN given_name       TEXT    NOT NULL DEFAULT '';
ALTER TABLE users   ADD COLUMN family_name      TEXT    NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN minimal_id_token BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down
ALTER TABLE users   DROP COLUMN given_name;
ALTER TABLE users   DROP COLUMN family_name;
ALTER TABLE clients DROP COLUMN minimal_id_token;
