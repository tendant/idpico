-- Two-step sign-in with an authenticator app (TOTP). Empty totp_secret means
-- off; recovery_codes is a JSON array of SHA-256 hashes of the unused codes.
-- sessions.amr / auth_codes.amr: JSON array of RFC 8176 authentication
-- methods, carried from the session through the code into the ID token.

-- +goose Up
ALTER TABLE users ADD COLUMN totp_secret    TEXT    NOT NULL DEFAULT '';
ALTER TABLE users ADD COLUMN totp_last_step INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN recovery_codes TEXT    NOT NULL DEFAULT '[]';
ALTER TABLE sessions   ADD COLUMN amr TEXT NOT NULL DEFAULT '[]';
ALTER TABLE auth_codes ADD COLUMN amr TEXT NOT NULL DEFAULT '[]';

-- +goose Down
ALTER TABLE users DROP COLUMN totp_secret;
ALTER TABLE users DROP COLUMN totp_last_step;
ALTER TABLE users DROP COLUMN recovery_codes;
ALTER TABLE sessions   DROP COLUMN amr;
ALTER TABLE auth_codes DROP COLUMN amr;
