package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

type revocationRepository struct {
	db *sql.DB
}

// execer is *sql.DB or *sql.Tx.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// upsertRevocation records kind/key, keeping the later not_before and
// expires_at if a row already exists.
func upsertRevocation(ctx context.Context, db execer, kind, key string, notBefore, expiresAt time.Time) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO token_revocations (kind, key, not_before, expires_at) VALUES (?, ?, ?, ?)
		ON CONFLICT (kind, key) DO UPDATE SET
			not_before = MAX(not_before, excluded.not_before),
			expires_at = MAX(expires_at, excluded.expires_at)`,
		kind, key, utc(notBefore), utc(expiresAt))
	if err != nil {
		return idperrors.Internal("failed to record revocation", err)
	}
	return nil
}

func (r *revocationRepository) RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return upsertRevocation(ctx, r.db, domain.RevocationJTI, jti, time.Now(), expiresAt)
}

func (r *revocationRepository) RevokeBefore(ctx context.Context, kind, key string, notBefore time.Time) error {
	return upsertRevocation(ctx, r.db, kind, key, notBefore, notBefore.Add(domain.RevocationRetention))
}

func (r *revocationRepository) IsRevoked(ctx context.Context, jti, userID, clientID string, issuedAt time.Time) (bool, error) {
	iat := utc(issuedAt)
	var one int
	err := r.db.QueryRowContext(ctx, `
		SELECT 1 FROM token_revocations
		WHERE (kind = ? AND key = ?)
		   OR (kind = ? AND key = ? AND not_before >= ?)
		   OR (kind = ? AND key = ? AND not_before >= ?)
		   OR (kind = ? AND key = ? AND not_before >= ?)
		LIMIT 1`,
		domain.RevocationJTI, jti,
		domain.RevocationUser, userID, iat,
		domain.RevocationUserClient, domain.UserClientKey(userID, clientID), iat,
		domain.RevocationClient, clientID, iat,
	).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, idperrors.Internal("failed to check revocation", err)
	}
	return true, nil
}

func (r *revocationRepository) DeleteExpired(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM token_revocations WHERE expires_at <= ?`, utc(time.Now())); err != nil {
		return idperrors.Internal("failed to delete expired revocations", err)
	}
	return nil
}
