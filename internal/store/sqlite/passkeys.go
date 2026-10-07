package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

type passkeyRepository struct {
	db *sql.DB
}

const passkeyColumns = "id, user_id, name, credential, created_at, last_used_at"

func scanPasskey(row interface{ Scan(...any) error }) (*domain.Passkey, error) {
	var (
		p          domain.Passkey
		credential string
		lastUsed   sql.NullTime
	)
	if err := row.Scan(&p.ID, &p.UserID, &p.Name, &credential, &p.CreatedAt, &lastUsed); err != nil {
		return nil, err
	}
	p.Credential = []byte(credential)
	if lastUsed.Valid {
		p.LastUsedAt = lastUsed.Time
	}
	return &p, nil
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return utc(t)
}

func (r *passkeyRepository) Create(ctx context.Context, p *domain.Passkey) error {
	p.CreatedAt = time.Now()
	_, err := r.db.ExecContext(ctx, `INSERT INTO passkeys (`+passkeyColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
		p.ID, p.UserID, p.Name, string(p.Credential), utc(p.CreatedAt), nullTime(p.LastUsedAt))
	if err != nil {
		if isForeignKeyViolation(err) {
			return referenceError("user")
		}
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("passkey", p.ID)
		}
		return idperrors.Internal("failed to create passkey", err)
	}
	return nil
}

func (r *passkeyRepository) ListByUserID(ctx context.Context, userID string) ([]*domain.Passkey, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+passkeyColumns+` FROM passkeys WHERE user_id = ? ORDER BY created_at`, userID)
	if err != nil {
		return nil, idperrors.Internal("failed to list passkeys", err)
	}
	defer rows.Close()
	out := []*domain.Passkey{}
	for rows.Next() {
		p, err := scanPasskey(rows)
		if err != nil {
			return nil, idperrors.Internal("failed to scan passkey", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (r *passkeyRepository) Update(ctx context.Context, p *domain.Passkey) error {
	res, err := r.db.ExecContext(ctx, `UPDATE passkeys SET name = ?, credential = ?, last_used_at = ? WHERE id = ? AND user_id = ?`,
		p.Name, string(p.Credential), nullTime(p.LastUsedAt), p.ID, p.UserID)
	if err != nil {
		return idperrors.Internal("failed to update passkey", err)
	}
	if ok, err := rowsAffected(res); err != nil {
		return idperrors.Internal("failed to update passkey", err)
	} else if !ok {
		return idperrors.NotFound("passkey", p.ID)
	}
	return nil
}

func (r *passkeyRepository) Delete(ctx context.Context, userID, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return idperrors.Internal("failed to delete passkey", err)
	}
	if ok, err := rowsAffected(res); err != nil {
		return idperrors.Internal("failed to delete passkey", err)
	} else if !ok {
		return idperrors.NotFound("passkey", id)
	}
	return nil
}

func (r *passkeyRepository) DeleteByUserID(ctx context.Context, userID string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM passkeys WHERE user_id = ?`, userID); err != nil {
		return idperrors.Internal("failed to delete passkeys", err)
	}
	return nil
}
