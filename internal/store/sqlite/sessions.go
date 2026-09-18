package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

type sessionRepository struct {
	db *sql.DB
}

const sessionColumns = "id, user_id, created_at, expires_at, user_agent, ip_address"

func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	session.CreatedAt = time.Now()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO sessions (`+sessionColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, utc(session.CreatedAt), utc(session.ExpiresAt), session.UserAgent, session.IPAddress,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return referenceError("user")
		}
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("session", session.ID)
		}
		return idperrors.Internal("failed to create session", err)
	}
	return nil
}

func (r *sessionRepository) GetByID(ctx context.Context, id string) (*domain.Session, error) {
	var s domain.Session
	err := r.db.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = ?`, id).
		Scan(&s.ID, &s.UserID, &s.CreatedAt, &s.ExpiresAt, &s.UserAgent, &s.IPAddress)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("session", id)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load session", err)
	}
	return &s, nil
}

func (r *sessionRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	if err != nil {
		return idperrors.Internal("failed to delete session", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to delete session", err)
	}
	if !ok {
		return idperrors.NotFound("session", id)
	}
	return nil
}

func (r *sessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, userID); err != nil {
		return idperrors.Internal("failed to delete sessions", err)
	}
	return nil
}

func (r *sessionRepository) DeleteExpired(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, utc(time.Now())); err != nil {
		return idperrors.Internal("failed to delete expired sessions", err)
	}
	return nil
}

func (r *sessionRepository) ListByUserID(ctx context.Context, userID string) ([]*domain.Session, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC`,
		userID, utc(time.Now()))
	if err != nil {
		return nil, idperrors.Internal("failed to list sessions", err)
	}
	defer rows.Close()

	sessions := []*domain.Session{}
	for rows.Next() {
		var s domain.Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.CreatedAt, &s.ExpiresAt, &s.UserAgent, &s.IPAddress); err != nil {
			return nil, idperrors.Internal("failed to scan session", err)
		}
		sessions = append(sessions, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to list sessions", err)
	}
	return sessions, nil
}
