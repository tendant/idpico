package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

type tokenRepository struct {
	db *sql.DB
}

const tokenColumns = "id, user_id, client_id, scope, created_at, expires_at, revoked"

func (r *tokenRepository) Create(ctx context.Context, token *domain.Token) error {
	token.CreatedAt = time.Now()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO tokens (`+tokenColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		token.ID, token.UserID, token.ClientID, token.Scope, utc(token.CreatedAt), utc(token.ExpiresAt), token.Revoked,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("token", token.ID)
		}
		return idperrors.Internal("failed to create token", err)
	}
	return nil
}

func (r *tokenRepository) GetByID(ctx context.Context, id string) (*domain.Token, error) {
	var t domain.Token
	err := r.db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM tokens WHERE id = ?`, id).
		Scan(&t.ID, &t.UserID, &t.ClientID, &t.Scope, &t.CreatedAt, &t.ExpiresAt, &t.Revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("token", id)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load token", err)
	}
	return &t, nil
}

func (r *tokenRepository) Revoke(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE tokens SET revoked = TRUE WHERE id = ?`, id)
	if err != nil {
		return idperrors.Internal("failed to revoke token", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to revoke token", err)
	}
	if !ok {
		return idperrors.NotFound("token", id)
	}
	return nil
}

func (r *tokenRepository) RevokeByUserID(ctx context.Context, userID string) error {
	if _, err := r.db.ExecContext(ctx, `UPDATE tokens SET revoked = TRUE WHERE user_id = ?`, userID); err != nil {
		return idperrors.Internal("failed to revoke tokens", err)
	}
	return nil
}

func (r *tokenRepository) RevokeByClientID(ctx context.Context, clientID string) error {
	if _, err := r.db.ExecContext(ctx, `UPDATE tokens SET revoked = TRUE WHERE client_id = ?`, clientID); err != nil {
		return idperrors.Internal("failed to revoke tokens", err)
	}
	return nil
}

func (r *tokenRepository) DeleteExpired(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM tokens WHERE expires_at <= ?`, utc(time.Now())); err != nil {
		return idperrors.Internal("failed to delete expired tokens", err)
	}
	return nil
}
