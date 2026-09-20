package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
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
		if isForeignKeyViolation(err) {
			return referenceError("user or client")
		}
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

// Revoke marks the refresh token revoked and, in the same transaction,
// revokes the user's access tokens for that client issued up to now.
func (r *tokenRepository) Revoke(ctx context.Context, id string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return idperrors.Internal("failed to revoke token", err)
	}
	defer tx.Rollback()

	var userID, clientID string
	err = tx.QueryRowContext(ctx, `SELECT user_id, client_id FROM tokens WHERE id = ?`, id).Scan(&userID, &clientID)
	if errors.Is(err, sql.ErrNoRows) {
		return idperrors.NotFound("token", id)
	}
	if err != nil {
		return idperrors.Internal("failed to revoke token", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE tokens SET revoked = TRUE WHERE id = ?`, id); err != nil {
		return idperrors.Internal("failed to revoke token", err)
	}
	if err := revokeGrantAccessTokens(ctx, tx, domain.RevocationUserClient, domain.UserClientKey(userID, clientID)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return idperrors.Internal("failed to revoke token", err)
	}
	return nil
}

// Rotate marks the refresh token revoked without touching access tokens.
func (r *tokenRepository) Rotate(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE tokens SET revoked = TRUE WHERE id = ?`, id)
	if err != nil {
		return idperrors.Internal("failed to rotate token", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to rotate token", err)
	}
	if !ok {
		return idperrors.NotFound("token", id)
	}
	return nil
}

// RevokeByUserID revokes the user's refresh tokens and every access token
// issued to them up to now.
func (r *tokenRepository) RevokeByUserID(ctx context.Context, userID string) error {
	return r.revokeWhere(ctx, `user_id = ?`, userID, domain.RevocationUser, userID)
}

// RevokeByClientID revokes the client's refresh tokens and every access
// token issued for it up to now.
func (r *tokenRepository) RevokeByClientID(ctx context.Context, clientID string) error {
	return r.revokeWhere(ctx, `client_id = ?`, clientID, domain.RevocationClient, clientID)
}

func (r *tokenRepository) revokeWhere(ctx context.Context, where, arg, kind, key string) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return idperrors.Internal("failed to revoke tokens", err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE tokens SET revoked = TRUE WHERE `+where, arg); err != nil {
		return idperrors.Internal("failed to revoke tokens", err)
	}
	if err := revokeGrantAccessTokens(ctx, tx, kind, key); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return idperrors.Internal("failed to revoke tokens", err)
	}
	return nil
}

// revokeGrantAccessTokens writes the watermark that invalidates the access
// tokens belonging to the refresh tokens just revoked.
func revokeGrantAccessTokens(ctx context.Context, tx execer, kind, key string) error {
	now := time.Now()
	return upsertRevocation(ctx, tx, kind, key, now, now.Add(domain.RevocationRetention))
}

func (r *tokenRepository) DeleteExpired(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM tokens WHERE expires_at <= ?`, utc(time.Now())); err != nil {
		return idperrors.Internal("failed to delete expired tokens", err)
	}
	return nil
}

func (r *tokenRepository) ListByUserID(ctx context.Context, userID string) ([]*domain.Token, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+tokenColumns+` FROM tokens WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC`,
		userID, utc(time.Now()))
	if err != nil {
		return nil, idperrors.Internal("failed to list tokens", err)
	}
	defer rows.Close()

	tokens := []*domain.Token{}
	for rows.Next() {
		var t domain.Token
		if err := rows.Scan(&t.ID, &t.UserID, &t.ClientID, &t.Scope, &t.CreatedAt, &t.ExpiresAt, &t.Revoked); err != nil {
			return nil, idperrors.Internal("failed to scan token", err)
		}
		tokens = append(tokens, &t)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to list tokens", err)
	}
	return tokens, nil
}
