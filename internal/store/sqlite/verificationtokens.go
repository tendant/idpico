package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

type verificationTokenRepository struct {
	db *sql.DB
}

const verificationTokenColumns = "token_hash, user_id, purpose, created_at, expires_at, used"

func (r *verificationTokenRepository) Create(ctx context.Context, token *domain.VerificationToken) error {
	token.CreatedAt = time.Now()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO verification_tokens (`+verificationTokenColumns+`) VALUES (?, ?, ?, ?, ?, ?)`,
		token.TokenHash, token.UserID, token.Purpose, utc(token.CreatedAt), utc(token.ExpiresAt), token.Used,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return referenceError("user")
		}
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("verification token", token.TokenHash)
		}
		return idperrors.Internal("failed to create verification token", err)
	}
	return nil
}

func (r *verificationTokenRepository) GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error) {
	var t domain.VerificationToken
	err := r.db.QueryRowContext(ctx,
		`SELECT `+verificationTokenColumns+` FROM verification_tokens WHERE token_hash = ?`, hash).
		Scan(&t.TokenHash, &t.UserID, &t.Purpose, &t.CreatedAt, &t.ExpiresAt, &t.Used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("verification token", "")
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load verification token", err)
	}
	return &t, nil
}

func (r *verificationTokenRepository) MarkUsed(ctx context.Context, hash string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE verification_tokens SET used = TRUE WHERE token_hash = ?`, hash)
	if err != nil {
		return idperrors.Internal("failed to mark verification token used", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to mark verification token used", err)
	}
	if !ok {
		return idperrors.NotFound("verification token", "")
	}
	return nil
}

func (r *verificationTokenRepository) DeleteByUserID(ctx context.Context, userID, purpose string) error {
	var err error
	if purpose == "" {
		_, err = r.db.ExecContext(ctx, `DELETE FROM verification_tokens WHERE user_id = ?`, userID)
	} else {
		_, err = r.db.ExecContext(ctx, `DELETE FROM verification_tokens WHERE user_id = ? AND purpose = ?`, userID, purpose)
	}
	if err != nil {
		return idperrors.Internal("failed to delete verification tokens", err)
	}
	return nil
}

func (r *verificationTokenRepository) DeleteExpired(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM verification_tokens WHERE expires_at <= ?`, utc(time.Now())); err != nil {
		return idperrors.Internal("failed to delete expired verification tokens", err)
	}
	return nil
}
