package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

type authCodeRepository struct {
	db *sql.DB
}

const authCodeColumns = "code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, nonce, auth_time, created_at, expires_at, used"

func (r *authCodeRepository) Create(ctx context.Context, code *domain.AuthCode) error {
	code.CreatedAt = time.Now()

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO auth_codes (`+authCodeColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		code.Code, code.ClientID, code.UserID, code.RedirectURI, code.Scope,
		code.CodeChallenge, code.CodeChallengeMethod, code.Nonce, utc(code.AuthTime),
		utc(code.CreatedAt), utc(code.ExpiresAt), code.Used,
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return referenceError("user or client")
		}
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("auth code", code.Code)
		}
		return idperrors.Internal("failed to create auth code", err)
	}
	return nil
}

func (r *authCodeRepository) GetByCode(ctx context.Context, code string) (*domain.AuthCode, error) {
	var ac domain.AuthCode
	err := r.db.QueryRowContext(ctx, `SELECT `+authCodeColumns+` FROM auth_codes WHERE code = ?`, code).
		Scan(&ac.Code, &ac.ClientID, &ac.UserID, &ac.RedirectURI, &ac.Scope,
			&ac.CodeChallenge, &ac.CodeChallengeMethod, &ac.Nonce, &ac.AuthTime,
			&ac.CreatedAt, &ac.ExpiresAt, &ac.Used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("auth code", code)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load auth code", err)
	}
	return &ac, nil
}

func (r *authCodeRepository) MarkUsed(ctx context.Context, code string) error {
	res, err := r.db.ExecContext(ctx, `UPDATE auth_codes SET used = TRUE WHERE code = ?`, code)
	if err != nil {
		return idperrors.Internal("failed to mark auth code used", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to mark auth code used", err)
	}
	if !ok {
		return idperrors.NotFound("auth code", code)
	}
	return nil
}

func (r *authCodeRepository) Delete(ctx context.Context, code string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM auth_codes WHERE code = ?`, code)
	if err != nil {
		return idperrors.Internal("failed to delete auth code", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to delete auth code", err)
	}
	if !ok {
		return idperrors.NotFound("auth code", code)
	}
	return nil
}

func (r *authCodeRepository) DeleteExpired(ctx context.Context) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM auth_codes WHERE expires_at <= ?`, utc(time.Now())); err != nil {
		return idperrors.Internal("failed to delete expired auth codes", err)
	}
	return nil
}
