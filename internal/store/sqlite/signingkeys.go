package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

// signingKeyRepository implements store.SigningKeyRepository over the
// signing_keys table. KeyRepository (keys.go) is a second view of the same
// table for the crypto package.
type signingKeyRepository struct {
	db *sql.DB
}

const signingKeyColumns = "id, algorithm, private_key, public_key, active, created_at, expires_at"

func scanSigningKey(row interface{ Scan(...any) error }) (*domain.SigningKey, error) {
	var k domain.SigningKey
	if err := row.Scan(&k.ID, &k.Algorithm, &k.PrivateKey, &k.PublicKey, &k.Active, &k.CreatedAt, &k.ExpiresAt); err != nil {
		return nil, err
	}
	return &k, nil
}

func (r *signingKeyRepository) Create(ctx context.Context, key *domain.SigningKey) error {
	key.CreatedAt = time.Now()

	err := withTx(ctx, r.db, func(tx *sql.Tx) error {
		// Preserve the single-active-key invariant enforced by signing_keys_active_idx.
		if key.Active {
			if _, err := tx.ExecContext(ctx, `UPDATE signing_keys SET active = FALSE WHERE active = TRUE`); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO signing_keys (`+signingKeyColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			key.ID, key.Algorithm, nonNilBytes(key.PrivateKey), nonNilBytes(key.PublicKey), key.Active, utc(key.CreatedAt), utc(key.ExpiresAt),
		)
		return err
	})
	if err != nil {
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("signing key", key.ID)
		}
		return idperrors.Internal("failed to create signing key", err)
	}
	return nil
}

func (r *signingKeyRepository) GetByID(ctx context.Context, id string) (*domain.SigningKey, error) {
	k, err := scanSigningKey(r.db.QueryRowContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("signing key", id)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load signing key", err)
	}
	return k, nil
}

func (r *signingKeyRepository) GetActive(ctx context.Context) (*domain.SigningKey, error) {
	k, err := scanSigningKey(r.db.QueryRowContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys WHERE active = TRUE`))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("active signing key", "")
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load active signing key", err)
	}
	return k, nil
}

func (r *signingKeyRepository) GetAll(ctx context.Context) ([]*domain.SigningKey, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys ORDER BY created_at, id`)
	if err != nil {
		return nil, idperrors.Internal("failed to list signing keys", err)
	}
	defer rows.Close()

	keys := []*domain.SigningKey{}
	for rows.Next() {
		k, err := scanSigningKey(rows)
		if err != nil {
			return nil, idperrors.Internal("failed to scan signing key", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to list signing keys", err)
	}
	return keys, nil
}

func (r *signingKeyRepository) SetActive(ctx context.Context, id string) error {
	err := setActiveKey(ctx, r.db, id)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			return err
		}
		return idperrors.Internal("failed to activate signing key", err)
	}
	return nil
}

func (r *signingKeyRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM signing_keys WHERE id = ?`, id)
	if err != nil {
		return idperrors.Internal("failed to delete signing key", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to delete signing key", err)
	}
	if !ok {
		return idperrors.NotFound("signing key", id)
	}
	return nil
}

// setActiveKey atomically makes id the only active key. Returns a NotFound
// error if id does not exist.
func setActiveKey(ctx context.Context, db *sql.DB, id string) error {
	return withTx(ctx, db, func(tx *sql.Tx) error {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM signing_keys WHERE id = ?`, id).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			return idperrors.NotFound("signing key", id)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE signing_keys SET active = FALSE WHERE active = TRUE AND id <> ?`, id); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `UPDATE signing_keys SET active = TRUE WHERE id = ?`, id)
		return err
	})
}

// withTx runs fn inside a transaction, committing on nil and rolling back on error.
func withTx(ctx context.Context, db *sql.DB, fn func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// nonNilBytes maps a nil slice to an empty one so NOT NULL BLOB columns accept it.
func nonNilBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}
