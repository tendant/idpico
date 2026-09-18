package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/tendant/simple-idp/internal/crypto"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

// KeyRepository implements crypto.KeyRepository over the signing_keys table.
// Keys are persisted PEM-encoded; callers restore the RSA material with
// KeyPair.LoadFromPEM as the crypto.KeyService already does.
type KeyRepository struct {
	db *sql.DB
}

// NewKeyRepository returns a crypto.KeyRepository sharing the given store's database.
func NewKeyRepository(s *Store) *KeyRepository {
	return s.keys
}

func scanKeyPair(row interface{ Scan(...any) error }) (*crypto.KeyPair, error) {
	var kp crypto.KeyPair
	if err := row.Scan(&kp.Kid, &kp.Alg, &kp.PrivateKeyPEM, &kp.PublicKeyPEM, &kp.Active, &kp.CreatedAt, &kp.ExpiresAt); err != nil {
		return nil, err
	}
	return &kp, nil
}

// GetByID returns a key by its ID.
func (r *KeyRepository) GetByID(ctx context.Context, kid string) (*crypto.KeyPair, error) {
	kp, err := scanKeyPair(r.db.QueryRowContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys WHERE id = ?`, kid))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("signing key", kid)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load key", err)
	}
	return kp, nil
}

// GetActive returns the active signing key.
func (r *KeyRepository) GetActive(ctx context.Context) (*crypto.KeyPair, error) {
	kp, err := scanKeyPair(r.db.QueryRowContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys WHERE active = TRUE`))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("active signing key", "")
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load active key", err)
	}
	return kp, nil
}

// GetAll returns all signing keys.
func (r *KeyRepository) GetAll(ctx context.Context) ([]*crypto.KeyPair, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+signingKeyColumns+` FROM signing_keys ORDER BY created_at, id`)
	if err != nil {
		return nil, idperrors.Internal("failed to load keys", err)
	}
	defer rows.Close()

	keys := []*crypto.KeyPair{}
	for rows.Next() {
		kp, err := scanKeyPair(rows)
		if err != nil {
			return nil, idperrors.Internal("failed to scan key", err)
		}
		keys = append(keys, kp)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to load keys", err)
	}
	return keys, nil
}

// Save inserts or updates a key.
func (r *KeyRepository) Save(ctx context.Context, keyPair *crypto.KeyPair) error {
	err := withTx(ctx, r.db, func(tx *sql.Tx) error {
		// Preserve the single-active-key invariant enforced by signing_keys_active_idx.
		if keyPair.Active {
			if _, err := tx.ExecContext(ctx, `UPDATE signing_keys SET active = FALSE WHERE active = TRUE AND id <> ?`, keyPair.Kid); err != nil {
				return err
			}
		}
		_, err := tx.ExecContext(ctx,
			`INSERT INTO signing_keys (`+signingKeyColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(id) DO UPDATE SET
			   algorithm = excluded.algorithm,
			   private_key = excluded.private_key,
			   public_key = excluded.public_key,
			   active = excluded.active,
			   created_at = excluded.created_at,
			   expires_at = excluded.expires_at`,
			keyPair.Kid, keyPair.Alg, nonNilBytes(keyPair.PrivateKeyPEM), nonNilBytes(keyPair.PublicKeyPEM),
			keyPair.Active, utc(keyPair.CreatedAt), utc(keyPair.ExpiresAt),
		)
		return err
	})
	if err != nil {
		return idperrors.Internal("failed to save key", err)
	}
	return nil
}

// SetActive sets the active key.
func (r *KeyRepository) SetActive(ctx context.Context, kid string) error {
	err := setActiveKey(ctx, r.db, kid)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			return err
		}
		return idperrors.Internal("failed to activate key", err)
	}
	return nil
}

// Delete removes a key.
func (r *KeyRepository) Delete(ctx context.Context, kid string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM signing_keys WHERE id = ?`, kid)
	if err != nil {
		return idperrors.Internal("failed to delete key", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to delete key", err)
	}
	if !ok {
		return idperrors.NotFound("signing key", kid)
	}
	return nil
}
