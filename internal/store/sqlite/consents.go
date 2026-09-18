package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

type consentRepository struct {
	db *sql.DB
}

const consentColumns = "id, user_id, client_id, scopes, granted_at"

func scanConsent(row interface{ Scan(...any) error }) (*domain.Consent, error) {
	var (
		c      domain.Consent
		scopes string
	)
	if err := row.Scan(&c.ID, &c.UserID, &c.ClientID, &scopes, &c.GrantedAt); err != nil {
		return nil, err
	}
	var err error
	if c.Scopes, err = unmarshalStrings(scopes); err != nil {
		return nil, err
	}
	return &c, nil
}

func (r *consentRepository) Upsert(ctx context.Context, consent *domain.Consent) error {
	scopes, err := marshalStrings(consent.Scopes)
	if err != nil {
		return idperrors.Internal("failed to encode consent", err)
	}
	if consent.ID == "" {
		consent.ID = uuid.New().String()
	}
	consent.GrantedAt = time.Now()

	_, err = r.db.ExecContext(ctx,
		`INSERT INTO consents (`+consentColumns+`) VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(user_id, client_id) DO UPDATE SET scopes = excluded.scopes, granted_at = excluded.granted_at`,
		consent.ID, consent.UserID, consent.ClientID, scopes, utc(consent.GrantedAt),
	)
	if err != nil {
		if isForeignKeyViolation(err) {
			return referenceError("user or client")
		}
		return idperrors.Internal("failed to save consent", err)
	}
	return nil
}

func (r *consentRepository) Get(ctx context.Context, userID, clientID string) (*domain.Consent, error) {
	c, err := scanConsent(r.db.QueryRowContext(ctx,
		`SELECT `+consentColumns+` FROM consents WHERE user_id = ? AND client_id = ?`, userID, clientID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("consent", userID+"/"+clientID)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load consent", err)
	}
	return c, nil
}

func (r *consentRepository) ListByUserID(ctx context.Context, userID string) ([]*domain.Consent, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+consentColumns+` FROM consents WHERE user_id = ? ORDER BY granted_at, client_id`, userID)
	if err != nil {
		return nil, idperrors.Internal("failed to list consents", err)
	}
	defer rows.Close()

	consents := []*domain.Consent{}
	for rows.Next() {
		c, err := scanConsent(rows)
		if err != nil {
			return nil, idperrors.Internal("failed to scan consent", err)
		}
		consents = append(consents, c)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to list consents", err)
	}
	return consents, nil
}

func (r *consentRepository) Delete(ctx context.Context, userID, clientID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM consents WHERE user_id = ? AND client_id = ?`, userID, clientID)
	if err != nil {
		return idperrors.Internal("failed to delete consent", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to delete consent", err)
	}
	if !ok {
		return idperrors.NotFound("consent", userID+"/"+clientID)
	}
	return nil
}

func (r *consentRepository) DeleteByUserID(ctx context.Context, userID string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM consents WHERE user_id = ?`, userID); err != nil {
		return idperrors.Internal("failed to delete consents", err)
	}
	return nil
}
