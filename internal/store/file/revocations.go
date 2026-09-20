package file

import (
	"context"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

// Revocation Repository

type revocationRepository struct {
	store *Store
}

type revocationsData struct {
	Revocations []*domain.Revocation `json:"revocations"`
}

func (r *revocationRepository) load() (*revocationsData, error) {
	var data revocationsData
	if err := r.store.readFile("revocations", &data); err != nil {
		return nil, err
	}
	if data.Revocations == nil {
		data.Revocations = []*domain.Revocation{}
	}
	return &data, nil
}

func (r *revocationRepository) save(data *revocationsData) error {
	return r.store.writeFile("revocations", data)
}

// upsert records kind/key, keeping the later not_before and expires_at if
// the row already exists.
func (r *revocationRepository) upsert(kind, key string, notBefore, expiresAt time.Time) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load revocations", err)
	}
	for _, rv := range data.Revocations {
		if rv.Kind == kind && rv.Key == key {
			if notBefore.After(rv.NotBefore) {
				rv.NotBefore = notBefore
			}
			if expiresAt.After(rv.ExpiresAt) {
				rv.ExpiresAt = expiresAt
			}
			return r.save(data)
		}
	}
	data.Revocations = append(data.Revocations, &domain.Revocation{Kind: kind, Key: key, NotBefore: notBefore, ExpiresAt: expiresAt})
	return r.save(data)
}

func (r *revocationRepository) RevokeAccessToken(ctx context.Context, jti string, expiresAt time.Time) error {
	return r.upsert(domain.RevocationJTI, jti, time.Now(), expiresAt)
}

func (r *revocationRepository) RevokeBefore(ctx context.Context, kind, key string, notBefore time.Time) error {
	return r.upsert(kind, key, notBefore, notBefore.Add(domain.RevocationRetention))
}

func (r *revocationRepository) IsRevoked(ctx context.Context, jti, userID, clientID string, issuedAt time.Time) (bool, error) {
	data, err := r.load()
	if err != nil {
		return false, idperrors.Internal("failed to load revocations", err)
	}
	for _, rv := range data.Revocations {
		switch rv.Kind {
		case domain.RevocationJTI:
			if rv.Key == jti {
				return true, nil
			}
		case domain.RevocationUser:
			if rv.Key == userID && !issuedAt.After(rv.NotBefore) {
				return true, nil
			}
		case domain.RevocationUserClient:
			if rv.Key == domain.UserClientKey(userID, clientID) && !issuedAt.After(rv.NotBefore) {
				return true, nil
			}
		case domain.RevocationClient:
			if rv.Key == clientID && !issuedAt.After(rv.NotBefore) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (r *revocationRepository) DeleteExpired(ctx context.Context) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load revocations", err)
	}
	now := time.Now()
	kept := data.Revocations[:0]
	for _, rv := range data.Revocations {
		if rv.ExpiresAt.After(now) {
			kept = append(kept, rv)
		}
	}
	data.Revocations = kept
	return r.save(data)
}
