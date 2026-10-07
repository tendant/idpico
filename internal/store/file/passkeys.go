package file

import (
	"context"
	"time"

	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

type passkeyRepository struct {
	store *Store
}

type passkeysData struct {
	Passkeys []*domain.Passkey `json:"passkeys"`
}

func (r *passkeyRepository) load() (*passkeysData, error) {
	var data passkeysData
	if err := r.store.readFile("passkeys", &data); err != nil {
		return nil, err
	}
	if data.Passkeys == nil {
		data.Passkeys = []*domain.Passkey{}
	}
	return &data, nil
}

func (r *passkeyRepository) save(data *passkeysData) error {
	return r.store.writeFile("passkeys", data)
}

func (r *passkeyRepository) Create(ctx context.Context, p *domain.Passkey) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load passkeys", err)
	}
	for _, existing := range data.Passkeys {
		if existing.ID == p.ID {
			return idperrors.AlreadyExists("passkey", p.ID)
		}
	}
	p.CreatedAt = time.Now()
	data.Passkeys = append(data.Passkeys, p)
	return r.save(data)
}

func (r *passkeyRepository) ListByUserID(ctx context.Context, userID string) ([]*domain.Passkey, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load passkeys", err)
	}
	out := []*domain.Passkey{}
	for _, p := range data.Passkeys {
		if p.UserID == userID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (r *passkeyRepository) Update(ctx context.Context, p *domain.Passkey) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load passkeys", err)
	}
	for i, existing := range data.Passkeys {
		if existing.ID == p.ID && existing.UserID == p.UserID {
			data.Passkeys[i] = p
			return r.save(data)
		}
	}
	return idperrors.NotFound("passkey", p.ID)
}

func (r *passkeyRepository) Delete(ctx context.Context, userID, id string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load passkeys", err)
	}
	for i, p := range data.Passkeys {
		if p.ID == id && p.UserID == userID {
			data.Passkeys = append(data.Passkeys[:i], data.Passkeys[i+1:]...)
			return r.save(data)
		}
	}
	return idperrors.NotFound("passkey", id)
}

func (r *passkeyRepository) DeleteByUserID(ctx context.Context, userID string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load passkeys", err)
	}
	kept := data.Passkeys[:0]
	for _, p := range data.Passkeys {
		if p.UserID != userID {
			kept = append(kept, p)
		}
	}
	data.Passkeys = kept
	return r.save(data)
}
