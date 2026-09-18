package file

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

// Consent Repository

type consentRepository struct {
	store *Store
}

type consentsData struct {
	Consents []*domain.Consent `json:"consents"`
}

func (r *consentRepository) load() (*consentsData, error) {
	var data consentsData
	if err := r.store.readFile("consents", &data); err != nil {
		return nil, err
	}
	if data.Consents == nil {
		data.Consents = []*domain.Consent{}
	}
	return &data, nil
}

func (r *consentRepository) save(data *consentsData) error {
	return r.store.writeFile("consents", data)
}

func (r *consentRepository) Upsert(ctx context.Context, consent *domain.Consent) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load consents", err)
	}

	if consent.ID == "" {
		consent.ID = uuid.New().String()
	}
	consent.GrantedAt = time.Now()

	for i, c := range data.Consents {
		if c.UserID == consent.UserID && c.ClientID == consent.ClientID {
			consent.ID = c.ID
			data.Consents[i] = consent
			return r.save(data)
		}
	}
	data.Consents = append(data.Consents, consent)
	return r.save(data)
}

func (r *consentRepository) Get(ctx context.Context, userID, clientID string) (*domain.Consent, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load consents", err)
	}

	for _, c := range data.Consents {
		if c.UserID == userID && c.ClientID == clientID {
			return c, nil
		}
	}
	return nil, idperrors.NotFound("consent", userID+"/"+clientID)
}

func (r *consentRepository) ListByUserID(ctx context.Context, userID string) ([]*domain.Consent, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load consents", err)
	}

	out := []*domain.Consent{}
	for _, c := range data.Consents {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *consentRepository) Delete(ctx context.Context, userID, clientID string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load consents", err)
	}

	for i, c := range data.Consents {
		if c.UserID == userID && c.ClientID == clientID {
			data.Consents = append(data.Consents[:i], data.Consents[i+1:]...)
			return r.save(data)
		}
	}
	return idperrors.NotFound("consent", userID+"/"+clientID)
}

func (r *consentRepository) DeleteByUserID(ctx context.Context, userID string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load consents", err)
	}

	filtered := make([]*domain.Consent, 0, len(data.Consents))
	for _, c := range data.Consents {
		if c.UserID != userID {
			filtered = append(filtered, c)
		}
	}
	data.Consents = filtered
	return r.save(data)
}

// VerificationToken Repository

type verificationTokenRepository struct {
	store *Store
}

type verificationTokensData struct {
	Tokens []*domain.VerificationToken `json:"verification_tokens"`
}

func (r *verificationTokenRepository) load() (*verificationTokensData, error) {
	var data verificationTokensData
	if err := r.store.readFile("verification_tokens", &data); err != nil {
		return nil, err
	}
	if data.Tokens == nil {
		data.Tokens = []*domain.VerificationToken{}
	}
	return &data, nil
}

func (r *verificationTokenRepository) save(data *verificationTokensData) error {
	return r.store.writeFile("verification_tokens", data)
}

func (r *verificationTokenRepository) Create(ctx context.Context, token *domain.VerificationToken) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load verification tokens", err)
	}

	for _, t := range data.Tokens {
		if t.TokenHash == token.TokenHash {
			return idperrors.AlreadyExists("verification token", token.TokenHash)
		}
	}

	token.CreatedAt = time.Now()
	data.Tokens = append(data.Tokens, token)
	return r.save(data)
}

func (r *verificationTokenRepository) GetByHash(ctx context.Context, hash string) (*domain.VerificationToken, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load verification tokens", err)
	}

	for _, t := range data.Tokens {
		if t.TokenHash == hash {
			return t, nil
		}
	}
	return nil, idperrors.NotFound("verification token", "")
}

func (r *verificationTokenRepository) MarkUsed(ctx context.Context, hash string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load verification tokens", err)
	}

	for _, t := range data.Tokens {
		if t.TokenHash == hash {
			t.Used = true
			return r.save(data)
		}
	}
	return idperrors.NotFound("verification token", "")
}

func (r *verificationTokenRepository) DeleteByUserID(ctx context.Context, userID, purpose string) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load verification tokens", err)
	}

	filtered := make([]*domain.VerificationToken, 0, len(data.Tokens))
	for _, t := range data.Tokens {
		if t.UserID == userID && (purpose == "" || t.Purpose == purpose) {
			continue
		}
		filtered = append(filtered, t)
	}
	data.Tokens = filtered
	return r.save(data)
}

func (r *verificationTokenRepository) DeleteExpired(ctx context.Context) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load verification tokens", err)
	}

	now := time.Now()
	filtered := make([]*domain.VerificationToken, 0, len(data.Tokens))
	for _, t := range data.Tokens {
		if t.ExpiresAt.After(now) {
			filtered = append(filtered, t)
		}
	}
	data.Tokens = filtered
	return r.save(data)
}
