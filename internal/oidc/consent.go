package oidc

import (
	"context"
	"fmt"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
	"github.com/tendant/simple-idp/internal/store"
)

// ConsentService decides whether a user must be shown the consent screen for
// a client and records the grants they make.
type ConsentService struct {
	consents store.ConsentRepository
}

// NewConsentService creates a ConsentService.
func NewConsentService(consents store.ConsentRepository) *ConsentService {
	return &ConsentService{consents: consents}
}

// IsGranted reports whether the user has already allowed the client every
// requested scope. First-party clients (SkipConsent) never need consent.
func (s *ConsentService) IsGranted(ctx context.Context, userID string, client *domain.Client, scopes []string) (bool, error) {
	if client.SkipConsent {
		return true, nil
	}

	consent, err := s.consents.Get(ctx, userID, client.ID)
	if err != nil {
		if idperrors.IsCode(err, idperrors.CodeNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("failed to load consent: %w", err)
	}
	return consent.Covers(scopes), nil
}

// Grant records that the user allowed the client the given scopes, merged
// with any scopes granted earlier so a narrower request never revokes a
// wider one.
func (s *ConsentService) Grant(ctx context.Context, userID, clientID string, scopes []string) error {
	merged := append([]string(nil), scopes...)
	if existing, err := s.consents.Get(ctx, userID, clientID); err == nil {
		merged = unionScopes(existing.Scopes, scopes)
	} else if !idperrors.IsCode(err, idperrors.CodeNotFound) {
		return fmt.Errorf("failed to load consent: %w", err)
	}

	return s.consents.Upsert(ctx, &domain.Consent{
		UserID:   userID,
		ClientID: clientID,
		Scopes:   merged,
	})
}

// Revoke removes the user's consent for a client.
func (s *ConsentService) Revoke(ctx context.Context, userID, clientID string) error {
	return s.consents.Delete(ctx, userID, clientID)
}

// ListForUser returns everything the user has consented to.
func (s *ConsentService) ListForUser(ctx context.Context, userID string) ([]*domain.Consent, error) {
	return s.consents.ListByUserID(ctx, userID)
}

func unionScopes(a, b []string) []string {
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, s := range list {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// ScopeDescription explains a scope to the user on the consent screen.
func ScopeDescription(scope string) string {
	switch scope {
	case "openid":
		return "Verify your identity"
	case "profile":
		return "View your name and profile details"
	case "email":
		return "View your email address"
	case "offline_access":
		return "Stay signed in (issue refresh tokens)"
	default:
		return "Access: " + scope
	}
}
