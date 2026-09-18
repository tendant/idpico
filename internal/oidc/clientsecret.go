package oidc

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"strings"

	"github.com/tendant/simple-idp/internal/auth"
	"github.com/tendant/simple-idp/internal/domain"
	"github.com/tendant/simple-idp/internal/store"
)

// Client secrets are stored as Argon2id hashes (the same scheme as user
// passwords). The plaintext is shown once when the secret is created and
// never again.

const clientSecretHashPrefix = "$argon2id$"

// HashClientSecret hashes a plaintext client secret for storage.
func HashClientSecret(secret string) (string, error) {
	return auth.HashPassword(secret)
}

// IsHashedClientSecret reports whether the stored value is already a hash.
// Stores created before secrets were hashed hold the plaintext.
func IsHashedClientSecret(stored string) bool {
	return strings.HasPrefix(stored, clientSecretHashPrefix)
}

// VerifyClientSecret checks a presented secret against the stored value.
// It returns whether it matched and whether the stored value is legacy
// plaintext that should be upgraded to a hash.
func VerifyClientSecret(stored, presented string) (ok, legacy bool) {
	if stored == "" || presented == "" {
		return false, false
	}
	if IsHashedClientSecret(stored) {
		match, err := auth.VerifyPassword(presented, stored)
		return err == nil && match, false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(presented)) == 1, true
}

// authenticateClient verifies a confidential client's secret and, when the
// store still holds the plaintext, replaces it with a hash on success.
func authenticateClient(ctx context.Context, clients store.ClientRepository, client *domain.Client, presented string) bool {
	if client.Public {
		return true
	}
	ok, legacy := VerifyClientSecret(client.Secret, presented)
	if !ok {
		return false
	}
	if legacy {
		if hash, err := HashClientSecret(presented); err == nil {
			client.Secret = hash
			if err := clients.Update(ctx, client); err != nil {
				slog.Warn("failed to upgrade plaintext client secret to hash", "client_id", client.ID, "error", err)
			} else {
				slog.Info("upgraded plaintext client secret to hash", "client_id", client.ID)
			}
		}
	}
	return true
}
