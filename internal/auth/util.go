package auth

import (
	"github.com/google/uuid"
)

// generateUUID generates a new UUID string.
func generateUUID() string {
	return uuid.New().String()
}
