package http

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/tendant/simple-idp/internal/crypto"
)

// JWKSHandler handles JWKS endpoints.
type JWKSHandler struct {
	keyService *crypto.KeyService
	logger     *slog.Logger
}

// NewJWKSHandler creates a new JWKSHandler.
func NewJWKSHandler(keyService *crypto.KeyService, logger *slog.Logger) *JWKSHandler {
	return &JWKSHandler{
		keyService: keyService,
		logger:     logger,
	}
}

// JWKS handles the /.well-known/jwks.json endpoint.
func (h *JWKSHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	jwks, err := h.keyService.GetJWKS(r.Context())
	if err != nil {
		h.logger.Error("failed to get JWKS", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(jwks); err != nil {
		h.logger.Error("failed to encode JWKS", "error", err)
	}
}
