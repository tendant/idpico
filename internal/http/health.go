// Package http provides HTTP server and handlers for the IdP.
package http

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

// HealthHandler handles health check endpoints.
type HealthHandler struct {
	// ready indicates if the server is ready to accept traffic.
	ready bool
	// check, when set, must succeed for /readyz to answer 200: it reaches
	// the persistence backend, so a pod whose database has gone away is
	// taken out of rotation rather than failing every login.
	check func(context.Context) error
}

// NewHealthHandler creates a new HealthHandler. check may be nil.
func NewHealthHandler(check func(context.Context) error) *HealthHandler {
	return &HealthHandler{
		ready: true,
		check: check,
	}
}

// SetReady sets the readiness status.
func (h *HealthHandler) SetReady(ready bool) {
	h.ready = ready
}

// Healthz handles the /healthz endpoint.
// Returns 200 OK if the server is alive.
func (h *HealthHandler) Healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Readyz handles the /readyz endpoint.
// Returns 200 OK if the server is ready to accept traffic, 503 otherwise.
func (h *HealthHandler) Readyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ready := h.ready
	if ready && h.check != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := h.check(ctx); err != nil {
			slog.Warn("readiness check failed", "error", err)
			ready = false
		}
	}
	if ready {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
	}
}
