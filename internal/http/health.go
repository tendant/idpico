// Package http provides HTTP server and handlers for the IdP.
package http

import (
	"encoding/json"
	"net/http"
)

// HealthHandler handles health check endpoints.
type HealthHandler struct {
	// ready indicates if the server is ready to accept traffic.
	ready bool
}

// NewHealthHandler creates a new HealthHandler.
func NewHealthHandler() *HealthHandler {
	return &HealthHandler{
		ready: true,
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
	if h.ready {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
	}
}
