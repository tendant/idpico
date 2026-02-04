// Package metrics provides Prometheus metrics for the IdP.
package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// HTTP request metrics
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "idp_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "idp_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// Authentication metrics
	loginAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "idp_login_attempts_total",
			Help: "Total number of login attempts",
		},
		[]string{"status"}, // "success", "failure", "locked"
	)

	activeSessionsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "idp_active_sessions",
			Help: "Number of active sessions",
		},
	)

	// Token metrics
	tokensIssuedTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "idp_tokens_issued_total",
			Help: "Total number of tokens issued",
		},
		[]string{"type", "grant_type"}, // type: "access", "refresh", "id"
	)

	tokenIntrospectionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "idp_token_introspections_total",
			Help: "Total number of token introspection requests",
		},
		[]string{"active"}, // "true" or "false"
	)

	tokenRevocationsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "idp_token_revocations_total",
			Help: "Total number of token revocation requests",
		},
	)

	// Authorization code metrics
	authCodesIssuedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "idp_auth_codes_issued_total",
			Help: "Total number of authorization codes issued",
		},
	)

	// Rate limiting metrics
	rateLimitExceededTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "idp_rate_limit_exceeded_total",
			Help: "Total number of rate limit exceeded events",
		},
		[]string{"endpoint"},
	)

	// Account lockout metrics
	accountLockoutsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "idp_account_lockouts_total",
			Help: "Total number of account lockouts",
		},
	)
)

// RecordLogin records a login attempt.
func RecordLogin(status string) {
	loginAttemptsTotal.WithLabelValues(status).Inc()
}

// RecordTokenIssued records a token being issued.
func RecordTokenIssued(tokenType, grantType string) {
	tokensIssuedTotal.WithLabelValues(tokenType, grantType).Inc()
}

// RecordTokenIntrospection records a token introspection.
func RecordTokenIntrospection(active bool) {
	tokenIntrospectionsTotal.WithLabelValues(strconv.FormatBool(active)).Inc()
}

// RecordTokenRevocation records a token revocation.
func RecordTokenRevocation() {
	tokenRevocationsTotal.Inc()
}

// RecordAuthCodeIssued records an authorization code being issued.
func RecordAuthCodeIssued() {
	authCodesIssuedTotal.Inc()
}

// RecordRateLimitExceeded records a rate limit exceeded event.
func RecordRateLimitExceeded(endpoint string) {
	rateLimitExceededTotal.WithLabelValues(endpoint).Inc()
}

// RecordAccountLockout records an account lockout.
func RecordAccountLockout() {
	accountLockoutsTotal.Inc()
}

// SetActiveSessions sets the number of active sessions.
func SetActiveSessions(count int) {
	activeSessionsGauge.Set(float64(count))
}

// Handler returns the Prometheus metrics HTTP handler.
func Handler() http.Handler {
	return promhttp.Handler()
}

// Middleware returns an HTTP middleware that records request metrics.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Seconds()
		path := normalizePath(r.URL.Path)

		httpRequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(wrapped.statusCode)).Inc()
		httpRequestDuration.WithLabelValues(r.Method, path).Observe(duration)
	})
}

type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// normalizePath normalizes the path for metrics to avoid high cardinality.
func normalizePath(path string) string {
	// Keep well-known paths as-is
	knownPaths := []string{
		"/healthz",
		"/readyz",
		"/metrics",
		"/login",
		"/logout",
		"/authorize",
		"/token",
		"/userinfo",
		"/revoke",
		"/introspect",
		"/.well-known/openid-configuration",
		"/.well-known/jwks.json",
		"/jwks",
	}

	for _, known := range knownPaths {
		if path == known {
			return path
		}
	}

	// Normalize unknown paths to prevent high cardinality
	return "/other"
}
