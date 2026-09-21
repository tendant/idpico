// Package maintenance runs periodic housekeeping: purging expired sessions,
// authorization codes and tokens, rotating the signing key once it reaches
// its maximum age, and removing signing keys whose grace period has ended.
package maintenance

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/tendant/idpico/internal/audit"
	"github.com/tendant/idpico/internal/crypto"
	"github.com/tendant/idpico/internal/store"
)

// Runner executes the maintenance tasks.
type Runner struct {
	store  store.Store
	keys   *crypto.KeyService
	logger *slog.Logger

	interval  time.Duration // how often Run executes the tasks
	keyMaxAge time.Duration // rotate the active key once older than this; 0 disables
	keyGrace  time.Duration // how long a rotated key stays valid for verification

	auditRetention time.Duration // prune audit events older than this; 0 keeps everything
	audit          *audit.Recorder
}

// WithAuditRetention prunes audit events older than d on each run (0 = keep forever).
func WithAuditRetention(d time.Duration) Option {
	return func(r *Runner) { r.auditRetention = d }
}

// WithAudit records key rotations performed by the maintenance loop.
func WithAudit(rec *audit.Recorder) Option {
	return func(r *Runner) { r.audit = rec }
}

// Option configures the Runner.
type Option func(*Runner)

// WithLogger sets the logger.
func WithLogger(logger *slog.Logger) Option {
	return func(r *Runner) { r.logger = logger }
}

// WithInterval sets how often the tasks run.
func WithInterval(d time.Duration) Option {
	return func(r *Runner) { r.interval = d }
}

// WithKeyRotation enables signing key rotation: keys older than maxAge are
// replaced, and the replaced key remains valid for verification for grace.
func WithKeyRotation(maxAge, grace time.Duration) Option {
	return func(r *Runner) {
		r.keyMaxAge = maxAge
		r.keyGrace = grace
	}
}

// NewRunner creates a Runner. keys may be nil to skip key maintenance.
func NewRunner(s store.Store, keys *crypto.KeyService, opts ...Option) *Runner {
	r := &Runner{
		store:    s,
		keys:     keys,
		logger:   slog.Default(),
		interval: 10 * time.Minute,
		keyGrace: 24 * time.Hour,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Run executes the tasks immediately and then on every interval until ctx is
// cancelled. Errors are logged, never fatal.
func (r *Runner) Run(ctx context.Context) {
	r.runLogged(ctx)

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.runLogged(ctx)
		}
	}
}

func (r *Runner) runLogged(ctx context.Context) {
	if err := r.RunOnce(ctx); err != nil {
		r.logger.Error("maintenance run failed", "error", err)
	}
}

// RunOnce executes every task a single time. Tasks are independent: one
// failing does not stop the others, and all errors are returned joined.
func (r *Runner) RunOnce(ctx context.Context) error {
	var errs []error

	if err := r.store.Sessions().DeleteExpired(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := r.store.AuthCodes().DeleteExpired(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := r.store.Tokens().DeleteExpired(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := r.store.Revocations().DeleteExpired(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := r.store.VerificationTokens().DeleteExpired(ctx); err != nil {
		errs = append(errs, err)
	}
	if r.auditRetention > 0 {
		if err := r.store.Audit().DeleteBefore(ctx, time.Now().Add(-r.auditRetention)); err != nil {
			errs = append(errs, err)
		}
	}

	if r.keys != nil {
		if err := r.maintainKeys(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	// Last, after the deletes above: keep the database file self-contained
	// so an operator's copy of idpico.db is never an empty page with the
	// data still in the WAL.
	if c, ok := r.store.(store.Checkpointer); ok {
		if err := c.Checkpoint(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	r.logger.Debug("maintenance run complete", "errors", len(errs))
	return errors.Join(errs...)
}

func (r *Runner) maintainKeys(ctx context.Context) error {
	rotate, err := r.keys.ShouldRotate(ctx, r.keyMaxAge)
	if err != nil {
		return err
	}
	if rotate {
		newKey, err := r.keys.RotateKey(ctx, r.keyGrace)
		if err != nil {
			return err
		}
		r.logger.Info("rotated signing key", "kid", newKey.Kid, "grace_period", r.keyGrace)
		r.audit.Record(ctx, audit.Event{ActorEmail: "maintenance", Action: audit.KeyRotated, TargetType: "key", TargetID: newKey.Kid, Detail: "scheduled rotation"})
	}

	return r.keys.CleanupExpiredKeys(ctx)
}
