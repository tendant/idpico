package file

import (
	"context"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

// Audit Repository

type auditRepository struct {
	store *Store
}

type auditData struct {
	Events []*domain.AuditEvent `json:"events"`
}

func (r *auditRepository) load() (*auditData, error) {
	var data auditData
	if err := r.store.readFile("audit_events", &data); err != nil {
		return nil, err
	}
	if data.Events == nil {
		data.Events = []*domain.AuditEvent{}
	}
	return &data, nil
}

func (r *auditRepository) save(data *auditData) error {
	return r.store.writeFile("audit_events", data)
}

func (r *auditRepository) Append(ctx context.Context, e *domain.AuditEvent) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load audit events", err)
	}
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	data.Events = append(data.Events, e)
	return r.save(data)
}

func (r *auditRepository) List(ctx context.Context, limit int) ([]*domain.AuditEvent, error) {
	data, err := r.load()
	if err != nil {
		return nil, idperrors.Internal("failed to load audit events", err)
	}
	if limit <= 0 {
		limit = 100
	}
	events := append([]*domain.AuditEvent(nil), data.Events...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].At.After(events[j].At) })
	if len(events) > limit {
		events = events[:limit]
	}
	return events, nil
}

func (r *auditRepository) DeleteBefore(ctx context.Context, cutoff time.Time) error {
	data, err := r.load()
	if err != nil {
		return idperrors.Internal("failed to load audit events", err)
	}
	kept := data.Events[:0]
	for _, e := range data.Events {
		if !e.At.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	data.Events = kept
	return r.save(data)
}
