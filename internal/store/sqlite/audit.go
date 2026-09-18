package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
	"github.com/tendant/idpico/internal/domain"
	idperrors "github.com/tendant/idpico/internal/errors"
)

type auditRepository struct {
	db *sql.DB
}

const auditColumns = "id, at, actor_id, actor_email, action, target_type, target_id, detail, ip"

func (r *auditRepository) Append(ctx context.Context, e *domain.AuditEvent) error {
	if e.ID == "" {
		e.ID = uuid.New().String()
	}
	if e.At.IsZero() {
		e.At = time.Now()
	}
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO audit_events (`+auditColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, utc(e.At), e.ActorID, e.ActorEmail, e.Action, e.TargetType, e.TargetID, e.Detail, e.IP,
	)
	if err != nil {
		return idperrors.Internal("failed to append audit event", err)
	}
	return nil
}

func (r *auditRepository) List(ctx context.Context, limit int) ([]*domain.AuditEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.QueryContext(ctx,
		`SELECT `+auditColumns+` FROM audit_events ORDER BY at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, idperrors.Internal("failed to list audit events", err)
	}
	defer rows.Close()

	events := []*domain.AuditEvent{}
	for rows.Next() {
		var e domain.AuditEvent
		if err := rows.Scan(&e.ID, &e.At, &e.ActorID, &e.ActorEmail, &e.Action, &e.TargetType, &e.TargetID, &e.Detail, &e.IP); err != nil {
			return nil, idperrors.Internal("failed to scan audit event", err)
		}
		events = append(events, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to list audit events", err)
	}
	return events, nil
}

func (r *auditRepository) DeleteBefore(ctx context.Context, cutoff time.Time) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM audit_events WHERE at < ?`, utc(cutoff)); err != nil {
		return idperrors.Internal("failed to prune audit events", err)
	}
	return nil
}
