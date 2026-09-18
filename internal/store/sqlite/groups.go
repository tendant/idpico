package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

type groupRepository struct {
	db *sql.DB
}

const groupColumns = "id, name, description, created_at, updated_at"

func scanGroup(row interface{ Scan(...any) error }) (*domain.Group, error) {
	var g domain.Group
	if err := row.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.UpdatedAt); err != nil {
		return nil, err
	}
	return &g, nil
}

func (r *groupRepository) Create(ctx context.Context, group *domain.Group) error {
	now := time.Now()
	group.CreatedAt = now
	group.UpdatedAt = now

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO groups (`+groupColumns+`) VALUES (?, ?, ?, ?, ?)`,
		group.ID, group.Name, group.Description, utc(group.CreatedAt), utc(group.UpdatedAt),
	)
	if err != nil {
		if isUniqueViolation(err) && strings.Contains(err.Error(), "groups_name_idx") {
			return idperrors.AlreadyExists("group with name", group.Name)
		}
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("group", group.ID)
		}
		return idperrors.Internal("failed to create group", err)
	}
	return nil
}

func (r *groupRepository) GetByID(ctx context.Context, id string) (*domain.Group, error) {
	g, err := scanGroup(r.db.QueryRowContext(ctx, `SELECT `+groupColumns+` FROM groups WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("group", id)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load group", err)
	}
	return g, nil
}

func (r *groupRepository) GetByName(ctx context.Context, name string) (*domain.Group, error) {
	g, err := scanGroup(r.db.QueryRowContext(ctx, `SELECT `+groupColumns+` FROM groups WHERE LOWER(name) = LOWER(?)`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("group with name", name)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load group", err)
	}
	return g, nil
}

func (r *groupRepository) Update(ctx context.Context, group *domain.Group) error {
	group.UpdatedAt = time.Now()
	res, err := r.db.ExecContext(ctx,
		`UPDATE groups SET name = ?, description = ?, updated_at = ? WHERE id = ?`,
		group.Name, group.Description, utc(group.UpdatedAt), group.ID,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("group with name", group.Name)
		}
		return idperrors.Internal("failed to update group", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to update group", err)
	}
	if !ok {
		return idperrors.NotFound("group", group.ID)
	}
	return nil
}

func (r *groupRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return idperrors.Internal("failed to delete group", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to delete group", err)
	}
	if !ok {
		return idperrors.NotFound("group", id)
	}
	return nil
}

func (r *groupRepository) List(ctx context.Context) ([]*domain.Group, error) {
	return r.query(ctx, `SELECT `+groupColumns+` FROM groups ORDER BY LOWER(name)`)
}

func (r *groupRepository) query(ctx context.Context, q string, args ...any) ([]*domain.Group, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, idperrors.Internal("failed to list groups", err)
	}
	defer rows.Close()

	groups := []*domain.Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, idperrors.Internal("failed to scan group", err)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to list groups", err)
	}
	return groups, nil
}

func (r *groupRepository) AddMember(ctx context.Context, groupID, userID string) error {
	_, err := r.db.ExecContext(ctx,
		`INSERT INTO user_groups (user_id, group_id) VALUES (?, ?) ON CONFLICT DO NOTHING`, userID, groupID)
	if err != nil {
		if isForeignKeyViolation(err) {
			return referenceError("user or group")
		}
		return idperrors.Internal("failed to add group member", err)
	}
	return nil
}

func (r *groupRepository) RemoveMember(ctx context.Context, groupID, userID string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM user_groups WHERE user_id = ? AND group_id = ?`, userID, groupID)
	if err != nil {
		return idperrors.Internal("failed to remove group member", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to remove group member", err)
	}
	if !ok {
		return idperrors.NotFound("group membership", userID+"/"+groupID)
	}
	return nil
}

func (r *groupRepository) MemberIDs(ctx context.Context, groupID string) ([]string, error) {
	rows, err := r.db.QueryContext(ctx,
		`SELECT ug.user_id FROM user_groups ug JOIN users u ON u.id = ug.user_id WHERE ug.group_id = ? ORDER BY LOWER(u.email)`, groupID)
	if err != nil {
		return nil, idperrors.Internal("failed to list group members", err)
	}
	defer rows.Close()

	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, idperrors.Internal("failed to scan group member", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to list group members", err)
	}
	return ids, nil
}

func (r *groupRepository) GroupsForUser(ctx context.Context, userID string) ([]*domain.Group, error) {
	return r.query(ctx,
		`SELECT g.id, g.name, g.description, g.created_at, g.updated_at
		 FROM groups g JOIN user_groups ug ON ug.group_id = g.id
		 WHERE ug.user_id = ? ORDER BY LOWER(g.name)`, userID)
}

func (r *groupRepository) RemoveUser(ctx context.Context, userID string) error {
	if _, err := r.db.ExecContext(ctx, `DELETE FROM user_groups WHERE user_id = ?`, userID); err != nil {
		return idperrors.Internal("failed to remove user from groups", err)
	}
	return nil
}
