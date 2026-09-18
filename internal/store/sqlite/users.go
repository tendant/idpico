package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/tendant/simple-idp/internal/domain"
	idperrors "github.com/tendant/simple-idp/internal/errors"
)

type userRepository struct {
	db *sql.DB
}

const userColumns = "id, email, password_hash, display_name, active, created_at, updated_at"

func scanUser(row interface{ Scan(...any) error }) (*domain.User, error) {
	var u domain.User
	if err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Active, &u.CreatedAt, &u.UpdatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := r.db.ExecContext(ctx,
		`INSERT INTO users (`+userColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Email, user.PasswordHash, user.DisplayName, user.Active, utc(user.CreatedAt), utc(user.UpdatedAt),
	)
	if err != nil {
		if violatesUserEmail(err) {
			return idperrors.AlreadyExists("user with email", user.Email)
		}
		if isUniqueViolation(err) {
			return idperrors.AlreadyExists("user", user.ID)
		}
		return idperrors.Internal("failed to create user", err)
	}
	return nil
}

func (r *userRepository) GetByID(ctx context.Context, id string) (*domain.User, error) {
	u, err := scanUser(r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("user", id)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load user", err)
	}
	return u, nil
}

func (r *userRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	u, err := scanUser(r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE LOWER(email) = LOWER(?)`, email))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, idperrors.NotFound("user with email", email)
	}
	if err != nil {
		return nil, idperrors.Internal("failed to load user", err)
	}
	return u, nil
}

func (r *userRepository) Update(ctx context.Context, user *domain.User) error {
	user.UpdatedAt = time.Now()

	res, err := r.db.ExecContext(ctx,
		`UPDATE users SET email = ?, password_hash = ?, display_name = ?, active = ?, updated_at = ? WHERE id = ?`,
		user.Email, user.PasswordHash, user.DisplayName, user.Active, utc(user.UpdatedAt), user.ID,
	)
	if err != nil {
		if violatesUserEmail(err) {
			return idperrors.AlreadyExists("user with email", user.Email)
		}
		return idperrors.Internal("failed to update user", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to update user", err)
	}
	if !ok {
		return idperrors.NotFound("user", user.ID)
	}
	return nil
}

func (r *userRepository) Delete(ctx context.Context, id string) error {
	res, err := r.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return idperrors.Internal("failed to delete user", err)
	}
	ok, err := rowsAffected(res)
	if err != nil {
		return idperrors.Internal("failed to delete user", err)
	}
	if !ok {
		return idperrors.NotFound("user", id)
	}
	return nil
}

func (r *userRepository) List(ctx context.Context) ([]*domain.User, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at, id`)
	if err != nil {
		return nil, idperrors.Internal("failed to list users", err)
	}
	defer rows.Close()

	users := []*domain.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, idperrors.Internal("failed to scan user", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, idperrors.Internal("failed to list users", err)
	}
	return users, nil
}
