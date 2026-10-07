// Package migrations embeds SQL schema migrations and applies them with goose.
//
// Migrations are grouped by dialect (one directory per SQL engine) so that the
// same repository code can run against multiple databases while each engine
// gets DDL written in its own type vocabulary.
//
// Released migrations are frozen: once a version has shipped, schema changes
// go in a new numbered file (goose applies them in order and records each in
// goose_db_version), never in an existing one.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
)

//go:embed sqlite/*.sql
var files embed.FS

// Option configures Up.
type Option func(*options)

type options struct {
	beforeMigrate func(ctx context.Context, current, target int64) error
}

// BeforeMigrate registers fn to run once before migrations are applied to a
// database that already has a schema (current > 0) and is behind the
// embedded migrations (current < target). A fresh database does not call it.
// If fn fails, nothing is migrated and Up returns its error.
func BeforeMigrate(fn func(ctx context.Context, current, target int64) error) Option {
	return func(o *options) { o.beforeMigrate = fn }
}

// Up applies all pending migrations for the given dialect to db.
func Up(ctx context.Context, db *sql.DB, dialect goose.Dialect, opts ...Option) error {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	provider, err := newProvider(db, dialect)
	if err != nil {
		return err
	}

	if o.beforeMigrate != nil {
		current, target, err := provider.GetVersions(ctx)
		if err != nil {
			return fmt.Errorf("failed to read schema version: %w", err)
		}
		if current > 0 && current < target {
			if err := o.beforeMigrate(ctx, current, target); err != nil {
				return err
			}
		}
	}

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}
	return nil
}

// UpTo applies migrations up to and including version; for tests that need
// a database as an older release left it.
func UpTo(ctx context.Context, db *sql.DB, dialect goose.Dialect, version int64) error {
	provider, err := newProvider(db, dialect)
	if err != nil {
		return err
	}
	if _, err := provider.UpTo(ctx, version); err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}
	return nil
}

func newProvider(db *sql.DB, dialect goose.Dialect) (*goose.Provider, error) {
	dir, ok := dialectDir(dialect)
	if !ok {
		return nil, fmt.Errorf("no migrations for dialect %q", dialect)
	}
	sub, err := fs.Sub(files, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open migrations for %s: %w", dialect, err)
	}
	provider, err := goose.NewProvider(dialect, db, sub)
	if err != nil {
		return nil, fmt.Errorf("failed to create migration provider: %w", err)
	}
	return provider, nil
}

func dialectDir(dialect goose.Dialect) (string, bool) {
	switch dialect {
	case goose.DialectSQLite3:
		return "sqlite", true
	default:
		return "", false
	}
}
