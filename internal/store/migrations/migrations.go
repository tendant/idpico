// Package migrations embeds SQL schema migrations and applies them with goose.
//
// Migrations are grouped by dialect (one directory per SQL engine) so that the
// same repository code can run against multiple databases while each engine
// gets DDL written in its own type vocabulary.
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

// Up applies all pending migrations for the given dialect to db.
func Up(ctx context.Context, db *sql.DB, dialect goose.Dialect) error {
	dir, ok := dialectDir(dialect)
	if !ok {
		return fmt.Errorf("no migrations for dialect %q", dialect)
	}

	sub, err := fs.Sub(files, dir)
	if err != nil {
		return fmt.Errorf("failed to open migrations for %s: %w", dialect, err)
	}

	provider, err := goose.NewProvider(dialect, db, sub)
	if err != nil {
		return fmt.Errorf("failed to create migration provider: %w", err)
	}

	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}
	return nil
}

func dialectDir(dialect goose.Dialect) (string, bool) {
	switch dialect {
	case goose.DialectSQLite3:
		return "sqlite", true
	default:
		return "", false
	}
}
