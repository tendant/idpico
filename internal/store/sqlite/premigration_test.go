package sqlite

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/tendant/idpico/internal/store/migrations"
)

// oldDatabase leaves a database at path as a release with schema version
// 3 would have: migrated that far, with one user in it.
func oldDatabase(t *testing.T, path string) {
	t.Helper()
	ctx := context.Background()
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := migrations.UpTo(ctx, db, goose.DialectSQLite3, 3); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO users (id, email, password_hash, display_name, active, email_verified, admin, created_at, updated_at)
		VALUES ('u1', 'old@example.com', 'x', 'Old', 1, 1, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
}

func backups(t *testing.T, dir string) []string {
	t.Helper()
	matches, _ := filepath.Glob(filepath.Join(dir, "backups", "*.db"))
	return matches
}

// Migrations are forward-only, so opening a database that needs migrating
// first copies it, unmigrated, to backups/.
func TestNewStore_BacksUpBeforeMigrating(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "idpico.db")
	oldDatabase(t, path)

	s, err := NewStore(ctx, path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if _, err := s.Users().GetByEmail(ctx, "old@example.com"); err != nil {
		t.Errorf("migrated database lost the user: %v", err)
	}
	s.Close()

	got := backups(t, dir)
	if len(got) != 1 || !strings.Contains(filepath.Base(got[0]), "-v3-to-v") {
		t.Fatalf("backups = %v, want one idpico-pre-migration-v3-to-v… file", got)
	}
	// The backup is the database as it was: schema 3, the user present.
	db, err := sql.Open("sqlite", dsn(got[0]))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version_id) FROM goose_db_version`).Scan(&version); err != nil || version != 3 {
		t.Errorf("backup schema version = %d, %v; want 3", version, err)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil || n != 1 {
		t.Errorf("backup users = %d, %v; want 1", n, err)
	}

	// Opening the now current database again takes no further backup.
	s, err = NewStore(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if got := backups(t, dir); len(got) != 1 {
		t.Errorf("reopening an up-to-date database added backups: %v", got)
	}
}

func TestNewStore_NoBackupForNewDatabase(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(context.Background(), filepath.Join(dir, "idpico.db"))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := os.Stat(filepath.Join(dir, "backups")); !os.IsNotExist(err) {
		t.Errorf("a new database was backed up (backups/ exists: %v)", err)
	}
}

// If the backup cannot be written the database is left unmigrated, so the
// previous release can still open it.
func TestNewStore_FailedBackupBlocksMigration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "idpico.db")
	oldDatabase(t, path)
	if err := os.WriteFile(filepath.Join(dir, "backups"), nil, 0o600); err != nil { // a file where the directory should go
		t.Fatal(err)
	}

	if _, err := NewStore(ctx, path); err == nil || !strings.Contains(err.Error(), "nothing was migrated") {
		t.Fatalf("NewStore error = %v, want a refused migration", err)
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int64
	if err := db.QueryRowContext(ctx, `SELECT MAX(version_id) FROM goose_db_version`).Scan(&version); err != nil || version != 3 {
		t.Errorf("schema version = %d, %v; want 3 (unmigrated)", version, err)
	}
}
