// Package sqlite implements store.Store and crypto.KeyRepository on top of a
// SQLite database using the pure-Go modernc.org/sqlite driver (no cgo).
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/tendant/simple-idp/internal/store"
	"github.com/tendant/simple-idp/internal/store/migrations"
	sqlite "modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

// Store implements store.Store using SQLite.
type Store struct {
	db *sql.DB

	users       *userRepository
	clients     *clientRepository
	sessions    *sessionRepository
	authCodes   *authCodeRepository
	tokens      *tokenRepository
	signingKeys *signingKeyRepository
	keys        *KeyRepository
}

// NewStore opens (creating if needed) the SQLite database at path, applies
// pending migrations, and returns a ready-to-use store.
//
// path may be a plain file path or a modernc.org/sqlite DSN. Use ":memory:"
// for an ephemeral in-memory database.
func NewStore(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("sqlite: database path is required")
	}

	if !isMemory(path) && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// SQLite allows a single writer; a single pooled connection keeps
	// database/sql from producing SQLITE_BUSY under concurrent writes and is
	// required for ":memory:" databases (each connection would otherwise get
	// its own empty database).
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to sqlite database: %w", err)
	}

	if err := migrations.Up(ctx, db, goose.DialectSQLite3); err != nil {
		db.Close()
		return nil, err
	}

	s := &Store{db: db}
	s.users = &userRepository{db: db}
	s.clients = &clientRepository{db: db}
	s.sessions = &sessionRepository{db: db}
	s.authCodes = &authCodeRepository{db: db}
	s.tokens = &tokenRepository{db: db}
	s.signingKeys = &signingKeyRepository{db: db}
	s.keys = &KeyRepository{db: db}

	return s, nil
}

func (s *Store) Users() store.UserRepository             { return s.users }
func (s *Store) Clients() store.ClientRepository         { return s.clients }
func (s *Store) Sessions() store.SessionRepository       { return s.sessions }
func (s *Store) AuthCodes() store.AuthCodeRepository     { return s.authCodes }
func (s *Store) Tokens() store.TokenRepository           { return s.tokens }
func (s *Store) SigningKeys() store.SigningKeyRepository { return s.signingKeys }
func (s *Store) Close() error                            { return s.db.Close() }

// Keys returns the crypto.KeyRepository backed by this store's signing_keys table.
func (s *Store) Keys() *KeyRepository { return s.keys }

// DB exposes the underlying database handle (for tests and tooling).
func (s *Store) DB() *sql.DB { return s.db }

func isMemory(path string) bool {
	return path == ":memory:" || strings.Contains(path, "mode=memory")
}

// dsn builds a modernc.org/sqlite DSN with the pragmas this store relies on.
func dsn(path string) string {
	if strings.HasPrefix(path, "file:") {
		return path // caller supplied a full DSN; trust it as-is
	}

	pragmas := []string{"busy_timeout(5000)", "foreign_keys(ON)"}
	if !isMemory(path) {
		pragmas = append(pragmas, "journal_mode(WAL)", "synchronous(NORMAL)")
	}
	return "file:" + path + "?_pragma=" + strings.Join(pragmas, "&_pragma=")
}

// Helpers shared by the repositories

// utc normalizes timestamps before binding so that string comparison in
// SQLite (e.g. expires_at < ?) is consistent regardless of the caller's zone.
func utc(t time.Time) time.Time { return t.UTC() }

// isUniqueViolation reports whether err is a UNIQUE / PRIMARY KEY constraint failure.
func isUniqueViolation(err error) bool {
	var serr *sqlite.Error
	if !errors.As(err, &serr) {
		return false
	}
	code := serr.Code()
	return code == sqlite3.SQLITE_CONSTRAINT_UNIQUE || code == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}

// violatesColumn reports whether a unique-violation error names table.column.
func violatesColumn(err error, table, column string) bool {
	return isUniqueViolation(err) && strings.Contains(err.Error(), table+"."+column)
}

// rowsAffected returns whether an UPDATE/DELETE touched at least one row.
func rowsAffected(res sql.Result) (bool, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
