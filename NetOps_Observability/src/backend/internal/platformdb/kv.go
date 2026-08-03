package platformdb

import (
	"context"
	"os"
	"path/filepath"
)

// kvstore.go — a process-wide persistence seam for the file-backed identity and
// saved-object stores (users, roles, tenants, api keys, refresh tokens, SNMP
// credentials, saved objects).
//
// Every one of those stores marshals its whole collection to a JSON blob and
// writes it durably; they only differ in the shape of that blob. Routing all of
// them through a single `Backend` means moving from local files to Postgres is
// a one-line backend swap (STORE_BACKEND=postgres) with NO change to any store's
// logic and NO change to the HTTP API — exactly the roadmap's "swap to Postgres
// later with no API-surface change".
//
// The default backend is `FileKV` (the original atomic-file behavior). The
// Postgres backend (pgstore.go) normalizes each store's collection into per-row,
// Row-Level-Security-protected tables via the allowlisted, vendored pgx driver
// (CLAUDE.md §6); it is compiled in but used only when an operator opts in with
// STORE_BACKEND=postgres, so the default file build is unaffected.

// Backend abstracts where a store persists its JSON blob. The `key` is the
// store's configured path (e.g. "/data/users.json"): the file backend treats it
// as a filesystem path; the Postgres backend treats it as a row key. A missing
// key must return an os.ErrNotExist-wrapped error so existing
// `errors.Is(err, os.ErrNotExist)` checks in the store constructors hold for
// both backends (an absent key just means "empty store").
type Backend interface {
	Load(key string) ([]byte, error)
	Save(key string, data []byte) error
}

// backend is the process-wide store backend, selected once at startup by
// initStoreBackend. Defaults to files so tests and the default build need no env.
// active is the process-wide store backend, selected once at boot by main's
// initStoreBackend (env switch stays with the integrator). Defaults to files
// so tests and the default build need no wiring.
var active Backend = FileKV{}

// UseFile selects the file backend (the default).
func UseFile() { active = FileKV{} }

// UsePostgres connects the per-row RLS-backed store and makes it active.
// Fails fast — never a silent fallback to files.
func UsePostgres(ctx context.Context, dsn string) error {
	pg, err := NewPGStore(ctx, dsn)
	if err != nil {
		return err
	}
	active = pg
	return nil
}

// ActivePG reports whether the current backend is the Postgres store (the
// selectors' pg-vs-file switch), returning it when so.
func ActivePG() (*PGStore, bool) {
	pg, ok := active.(*PGStore)
	return pg, ok
}

// kvLoad / kvSave are the helpers the stores call instead of touching os/sql
// directly.
// Load / Save are the helpers the stores call instead of touching os/sql.
func Load(key string) ([]byte, error)    { return active.Load(key) }
func Save(key string, data []byte) error { return active.Save(key, data) }

// FileKV is the default backend: atomic JSON files on local disk. Centralizing
// the temp-file + rename write here gives every store the same durable-write
// contract (and removes the copy that used to live in each store's flushLocked).
type FileKV struct{}

func (FileKV) Load(key string) ([]byte, error) { return os.ReadFile(key) }

func (FileKV) Save(key string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(key), 0o755); err != nil {
		return err
	}
	tmp := key + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, key)
}
