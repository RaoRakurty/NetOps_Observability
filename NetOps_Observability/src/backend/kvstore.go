package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// kvstore.go — a process-wide persistence seam for the file-backed identity and
// saved-object stores (users, roles, tenants, api keys, refresh tokens, SNMP
// credentials, saved objects).
//
// Every one of those stores marshals its whole collection to a JSON blob and
// writes it durably; they only differ in the shape of that blob. Routing all of
// them through a single `kvBackend` means moving from local files to Postgres is
// a one-line backend swap (STORE_BACKEND=postgres) with NO change to any store's
// logic and NO change to the HTTP API — exactly the roadmap's "swap to Postgres
// later with no API-surface change".
//
// The default backend is `fileKV` (the original atomic-file behavior). The
// Postgres backend (pgstore.go) normalizes each store's collection into per-row,
// Row-Level-Security-protected tables via the allowlisted, vendored pgx driver
// (CLAUDE.md §6); it is compiled in but used only when an operator opts in with
// STORE_BACKEND=postgres, so the default file build is unaffected.

// kvBackend abstracts where a store persists its JSON blob. The `key` is the
// store's configured path (e.g. "/data/users.json"): the file backend treats it
// as a filesystem path; the Postgres backend treats it as a row key. A missing
// key must return an os.ErrNotExist-wrapped error so existing
// `errors.Is(err, os.ErrNotExist)` checks in the store constructors hold for
// both backends (an absent key just means "empty store").
type kvBackend interface {
	Load(key string) ([]byte, error)
	Save(key string, data []byte) error
}

// backend is the process-wide store backend, selected once at startup by
// initStoreBackend. Defaults to files so tests and the default build need no env.
var backend kvBackend = fileKV{}

// initStoreBackend selects the backend from STORE_BACKEND (default "file").
// Returns an error (so startup fails fast) when "postgres" is requested but the
// DSN/driver isn't usable — never a silent fallback to files.
func initStoreBackend() error {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("STORE_BACKEND"))) {
	case "", "file":
		backend = fileKV{}
		return nil
	case "postgres", "postgresql", "pg":
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		pg, err := newPgStore(ctx, os.Getenv("DATABASE_URL"))
		if err != nil {
			return err
		}
		backend = pg
		return nil
	default:
		return fmt.Errorf("unknown STORE_BACKEND %q (want file|postgres)", os.Getenv("STORE_BACKEND"))
	}
}

// kvLoad / kvSave are the helpers the stores call instead of touching os/sql
// directly.
func kvLoad(key string) ([]byte, error)    { return backend.Load(key) }
func kvSave(key string, data []byte) error { return backend.Save(key, data) }

// fileKV is the default backend: atomic JSON files on local disk. Centralizing
// the temp-file + rename write here gives every store the same durable-write
// contract (and removes the copy that used to live in each store's flushLocked).
type fileKV struct{}

func (fileKV) Load(key string) ([]byte, error) { return os.ReadFile(key) }

func (fileKV) Save(key string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(key), 0o755); err != nil {
		return err
	}
	tmp := key + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, key)
}
