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

// fileRoot anchors RELATIVE keys on the file backend. Store keys are
// documented as absolute paths (":27 above"), but the vault's wrapped-keys key
// is bare — which, unanchored, resolved against the process CWD
// (/home/nonroot in the distroless image, unwritable) and silently broke
// sealing custody on every file-backend deployment (found by the CI tls-boot
// leg, 2026-08-12; invisible until then because every TLS deployment ran the
// Postgres backend, where a bare key is a ROW KEY and must stay bare —
// re-keying it would orphan the existing custody row). Empty = legacy
// CWD-relative behavior (tests, default build).
var fileRoot string

// SetFileRoot sets the anchor for relative file-backend keys. Called once by
// main's initStoreBackend with the data volume; absolute keys are unaffected.
func SetFileRoot(root string) { fileRoot = root }

func (FileKV) resolve(key string) string {
	if fileRoot == "" || filepath.IsAbs(key) {
		return key
	}
	return filepath.Join(fileRoot, key)
}

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

func (f FileKV) Load(key string) ([]byte, error) { return os.ReadFile(f.resolve(key)) }

// Save writes `data` durably at the resolved key: a temp file in the SAME
// directory, then an atomic rename over the target.
//
// The temp name is UNIQUE per call (os.CreateTemp). It used to be the fixed
// "<key>.tmp", which made two concurrent Saves of the SAME key corrupt each
// other:
//
//	A: write tmp → B: write tmp → A: rename(tmp,key) ok → B: rename(tmp,key) ENOENT
//
// — i.e. B's write was LOST and surfaced as
// "rename /data/audit.json.tmp /data/audit.json: no such file or directory".
// The audit trail (Record runs on essentially every authenticated request) was
// the heaviest concurrent writer of a single key and lost writes constantly, so
// the trail did not survive an api restart on the file backend.
//
// The pattern keeps the ".tmp" SUFFIX ("<base>.<random>.tmp") because
// LoadPrefix skips in-flight temporaries by that suffix — see prefix.go.
func (f FileKV) Save(key string, data []byte) error {
	key = f.resolve(key)
	dir := filepath.Dir(key)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Same directory ⇒ same filesystem ⇒ the rename below is atomic.
	tmp, err := os.CreateTemp(dir, filepath.Base(key)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	committed := false
	defer func() {
		if committed {
			return
		}
		// Litter cleanup on every failure path. The temp file is a
		// never-committed record nothing can read, and there is no useful
		// recovery from failing to abandon a file we are already abandoning —
		// the returned error is the one the caller must act on.
		_ = tmp.Close()     // best-effort: closing an abandoned temp file; the Save error is what matters
		_ = os.Remove(name) // best-effort: unlink of an uncommitted temp; nothing can read it either way
	}()
	// CreateTemp opens 0600 already; set it explicitly so the data file's mode
	// does not depend on the process umask.
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, key); err != nil {
		return err
	}
	committed = true
	return nil
}
