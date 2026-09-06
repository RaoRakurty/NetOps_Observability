package platformdb

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SwapBackendForTest replaces the active backend and returns a restore func —
// TEST SUPPORT ONLY (production selects the backend once at boot).
func SwapBackendForTest(b Backend) (restore func()) {
	prev := active
	active = b
	return func() { active = prev }
}

// BeginForTest opens a raw (RLS-unscoped) transaction — TEST SUPPORT ONLY, for
// seeding shapes production writes refuse; production code goes through
// WithTenant exclusively.
func (db *DB) BeginForTest(ctx context.Context) (pgx.Tx, error) { return db.pool.Begin(ctx) }

// PoolForTest exposes the raw pool — TEST SUPPORT ONLY. The pgintegration
// suite (F-12) proves pool-level runtime params (statement_timeout,
// lock_timeout) and advisory-lock behaviour, which by design are not reachable
// through the tenant-scoped production surface.
func (db *DB) PoolForTest() *pgxpool.Pool { return db.pool }

// MigrationLockKeyForTest exposes the migration advisory-lock key — TEST
// SUPPORT ONLY, so the pgintegration suite can prove the lock actually
// excludes a second migrator.
func MigrationLockKeyForTest() int64 { return migrationLockKey }

// StoredRecordCountForTest reports how many records the Postgres target for a
// backend key holds — table rows for a normalized collection, the stored blob's
// record count for an app_kv one. TEST SUPPORT ONLY: production reads the same
// number through the importer's own verification step, never through an
// exported accessor. It exists so the cutover rehearsal can print the
// per-collection file→rows table the runbook asks for.
func (p *PGStore) StoredRecordCountForTest(ctx context.Context, key string) (int, error) {
	return p.storedRowCount(ctx, key)
}

// FileRecordCountForTest reports how many records a file-backend blob holds, by
// shape (array elements, or 1 for a singleton document). TEST SUPPORT ONLY —
// the rehearsal's "file count" column.
func FileRecordCountForTest(data []byte) int { return blobRecordCount(data) }
