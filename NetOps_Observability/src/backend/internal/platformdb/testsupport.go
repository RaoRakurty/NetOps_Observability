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
