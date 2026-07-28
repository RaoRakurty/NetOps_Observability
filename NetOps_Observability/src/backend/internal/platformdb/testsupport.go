package platformdb

import (
	"context"

	"github.com/jackc/pgx/v5"
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
