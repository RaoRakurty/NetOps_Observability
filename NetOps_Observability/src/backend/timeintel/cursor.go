package timeintel

// cursor.go — the incident_time_metrics backfill HIGH-WATER MARK (tracker 186).
//
// THE PROBLEM IT SOLVES
// The backfill pass used to be stateless: every 15 minutes it re-picked the
// OLDEST 20 000 objects in the 30-day window (ORDER BY window_start ASC LIMIT
// 20000) and re-derived them. Two consequences, both measured on storm-s07:
//
//   - 97 % of the 757 k objects in the window never got a snapshot at all —
//     the pass could not advance past the first cap-sized page, ever.
//   - the read grew with retention (56.81 → 59.89 GiB, ~0.6 GiB per leg) and
//     at 1.86 GiB / 35.4 GB / 1 931 054 rows it became the named victim of a
//     ClickHouse 4 GiB total-memory overcommit, evicting two background merges.
//
// THE CURSOR
// A pass now reads only what is NEW since the last one. The cursor is a point
// in the (created_at, correlation_id) order of netops.corr_current:
//
//   - created_at is the ReplacingMergeTree VERSION column of corr_current, so
//     an object's projection row is only ever replaced by one with a LATER
//     created_at. That makes it the monotone cursor for "this object changed",
//     covering both a brand-new object and a new version of an old one —
//     which window_start (device event time, and immutable across versions)
//     is not.
//   - correlation_id breaks ties INSIDE a pass so a page boundary that lands
//     in the middle of a millisecond can neither skip nor re-read forever.
//
// IDEMPOTENCY (why re-reading is always safe)
// The fold writes through MetricsStore.Upsert, which is a pure overwrite on
// the primary key (tenant_id, correlation_id, calculation_version) — a map
// assignment in memory, ON CONFLICT DO UPDATE in Postgres. Re-processing a
// page therefore cannot double-count: it rewrites the same row with the same
// derivation. The cursor is persisted only AFTER a page's upserts have all
// succeeded, so a crash mid-page costs a redo, never a gap.
//
// WHERE IT LIVES
// platformdb's key/value seam — the same one the export policy, token policy
// and notification config use — so it works unchanged on the file backend
// (atomic write under the data root) and the Postgres backend (a row in
// app_kv). No migration, and no new table for one timestamp.
//
// TENANT SCOPE (§3a)
// The cursor is PLATFORM-GLOBAL worker plumbing, not per-tenant data: the pass
// spans every tenant by design (each row is written back under the corr
// object's OWN tenant). One global cursor is therefore correct, and it is
// reachable only from the platform-admin-gated worker surface.

import (
	"encoding/json"
	"errors"
	"os"
	"time"

	"netops/backend/internal/platformdb"
)

// BackfillCursorKey is the platformdb key holding the cursor. RELATIVE on
// purpose: the file backend anchors it under the data root (platformdb.SetFileRoot),
// the Postgres backend treats it as a blob row key.
const BackfillCursorKey = "timeintel_backfill_cursor.json"

// BackfillCursor is the last (created_at, correlation_id) position a backfill
// pass has fully processed. The zero value means "nothing processed yet" and
// makes the first pass read from the start of the lookback window.
type BackfillCursor struct {
	// CreatedAt is corr_current.created_at of the last processed object.
	CreatedAt time.Time `json:"created_at"`
	// CorrelationID is the tie-break within CreatedAt. Empty means "no
	// tie-break" — the predicate degrades to a closed lower bound, which
	// re-reads the boundary instead of skipping it.
	CorrelationID string `json:"correlation_id,omitempty"`
	// UpdatedAt is when the cursor was last written. Operational only.
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// IsZero reports whether the cursor has never been advanced.
func (c BackfillCursor) IsZero() bool { return c.CreatedAt.IsZero() }

// Ahead reports whether (createdAt, corrID) sorts strictly AFTER the cursor in
// the (created_at, correlation_id) order.
func (c BackfillCursor) Ahead(createdAt time.Time, corrID string) bool {
	if c.IsZero() {
		return true
	}
	if createdAt.After(c.CreatedAt) {
		return true
	}
	if createdAt.Before(c.CreatedAt) {
		return false
	}
	return corrID > c.CorrelationID
}

// Advance returns the cursor moved to (createdAt, corrID). It NEVER moves
// backwards: a page whose last row sorts before the current mark leaves the
// cursor where it is, so an out-of-order answer cannot rewind progress and
// turn the pass back into a full re-read.
func (c BackfillCursor) Advance(createdAt time.Time, corrID string, now time.Time) BackfillCursor {
	if createdAt.IsZero() || !c.Ahead(createdAt, corrID) {
		return c
	}
	return BackfillCursor{CreatedAt: createdAt.UTC(), CorrelationID: corrID, UpdatedAt: now.UTC()}
}

// Rewind returns the cursor moved back by slack, with the tie-break dropped —
// the bounded RE-SCAN a pass starts from.
//
// Why a rewind is needed at all: corr_current is not only written by the
// engine's dual-write (which stamps the object's own created_at at the moment
// it is persisted, i.e. monotonically). corr_current_reconcile.go also repairs
// a drifted or missing projection row HOURLY, and it carries the ORIGINAL
// created_at across — so a row can appear in corr_current with a created_at
// that is already behind the mark. Starting each pass one reconcile period +
// one missed period behind the mark catches those; re-reading them costs
// nothing because the fold is an idempotent upsert.
//
// It is deliberately applied only at the START of a pass. Inside a pass the
// exact tie-broken cursor is used, or a page boundary would re-read its own
// predecessor and the loop would never advance.
func (c BackfillCursor) Rewind(slack time.Duration) BackfillCursor {
	if c.IsZero() || slack <= 0 {
		return c
	}
	return BackfillCursor{CreatedAt: c.CreatedAt.Add(-slack).UTC(), UpdatedAt: c.UpdatedAt}
}

// ── persistence ───────────────────────────────────────────────────────────────

// BackfillCursorStore persists one cursor through the platformdb KV seam.
type BackfillCursorStore struct{ key string }

// NewBackfillCursorStore builds the store. An empty key uses BackfillCursorKey.
func NewBackfillCursorStore(key string) *BackfillCursorStore {
	if key == "" {
		key = BackfillCursorKey
	}
	return &BackfillCursorStore{key: key}
}

// Load reads the cursor. THREE states, never two: the store did not answer
// (error — the caller must NOT treat that as "start from scratch", or an
// unreadable blob silently reinstates the full re-read this cursor exists to
// end), the key is absent or empty (zero cursor, first run), or a stored
// position.
func (s *BackfillCursorStore) Load() (BackfillCursor, error) {
	b, err := platformdb.Load(s.key)
	if errors.Is(err, os.ErrNotExist) {
		return BackfillCursor{}, nil
	}
	if err != nil {
		return BackfillCursor{}, err
	}
	if len(b) == 0 {
		return BackfillCursor{}, nil
	}
	var c BackfillCursor
	if err := json.Unmarshal(b, &c); err != nil {
		return BackfillCursor{}, err
	}
	// Zero-trust on stored state (§3): a corrupt tie-break must not reach the
	// SQL builder. Drop it rather than fail the pass — a cursor without a
	// tie-break is still a correct (merely closed) lower bound.
	if !ValidCorrelationUUID(c.CorrelationID) {
		c.CorrelationID = ""
	}
	c.CreatedAt = c.CreatedAt.UTC()
	return c, nil
}

// Save persists the cursor.
func (s *BackfillCursorStore) Save(c BackfillCursor) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return platformdb.Save(s.key, b)
}

// Reset clears the cursor so the next pass restarts from the beginning of the
// lookback window (an operator-triggered full re-derivation, e.g. after a
// calculation-version bump).
func (s *BackfillCursorStore) Reset() error { return s.Save(BackfillCursor{}) }

// ValidCorrelationUUID reports whether s is a canonical 8-4-4-4-12 hex UUID.
// Everything that reaches a ClickHouse literal is validated here rather than
// merely escaped: correlation ids are UUIDs by schema, so anything else is a
// corrupted cursor or a corrupted row, and neither belongs in a query.
func ValidCorrelationUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}
