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
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
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
// the (created_at, correlation_id) order — the order the pick SQL scans in,
// which for the UUID tie-break is ClickHouse's NATIVE order, not Go's text
// order (ultra finding #4; see CompareCorrelationUUID). Comparing here in any
// other order makes Go and the server disagree about which boundary rows are
// "already processed" whenever a page boundary lands inside one millisecond:
// the mark then refuses to advance past rows the server has already returned
// and the pass re-reads them every tick.
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
	return CompareCorrelationUUID(corrID, c.CorrelationID) > 0
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

// CompareCorrelationUUID compares two correlation-id UUIDs in ClickHouse's
// NATIVE UUID order (-1/0/+1, strcmp-style).
//
// ClickHouse does not order UUIDs the way their canonical text orders: a UUID
// is stored as a UInt128 whose two 64-bit halves are SWAPPED relative to the
// text — the LOW half of the integer holds the first 8 text bytes and the HIGH
// half holds the last 8 — so ORDER BY compares the SECOND half of the text
// first, then the first, big-endian within each half.
//
// MEASURED, not assumed (read-only probe, log_comment 'probe-ultra-ti',
// ClickHouse 24.8.14.39, 2026-09-01): ORDER BY u ASC over crafted UUIDs gives
//
//	0000000a-0000-0000-0000-000000000000
//	a0000000-0000-0000-0000-000000000000
//	ffffffff-ffff-ffff-0000-000000000001
//	00000000-0000-0000-0000-00000000000a
//	00000000-0000-0000-a000-000000000000
//	00000000-0000-0000-ffff-ffffffffffff
//	00000000-0000-0001-ffff-ffffffffffff
//
// i.e. every UUID with a zero second half sorts before every UUID with a
// non-zero one, whatever its first half — text order says the opposite for
// rows 3 and 4. The same probe confirmed each half compares big-endian
// (byte 0 outranks byte 7; byte 8 outranks byte 15).
//
// WHY THE CURSOR MUST USE THIS ORDER (ultra finding #4): the pick SQL both
// ORDERs BY and compares the cursor tuple against the RAW UUID column
// (deliberately — see timeIntelBackfillPickSQL's alias-shadowing note), so the
// server's scan order is the native order. If Go advances the mark using TEXT
// order instead, then on a created_at tie the two sides disagree: rows the
// server already returned can look "not ahead" to Go, the mark refuses to
// advance past them, and the pass re-reads the boundary every tick (a
// degradation; a stall needs >page-size rows in one millisecond).
//
// A string that is not a canonical UUID cannot be given a native position, so
// the comparison degrades to plain byte order — which keeps the one property
// the cursor relies on: the empty string ("no tie-break") sorts before every
// real id.
func CompareCorrelationUUID(a, b string) int {
	ab, aok := uuidBytes(a)
	bb, bok := uuidBytes(b)
	if !aok || !bok {
		return strings.Compare(a, b)
	}
	if c := bytes.Compare(ab[8:], bb[8:]); c != 0 {
		return c
	}
	return bytes.Compare(ab[:8], bb[:8])
}

// uuidBytes parses a canonical 8-4-4-4-12 UUID into its 16 big-endian bytes.
// Case-insensitive, like the server's parser: 'AA' and 'aa' are the same octet.
func uuidBytes(s string) ([16]byte, bool) {
	var out [16]byte
	if !ValidCorrelationUUID(s) {
		return out, false
	}
	i := 0
	for j := 0; j < len(s); j++ {
		c := s[j]
		if c == '-' {
			continue
		}
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		default: // 'A'..'F' — ValidCorrelationUUID admits nothing else
			v = c - 'A' + 10
		}
		if i%2 == 0 {
			out[i/2] = v << 4
		} else {
			out[i/2] |= v
		}
		i++
	}
	return out, true
}

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
