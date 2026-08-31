package timeintel

// cursor_test.go — the watermark's own invariants (tracker 186). These are the
// properties the backfill worker's page loop assumes; if any of them stops
// holding, the pass silently either re-reads the world or skips rows.

import (
	"errors"
	"os"
	"testing"
	"time"

	"netops/backend/internal/platformdb"
)

func ts(min int) time.Time {
	return time.Date(2026, 8, 31, 0, 0, 0, 0, time.UTC).Add(time.Duration(min) * time.Minute)
}

const (
	idLow  = "11111111-1111-4111-8111-111111111111"
	idHigh = "22222222-2222-4222-8222-222222222222"
)

func TestBackfillCursorOrdersOnCreatedThenCorrelation(t *testing.T) {
	c := BackfillCursor{CreatedAt: ts(10), CorrelationID: idLow}
	cases := []struct {
		name    string
		at      time.Time
		id      string
		want    bool
		because string
	}{
		{"later timestamp", ts(11), idLow, true, "a newer object is always ahead"},
		{"earlier timestamp", ts(9), idHigh, false, "an older object is behind whatever its id"},
		{"same ms, higher id", ts(10), idHigh, true, "the tie-break carries the page boundary forward"},
		{"same ms, same id", ts(10), idLow, false, "the mark itself is not ahead of itself"},
		{"same ms, lower id", ts(10), "00000000-0000-4000-8000-000000000000", false, "already processed"},
	}
	for _, tc := range cases {
		if got := c.Ahead(tc.at, tc.id); got != tc.want {
			t.Errorf("%s: Ahead = %v, want %v (%s)", tc.name, got, tc.want, tc.because)
		}
	}
	// A zero cursor is behind everything — a cold pass must read from the start.
	if !(BackfillCursor{}).Ahead(ts(-1000), idLow) {
		t.Error("a zero cursor must consider every object ahead of it")
	}
}

// TestBackfillCursorNeverMovesBackwards is the anti-stall invariant: an
// out-of-order answer must not rewind progress and turn the next pass back into
// the full re-read the watermark exists to end.
func TestBackfillCursorNeverMovesBackwards(t *testing.T) {
	now := ts(999)
	c := BackfillCursor{}.Advance(ts(10), idLow, now)
	if !c.CreatedAt.Equal(ts(10)) || c.CorrelationID != idLow {
		t.Fatalf("first advance = %+v", c)
	}
	if got := c.Advance(ts(5), idHigh, now); !got.CreatedAt.Equal(ts(10)) || got.CorrelationID != idLow {
		t.Errorf("an older row moved the cursor backwards: %+v", got)
	}
	if got := c.Advance(time.Time{}, idHigh, now); !got.CreatedAt.Equal(ts(10)) {
		t.Errorf("a zero timestamp moved the cursor: %+v", got)
	}
	if got := c.Advance(ts(10), idHigh, now); got.CorrelationID != idHigh {
		t.Errorf("the tie-break did not advance within the same millisecond: %+v", got)
	}
	if got := c.Advance(ts(20), idLow, now); !got.CreatedAt.Equal(ts(20)) || !got.UpdatedAt.Equal(now) {
		t.Errorf("a newer row did not advance the cursor: %+v", got)
	}
}

// TestBackfillCursorRewindDropsTheTieBreak: a pass restarts a bounded distance
// behind the mark to catch corr_current rows that corr_current_reconcile.go
// backfilled with an ORIGINAL created_at already behind it. The tie-break must
// go with the rewind, or the predicate would still exclude the very rows the
// rewind is for.
func TestBackfillCursorRewindDropsTheTieBreak(t *testing.T) {
	c := BackfillCursor{CreatedAt: ts(600), CorrelationID: idLow}
	r := c.Rewind(2 * time.Hour)
	if !r.CreatedAt.Equal(ts(600 - 120)) {
		t.Errorf("rewound to %s, want %s", r.CreatedAt, ts(480))
	}
	if r.CorrelationID != "" {
		t.Errorf("rewind kept the tie-break %q — it would re-exclude the rows it exists to re-read", r.CorrelationID)
	}
	if got := (BackfillCursor{}).Rewind(time.Hour); !got.IsZero() {
		t.Errorf("rewinding a zero cursor invented a position: %+v", got)
	}
	if got := c.Rewind(0); !got.CreatedAt.Equal(c.CreatedAt) || got.CorrelationID != c.CorrelationID {
		t.Errorf("a zero rewind changed the cursor: %+v", got)
	}
}

func TestValidCorrelationUUID(t *testing.T) {
	good := []string{idLow, "AAAAAAAA-bbbb-4ccc-8ddd-eeeeeeeeeeee"}
	bad := []string{
		"", "not-a-uuid",
		"11111111-1111-4111-8111-11111111111",   // short
		"11111111-1111-4111-8111-1111111111111", // long
		"11111111_1111-4111-8111-111111111111",  // wrong separator
		"1111111g-1111-4111-8111-111111111111",  // non-hex
		"'); DROP TABLE netops.corr_objects --",
	}
	for _, s := range good {
		if !ValidCorrelationUUID(s) {
			t.Errorf("ValidCorrelationUUID(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if ValidCorrelationUUID(s) {
			t.Errorf("ValidCorrelationUUID(%q) = true — this reaches a ClickHouse literal", s)
		}
	}
}

// ── persistence ───────────────────────────────────────────────────────────────

type cursorKV struct {
	blobs  map[string][]byte
	loadEr error
}

func (k *cursorKV) Load(key string) ([]byte, error) {
	if k.loadEr != nil {
		return nil, k.loadEr
	}
	b, ok := k.blobs[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}

func (k *cursorKV) Save(key string, data []byte) error {
	k.blobs[key] = append([]byte(nil), data...)
	return nil
}

func withCursorKV(t *testing.T) *cursorKV {
	t.Helper()
	kv := &cursorKV{blobs: map[string][]byte{}}
	t.Cleanup(platformdb.SwapBackendForTest(kv))
	return kv
}

func TestBackfillCursorStoreRoundTrip(t *testing.T) {
	withCursorKV(t)
	s := NewBackfillCursorStore("")

	// Absent key = first run, NOT an error: a cold pass reads from the lookback
	// floor. (An unreadable key IS an error — see below.)
	got, err := s.Load()
	if err != nil || !got.IsZero() {
		t.Fatalf("first Load = %+v, %v; want a zero cursor and no error", got, err)
	}
	want := BackfillCursor{CreatedAt: ts(42), CorrelationID: idLow, UpdatedAt: ts(43)}
	if err := s.Save(want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// A SECOND store over the same key reloads it — this is the restart path.
	got, err = NewBackfillCursorStore("").Load()
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) || got.CorrelationID != want.CorrelationID {
		t.Errorf("reloaded %+v, want %+v", got, want)
	}
	if err := s.Reset(); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if got, _ = s.Load(); !got.IsZero() {
		t.Errorf("after Reset = %+v, want zero", got)
	}
}

// TestBackfillCursorStoreRejectsCorruptTieBreak: stored state is untrusted
// input (§3). A tie-break that is not a UUID must be dropped, never carried
// into a ClickHouse literal — and dropping it degrades to a CLOSED lower bound,
// which re-reads the boundary rather than skipping past it.
func TestBackfillCursorStoreRejectsCorruptTieBreak(t *testing.T) {
	kv := withCursorKV(t)
	kv.blobs[BackfillCursorKey] = []byte(`{"created_at":"2026-08-31T00:42:00Z","correlation_id":"'); DROP TABLE x --"}`)
	got, err := NewBackfillCursorStore("").Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got.CorrelationID != "" {
		t.Errorf("a corrupt tie-break survived Load: %q", got.CorrelationID)
	}
	if got.CreatedAt.IsZero() {
		t.Error("the timestamp half of a usable cursor was discarded with the tie-break")
	}
}

// TestBackfillCursorStoreLoadFailureIsAnError: an unreadable cursor must NOT
// look like "never ran". Confusing the two silently reinstates a full re-read
// of the whole retention window, every 15 minutes.
func TestBackfillCursorStoreLoadFailureIsAnError(t *testing.T) {
	kv := withCursorKV(t)
	kv.loadEr = errors.New("kv is down")
	got, err := NewBackfillCursorStore("").Load()
	if err == nil {
		t.Fatal("an unreadable cursor must return an error, not a zero cursor")
	}
	if !got.IsZero() {
		t.Errorf("a failed Load returned a position: %+v", got)
	}
	// A CORRUPT blob is also an error, for the same reason.
	kv.loadEr = nil
	kv.blobs[BackfillCursorKey] = []byte("{not json")
	if _, err := NewBackfillCursorStore("").Load(); err == nil {
		t.Error("a corrupt cursor blob must return an error, not a zero cursor")
	}
}
