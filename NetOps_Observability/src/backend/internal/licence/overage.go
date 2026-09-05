package licence

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"netops/backend/internal/entitlement"
)

// overage.go — the durable register of "since when have you been over".
//
// WHY THIS IS NOT DERIVED. Everything else about an overage is a function of
// the current reading: how many are in use, what the ceiling is, how many are
// above it. `since` is the one fact that is not — it is the moment a condition
// STARTED, and a process that only ever sees "now" cannot recover it after a
// restart. The owner's soft-overage decision (2026-09-05) names it explicitly:
// "record `overage_since` and let the order form decide". So it is written
// down, atomically, beside the licence.
//
// WHAT IS DELIBERATELY ABSENT. No window, no countdown, no expiry of an
// overage, no consequence. How long a paid customer may run over and what it
// costs are ORDER-FORM terms; encoding a number here would be the product
// inventing commercial policy, which is the one thing the licensing design
// forbids most consistently. This file records a start time and a peak and
// stops.
//
// FAILING SOFT, ON PURPOSE. A tracker that cannot read or write its file still
// answers every question — it simply reports no `since`. The alternative would
// be a bookkeeping problem able to interfere with device admission, which is
// exactly the inversion the safety invariant exists to prevent.

// OverageRecord is one ceiling's current over-limit episode.
type OverageRecord struct {
	// Ceiling is the entitlement ceiling vocabulary name.
	Ceiling string `json:"ceiling"`
	// Since is when the current episode began (UTC).
	Since time.Time `json:"since"`
	// Peak is the highest usage seen during this episode — the number a true-up
	// conversation actually needs, since an overage that touched 300 and
	// settled at 260 was a 300 overage.
	Peak int `json:"peak"`
	// Limit is the ceiling in force when the episode began, kept so a record
	// read a month later explains itself without a second lookup.
	Limit int `json:"limit"`
}

// overageFile is the on-disk shape. A wrapper object rather than a bare map so
// the format can grow a version or a note without breaking the parse.
type overageFile struct {
	Records []OverageRecord `json:"records"`
}

// OveragePathFor is where the register lives for a given licence path: beside
// the licence, because they are the same operational object and an operator
// copying /data/api out gets both.
func OveragePathFor(licencePath string) string {
	return filepath.Join(filepath.Dir(licencePath), "licence-overage.json")
}

// OverageTracker records when each enforced ceiling went over and how far.
//
// Safe for concurrent use: Observe runs on the /metrics path and on every read
// of the Licence page.
type OverageTracker struct {
	path string
	// warn reports a persistence problem to the platform's logger. Optional —
	// a nil warn makes the tracker silent, which is what tests want and what a
	// build without logging wiring gets.
	warn func(msg string, err error)

	mu      sync.Mutex
	recs    map[string]OverageRecord
	loaded  bool
	dirty   bool
	lastErr error
}

// NewOverageTracker builds a tracker over path. It does NOT touch the disk:
// the first Observe loads, so construction cannot fail and a missing register
// is the normal first-run state.
//
// warn may be nil.
func NewOverageTracker(path string, warn func(msg string, err error)) *OverageTracker {
	return &OverageTracker{path: path, warn: warn, recs: map[string]OverageRecord{}}
}

// Path is where the register lives, for the runbook and the admin page.
func (t *OverageTracker) Path() string {
	if t == nil {
		return ""
	}
	return t.path
}

// Observe records the over-ceiling state implied by st and u, and returns the
// overages with Since and Peak filled in.
//
// It is the ONLY writer of the register, and it writes only when something
// actually changed — an episode starting, a new peak, an episode ending — so a
// scrape every 15 seconds does not rewrite a file every 15 seconds.
//
// Nil-safe: a nil tracker still returns the state's own overages, without a
// `since`. That is the honest degradation for a build with no register wired,
// and it keeps the Licence page working rather than blanking a panel over a
// bookkeeping detail.
func (t *OverageTracker) Observe(st State, u Usage, now time.Time) []Overage {
	over := st.Overages(u)
	if t == nil {
		return over
	}
	now = now.UTC()

	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadLocked()

	live := make(map[string]bool, len(over))
	for i := range over {
		o := &over[i]
		live[o.Ceiling] = true
		rec, had := t.recs[o.Ceiling]
		switch {
		case !had:
			rec = OverageRecord{Ceiling: o.Ceiling, Since: now, Peak: o.Current, Limit: o.Limit}
			t.recs[o.Ceiling] = rec
			t.dirty = true
			if t.warn != nil {
				// Once per episode, not once per scrape: the transition is the
				// event, and a line every fifteen seconds would bury it.
				t.warn("licence: "+o.Message, nil)
			}
		case o.Current > rec.Peak || o.Limit != rec.Limit:
			rec.Peak = max(rec.Peak, o.Current)
			rec.Limit = o.Limit
			t.recs[o.Ceiling] = rec
			t.dirty = true
		}
		o.Since = rec.Since
	}
	// An episode that ended is FORGOTTEN, not archived. This register answers
	// "since when are you over", and a closed episode is not an answer to it;
	// keeping a history here would be a metering store, which is tracker 258's
	// job and a different data contract.
	for name := range t.recs {
		if !live[name] {
			delete(t.recs, name)
			t.dirty = true
		}
	}
	t.flushLocked()
	return over
}

// Since reports when a ceiling's current episode began.
func (t *OverageTracker) Since(ceiling string) (time.Time, bool) {
	if t == nil {
		return time.Time{}, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadLocked()
	rec, ok := t.recs[ceiling]
	if !ok || rec.Since.IsZero() {
		return time.Time{}, false
	}
	return rec.Since, true
}

// Records returns the open episodes, ceiling order stable.
func (t *OverageTracker) Records() []OverageRecord {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.loadLocked()
	out := make([]OverageRecord, 0, len(t.recs))
	for _, r := range t.recs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ceiling < out[j].Ceiling })
	return out
}

// Err is the last persistence problem, or nil. Exposed so an operator surface
// can say the register is not being kept rather than quietly reporting no
// `since` for ever.
func (t *OverageTracker) Err() error {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.lastErr
}

// loadLocked reads the register once. A missing file is the normal first run
// and is NOT an error; anything else is recorded and the tracker carries on
// empty — a bookkeeping file must never be able to block an admission path.
func (t *OverageTracker) loadLocked() {
	if t.loaded {
		return
	}
	t.loaded = true
	if t.path == "" {
		return
	}
	raw, err := os.ReadFile(t.path) // #nosec G304 -- an operator-configured platform path, not caller input
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			t.fail("the overage register could not be read; overage start times will be recorded from now", err)
		}
		return
	}
	var f overageFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.fail("the overage register is unreadable and is being started again; overage start times will be recorded from now", err)
		return
	}
	for _, r := range f.Records {
		if r.Ceiling == "" || !entitlement.ValidCeiling(r.Ceiling) || r.Since.IsZero() {
			// A record naming a ceiling outside the closed vocabulary is a
			// hand-edit or a downgrade; drop it rather than carrying a fact
			// nothing can interpret.
			continue
		}
		r.Since = r.Since.UTC()
		t.recs[r.Ceiling] = r
	}
}

// flushLocked writes the register when it changed.
func (t *OverageTracker) flushLocked() {
	if !t.dirty || t.path == "" {
		return
	}
	f := overageFile{Records: make([]OverageRecord, 0, len(t.recs))}
	for _, r := range t.recs {
		f.Records = append(f.Records, r)
	}
	sort.Slice(f.Records, func(i, j int) bool { return f.Records[i].Ceiling < f.Records[j].Ceiling })
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.fail("the overage register could not be encoded", err)
		return
	}
	if err := atomicWrite(t.path, append(body, '\n')); err != nil {
		t.fail("the overage register could not be written; overage start times will not survive a restart", err)
		return
	}
	t.dirty = false
	t.lastErr = nil
}

// fail records a persistence problem and reports it once to the platform. It
// never returns an error to the caller: Observe is on the metrics and page
// paths, and a register that cannot be written must degrade to "no since", not
// to a broken page.
func (t *OverageTracker) fail(msg string, err error) {
	if t.lastErr == nil && t.warn != nil {
		t.warn("licence: "+msg, err)
	}
	t.lastErr = err
}
