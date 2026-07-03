package nms

import (
	"context"
	"sync"
	"time"
)

// state.go — the controller-state tracker. Diffs each incoming snapshot against
// the prior one to maintain first_seen / last_seen / previous_state /
// flap_count (§3.2), and reports whether a transition occurred (so the runtime
// can optionally emit a change-event into netops.events).

// StateRecord is the tracked state of one entity.
type StateRecord struct {
	EntityKey     string
	StateKind     string
	CurrentState  string
	PreviousState string
	FirstSeen     time.Time
	LastSeen      time.Time
	FlapCount     int64
	DeviceID      string
	SiteID        string
}

// StateChange is emitted when an entity's state transitions.
type StateChange struct {
	Record StateRecord
	From   string
	To     string
}

// StateTracker maintains current state + flap history. Safe for concurrent use.
// The in-memory implementation is the P1 store; a PG-backed one implements the
// same Apply contract later without changing callers.
type StateTracker struct {
	mu   sync.Mutex
	recs map[string]StateRecord
}

// NewStateTracker builds an empty tracker.
func NewStateTracker() *StateTracker {
	return &StateTracker{recs: make(map[string]StateRecord)}
}

// Apply folds a snapshot in and returns the updated record + a StateChange if
// the state transitioned (nil if unchanged / first sighting-with-no-transition).
// A first sighting sets first_seen and is NOT a flap. A change from a known
// prior state increments flap_count and returns a StateChange.
func (t *StateTracker) Apply(s ControllerState) (StateRecord, *StateChange) {
	key := StateEntityKey(s)
	ts := s.Time
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	prev, ok := t.recs[key]
	if !ok {
		rec := StateRecord{
			EntityKey: s.EntityKey, StateKind: s.StateKind,
			CurrentState: s.CurrentState, PreviousState: "",
			FirstSeen: ts, LastSeen: ts, FlapCount: 0,
			DeviceID: s.DeviceID, SiteID: s.SiteID,
		}
		t.recs[key] = rec
		return rec, nil // first sighting: not a flap
	}

	prev.LastSeen = ts
	prev.DeviceID, prev.SiteID = s.DeviceID, s.SiteID
	if s.CurrentState == prev.CurrentState {
		t.recs[key] = prev
		return prev, nil // steady state
	}
	// Transition.
	from := prev.CurrentState
	prev.PreviousState = from
	prev.CurrentState = s.CurrentState
	prev.FlapCount++
	t.recs[key] = prev
	return prev, &StateChange{Record: prev, From: from, To: s.CurrentState}
}

// Get returns the tracked record for an entity key.
func (t *StateTracker) Get(key string) (StateRecord, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.recs[key]
	return r, ok
}

// ── in-memory CheckpointStore (P1; PG-backed later) ──────────────────────────

// MemCheckpoints is an in-memory CheckpointStore for P1 + tests.
type MemCheckpoints struct {
	mu sync.Mutex
	m  map[string]Checkpoint
}

// NewMemCheckpoints builds an empty in-memory checkpoint store.
func NewMemCheckpoints() *MemCheckpoints { return &MemCheckpoints{m: make(map[string]Checkpoint)} }

func ckKey(tenant, integrationID, stream string) string {
	return tenant + "\x00" + integrationID + "\x00" + stream
}

// Load returns the stored checkpoint (zero value if none).
func (c *MemCheckpoints) Load(_ context.Context, tenant, integrationID, stream string) (Checkpoint, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.m[ckKey(tenant, integrationID, stream)], nil
}

// Save persists a checkpoint.
func (c *MemCheckpoints) Save(_ context.Context, tenant, integrationID, stream string, cp Checkpoint) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[ckKey(tenant, integrationID, stream)] = cp
	return nil
}
