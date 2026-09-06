package audit

// platformtrail_test.go — tracker 235.
//
// The question the incident asked and could not answer was "who disabled the
// snapshot schedule in the GUI, and when?". The event existed; it had been
// evicted from a 5,000-row ring that spans four hours on this deployment. Every
// test below is a form of that question.

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// memKV is the kv seam, in memory, so a store can be reopened over the same
// bytes the previous one wrote (the persistence half of the question).
type memKV struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemKV() *memKV { return &memKV{data: map[string][]byte{}} }

func (m *memKV) Load(key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, ok := m.data[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return append([]byte(nil), b...), nil
}

func (m *memKV) Save(key string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[key] = append([]byte(nil), data...)
	return nil
}

func (m *memKV) keys() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.data))
	for k := range m.data {
		out = append(out, k)
	}
	return out
}

// snapshotOff is the event the 2026-09-03 investigation went looking for.
func snapshotOff(at time.Time) Event {
	return Event{
		ID: "snapshot-off", Time: at, Actor: "rao", Cross: true,
		Method: "PUT", Path: "/api/system/backup/schedule", Status: 200, Decision: "allow",
	}
}

// TestAPlatformChangeSurvivesTheRequestRingRolling is the row, exactly: make
// the change, then bury it under more ordinary requests than the ring can hold,
// then ask who made it.
func TestAPlatformChangeSurvivesTheRequestRingRolling(t *testing.T) {
	kv := newMemKV()
	s, err := NewFileStore("/data/audit.json", kv)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	base := time.Date(2026, 9, 3, 8, 0, 0, 0, time.UTC)
	s.Record(snapshotOff(base))

	// The wall of ordinary reads that evicted it on the real deployment. They go
	// into the ring DIRECTLY: Record marshals the whole blob per event, and
	// paying 5,100 whole-ring marshals here would cost half a minute of CI to
	// prove something the single Record below proves in one — the ring trims to
	// MaxEvents and the oldest event falls off.
	s.mu.Lock()
	for i := 0; i < MaxEvents+100; i++ {
		s.events = append(s.events, Event{
			ID: fmt.Sprintf("get-%05d", i), Time: base.Add(time.Duration(i+1) * time.Second),
			Actor: "someone", Cross: true, Method: "GET", Path: "/api/devices",
			Status: 200, Decision: "allow",
		})
	}
	s.mu.Unlock()
	s.Record(Event{ID: "get-last", Time: base.Add(2 * time.Hour), Actor: "someone", Cross: true,
		Method: "GET", Path: "/api/devices", Status: 200, Decision: "allow"})

	// It is GONE from the request ring — that part is unchanged and expected.
	s.mu.RLock()
	inRing := false
	for _, e := range s.events {
		if e.ID == "snapshot-off" {
			inRing = true
		}
	}
	s.mu.RUnlock()
	if inRing {
		t.Fatal("the fixture did not roll the ring — the test is not exercising the defect")
	}

	// And it is still ANSWERABLE, which is the whole point. The query is the
	// one an investigation actually runs: "show me the changes to THIS route".
	events, err := s.List("", true, Query{Limit: MaxQueryLimit, Path: "/api/system/backup/schedule"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found *Event
	for i := range events {
		if events[i].ID == "snapshot-off" {
			found = &events[i]
		}
	}
	if found == nil {
		t.Fatal("the platform config change was evicted by ordinary GETs — " +
			"exactly the 2026-09-03 unanswerable question this trail exists to prevent")
	}
	if found.Actor != "rao" || found.Path != "/api/system/backup/schedule" {
		t.Fatalf("the retained event lost its attribution: %+v", *found)
	}

	// It is reported ONCE, not twice, when it is in both places.
	s.Record(snapshotOff(base.Add(3 * time.Hour)))
	events, err = s.List("", true, Query{Limit: MaxQueryLimit, Path: "/api/system/backup/schedule"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	n := 0
	for _, e := range events {
		if e.ID == "snapshot-off" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the change was reported %d times — the ring and the trail are not deduplicated", n)
	}
}

// TestTheTrailSurvivesARestart — the trail is only worth having if it outlives
// the process that wrote it.
func TestTheTrailSurvivesARestart(t *testing.T) {
	kv := newMemKV()
	s, err := NewFileStore("/data/audit.json", kv)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	s.Record(snapshotOff(time.Now().UTC().Add(-48 * time.Hour)))

	// It is a SEPARATE file, so the request ring's rewrite cannot truncate it.
	keys := kv.keys()
	if len(keys) != 2 {
		t.Fatalf("expected the ring and the trail as two files, got %v", keys)
	}
	reopened, err := NewFileStore("/data/audit.json", kv)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	events, err := reopened.List("", true, Query{Limit: MaxQueryLimit})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 1 || events[0].ID != "snapshot-off" {
		t.Fatalf("the trail did not survive a restart: %+v", events)
	}
}

// TestTheTrailIsBoundedAndSaysWhatItDropped — the ceiling is real, and hitting
// it is never silent: an evicted platform change is a permanent loss of
// attribution, so it is counted.
func TestTheTrailIsBoundedAndSaysWhatItDropped(t *testing.T) {
	kv := newMemKV()
	const ceiling = 10
	s, err := NewFileStore("/data/audit.json", kv, WithTrailPolicy(TrailPolicy{Days: 90, MaxEvents: ceiling}))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	base := time.Now().UTC().Add(-time.Hour)
	for i := 0; i < ceiling+5; i++ {
		s.Record(Event{
			ID: fmt.Sprintf("chg-%02d", i), Time: base.Add(time.Duration(i) * time.Minute),
			Actor: "rao", Cross: true, Method: "POST", Path: "/api/auth/providers",
			Status: 200, Decision: "allow",
		})
	}
	st := s.TrailStats()
	if st.Kept != ceiling {
		t.Fatalf("trail holds %d events, want the configured ceiling %d", st.Kept, ceiling)
	}
	if st.Dropped != 5 {
		t.Fatalf("dropped = %d, want 5 — an eviction that is not COUNTED is a silent loss of evidence", st.Dropped)
	}
	// The NEWEST are what survive: during an investigation the recent change is
	// the one being asked about. (The request ring still holds all fifteen —
	// this is about what the TRAIL keeps once the ring has rolled.)
	s.mu.RLock()
	retained := append([]Event(nil), s.retained...)
	s.mu.RUnlock()
	if retained[0].ID != "chg-05" || retained[len(retained)-1].ID != "chg-14" {
		t.Fatalf("the trail kept the wrong window: %s … %s, want chg-05 … chg-14",
			retained[0].ID, retained[len(retained)-1].ID)
	}
}

// TestTheTrailAgesOutOnItsHorizon — the age bound bites, and it bites BEFORE
// the count bound (dropping a 91-day-old event is the policy working; dropping
// a two-day-old one is the ceiling being too low, and they are reported apart).
func TestTheTrailAgesOutOnItsHorizon(t *testing.T) {
	now := time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	events := []Event{
		{ID: "ancient", Time: now.AddDate(0, 0, -400)},
		{ID: "old", Time: now.AddDate(0, 0, -91)},
		{ID: "recent", Time: now.AddDate(0, 0, -2)},
	}
	kept, byAge, byCount := pruneTrail(events, TrailPolicy{Days: 90, MaxEvents: 100}, now)
	if byAge != 2 || byCount != 0 {
		t.Fatalf("byAge=%d byCount=%d, want 2/0", byAge, byCount)
	}
	if len(kept) != 1 || kept[0].ID != "recent" {
		t.Fatalf("kept = %+v, want only the in-horizon event", kept)
	}
	// Days<=0 is "no age bound", and the count ceiling still applies.
	kept, byAge, byCount = pruneTrail(events, TrailPolicy{Days: 0, MaxEvents: 2}, now)
	if byAge != 0 || byCount != 1 || len(kept) != 2 {
		t.Fatalf("no-age-bound prune = kept %d byAge %d byCount %d, want 2/0/1", len(kept), byAge, byCount)
	}
}

// TestTheTrailIsTenantScopedLikeTheRing — §3a: the retained events go through
// the SAME scope filter as the ring, so widening the horizon can never widen
// WHOSE actions a scoped admin can read.
func TestTheTrailIsTenantScopedLikeTheRing(t *testing.T) {
	kv := newMemKV()
	s, err := NewFileStore("/data/audit.json", kv)
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	now := time.Now().UTC()
	s.Record(Event{ID: "acme-change", Time: now, Tenant: "acme", Actor: "a",
		Method: "POST", Path: "/api/users", Status: 200, Decision: "allow"})
	s.Record(Event{ID: "globex-change", Time: now, Tenant: "globex", Actor: "b",
		Method: "POST", Path: "/api/users", Status: 200, Decision: "allow"})

	events, err := s.List("acme", false, Query{Limit: MaxQueryLimit})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(events) != 1 || events[0].ID != "acme-change" {
		t.Fatalf("CROSS-TENANT LEAK through the retained trail: %+v", events)
	}
	if n := s.Count("acme", false, Query{}); n != 1 {
		t.Fatalf("Count = %d, want 1 — the page and its total must share the scope", n)
	}
}

// TestOnlyPlatformChangesAreRetained — the trail is narrow on purpose. A GET is
// not a change, and a tenant-scoped write has its own history; retaining either
// would turn the long-lived file back into the ring it exists to escape.
func TestOnlyPlatformChangesAreRetained(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         bool
	}{
		{"PUT", "/api/system/backup/schedule", true},
		{"POST", "/api/auth/providers", true},
		{"DELETE", "/api/auth/providers/okta", true},
		{"PATCH", "/api/auth/token-policy", true},
		{"POST", "/api/copilot/config", true},
		{"POST", "/api/notify/slack", true},
		{"POST", "/api/tenants", true},
		{"POST", "/api/apikeys", true},
		{"POST", "/api/system/backup/run?force=1", true}, // query string ignored
		{"GET", "/api/system/backup/schedule", false},    // a read is not a change
		{"POST", "/api/devices", false},                  // tenant data, own history
		{"POST", "/api/incidents/42/ack", false},
		{"POST", "/api/systemic-nonsense", false}, // prefix must not match loosely
		{"POST", "/api/auth/login", false},        // the highest-volume POST there is
		{"POST", "/api/auth/refresh", false},
		{"POST", "/api/copilot/chat", false},           // a chat turn is not config
		{"POST", "/api/integrations/webhook/x", false}, // inbound third-party call
		{"POST", "/api/notify/contact-points", false},  // tenant data, own history
	} {
		got := IsPlatformChange(Event{Method: tc.method, Path: tc.path})
		if got != tc.want {
			t.Errorf("IsPlatformChange(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
		}
	}
}

// TestADeniedPlatformChangeIsRetainedToo — "who TRIED to rotate the key and was
// refused" is part of the record an investigation needs.
func TestADeniedPlatformChangeIsRetainedToo(t *testing.T) {
	if !IsPlatformChange(Event{Method: "POST", Path: "/api/copilot/config", Status: 403, Decision: "deny"}) {
		t.Fatal("a DENIED platform change is not retained — the trail would answer only half the question")
	}
}

// TestTrailPolicyDefaultsToRetaining is the mirror image of
// TestRetentionIsOffUnlessExplicitlyConfigured: retention DELETES on a typo, so
// it must default off; the trail KEEPS, so it must default on.
func TestTrailPolicyDefaultsToRetaining(t *testing.T) {
	for _, tc := range []struct{ days, max string }{
		{"", ""}, {"  ", "  "}, {"90d", "lots"}, {"-1", "0"}, {"forever", "-5"},
	} {
		p := ParseTrailPolicy(tc.days, tc.max)
		if p.Days != DefaultTrailDays || p.MaxEvents != DefaultTrailMaxEvents {
			t.Errorf("ParseTrailPolicy(%q, %q) = %+v, want the defaults — an operator typo "+
				"must never silently shorten the horizon that answers 'who changed this?'",
				tc.days, tc.max, p)
		}
	}
	if p := ParseTrailPolicy("365", "50000"); p.Days != 365 || p.MaxEvents != 50000 {
		t.Errorf("explicit values not honoured: %+v", p)
	}
	// 0 days is a real choice ("no age bound"), not a typo.
	if p := ParseTrailPolicy("0", ""); p.Days != 0 {
		t.Errorf("an explicit 0 must mean 'no age bound', got %+v", p)
	}
	// A ceiling nobody could serve is clamped, never accepted.
	if p := ParseTrailPolicy("", "999999999"); p.MaxEvents != TrailMaxEventsCeiling {
		t.Errorf("over-ceiling max = %d, want the clamp %d", p.MaxEvents, TrailMaxEventsCeiling)
	}
}

// TestPlatformPrefixesAreLiteralForLIKE — the Postgres sweep binds these
// prefixes as `LIKE prefix || '%'` patterns. A '%' or '_' inside one would turn
// an exact prefix test into a wildcard and silently WIDEN what the retention
// floor protects (or, worse, narrow it).
func TestPlatformPrefixesAreLiteralForLIKE(t *testing.T) {
	for _, p := range platformPathPrefixes {
		if strings.ContainsAny(p, `%_\`) {
			t.Errorf("prefix %q carries a LIKE metacharacter — escape it or the SQL floor stops meaning what it reads", p)
		}
		if !strings.HasPrefix(p, "/api/") {
			t.Errorf("prefix %q is not an /api route prefix", p)
		}
	}
}
