package bgpwatch

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// harness is the offline evaluator rig. CI has no network, no bus and no
// Postgres (§11), so every upstream here is a scripted fake.
type harness struct {
	mu       sync.Mutex
	now      time.Time
	tenants  []string
	watch    map[string][]string
	obs      map[string]Observation
	obsErr   map[string]error
	peers    map[string][]PeerObservation
	sights   map[string][]PrefixSighting
	fired    []Alert
	resolved []Alert
	records  []Record
	pubErr   error
	eval     *Evaluator
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		now:     time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC),
		tenants: []string{"acme"},
		watch:   map[string][]string{"acme": {"193.0.0.0/21"}},
		obs:     map[string]Observation{"193.0.0.0/21": healthy()},
		obsErr:  map[string]error{},
		peers:   map[string][]PeerObservation{},
		sights:  map[string][]PrefixSighting{},
	}
	store := NewFileStore("")
	if err := store.SetPolicy(context.Background(), "acme", "tester", TenantPolicy{Default: policy()}); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	e, err := New(Deps{
		Now:      func() time.Time { h.mu.Lock(); defer h.mu.Unlock(); return h.now },
		Interval: time.Minute,
		Cooldown: 30 * time.Minute,
		Tenants:  func() []string { h.mu.Lock(); defer h.mu.Unlock(); return append([]string(nil), h.tenants...) },
		Watchlist: func(_ context.Context, tn string) ([]string, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.watch[tn], nil
		},
		Policies: store,
		Observe: func(_ context.Context, p string) (Observation, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if err := h.obsErr[p]; err != nil {
				return Observation{}, err
			}
			o := h.obs[p]
			o.Prefix = p
			return o, nil
		},
		Peers: func(_ context.Context, tn string) ([]PeerObservation, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.peers[tn], nil
		},
		Sightings: func(_ context.Context, tn string) ([]PrefixSighting, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			return h.sights[tn], nil
		},
		Notify:  func(a Alert) { h.mu.Lock(); defer h.mu.Unlock(); h.fired = append(h.fired, a) },
		Resolve: func(a Alert) { h.mu.Lock(); defer h.mu.Unlock(); h.resolved = append(h.resolved, a) },
		Publish: PublisherFunc(func(_ context.Context, _ string, recs []Record) (int, error) {
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.pubErr != nil {
				return 0, h.pubErr
			}
			h.records = append(h.records, recs...)
			return len(recs), nil
		}),
		Bogons:   NewBogonSet(),
		LogWarn:  func(string, map[string]any) {},
		LogError: func(string, map[string]any) {},
		Rand:     fixedJitter,
		Sleep:    noSleep,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	h.eval = e
	return h
}

func (h *harness) advance(d time.Duration) {
	h.mu.Lock()
	h.now = h.now.Add(d)
	h.mu.Unlock()
}

func (h *harness) setObs(p string, o Observation) {
	h.mu.Lock()
	h.obs[p] = o
	h.mu.Unlock()
}

func (h *harness) snapshot() ([]Alert, []Alert, []Record) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Alert(nil), h.fired...), append([]Alert(nil), h.resolved...), append([]Record(nil), h.records...)
}

func TestNewFailsClosedOnIncompleteDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("an incomplete Deps must fail construction, not yield a silently inert evaluator")
	}
}

func TestEvaluatorFiresOnTransitionOnlyAndResolves(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// Healthy → nothing.
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if fired, _, recs := h.snapshot(); len(fired) != 0 || len(recs) != 0 {
		t.Fatalf("a healthy prefix must not alert: %d alerts, %d records", len(fired), len(recs))
	}

	// RPKI goes invalid → ONE alert + ONE evidence record.
	bad := healthy()
	bad.RPKIState = "invalid"
	h.setObs("193.0.0.0/21", bad)
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	fired, _, recs := h.snapshot()
	if len(fired) != 1 || fired[0].Class != ClassRPKIInvalid {
		t.Fatalf("want one rpki_invalid alert, got %+v", fired)
	}
	if len(recs) != 1 {
		t.Fatalf("want one evidence record, got %d", len(recs))
	}
	ev, ok := recs[0].Value.(EvidenceEvent)
	if !ok || ev.Kind != KindRPKIInvalid || ev.TenantID != "acme" {
		t.Fatalf("evidence record is wrong: %+v", recs[0])
	}
	if recs[0].Key != "acme" {
		t.Fatalf("the partition key must be the tenant, got %q", recs[0].Key)
	}

	// Still invalid, inside the cool-down → NO second page.
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 3: %v", err)
	}
	if fired, _, _ = h.snapshot(); len(fired) != 1 {
		t.Fatalf("the cool-down did not suppress the re-fire: %d alerts", len(fired))
	}
	if h.eval.Metrics().AlertsSuppressed.Load() == 0 {
		t.Fatal("a suppressed alert must be counted, not invisible")
	}

	// Cleared → a RESOLUTION goes out and the cool-down is released.
	h.setObs("193.0.0.0/21", healthy())
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 4: %v", err)
	}
	_, resolved, _ := h.snapshot()
	if len(resolved) != 1 || resolved[0].Class != ClassRPKIInvalid || !resolved[0].Resolved {
		t.Fatalf("the cleared incident must resolve: %+v", resolved)
	}

	// It comes back → a NEW episode fires immediately (the cool-down was released).
	h.setObs("193.0.0.0/21", bad)
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 5: %v", err)
	}
	if fired, _, _ = h.snapshot(); len(fired) != 2 {
		t.Fatalf("a new episode after a clear must fire again: %d alerts", len(fired))
	}
}

func TestEvaluatorUnmeasuredPrefixNeverAlertsAndIsCounted(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.obsErr["193.0.0.0/21"] = errors.New("upstream 502")
	h.mu.Unlock()
	if err := h.eval.EvaluateTenant(context.Background(), "acme"); err != nil {
		t.Fatalf("run: %v", err)
	}
	fired, _, recs := h.snapshot()
	if len(fired) != 0 || len(recs) != 0 {
		t.Fatal("an unmeasurable prefix must not alert or ground")
	}
	if h.eval.Metrics().ObserveErrors.Load() != 1 {
		t.Fatal("a failed measurement must be counted (§10)")
	}
	inc, err := h.eval.Incidents("acme")
	if err != nil {
		t.Fatalf("incidents: %v", err)
	}
	if len(inc) != 1 || inc[0].Class != ClassUnknown {
		t.Fatalf("want one unknown incident, got %+v", inc)
	}
}

func TestEvaluatorPeerDownFiresOnceAndRecovers(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mu.Lock()
	h.peers["acme"] = []PeerObservation{{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "down", ChangedAt: h.now}}
	h.mu.Unlock()

	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	fired, _, recs := h.snapshot()
	if len(fired) != 1 || fired[0].Rule != "bgp_peer_down" {
		t.Fatalf("want one peer-down alert, got %+v", fired)
	}
	if len(recs) != 1 {
		t.Fatalf("want one peer-down evidence record, got %d", len(recs))
	}

	// Still down → no second page (the transition already fired).
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if fired, _, _ = h.snapshot(); len(fired) != 1 {
		t.Fatalf("a still-down peer must not re-page: %d", len(fired))
	}

	// Back up → a resolution.
	h.mu.Lock()
	h.peers["acme"] = []PeerObservation{{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "up"}}
	h.mu.Unlock()
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 3: %v", err)
	}
	if _, resolved, _ := h.snapshot(); len(resolved) != 1 {
		t.Fatalf("a recovered peer must resolve: %+v", resolved)
	}
}

// A peer that VANISHES from the report is not a recovery — we simply stopped
// being told about it, and claiming it came back would be fabrication.
func TestEvaluatorVanishedPeerIsNotAResolution(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mu.Lock()
	h.peers["acme"] = []PeerObservation{{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "down"}}
	h.mu.Unlock()
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.peers["acme"] = nil
	h.mu.Unlock()
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, resolved, _ := h.snapshot(); len(resolved) != 0 {
		t.Fatalf("a peer that stopped being reported must not be resolved: %+v", resolved)
	}
}

func TestEvaluatorBogonSightingsAreRecordedOnce(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.sights["acme"] = []PrefixSighting{
		{Prefix: "10.9.0.0/16", Peer: "rrc00", Source: "feed", At: h.now},
		{Prefix: "193.0.0.0/21", Peer: "rrc00", Source: "feed", At: h.now}, // not a bogon
	}
	h.mu.Unlock()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
			t.Fatal(err)
		}
		h.advance(time.Minute)
	}
	got, err := h.eval.Sightings("acme", 0)
	if err != nil {
		t.Fatalf("sightings: %v", err)
	}
	if len(got) != 1 || got[0].Prefix != "10.9.0.0/16" {
		t.Fatalf("want exactly the bogon sighting, got %+v", got)
	}
	if got[0].Count != 3 {
		t.Fatalf("repeat sightings must accumulate a count, got %d", got[0].Count)
	}
	if h.eval.Metrics().BogonSightings.Load() != 1 {
		t.Fatal("only the FIRST sighting is new; the counter must not re-count it")
	}
}

// §3a: one tenant's alerts, incidents and sightings never reach another.
func TestEvaluatorStateIsTenantIsolated(t *testing.T) {
	h := newHarness(t)
	h.mu.Lock()
	h.tenants = []string{"acme", "globex"}
	h.watch["globex"] = []string{"193.0.16.0/21"}
	bad := healthy()
	bad.Prefix = "193.0.16.0/21"
	bad.RPKIState = "invalid"
	h.obs["193.0.16.0/21"] = bad
	h.sights["globex"] = []PrefixSighting{{Prefix: "172.16.0.0/12", Source: "bmp", At: h.now}}
	h.mu.Unlock()

	h.eval.RunOnce(context.Background())

	acme, _ := h.eval.Alerts("acme", 0)
	if len(acme) != 0 {
		t.Fatalf("acme must not see globex's alerts: %+v", acme)
	}
	globex, _ := h.eval.Alerts("globex", 0)
	if len(globex) != 1 || globex[0].Resource != "193.0.16.0/21" {
		t.Fatalf("globex alerts wrong: %+v", globex)
	}
	if inc, _ := h.eval.Incidents("acme"); len(inc) != 1 || inc[0].Prefix != "193.0.0.0/21" {
		t.Fatalf("acme incidents leaked: %+v", inc)
	}
	if s, _ := h.eval.Sightings("acme", 0); len(s) != 0 {
		t.Fatalf("acme must not see globex's bogon sightings: %+v", s)
	}
	// A scopeless / wildcard read returns NOTHING, never everything.
	for _, bad := range []string{"", "*", "  "} {
		if _, err := h.eval.Alerts(bad, 0); err == nil {
			t.Fatalf("Alerts(%q) must be refused", bad)
		}
		if _, err := h.eval.Incidents(bad); err == nil {
			t.Fatalf("Incidents(%q) must be refused", bad)
		}
		if _, err := h.eval.Sightings(bad, 0); err == nil {
			t.Fatalf("Sightings(%q) must be refused", bad)
		}
	}
}

func TestEvaluatorAlertHistoryIsBounded(t *testing.T) {
	h := newHarness(t)
	st := h.eval.tenantState("acme")
	for i := 0; i < AlertHistoryMax+50; i++ {
		h.eval.recordAlert(st, Alert{ID: "a", Rule: "r"})
	}
	got, _ := h.eval.Alerts("acme", 0)
	if len(got) != AlertHistoryMax {
		t.Fatalf("history holds %d, bound is %d", len(got), AlertHistoryMax)
	}
}

// A run that cannot read the tenant's policy must STOP for that tenant rather
// than silently evaluating against an empty (learned-baseline) policy.
func TestEvaluatorRefusesToRunOnAnUnreadablePolicy(t *testing.T) {
	h := newHarness(t)
	e, err := New(Deps{
		Now:       func() time.Time { return h.now },
		Tenants:   func() []string { return []string{"acme"} },
		Watchlist: func(context.Context, string) ([]string, error) { return []string{"193.0.0.0/21"}, nil },
		Policies:  errPolicyStore{},
		Observe:   func(context.Context, string) (Observation, error) { return healthy(), nil },
		Bogons:    NewBogonSet(),
		LogWarn:   func(string, map[string]any) {},
		LogError:  func(string, map[string]any) {},
		Rand:      fixedJitter, Sleep: noSleep,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.EvaluateTenant(context.Background(), "acme"); err == nil {
		t.Fatal("an unreadable policy must fail the run, not fall back to an empty one")
	}
	if st := e.Status("acme"); !strings.Contains(st.LastError, "boom") {
		t.Fatalf("the failure must be visible on the status block: %+v", st)
	}
}

type errPolicyStore struct{}

func (errPolicyStore) Policy(context.Context, string) (TenantPolicy, error) {
	return TenantPolicy{}, errors.New("boom")
}
func (errPolicyStore) SetPolicy(context.Context, string, string, TenantPolicy) error { return nil }

// The evaluator must be bounded: a run never overlaps itself.
func TestRunOnceDoesNotOverlapItself(t *testing.T) {
	h := newHarness(t)
	h.eval.runSem <- struct{}{} // pretend a run is in flight
	h.eval.RunOnce(context.Background())
	<-h.eval.runSem
	if h.eval.Metrics().RunsSkipped.Load() != 1 {
		t.Fatal("an overlapping tick must be skipped and counted, not stacked")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.eval.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return on context cancellation")
	}
}
