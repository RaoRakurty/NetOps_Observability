// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// setPeers replaces the tenant's peer report.
func (h *harness) setPeers(tenant string, ps ...PeerObservation) {
	h.mu.Lock()
	h.peers[tenant] = ps
	h.mu.Unlock()
}

// A peer we cannot SEE is not a peer that is UP.
//
// bmp.Store.Close sets every peer of a dropped session to the documented third
// state "unknown" (pinned by internal/bmp/store_test.go). Before 2026-09-08
// checkPeers computed down as State == "down" and treated everything else as
// up, so the very next pass after a BMP session dropped dispatched "BGP peer
// 10.0.0.5 on edge-r1 is back up" and closed a live peer-down incident for a
// peer nobody could see.
func TestEvaluatorUnknownPeerIsNotAResolution(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.setPeers("acme", PeerObservation{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "down"})
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if fired, _, _ := h.snapshot(); len(fired) != 1 || fired[0].Rule != "bgp_peer_down" {
		t.Fatalf("want one peer-down alert, got %+v", fired)
	}

	// The BMP session drops: the peer is reported unknown, twice.
	h.setPeers("acme", PeerObservation{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "unknown", Reason: "bmp session closed"})
	for i := 0; i < 2; i++ {
		h.advance(time.Minute)
		if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
			t.Fatalf("blind run %d: %v", i, err)
		}
	}

	fired, resolved, _ := h.snapshot()
	if len(resolved) != 0 {
		t.Fatalf("a peer we cannot measure was reported as recovered: %+v", resolved)
	}
	for _, a := range fired {
		if a.Resolved {
			t.Fatalf("an unmeasured peer produced a resolution record: %+v", a)
		}
		if strings.Contains(a.Summary, "back up") {
			t.Fatalf("an unmeasured peer was announced as back up: %q", a.Summary)
		}
	}
	// The going-blind episode is SAID, once, on its own dedup id.
	var notices []Alert
	for _, a := range fired {
		if a.Rule == "bgp_peer_measurement_lost" {
			notices = append(notices, a)
		}
	}
	if len(notices) != 1 {
		t.Fatalf("want exactly one measurement-lost notice, got %d (%+v)", len(notices), fired)
	}
	if notices[0].ID == fired[0].ID {
		t.Fatalf("the notice reuses the peer-down dedup id %q, so it would close the incident it is warning about", notices[0].ID)
	}
	if notices[0].Resolved {
		t.Fatal("the measurement-lost notice must never carry Resolved")
	}
	if h.eval.Metrics().PeerStateUnmeasured.Load() != 2 {
		t.Fatalf("peer_state_unmeasured_total = %d, want 2 — an unmeasured peer must be counted, not invisible",
			h.eval.Metrics().PeerStateUnmeasured.Load())
	}
	if h.eval.Metrics().MeasurementLost.Load() != 1 {
		t.Fatalf("measurement_lost_total = %d, want 1", h.eval.Metrics().MeasurementLost.Load())
	}
	tm, err := h.eval.TenantMetrics("acme")
	if err != nil {
		t.Fatalf("tenant metrics: %v", err)
	}
	if tm["peer_state_unmeasured_total"] != 2 {
		t.Fatalf("the tenant's own counters hide the unmeasured peers: %+v", tm)
	}
}

// The guard against over-correcting into "nothing is ever up again": a peer
// that is genuinely up still reads up, and a REAL recovery still resolves even
// when it arrives after a run of unmeasured passes.
func TestEvaluatorMeasuredUpStillResolvesAcrossAnUnknownGap(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	// A peer that has always been up pages nobody and resolves nothing.
	h.setPeers("acme", PeerObservation{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "up"})
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	if fired, resolved, _ := h.snapshot(); len(fired) != 0 || len(resolved) != 0 {
		t.Fatalf("an up peer must produce nothing: fired %+v resolved %+v", fired, resolved)
	}

	// Down → one page.
	h.setPeers("acme", PeerObservation{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "down"})
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 2: %v", err)
	}
	if fired, _, _ := h.snapshot(); len(fired) != 1 {
		t.Fatalf("want one peer-down page, got %+v", fired)
	}

	// Three unmeasured passes.
	h.setPeers("acme", PeerObservation{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "unknown"})
	for i := 0; i < 3; i++ {
		h.advance(time.Minute)
		if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
			t.Fatalf("blind run %d: %v", i, err)
		}
	}
	if _, resolved, _ := h.snapshot(); len(resolved) != 0 {
		t.Fatalf("the blind passes resolved the incident: %+v", resolved)
	}

	// The session comes back and the peer is MEASURED up → the resolution the
	// operator is owed, exactly once, with mixed case accepted.
	h.setPeers("acme", PeerObservation{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "Up"})
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("recovery run: %v", err)
	}
	_, resolved, _ := h.snapshot()
	if len(resolved) != 1 || !resolved[0].Resolved || resolved[0].Rule != "bgp_peer_down" {
		t.Fatalf("a measured recovery after a blind gap must resolve exactly once: %+v", resolved)
	}

	// And the next real outage still pages: the state machine is not stuck.
	h.setPeers("acme", PeerObservation{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "down"})
	h.advance(31 * time.Minute) // past the harness cool-down
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("second outage: %v", err)
	}
	fired, _, _ := h.snapshot()
	downs := 0
	for _, a := range fired {
		if a.Rule == "bgp_peer_down" {
			downs++
		}
	}
	if downs != 2 {
		t.Fatalf("the second outage did not page: %d peer-down alerts in %+v", downs, fired)
	}
}

// A peer that has NEVER been seen down and is reported unknown holds nothing
// open, so it must not page and must not emit a measurement-lost notice.
func TestEvaluatorUnknownPeerWithNothingOpenIsQuiet(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.setPeers("acme", PeerObservation{DeviceID: "edge-r1", Peer: "10.0.0.5", State: "unknown"})
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatal(err)
	}
	fired, resolved, recs := h.snapshot()
	if len(fired) != 0 || len(resolved) != 0 || len(recs) != 0 {
		t.Fatalf("an unmeasured peer with no open alert must be silent: fired %+v resolved %+v recs %d", fired, resolved, len(recs))
	}
	if h.eval.Metrics().PeerStateUnmeasured.Load() != 1 {
		t.Fatal("it must still be COUNTED — silent is not the same as invisible")
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

// ── the sighting sweep is independent of the two per-tenant reads ───────────
//
// Regression for the 2026-09-03 live finding: the sweep used to sit at the END
// of EvaluateTenant, after the policy read and the watchlist read, both of
// which `return` on error. On a deployment whose watchlist store was
// unreadable the sweep therefore never ran ONCE — /api/bgp/bogons showed
// "none seen" while real BMP updates for a bogon prefix sat in the store.
// Sightings depend on neither read: they are a fact about what arrived.
func TestSightingSweepRunsEvenWhenTheTenantReadsFail(t *testing.T) {
	for _, tc := range []struct {
		name              string
		policyErr, wlErr  error
		wantEvaluateError bool
	}{
		{name: "watchlist unreadable", wlErr: errors.New("watchlist store down"), wantEvaluateError: true},
		{name: "policy unreadable", policyErr: errors.New("policy store down"), wantEvaluateError: true},
		{name: "both readable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
			swept := 0
			e, err := New(Deps{
				Now:      func() time.Time { return now },
				Interval: time.Minute,
				Cooldown: time.Minute,
				Tenants:  func() []string { return []string{"acme"} },
				Watchlist: func(_ context.Context, _ string) ([]string, error) {
					return nil, tc.wlErr
				},
				Policies: policyStoreFunc{err: tc.policyErr},
				Observe: func(_ context.Context, p string) (Observation, error) {
					return Observation{Prefix: p}, nil
				},
				Sightings: func(_ context.Context, tn string) ([]PrefixSighting, error) {
					swept++
					if tn != "acme" {
						t.Errorf("sweep ran for %q, want the tenant it was called with", tn)
					}
					// 192.0.2.0/24 is RFC 5737 TEST-NET-1 — a bogon in the
					// embedded set, so a working sweep MUST register it.
					return []PrefixSighting{{Prefix: "192.0.2.0/24", Peer: "rrc00", Source: "bmp", At: now}}, nil
				},
				Bogons:   NewBogonSet(),
				LogWarn:  func(string, map[string]any) {},
				LogError: func(string, map[string]any) {},
				Rand:     func() float64 { return 0.5 },
				Sleep:    func(context.Context, time.Duration) error { return nil },
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			evalErr := e.EvaluateTenant(context.Background(), "acme")
			if tc.wantEvaluateError && evalErr == nil {
				t.Fatal("a failed tenant read must still be REPORTED as an error")
			}
			if !tc.wantEvaluateError && evalErr != nil {
				t.Fatalf("unexpected error: %v", evalErr)
			}
			if swept != 1 {
				t.Fatalf("the sighting sweep ran %d times, want exactly 1 — a read failure "+
					"upstream of it must never blind the sighting register", swept)
			}
			rows, err := e.Sightings("acme", 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].Prefix != "192.0.2.0/24" {
				t.Fatalf("sightings = %+v, want the swept bogon", rows)
			}
			if rows[0].Entry.Block == "" || rows[0].Entry.Reason == "" {
				t.Fatalf("sighting carries no block/reason: %+v", rows[0].Entry)
			}
		})
	}
}

// policyStoreFunc is a PolicyStore that fails (or succeeds emptily) on demand.
type policyStoreFunc struct{ err error }

func (p policyStoreFunc) Policy(context.Context, string) (TenantPolicy, error) {
	return TenantPolicy{Prefixes: map[string]PolicyConfig{}}, p.err
}

func (p policyStoreFunc) SetPolicy(context.Context, string, string, TenantPolicy) error {
	return p.err
}

// ── L-05: un-watching a prefix must take its verdict with it ───────────────

// The live 2026-09-03 finding: deleting a watchlist prefix left its `incidents`
// entry behind, so the Prefixes view kept showing a hijack/leak class for a
// resource nothing was measuring any more.
func TestForgetPrefixClearsTheVerdictAndCooldown(t *testing.T) {
	h := newHarness(t)
	// A bogon on the watchlist classifies immediately, with no network.
	h.watch["acme"] = []string{"10.9.0.0/16"}
	h.obs["10.9.0.0/16"] = healthy()
	h.eval.RunOnce(context.Background())

	incidents, err := h.eval.Incidents("acme")
	if err != nil {
		t.Fatal(err)
	}
	var open Incident
	for _, inc := range incidents {
		if inc.Prefix == "10.9.0.0/16" {
			open = inc
		}
	}
	if open.Prefix == "" || open.Class == ClassNone {
		t.Fatalf("the fixture did not produce a verdict to forget: %+v", incidents)
	}

	had, err := h.eval.ForgetPrefix("acme", "10.9.0.0/16")
	if err != nil {
		t.Fatalf("ForgetPrefix: %v", err)
	}
	if !had {
		t.Fatal("ForgetPrefix reported nothing to clear when a verdict was open")
	}
	after, err := h.eval.Incidents("acme")
	if err != nil {
		t.Fatal(err)
	}
	for _, inc := range after {
		if inc.Prefix == "10.9.0.0/16" {
			t.Fatalf("the verdict outlived the watchlist row: %+v", inc)
		}
	}

	// The history is the record of what was RAISED and must survive: forgetting
	// a prefix is not permission to rewrite what already happened.
	hist, err := h.eval.Alerts("acme", 50)
	if err != nil {
		t.Fatal(err)
	}
	sawOriginal := false
	for _, a := range hist {
		if a.Resource == "10.9.0.0/16" && !a.Resolved {
			sawOriginal = true
		}
	}
	if !sawOriginal {
		t.Fatal("the original alert was erased from the history ring")
	}

	// The destination that was paged is CLOSED, and the text does not claim the
	// condition cleared — it says the prefix stopped being measured.
	h.mu.Lock()
	resolved := append([]Alert(nil), h.resolved...)
	h.mu.Unlock()
	var closer *Alert
	for i := range resolved {
		if resolved[i].Resource == "10.9.0.0/16" {
			closer = &resolved[i]
		}
	}
	if closer == nil {
		t.Fatal("an OPEN alert was left with no evaluator that could ever resolve it")
	}
	if !strings.Contains(closer.Summary, "removed from the watchlist") ||
		!strings.Contains(closer.Summary, "NOT a statement that the condition cleared") {
		t.Fatalf("the close text claims something we did not measure: %q", closer.Summary)
	}

	// Re-adding inside the cool-down must be able to alert again: a stale
	// cool-down entry would silently swallow the first real verdict.
	h.watch["acme"] = []string{"10.9.0.0/16"}
	h.mu.Lock()
	h.fired = nil
	h.mu.Unlock()
	h.eval.RunOnce(context.Background())
	h.mu.Lock()
	fired := len(h.fired)
	h.mu.Unlock()
	if fired == 0 {
		t.Fatal("a re-added prefix was suppressed by the cool-down of the watch that was deleted")
	}
}

// §3a: forgetting is scoped to one tenant, and refuses a non-concrete one.
func TestForgetPrefixIsTenantScopedAndFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.tenants = []string{"acme", "globex"}
	h.watch["acme"] = []string{"10.9.0.0/16"}
	h.watch["globex"] = []string{"10.9.0.0/16"}
	h.obs["10.9.0.0/16"] = healthy()
	h.eval.RunOnce(context.Background())

	if _, err := h.eval.ForgetPrefix("acme", "10.9.0.0/16"); err != nil {
		t.Fatal(err)
	}
	gx, err := h.eval.Incidents("globex")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, inc := range gx {
		if inc.Prefix == "10.9.0.0/16" {
			found = true
		}
	}
	if !found {
		t.Fatal("acme's delete cleared GLOBEX's verdict for the same prefix")
	}
	for _, tenant := range []string{"", "  ", "*"} {
		if _, err := h.eval.ForgetPrefix(tenant, "10.9.0.0/16"); err == nil {
			t.Errorf("ForgetPrefix(%q) accepted a non-concrete tenant", tenant)
		}
	}
	// An unknown prefix (or a tenant with no state) is not an error — deleting
	// a watch that never classified anything is a normal, successful no-op.
	if had, err := h.eval.ForgetPrefix("acme", "203.0.113.0/24"); err != nil || had {
		t.Fatalf("unknown prefix: had=%v err=%v, want false/nil", had, err)
	}
	if had, err := h.eval.ForgetPrefix("initech", "203.0.113.0/24"); err != nil || had {
		t.Fatalf("unknown tenant: had=%v err=%v, want false/nil", had, err)
	}
	// A non-canonical spelling of the same prefix still finds the verdict.
	if _, err := h.eval.ForgetPrefix("globex", "10.9.0.1/16"); err != nil {
		t.Fatal(err)
	}
	after, _ := h.eval.Incidents("globex")
	for _, inc := range after {
		if inc.Prefix == "10.9.0.0/16" {
			t.Fatal("a non-canonical prefix spelling failed to match the stored verdict")
		}
	}
}

// ── H3: an unmeasurable pass is not a clear ─────────────────────────────────
//
// Review 2026-09-08 found applyIncident treating ClassUnknown (we could not
// measure) exactly like ClassNone (we measured and it is fine). One upstream
// 502 therefore dispatched Alert{Resolved: true, "Cleared: … is no longer
// classified origin_change."} on the OPEN incident's dedup id, closing a live
// hijack on the destination, and resolveAlert dropped the cool-down stamp with
// it, so a flapping upstream re-fired past the 60-minute floor.

// hijacked is `healthy` with two vantage points agreeing on a foreign origin —
// the corroborated origin_change the evaluator pages on.
func hijacked() Observation {
	o := healthy()
	o.Paths = []VantagePath{
		vp("rrc00-1", 174, 65001),
		vp("rrc03-4", 174, 65001),
	}
	return o
}

func TestEvaluatorUnmeasurablePassDoesNotClearALiveIncident(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.setObs("193.0.0.0/21", hijacked())
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 1: %v", err)
	}
	fired, resolved, _ := h.snapshot()
	if len(fired) != 1 || fired[0].Class != ClassOriginChange {
		t.Fatalf("want one origin_change alert, got %+v", fired)
	}
	if len(resolved) != 0 {
		t.Fatalf("nothing may resolve on the opening pass: %+v", resolved)
	}
	openID := fired[0].ID

	// The upstream goes down. The hijack is still live; we simply cannot see it.
	h.mu.Lock()
	h.obsErr["193.0.0.0/21"] = errors.New("upstream 502")
	h.mu.Unlock()
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 2: %v", err)
	}

	fired, resolved, _ = h.snapshot()
	if len(resolved) != 0 {
		t.Fatalf("a failed lookup must NEVER resolve a live incident: %+v", resolved)
	}
	for _, a := range h.eval.mustHistory(t, "acme") {
		if a.Resolved {
			t.Fatalf("no record of an unmeasurable pass may carry Resolved: %+v", a)
		}
	}
	// Whatever is emitted must be a DISTINCT notice, not a clear on the open id.
	if len(fired) != 2 {
		t.Fatalf("an open incident going unmeasured must be announced once, got %+v", fired)
	}
	notice := fired[1]
	if notice.Resolved || notice.ResolvedAt != nil {
		t.Fatalf("the notice must not be a resolution: %+v", notice)
	}
	if notice.ID == openID {
		t.Fatal("the notice must carry its own dedup id, or a dedup destination overwrites the open incident")
	}
	if notice.Class != ClassUnknown || notice.Rule != "bgp_measurement_lost" {
		t.Fatalf("the notice must name itself as unmeasured: %+v", notice)
	}
	if !strings.Contains(notice.Summary, "NO LONGER BEING MEASURED") ||
		!strings.Contains(notice.Summary, "stays open") {
		t.Fatalf("the notice must say the incident is still open: %q", notice.Summary)
	}
	if h.eval.Metrics().MeasurementLost.Load() != 1 {
		t.Fatal("going blind on an open incident must be counted (§10)")
	}

	// The page must not lose the open incident either. The class is honestly
	// "unknown" for this pass, and the verdict says what is still open.
	incs, err := h.eval.Incidents("acme")
	if err != nil {
		t.Fatalf("incidents: %v", err)
	}
	if len(incs) != 1 || incs[0].Class != ClassUnknown {
		t.Fatalf("the blind pass must classify unknown, got %+v", incs)
	}
	if !strings.Contains(incs[0].Summary, "origin_change incident opened at") ||
		!strings.Contains(incs[0].Summary, "stays open") {
		t.Fatalf("the blind verdict must still name the open incident: %q", incs[0].Summary)
	}
}

// The second half of the same defect: resolveAlert also DELETES the cool-down
// stamp, so a false clear on every failed lookup let a flapping upstream page
// past the 60-minute floor — fire, false clear, fire, up to 288 times a day on
// one prefix. An unmeasurable pass must leave the stamp alone.
func TestEvaluatorUnmeasurablePassKeepsTheCoolDown(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.setObs("193.0.0.0/21", hijacked())
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 1: %v", err)
	}

	// Five flaps of the upstream, well inside the harness's 30-minute cool-down.
	for i := 0; i < 5; i++ {
		h.mu.Lock()
		h.obsErr["193.0.0.0/21"] = errors.New("upstream 502")
		h.mu.Unlock()
		h.advance(time.Minute)
		if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
			t.Fatalf("blind pass %d: %v", i, err)
		}
		h.mu.Lock()
		delete(h.obsErr, "193.0.0.0/21")
		h.mu.Unlock()
		h.advance(time.Minute)
		if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
			t.Fatalf("measured pass %d: %v", i, err)
		}
	}

	fired, resolved, _ := h.snapshot()
	if len(resolved) != 0 {
		t.Fatalf("a flapping upstream must not produce a single false clear: %+v", resolved)
	}
	pages := 0
	for _, a := range fired {
		if a.Class == ClassOriginChange {
			pages++
		}
	}
	if pages != 1 {
		t.Fatalf("the cool-down was bypassed: the same live hijack paged %d times in 10 minutes", pages)
	}
	// The blind stretch is announced ONCE per episode too, not once per flap.
	notices := 0
	for _, a := range fired {
		if a.Rule == "bgp_measurement_lost" {
			notices++
		}
	}
	if notices != 1 {
		t.Fatalf("the measurement-lost notice must be cooled down like any other emission, got %d", notices)
	}
}

// The other half of the fix: the guard must not turn into "never resolves". A
// genuine measured clear still closes the incident, even across a blind pass.
func TestEvaluatorResolvesOnAMeasuredClearAfterABlindPass(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	h.setObs("193.0.0.0/21", hijacked())
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 1: %v", err)
	}

	h.mu.Lock()
	h.obsErr["193.0.0.0/21"] = errors.New("upstream 502")
	h.mu.Unlock()
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 2: %v", err)
	}

	// Measured, and genuinely clean.
	h.mu.Lock()
	delete(h.obsErr, "193.0.0.0/21")
	h.mu.Unlock()
	h.setObs("193.0.0.0/21", healthy())
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 3: %v", err)
	}
	_, resolved, _ := h.snapshot()
	if len(resolved) != 1 {
		t.Fatalf("a measured clear must still resolve, even after a blind pass: %+v", resolved)
	}
	if !resolved[0].Resolved || resolved[0].Class != ClassOriginChange {
		t.Fatalf("the resolution must close the origin_change that was opened: %+v", resolved[0])
	}
	if h.eval.Metrics().AlertsResolved.Load() != 1 {
		t.Fatal("the resolution must be counted exactly once")
	}

	// And the episode is over, so the hijack returning pages again at once.
	h.setObs("193.0.0.0/21", hijacked())
	h.advance(time.Minute)
	if err := h.eval.EvaluateTenant(ctx, "acme"); err != nil {
		t.Fatalf("run 4: %v", err)
	}
	fired, _, _ := h.snapshot()
	got := 0
	for _, a := range fired {
		if a.Class == ClassOriginChange {
			got++
		}
	}
	if got != 2 {
		t.Fatalf("a new episode after a real clear must page again: %+v", fired)
	}
}

// mustHistory reads one tenant's alert ring or fails the test.
func (e *Evaluator) mustHistory(t *testing.T, tenant string) []Alert {
	t.Helper()
	a, err := e.Alerts(tenant, AlertHistoryMax)
	if err != nil {
		t.Fatalf("alerts: %v", err)
	}
	return a
}
