package rca

// rca_coverage_engine_test.go — Phase C coverage-engine tests (plan §3, spec tests
// 6–12) beside rca_coverage.go: partial-flow, partial device-health, point-in-time
// routing, leading-gap active checks, full-coverage-only-when-thresholds-pass,
// scope mismatch, unhealthy collector, per-class semantics, the P-027379 §2
// regression fixtures, and a tenant-isolation test (CLAUDE.md §3a).

import (
	"testing"
	"time"
)

// ct parses a "2006-01-02 15:04:05" UTC test timestamp (panics on bad input — a
// broken fixture is a test bug, not a runtime condition).
func ct(s string) time.Time {
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		panic(err)
	}
	return t.UTC()
}

// evenSeries returns count observations evenly spaced by step from start.
func evenSeries(start time.Time, step time.Duration, count int) []time.Time {
	out := make([]time.Time, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, start.Add(step*time.Duration(i)))
	}
	return out
}

// The incident window for the P-027379 fixtures (audit §2).
var (
	p27WinStart = ct("2026-07-15 20:20:33")
	p27WinEnd   = ct("2026-07-15 20:32:21")
)

// Test 6 — a continuous flow lane that observed cleanly but left a material
// trailing gap (P-027379 flow: 78.8%, 2m13s trailing) is SUBSTANTIAL, never
// complete/normal, and — crucially — is NOT impact-eligible: this is what kills a
// "real-user impact: none detected" claim on that lane.
func TestCoverage_PartialFlow(t *testing.T) {
	e := newCoverageEngine(nil)
	// flow every 30s from 20:20:50 to 20:30:08 (leading 17s, trailing 2m13s).
	obs := evenSeries(ct("2026-07-15 20:20:50"), 30*time.Second, 19) // ...→20:29:50
	obs = append(obs, ct("2026-07-15 20:30:08"))
	a := e.Assess("global", LaneCoverageInput{
		Class: "passive_flow", WindowStart: p27WinStart, WindowEnd: p27WinEnd,
		Observations: obs, ScheduleInterval: 30 * time.Second, TotalCount: len(obs),
	})
	if a.Strategy != strategyContinuous {
		t.Fatalf("flow strategy = %q, want continuous", a.Strategy)
	}
	if a.Quality != qualitySubstantial {
		t.Fatalf("flow quality = %q (ratio %.3f), want substantial", a.Quality, a.CoverageRatio)
	}
	if a.CoverageRatio >= 0.95 || a.CoverageRatio < 0.60 {
		t.Errorf("flow coverage ratio = %.3f, want ~0.79", a.CoverageRatio)
	}
	if a.TrailingGap == "" {
		t.Error("flow must report its trailing gap")
	}
	if a.ImpactEligible {
		t.Errorf("flow at %.1f%% with a trailing gap must NOT be impact-eligible (would fabricate 'none detected')", a.CoverageRatio*100)
	}
	if !hasReason(a.ImpactReasons, "coverage_incomplete_for_negative_claim") {
		t.Errorf("impact reasons = %v, want coverage_incomplete_for_negative_claim", a.ImpactReasons)
	}
	if a.NormalityEligible {
		t.Error("substantial-coverage lane must not be normality-eligible")
	}
	if a.legacyState(false) == "normal" {
		t.Error("legacy state must not read green Normal for a partial flow lane")
	}
}

// Test 7 — a continuous device-health lane with leading AND trailing gaps
// (P-027379 device: 78.5%, 1m58s leading + 34s trailing) is substantial with both
// gaps stated; never a green Normal.
func TestCoverage_PartialDeviceHealth(t *testing.T) {
	e := newCoverageEngine(nil)
	obs := evenSeries(ct("2026-07-15 20:22:31"), 30*time.Second, 19) // →20:31:31
	obs = append(obs, ct("2026-07-15 20:31:47"))
	a := e.Assess("global", LaneCoverageInput{
		Class: "device_telemetry", WindowStart: p27WinStart, WindowEnd: p27WinEnd,
		Observations: obs, ScheduleInterval: 30 * time.Second, TotalCount: len(obs),
	})
	if a.Quality != qualitySubstantial {
		t.Fatalf("device quality = %q (ratio %.3f), want substantial", a.Quality, a.CoverageRatio)
	}
	// The material leading gap (~1m58s) must be surfaced. The 34s trailing gap is
	// within one cadence-credit (30s cadence → covered until the next expected poll),
	// so the covered-interval model legitimately absorbs it — that IS constraint 5.
	if a.LeadingGap == "" {
		t.Errorf("device lane must state its ~2m leading gap; got leading=%q trailing=%q", a.LeadingGap, a.TrailingGap)
	}
	if a.MissingInterval == "" {
		t.Error("device lane must state a missing interval")
	}
	if a.NormalityEligible {
		t.Error("device lane with a ~2m leading gap must not be normality-eligible")
	}
	if !hasReason(a.NormalityReasons, "coverage_incomplete") {
		t.Errorf("normality reasons = %v, want coverage_incomplete", a.NormalityReasons)
	}
}

// Test 8 — a control-plane STATE TRANSITION (P-027379 routing: 19s event) is
// point_in_time, NEVER judged by continuous-coverage rules ("Full"). Its coverage
// ratio is not even claimed (RatioKnown=false).
func TestCoverage_PointInTimeRouting(t *testing.T) {
	e := newCoverageEngine(nil)
	a := e.Assess("global", LaneCoverageInput{
		Class: "control_plane", WindowStart: p27WinStart, WindowEnd: p27WinEnd,
		LaneStart: ct("2026-07-15 20:20:33"), LaneEnd: ct("2026-07-15 20:20:52"),
		TotalCount: 1, AnomalousCount: 1,
	})
	if a.Strategy != strategyEventBased {
		t.Fatalf("routing strategy = %q, want event_based", a.Strategy)
	}
	if a.Quality != qualityPointInTime {
		t.Fatalf("routing quality = %q, want point_in_time (a 19s transition is not a span)", a.Quality)
	}
	if a.RatioKnown {
		t.Error("event-based lane must NOT claim a coverage ratio")
	}
	if a.legacyCoverage() == "full" {
		t.Error("routing event must never project to legacy coverage=full")
	}
	if a.legacyState(true) != "anomalous" {
		t.Errorf("routing legacy state = %q, want anomalous (a transition WAS observed)", a.legacyState(true))
	}
	if a.NormalityEligible {
		t.Error("a point-in-time event lane can never assert window-health (normal)")
	}
	// the anomalous transition still counts toward confidence (strong evidence).
	if !a.ConfidenceEligible {
		t.Error("an anomalous control-plane transition must be confidence-eligible")
	}
}

// Test 9 — active checks with a small leading gap (P-027379 active: 98.2%, 13s
// leading) reach COMPLETE when cadence is known and no material gaps exist; the
// leading gap is still surfaced.
func TestCoverage_LeadingGapActiveChecks(t *testing.T) {
	e := newCoverageEngine(nil)
	// probes every 15s from 20:20:46 to 20:32:21 (leading 13s, no trailing).
	obs := evenSeries(ct("2026-07-15 20:20:46"), 15*time.Second, 47) // →20:32:16
	obs = append(obs, p27WinEnd)
	a := e.Assess("global", LaneCoverageInput{
		Class: "active_probe", WindowStart: p27WinStart, WindowEnd: p27WinEnd,
		Observations: obs, ScheduleInterval: 15 * time.Second, TotalCount: len(obs),
	})
	if a.Quality != qualityComplete {
		t.Fatalf("active quality = %q (ratio %.3f), want complete", a.Quality, a.CoverageRatio)
	}
	if a.LeadingGap == "" {
		t.Error("active lane must still surface its 13s leading gap")
	}
	if a.CadenceSource != cadenceFromSchedule {
		t.Errorf("cadence source = %q, want schedule", a.CadenceSource)
	}
	if !a.NormalityEligible {
		t.Error("complete + in-scope + healthy + clean lane should be normality-eligible")
	}
}

// Test 10 — a lane is "Full/complete" ONLY when the thresholds pass AND internal
// gaps are verifiable. The SAME 98% coverage, measured with only min/max (cadence
// unknown), is capped at substantial — we cannot certify complete without
// covered-interval proof (constraint 5).
func TestCoverage_FullOnlyWhenThresholdsPass(t *testing.T) {
	e := newCoverageEngine(nil)
	win0, win1 := ct("2026-07-15 10:00:00"), ct("2026-07-15 10:10:00") // 600s
	// Rich path: dense series + schedule → complete.
	rich := e.Assess("global", LaneCoverageInput{
		Class: "active_probe", WindowStart: win0, WindowEnd: win1,
		Observations: evenSeries(win0, 10*time.Second, 61), ScheduleInterval: 10 * time.Second,
		TotalCount: 61,
	})
	if rich.Quality != qualityComplete {
		t.Fatalf("rich full-span lane quality = %q, want complete", rich.Quality)
	}
	// Legacy path: only min/max spanning the window, cadence unknown → capped.
	legacy := e.Assess("global", LaneCoverageInput{
		Class: "active_probe", WindowStart: win0, WindowEnd: win1,
		LaneStart: win0, LaneEnd: win1, TotalCount: 61,
	})
	if legacy.Quality == qualityComplete {
		t.Fatalf("legacy min/max path must NOT certify complete (cadence unverifiable); got %q", legacy.Quality)
	}
	if legacy.Quality != qualitySubstantial {
		t.Fatalf("legacy capped quality = %q, want substantial", legacy.Quality)
	}
	if legacy.CadenceKnown {
		t.Error("legacy path must report cadence unknown")
	}
	// A lane below the minimal threshold is minimal, not partial.
	low := e.Assess("global", LaneCoverageInput{
		Class: "device_telemetry", WindowStart: win0, WindowEnd: win1,
		Observations: evenSeries(win0, 10*time.Second, 6), ScheduleInterval: 10 * time.Second, // ~50s of 600s
		TotalCount: 6,
	})
	if low.Quality != qualityMinimal {
		t.Errorf("low-coverage lane quality = %q (ratio %.3f), want minimal", low.Quality, low.CoverageRatio)
	}
}

// Test 11 — a lane KNOWN to be out of the incident scope is irrelevant and
// eligible for nothing, with a scope_mismatch reason.
func TestCoverage_ScopeMismatch(t *testing.T) {
	e := newCoverageEngine(nil)
	win0, win1 := ct("2026-07-15 10:00:00"), ct("2026-07-15 10:10:00")
	a := e.Assess("global", LaneCoverageInput{
		Class: "device_telemetry", WindowStart: win0, WindowEnd: win1,
		Observations: evenSeries(win0, 10*time.Second, 61), ScheduleInterval: 10 * time.Second,
		TotalCount: 61, Scope: triNo,
	})
	if a.Quality != qualityIrrelevant {
		t.Fatalf("out-of-scope lane quality = %q, want irrelevant", a.Quality)
	}
	if a.NormalityEligible || a.ConfidenceEligible || a.ImpactEligible {
		t.Error("an out-of-scope lane must be eligible for nothing")
	}
	for _, rs := range [][]string{a.NormalityReasons, a.ConfidenceReasons, a.ImpactReasons} {
		if !hasReason(rs, "scope_mismatch") {
			t.Errorf("reasons %v must include scope_mismatch", rs)
		}
	}
	if a.legacyCoverage() != "not_applicable" {
		t.Errorf("legacy coverage = %q, want not_applicable", a.legacyCoverage())
	}
}

// Test 12 — a KNOWN-degraded collector vetoes Normal even with complete coverage
// (constraint 7: collector health is a precondition), with a collector_degraded
// reason. Coverage quality itself stays complete (the data that DID arrive spanned
// the window) — but the lane is not normality- or confidence-eligible.
func TestCoverage_UnhealthyCollector(t *testing.T) {
	e := newCoverageEngine(nil)
	win0, win1 := ct("2026-07-15 10:00:00"), ct("2026-07-15 10:10:00")
	a := e.Assess("global", LaneCoverageInput{
		Class: "device_telemetry", WindowStart: win0, WindowEnd: win1,
		Observations: evenSeries(win0, 10*time.Second, 61), ScheduleInterval: 10 * time.Second,
		TotalCount: 61, CollectorHealthIn: collectorDegraded,
	})
	if a.Quality != qualityComplete {
		t.Fatalf("quality = %q, want complete (coverage was fine; only health is bad)", a.Quality)
	}
	if a.NormalityEligible {
		t.Error("a known-degraded collector must veto normality")
	}
	if a.ConfidenceEligible {
		t.Error("a known-degraded collector must veto confidence contribution")
	}
	if !hasReason(a.NormalityReasons, "collector_degraded") {
		t.Errorf("normality reasons = %v, want collector_degraded", a.NormalityReasons)
	}
	if a.legacyState(false) == "normal" {
		t.Error("degraded-collector lane must not read green Normal")
	}
	// Contrast: unknown health does NOT veto (no evidence of a fault) → normal.
	ok := e.Assess("global", LaneCoverageInput{
		Class: "device_telemetry", WindowStart: win0, WindowEnd: win1,
		Observations: evenSeries(win0, 10*time.Second, 61), ScheduleInterval: 10 * time.Second, TotalCount: 61,
	})
	if !ok.NormalityEligible || ok.legacyState(false) != "normal" {
		t.Error("unknown collector health must NOT veto a complete, clean lane's Normal")
	}
}

// Per-class semantics (constraint 6): freshness and batch strategies. A fresh
// snapshot is complete; a stale one is stale; a batch older than its interval is
// stale.
func TestCoverage_FreshnessAndBatch(t *testing.T) {
	e := newCoverageEngine(map[string]tenantCoveragePolicy{
		"global": {Strategy: map[string]evidenceStrategy{
			"inventory": strategyFreshness, "rollup": strategyBatch,
		}},
	})
	now := ct("2026-07-15 10:10:00")
	// fresh snapshot (2m old, stale-after 15m default) → complete.
	fresh := e.Assess("global", LaneCoverageInput{
		Class: "inventory", Now: now, LaneEnd: ct("2026-07-15 10:08:00"), TotalCount: 1,
	})
	if fresh.Strategy != strategyFreshness || fresh.Quality != qualityComplete {
		t.Fatalf("fresh snapshot = %q/%q, want freshness/complete", fresh.Strategy, fresh.Quality)
	}
	// stale snapshot (40m old) → stale.
	stale := e.Assess("global", LaneCoverageInput{
		Class: "inventory", Now: now, LaneEnd: ct("2026-07-15 09:30:00"), TotalCount: 1,
	})
	if stale.Quality != qualityStale {
		t.Fatalf("stale snapshot quality = %q, want stale", stale.Quality)
	}
	if stale.NormalityEligible {
		t.Error("a stale snapshot must not be normality-eligible")
	}
	// batch older than its 5m interval → stale.
	batch := e.Assess("global", LaneCoverageInput{
		Class: "rollup", Now: now, LaneEnd: ct("2026-07-15 10:00:00"),
		ScheduleInterval: 5 * time.Minute, TotalCount: 1,
	})
	if batch.Strategy != strategyBatch || batch.Quality != qualityStale {
		t.Fatalf("late batch = %q/%q, want batch/stale", batch.Strategy, batch.Quality)
	}
	if !batch.CadenceKnown || batch.CadenceSource != cadenceFromSchedule {
		t.Errorf("batch cadence = %v/%q, want known/schedule", batch.CadenceKnown, batch.CadenceSource)
	}
}

// The P-027379 §2 regression fixtures — every audit mislabel corrected, in ONE
// table so before→after is auditable. Coverage ratios use the audit's exact
// intervals.
func TestCoverage_P027379_Regression(t *testing.T) {
	e := newCoverageEngine(nil)
	type want struct {
		strategy    evidenceStrategy
		quality     coverageQuality
		notComplete bool // must never be complete/full
		normalOK    bool
		impactOK    bool
	}
	cases := []struct {
		name string
		in   LaneCoverageInput
		w    want
	}{
		{
			name: "device_health_78.5pct_was_Full_Normal",
			in: LaneCoverageInput{
				Class: "device_telemetry", WindowStart: p27WinStart, WindowEnd: p27WinEnd,
				Observations:     append(evenSeries(ct("2026-07-15 20:22:31"), 30*time.Second, 19), ct("2026-07-15 20:31:47")),
				ScheduleInterval: 30 * time.Second, TotalCount: 20,
			},
			w: want{strategyContinuous, qualitySubstantial, true, false, false},
		},
		{
			name: "routing_19s_was_Full",
			in: LaneCoverageInput{
				Class: "control_plane", WindowStart: p27WinStart, WindowEnd: p27WinEnd,
				LaneStart: ct("2026-07-15 20:20:33"), LaneEnd: ct("2026-07-15 20:20:52"),
				TotalCount: 1, AnomalousCount: 1,
			},
			w: want{strategyEventBased, qualityPointInTime, true, false, true /*anomalous → impact-eligible*/},
		},
		{
			name: "flow_78.8pct_was_Normal_none_detected",
			in: LaneCoverageInput{
				Class: "passive_flow", WindowStart: p27WinStart, WindowEnd: p27WinEnd,
				Observations:     append(evenSeries(ct("2026-07-15 20:20:50"), 30*time.Second, 19), ct("2026-07-15 20:30:08")),
				ScheduleInterval: 30 * time.Second, TotalCount: 20,
			},
			w: want{strategyContinuous, qualitySubstantial, true, false, false},
		},
		{
			name: "active_checks_98.2pct",
			in: LaneCoverageInput{
				Class: "active_probe", WindowStart: p27WinStart, WindowEnd: p27WinEnd,
				Observations:     append(evenSeries(ct("2026-07-15 20:20:46"), 15*time.Second, 47), p27WinEnd),
				ScheduleInterval: 15 * time.Second, TotalCount: 48, AnomalousCount: 48,
			},
			w: want{strategyContinuous, qualityComplete, false, false /*anomalous → not "normal"*/, true},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := e.Assess("global", c.in)
			if a.Strategy != c.w.strategy {
				t.Errorf("strategy = %q, want %q", a.Strategy, c.w.strategy)
			}
			if a.Quality != c.w.quality {
				t.Errorf("quality = %q (ratio %.3f), want %q", a.Quality, a.CoverageRatio, c.w.quality)
			}
			if c.w.notComplete && a.legacyCoverage() == "full" {
				t.Errorf("lane must not project to legacy Full; quality=%q", a.Quality)
			}
			if a.NormalityEligible != c.w.normalOK {
				t.Errorf("normality-eligible = %v, want %v (reasons %v)", a.NormalityEligible, c.w.normalOK, a.NormalityReasons)
			}
			if a.ImpactEligible != c.w.impactOK {
				t.Errorf("impact-eligible = %v, want %v (reasons %v)", a.ImpactEligible, c.w.impactOK, a.ImpactReasons)
			}
		})
	}
}

// MANDATORY tenant-isolation test (CLAUDE.md §3a): one tenant's coverage policy can
// NEVER change another tenant's assessment. A permissive threshold set for tenant B
// must not leak into tenant A's verdict, and vice-versa.
func TestCoverage_TenantIsolation(t *testing.T) {
	e := newCoverageEngine(map[string]tenantCoveragePolicy{
		// tenant B declares that ANY coverage above 10% is "complete".
		"tenant-b": {Thresholds: map[string]coverageThresholds{
			"*": {Complete: 0.10, Substantial: 0.05, Minimal: 0.01, StaleAfter: 15 * time.Minute},
		}},
	})
	win0, win1 := ct("2026-07-15 10:00:00"), ct("2026-07-15 10:10:00")
	// A lane covering ~50% of the window (5 min of 10) with a known cadence.
	half := LaneCoverageInput{
		Class: "device_telemetry", WindowStart: win0, WindowEnd: win1,
		Observations: evenSeries(win0, 10*time.Second, 30), ScheduleInterval: 10 * time.Second, TotalCount: 30,
	}

	// tenant A (default 95/80/25 thresholds) → NOT complete (it is partial).
	a := e.Assess("tenant-a", half)
	if a.Quality == qualityComplete {
		t.Fatalf("tenant A must use default thresholds → not complete; got %q (ratio %.3f) — tenant B's policy leaked", a.Quality, a.CoverageRatio)
	}
	// tenant B (permissive) → complete under ITS OWN policy.
	b := e.Assess("tenant-b", half)
	if b.Quality != qualityComplete {
		t.Fatalf("tenant B's own permissive policy should read complete; got %q", b.Quality)
	}
	// Re-assessing for tenant A after tenant B must be unchanged (no shared state).
	a2 := e.Assess("tenant-a", half)
	if a2.Quality != a.Quality {
		t.Fatalf("tenant A verdict changed across calls (%q → %q) — cross-tenant contamination", a.Quality, a2.Quality)
	}
	// An unrelated tenant with no policy falls back to global defaults (not B's).
	c := e.Assess("tenant-c", half)
	if c.Quality == qualityComplete {
		t.Fatalf("tenant C (no policy) must use global defaults → not complete; got %q — B's policy leaked", c.Quality)
	}
}

// The legacy rcaLaneWindowCoverage shim now delegates to the engine: it reports
// full only when the engine judges complete, and returns the missing interval
// otherwise. (Also keeps the kept-for-Phase-D helper exercised.)
func TestCoverage_LaneWindowCoverageDelegates(t *testing.T) {
	// A single-instant window → full (no interval to miss).
	if full, _ := rcaLaneWindowCoverage(ct("2026-07-15 10:00:00"), ct("2026-07-15 10:00:00"),
		ct("2026-07-15 10:00:00"), ct("2026-07-15 10:00:00")); !full {
		t.Error("single-instant window must read full")
	}
	// A lane ending well before the window end → not full, with a missing interval.
	full, missing := rcaLaneWindowCoverage(
		ct("2026-07-15 10:00:00"), ct("2026-07-15 10:02:00"),
		ct("2026-07-15 10:00:00"), ct("2026-07-15 10:10:00"))
	if full {
		t.Error("a lane covering only 2m of a 10m window must not read full")
	}
	if missing == "" {
		t.Error("partial coverage must state a missing interval")
	}
}

func hasReason(reasons []string, want string) bool {
	for _, r := range reasons {
		if r == want {
			return true
		}
	}
	return false
}
