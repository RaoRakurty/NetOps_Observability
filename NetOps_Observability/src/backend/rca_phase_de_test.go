package main

// rca_phase_de_test.go — Phase D (renderers + wording) and Phase E (quality gate
// + P-027379 regeneration) tests.
//
//   - Test 13 (impact-wording matrix): coverage → eligibility → wording. The
//     canonical defect it pins: a partial impact lane must NEVER render a
//     definitive "none detected"; both impact renderers read one assessment.
//   - Evidence-accounting block + coverage-column render tests.
//   - Tenant isolation: coverage policy / observer classification / accounting
//     stamping never cross tenants.
//   - The 12 quality-gate blockers (each fires when it should; none fire on the
//     corrected P-027379).
//   - Test 14 (P-027379 regeneration snapshot): counts reconcile, no
//     api-as-vantage, gaps visible, the false "none detected" is killed.

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// deSig builds a fully-populated corr_signals-shaped map for the report builder
// (testSig defaults + explicit attrs/probe_scope/probe_authority/observer_type).
type deSigOpt struct {
	kind, modality, observer, observerType, entityType, entity, sev, ts string
	attached                                                           bool
	probeScope, probeAuth                                              string
	agentHost, sourceEgress, seamID, target                           string
}

func deSig(o deSigOpt) map[string]any {
	attrs := map[string]any{}
	if o.agentHost != "" {
		attrs["agent_host"] = o.agentHost
	}
	if o.sourceEgress != "" {
		attrs["source_egress"] = o.sourceEgress
	}
	if o.seamID != "" {
		attrs["seam_id"] = o.seamID
	}
	if o.target != "" {
		attrs["target"] = o.target
	}
	b, _ := json.Marshal(attrs)
	extra := map[string]any{
		"attrs": string(b), "probe_scope": o.probeScope,
		"probe_authority": o.probeAuth, "observer_type": o.observerType,
	}
	return testSig(o.kind, o.modality, o.observer, o.entityType, o.entity, o.sev, o.ts, o.attached, extra)
}

func deTS(base time.Time, addSec int) string {
	return base.Add(time.Duration(addSec) * time.Second).Format("2006-01-02 15:04:05")
}

// ── Test 13: impact-wording matrix (coverage → eligibility → wording) ──────────

func TestPhaseD_ImpactWordingMatrix(t *testing.T) {
	// A window anchored by an anomalous control-plane event + a customer-path
	// synthetic failure. The ONLY thing that varies per row is the real-traffic
	// (passive_flow) coverage — and it must drive the real-user impact wording.
	winStart := time.Date(2026, 7, 12, 18, 10, 0, 0, time.UTC)
	base := func() []map[string]any {
		return []map[string]any{
			deSig(deSigOpt{kind: "ipsec_tunnel_down", modality: "control_plane", observer: "ipsec:edge",
				entityType: "seam", entity: "tunnel:lab", sev: "crit", ts: deTS(winStart, 0), attached: true,
				seamID: "tunnel:lab"}),
			deSig(deSigOpt{kind: "probe_loss", modality: "active_probe", observer: "lan-vantage-1",
				entityType: "path", entity: "lan-vantage-1->10.60.10.10", sev: "crit", ts: deTS(winStart, 0),
				attached: true, probeScope: "customer_path", probeAuth: "high", agentHost: "lan-host"}),
			deSig(deSigOpt{kind: "probe_loss", modality: "active_probe", observer: "lan-vantage-1",
				entityType: "path", entity: "lan-vantage-1->10.60.10.10", sev: "crit", ts: deTS(winStart, 840),
				attached: true, probeScope: "customer_path", probeAuth: "high", agentHost: "lan-host"}),
		}
	}
	meta := testMeta("open", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"ipsec_tunnel_down", "probe_loss"}, nil, nil, "netops", false))

	// flow lane that only covers the FIRST half of the window → partial → NOT
	// impact-eligible → real-user impact must stay not_observable (the P1 kill).
	partialFlow := func() []map[string]any {
		var f []map[string]any
		for s := 0; s <= 300; s += 30 {
			f = append(f, deSig(deSigOpt{kind: "flow_volume", modality: "passive_flow", observer: "exp-1",
				entityType: "interface", entity: "if1", sev: "info", ts: deTS(winStart, s), attached: false}))
		}
		return f
	}

	cases := []struct {
		name            string
		sigs            []map[string]any
		wantImpactRU    string
		wantImpact      string
		mgmtMustContain string
		mgmtMustNot     string
	}{
		{
			name:            "partial flow coverage — real-user NOT none_detected (P1 kill)",
			sigs:            append(base(), partialFlow()...),
			wantImpactRU:    "not_observable",
			wantImpact:      "detected", // synthetic confirmed
			mgmtMustNot:     "No customer impact was detected",
		},
		{
			name: "anomalous flow — indicator_detected",
			sigs: append(base(),
				deSig(deSigOpt{kind: "flow_volume_anomaly", modality: "passive_flow", observer: "exp-1",
					entityType: "interface", entity: "if1", sev: "warn", ts: deTS(winStart, 120), attached: true})),
			wantImpactRU: "indicator_detected",
			// synthetic path impact is confirmed here, so the overall (strongest-axis)
			// impact is "detected"; the real-user axis stays an indicator.
			wantImpact: "detected",
		},
		{
			name:            "no real-traffic lane — real-user not_observable, no no-impact claim",
			sigs:            base(),
			wantImpactRU:    "not_observable",
			wantImpact:      "detected",
			mgmtMustNot:     "No customer impact was detected",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := buildTestReport(t, meta, tc.sigs)
			if rep.States.ImpactRealUser != tc.wantImpactRU {
				t.Fatalf("impact_real_user = %q, want %q (impact=%q syn=%q)",
					rep.States.ImpactRealUser, tc.wantImpactRU, rep.States.Impact, rep.States.ImpactSynthetic)
			}
			if tc.wantImpact != "" && rep.States.Impact != tc.wantImpact {
				t.Fatalf("impact = %q, want %q", rep.States.Impact, tc.wantImpact)
			}
			if tc.mgmtMustContain != "" && !strings.Contains(rep.Summary.Management, tc.mgmtMustContain) {
				t.Fatalf("mgmt summary missing %q: %s", tc.mgmtMustContain, rep.Summary.Management)
			}
			if tc.mgmtMustNot != "" && strings.Contains(rep.Summary.Management, tc.mgmtMustNot) {
				t.Fatalf("mgmt summary must not contain %q: %s", tc.mgmtMustNot, rep.Summary.Management)
			}
			// Both renderers read the SAME state: the NOC "Real-user impact" line
			// equals the management-summary-derived state, never a second derivation.
			nocRU := ""
			for _, kv := range rep.Summary.Noc {
				if kv.K == "Real-user impact" {
					nocRU = kv.V
				}
			}
			if nocRU != strings.ReplaceAll(tc.wantImpactRU, "_", " ") {
				t.Fatalf("NOC Real-user impact = %q, want %q", nocRU, tc.wantImpactRU)
			}
			// the report never fails its own gate on any matrix row
			if !rep.Quality.Passed {
				t.Fatalf("quality gate failed: %+v", rep.Quality.Errors)
			}
		})
	}
}

// A clean multi-class window (both axes covered, neither anomalous) KEEPS the
// honest "none detected within coverage" claim — the eligibility gate is not a
// blanket suppressor.
func TestPhaseD_CleanMultiClassKeepsNoneDetected(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.access.uplink-down",
		testHyp("sig.ent.access.uplink-down", 0.9, "confirmed",
			[]string{"interface_down"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("interface_down", "control_plane", "lan-sw1", "interface", "lan-sw1:Gi0/1", "high", "2026-07-12 18:00:00", true, nil),
		testSig("probe_rtt", "active_probe", "prober-1", "path", "prober-1->10.10.1.1", "info", "2026-07-12 18:00:00", false, nil),
		testSig("flow_volume", "passive_flow", "exp-1", "interface", "if1", "info", "2026-07-12 18:00:00", false, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.States.Impact != "none_detected" {
		t.Fatalf("impact = %q (syn=%s ru=%s), want none_detected", rep.States.Impact, rep.States.ImpactSynthetic, rep.States.ImpactRealUser)
	}
	if !strings.Contains(rep.Summary.Management, "No customer impact was detected within available telemetry coverage") {
		t.Fatalf("clean coverage must keep the honest none-detected claim: %s", rep.Summary.Management)
	}
	if !rep.Quality.Passed {
		t.Fatalf("gate failed on clean multi-class none_detected: %+v", rep.Quality.Errors)
	}
}

// ── Evidence-accounting block render ──────────────────────────────────────────

func TestPhaseD_EvidenceAccountingBlockRendered(t *testing.T) {
	rep := buildP027379Report(t)

	// customer-view numbers are the RECONCILED accounting, never the raw observer set.
	if rep.Accounting.IndependentConfirmingSources != 2 {
		t.Errorf("independent confirming sources = %d, want 2", rep.Accounting.IndependentConfirmingSources)
	}
	if rep.Accounting.EvidenceGroups != 4 {
		t.Errorf("evidence groups = %d, want 4", rep.Accounting.EvidenceGroups)
	}
	// api is a collector, NEVER a logical vantage.
	for _, v := range rep.Accounting.LogicalVantages {
		if v == "api" {
			t.Errorf("api appears as a logical vantage")
		}
	}
	foundApiCollector := false
	for _, c := range rep.Accounting.Collectors {
		if c == "api" {
			foundApiCollector = true
		}
	}
	if !foundApiCollector {
		t.Errorf("api should be classified as a collector, got collectors=%v", rep.Accounting.Collectors)
	}
	// configured tests render Unavailable-with-reason (historical), never a bare 0.
	if !strings.HasPrefix(rep.Accounting.ConfiguredTests, "Unavailable") {
		t.Errorf("configured tests = %q, want Unavailable — reason", rep.Accounting.ConfiguredTests)
	}
	// operator lineage ladder is present and descends.
	if len(rep.Accounting.Ladder) == 0 {
		t.Fatalf("reconciliation ladder empty")
	}

	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	for _, want := range []string{
		"Evidence accounting", "Independent confirming sources",
		"Control-plane sources", "Collectors (not vantages)", "Window observations",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("rendered HTML missing %q", want)
		}
	}
}

// ── Coverage table columns render ─────────────────────────────────────────────

func TestPhaseD_CoverageColumnsRendered(t *testing.T) {
	rep := buildP027379Report(t)
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	for _, want := range []string{
		"Coverage &amp; gaps", "Contributes", "covered", "trailing gap",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("coverage table missing spec column/content %q", want)
		}
	}
	// the flow + device lanes are PARTIAL (not a green Normal) with gaps visible.
	var flow *rcaEvidenceLane
	for i := range rep.Coverage {
		if rep.Coverage[i].Class == "passive_flow" {
			flow = &rep.Coverage[i]
		}
	}
	if flow == nil || flow.State == "normal" {
		t.Fatalf("passive_flow lane must be partial/inconclusive, got %+v", flow)
	}
	if flow.Assessment == nil || flow.Assessment.TrailingGap == "" {
		t.Fatalf("partial flow lane must expose a trailing gap: %+v", flow)
	}
}

// ── Tenant isolation: coverage policy / classification / accounting stamping ───

func TestPhaseD_TenantIsolation(t *testing.T) {
	// A per-tenant coverage policy that flips active_probe to event-based must be
	// visible ONLY to that tenant — another tenant sees the continuous default.
	eng := newCoverageEngine(map[string]tenantCoveragePolicy{
		"tenant-a": {Strategy: map[string]evidenceStrategy{"active_probe": strategyEventBased}},
	})
	in := LaneCoverageInput{Class: "active_probe", TotalCount: 1,
		WindowStart: time.Now().Add(-time.Hour), WindowEnd: time.Now(), Observations: []time.Time{time.Now()}}
	if got := eng.Assess("tenant-a", in).Strategy; got != strategyEventBased {
		t.Errorf("tenant-a strategy = %q, want event_based (its policy)", got)
	}
	if got := eng.Assess("tenant-b", in).Strategy; got != strategyContinuous {
		t.Errorf("tenant-b strategy = %q, want continuous (no policy leak across tenants)", got)
	}

	// A per-tenant observer policy that elevates a probe to a vantage must not leak.
	reg := newObserverRegistry(map[string]map[string]observerKind{
		"tenant-a": {"site-probe-9": observerLogicalVantage},
	})
	f := observerFacts{ObserverID: "site-probe-9", Modality: "active_probe", ProbeAuthority: "low"}
	if got := reg.classify("tenant-a", f); got != observerLogicalVantage {
		t.Errorf("tenant-a classify = %q, want logical_vantage", got)
	}
	if got := reg.classify("tenant-b", f); got == observerLogicalVantage {
		t.Errorf("tenant-b saw tenant-a's vantage policy — cross-tenant leak")
	}

	// The accounting stamps TenantID from the caller input, NEVER from a signal
	// body that tries to claim another tenant.
	sigs := []map[string]any{
		deSig(deSigOpt{kind: "probe_loss", modality: "active_probe", observer: "prober",
			entityType: "path", entity: "prober->x", sev: "warn", ts: "2026-07-12 18:00:00", attached: true,
			probeAuth: "low", agentHost: "h1"}),
	}
	sigs[0]["tenant_id"] = "attacker-tenant" // ignored — not the token
	acc, err := buildEvidenceAccounting(accountingInput{TenantID: "victim-tenant", Signals: sigs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acc.TenantID != "victim-tenant" {
		t.Errorf("accounting tenant = %q, want victim-tenant (stamped from the token, not the payload)", acc.TenantID)
	}
}

// ── Phase E: the 12 quality-gate blockers ─────────────────────────────────────

// baseValidReport is a minimal report that PASSES the gate — each blocker test
// mutates ONE field to trip exactly one blocker.
func baseValidReport(t *testing.T) rcaReport {
	t.Helper()
	meta := testMeta("open", "confirmed", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.9, "confirmed",
			[]string{"bgp_adjacency_change", "probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss", "active_probe", "lan-vantage-1", "path", "lan-vantage-1->10.0.0.1", "crit", "2026-07-12 18:12:30", true,
			map[string]any{"probe_scope": "customer_path", "probe_authority": "high"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if !rep.Quality.Passed {
		t.Fatalf("base report must pass the gate: %+v", rep.Quality.Errors)
	}
	return rep
}

func gateErrorCodes(rep rcaReport) map[string]bool {
	q := validateRcaReport(&rep, rcaTestNow)
	out := map[string]bool{}
	for _, e := range q.Errors {
		out[e.Code] = true
	}
	return out
}

func TestPhaseE_Blockers(t *testing.T) {
	full := coverageComplete() // a complete, impact-eligible synthetic assessment
	partial := coveragePartial()

	tests := []struct {
		name   string
		mutate func(r *rcaReport)
		code   string
	}{
		{"case_linked>total", func(r *rcaReport) {
			r.accounting.CaseLinkedSignals = make([]observationRecord, 5)
			r.accounting.WindowObservations = make([]observationRecord, 2)
		}, "accounting_case_linked_exceeds_total"},
		{"anomalous>case_linked", func(r *rcaReport) {
			r.accounting.AnomalousSignals = make([]observationRecord, 5)
			r.accounting.CaseLinkedSignals = make([]observationRecord, 2)
			r.accounting.WindowObservations = make([]observationRecord, 9)
		}, "accounting_anomalous_exceeds_case_linked"},
		{"failed>executions", func(r *rcaReport) {
			r.accounting.TestExecutions = availableCount(2)
			r.accounting.FailedTestExecutions = availableCount(5)
		}, "accounting_failed_exceeds_executions"},
		{"independent>observers", func(r *rcaReport) {
			r.accounting.AnomalyObservers = make([]observerRecord, 1)
			r.accounting.IndependentGroups = make([]independenceGroup, 3)
		}, "accounting_independent_exceeds_observers"},
		{"verdict_gate_disagreement", func(r *rcaReport) {
			r.accounting.VerdictIndependentPair = []string{"ghost-a", "ghost-b"}
			r.accounting.IndependentGroups = nil
		}, "accounting_verdict_gate_disagreement"},
		{"api_as_vantage", func(r *rcaReport) {
			r.accounting.AnomalyObservers = []observerRecord{{ObserverID: "api", Kind: observerLogicalVantage}}
		}, "api_or_collector_as_vantage"},
		{"full_below_threshold", func(r *rcaReport) {
			a := partial
			a.CoverageRatio = 0.4
			r.Coverage = []rcaEvidenceLane{{Class: "active_probe", Coverage: "full", State: "normal", Assessment: &a}}
		}, "coverage_full_below_threshold"},
		{"normal_with_material_gap", func(r *rcaReport) {
			a := partial // quality substantial, not complete
			r.Coverage = []rcaEvidenceLane{{Class: "passive_flow", Coverage: "partial", State: "normal", Assessment: &a}}
		}, "coverage_normal_with_material_gap"},
		{"point_in_time_as_full", func(r *rcaReport) {
			a := full
			a.Strategy = strategyEventBased
			r.Coverage = []rcaEvidenceLane{{Class: "control_plane", Coverage: "full", State: "anomalous", Assessment: &a}}
		}, "coverage_point_in_time_as_full"},
		{"impact_none_detected_without_coverage", func(r *rcaReport) {
			r.States.Impact = "none_detected"
			r.States.ImpactSynthetic = "none_detected"
			r.States.ImpactRealUser = "none_detected"
			a := partial
			r.Coverage = []rcaEvidenceLane{{Class: "active_probe", Assessment: &a}, {Class: "passive_flow", Assessment: &a}}
		}, "impact_none_detected_without_coverage"},
		{"real_user_none_detected_without_eligible_coverage", func(r *rcaReport) {
			r.States.ImpactRealUser = "none_detected"
			a := partial
			r.Coverage = []rcaEvidenceLane{{Class: "passive_flow", Assessment: &a}}
		}, "real_user_none_detected_without_eligible_coverage"},
		{"synthetic_none_detected_without_eligible_coverage", func(r *rcaReport) {
			r.States.ImpactSynthetic = "none_detected"
			a := partial
			r.Coverage = []rcaEvidenceLane{{Class: "active_probe", Assessment: &a}}
		}, "synthetic_none_detected_without_eligible_coverage"},
	}
	seen := map[string]bool{}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rep := baseValidReport(t)
			tc.mutate(&rep)
			codes := gateErrorCodes(rep)
			if !codes[tc.code] {
				t.Fatalf("blocker %q did not fire; codes=%v", tc.code, codes)
			}
		})
		seen[tc.code] = true
	}
	if len(seen) != 12 {
		t.Fatalf("expected 12 distinct blockers, wired %d: %v", len(seen), seen)
	}
}

// coverageComplete / coveragePartial — assessments for the blocker tests.
func coverageComplete() CoverageAssessment {
	return CoverageAssessment{Class: "active_probe", Strategy: strategyContinuous, Quality: qualityComplete,
		CoverageRatio: 1, RatioKnown: true, ConfidenceEligible: true, ImpactEligible: true, NormalityEligible: true}
}
func coveragePartial() CoverageAssessment {
	return CoverageAssessment{Class: "passive_flow", Strategy: strategyContinuous, Quality: qualitySubstantial,
		CoverageRatio: 0.78, RatioKnown: true, TrailingGap: "2m13s", ConfidenceEligible: true, ImpactEligible: false}
}

// ── Test 14: P-027379 regeneration snapshot ───────────────────────────────────

// buildP027379Report reconstructs the P-027379 incident from the Phase A audit
// (§2/§5 intervals) and regenerates the full report view model end-to-end.
func buildP027379Report(t *testing.T) rcaReport {
	t.Helper()
	win := time.Date(2026, 7, 15, 20, 20, 33, 0, time.UTC) // window start (708s incident)
	var sigs []map[string]any
	add := func(o deSigOpt) { sigs = append(sigs, deSig(o)) }

	// control_plane: the 19s tunnel-down event (audit §2) + one non-anomalous obs.
	add(deSigOpt{kind: "ipsec_tunnel_down", modality: "control_plane", observer: "ipsec:lab-vpn-edge",
		entityType: "seam", entity: "tunnel:lab-vpn", sev: "crit", ts: deTS(win, 0), attached: true, seamID: "tunnel:lab-vpn"})
	add(deSigOpt{kind: "ipsec_status", modality: "control_plane", observer: "ipsec:lab-vpn-edge",
		entityType: "seam", entity: "tunnel:lab-vpn", sev: "info", ts: deTS(win, 19), attached: false, seamID: "tunnel:lab-vpn"})

	// active_probe — 6 anomalous across 3 observers (prober+api co-located on the
	// lab host; lan-vantage-1 on its own host). All customer_path.
	add(deSigOpt{kind: "probe_rtt_anomaly", modality: "active_probe", observer: "prober", entityType: "path",
		entity: "prober->tunnel", sev: "crit", ts: deTS(win, 13), attached: true, probeScope: "customer_path",
		probeAuth: "low", agentHost: "lab-host", sourceEgress: "203.0.113.9", target: "tunnel"})
	add(deSigOpt{kind: "probe_loss", modality: "active_probe", observer: "prober", entityType: "path",
		entity: "prober->tunnel", sev: "crit", ts: deTS(win, 330), attached: true, probeScope: "customer_path",
		probeAuth: "low", agentHost: "lab-host", sourceEgress: "203.0.113.9", target: "tunnel"})
	add(deSigOpt{kind: "probe_loss", modality: "active_probe", observer: "prober", entityType: "path",
		entity: "prober->tunnel", sev: "crit", ts: deTS(win, 708), attached: true, probeScope: "customer_path",
		probeAuth: "low", agentHost: "lab-host", sourceEgress: "203.0.113.9", target: "tunnel"})
	add(deSigOpt{kind: "probe_rtt_anomaly", modality: "active_probe", observer: "lan-vantage-1", entityType: "path",
		entity: "lan-vantage-1->tunnel", sev: "crit", ts: deTS(win, 120), attached: true, probeScope: "customer_path",
		probeAuth: "high", agentHost: "lan-vantage-host", sourceEgress: "198.51.100.4", target: "tunnel"})
	add(deSigOpt{kind: "probe_rtt_anomaly", modality: "active_probe", observer: "api", observerType: "vantage_agent",
		entityType: "path", entity: "api->tunnel", sev: "crit", ts: deTS(win, 27), attached: true, probeScope: "customer_path",
		probeAuth: "low", agentHost: "lab-host", sourceEgress: "203.0.113.9", target: "tunnel"})
	add(deSigOpt{kind: "probe_loss", modality: "active_probe", observer: "api", observerType: "vantage_agent",
		entityType: "path", entity: "api->tunnel", sev: "crit", ts: deTS(win, 600), attached: true, probeScope: "customer_path",
		probeAuth: "low", agentHost: "lab-host", sourceEgress: "203.0.113.9", target: "tunnel"})

	// recovery: 1 attached + 3 unattached clears (window recovery=4).
	add(deSigOpt{kind: "probe_loss_clear", modality: "active_probe", observer: "prober", entityType: "path",
		entity: "prober->tunnel", sev: "info", ts: deTS(win, 300), attached: true, probeAuth: "low", agentHost: "lab-host"})
	for i := 0; i < 3; i++ {
		add(deSigOpt{kind: "rtt_anomaly_clear", modality: "active_probe", observer: "prober", entityType: "path",
			entity: "prober->tunnel", sev: "info", ts: deTS(win, 290+i), attached: false, probeAuth: "low", agentHost: "lab-host"})
	}

	// device_telemetry: 5 non-anomalous samples 20:22:31→20:31:47 (partial — leading
	// 1m58s, trailing 34s → ~78.5%; audit §2 device-health row).
	devStart, devEnd, devN := 118, 674, 5
	for i := 0; i < devN; i++ {
		ts := devStart + i*(devEnd-devStart)/(devN-1)
		add(deSigOpt{kind: "cpu_util", modality: "device_telemetry", observer: "dev-1", entityType: "device",
			entity: "dev-1", sev: "info", ts: deTS(win, ts), attached: false})
	}
	// passive_flow: 13 non-anomalous samples 20:20:50→20:30:08 (partial — trailing
	// 2m13s → ~78.8%; audit §2 traffic-flow row).
	flowStart, flowEnd, flowN := 17, 575, 13
	for i := 0; i < flowN; i++ {
		ts := flowStart + i*(flowEnd-flowStart)/(flowN-1)
		add(deSigOpt{kind: "flow_volume", modality: "passive_flow", observer: "exporter-cloud-1", entityType: "interface",
			entity: "vpc-flow-if1", sev: "info", ts: deTS(win, ts), attached: false})
	}

	// pad active-check filler (unattached probe_ok) so window total = 147 (audit §5),
	// spread evenly 20:20:46→20:32:21 so the active-check lane spans the incident
	// (~98% coverage, audit §2) instead of clustering.
	need := 147 - len(sigs)
	for i := 0; i < need; i++ {
		ts := 13 + i*(708-13)/(need-1)
		add(deSigOpt{kind: "probe_ok", modality: "active_probe", observer: "prober", entityType: "path",
			entity: "prober->tunnel", sev: "info", ts: deTS(win, ts), attached: false, probeAuth: "low"})
	}

	hypBlob := `{"ranking":{"hypotheses":[{"id":"sig.ent.cloud.ipsec-tunnel-down","confidence":0.95,` +
		`"confidence_label":"confirmed","satisfied":["ipsec_tunnel_down","probe_loss"],` +
		`"verdict":{"verdict_tier":"confirmed","owner":"netops",` +
		`"independent_pair":["ipsec:lab-vpn-edge","lan-vantage-1"],` +
		`"modality_coverage":["control_plane","active_probe"],` +
		`"observer_coverage":["ipsec:lab-vpn-edge","lan-vantage-1"]}}]}}`
	meta := map[string]any{
		"version": float64(4), "state": "open", "verdict_tier": "confirmed",
		"top_hypothesis": "sig.ent.cloud.ipsec-tunnel-down", "top_confidence": 0.95,
		"window_start": deTS(win, 0), "window_end": deTS(win, 708),
		"hypotheses": hypBlob, "affected": `{"services":["private-app"]}`,
		"app_impact": "{}", "evidence_missing": "[]", "tenant_id": "global",
	}
	return buildRcaReport(rcaReportInput{
		ID: "02737923-1f7a-57a2-ae88-6d650c608b51", Meta: meta, Signals: sigs,
		Policy: defaultIncidentPolicy("global"), Now: win.Add(20 * time.Minute),
	})
}

// TestPhaseE_P027379Regeneration is the spec's test 14: the regenerated report's
// counts reconcile, no api-as-vantage, coverage gaps are visible, the false
// "none detected" is killed, and the quality gate ships zero blockers.
func TestPhaseE_P027379Regeneration(t *testing.T) {
	rep := buildP027379Report(t)

	// counts reconcile at every layer (mirror the audit §5 ladder).
	acc := rep.accounting
	for _, w := range []struct {
		name     string
		got, exp int
	}{
		{"window observations", acc.WindowObservationCount(), 147},
		{"case-linked", acc.CaseLinkedSignalCount(), 8},
		{"anomalous", acc.AnomalousSignalCount(), 7},
		{"evidence groups", acc.CaseLinkedEvidenceGroupCount(), 4},
		{"anomaly observers", acc.AnomalyObserverCount(), 4},
		{"independence groups", acc.IndependenceGroupCount(), 3},
		{"independent confirming sources", acc.IndependentObserverCount(), 2},
		{"recovery observations", acc.RecoveryObservationCount(), 4},
	} {
		if w.got != w.exp {
			t.Errorf("%s = %d, want %d", w.name, w.got, w.exp)
		}
	}
	if rep.accountingErr != nil {
		t.Errorf("accounting invariant error on P-027379: %v", rep.accountingErr)
	}

	// no api-as-vantage.
	for _, v := range rep.Accounting.LogicalVantages {
		if v == "api" {
			t.Errorf("api rendered as a logical vantage")
		}
	}

	// the false real-user "none detected" is KILLED — the partial flow lane cannot
	// ground a definitive negative impact claim.
	if rep.States.ImpactRealUser == "none_detected" {
		t.Errorf("real-user impact still renders none_detected on partial flow coverage")
	}

	// gaps are visible in the rendered document.
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	doc := string(html)
	if !strings.Contains(doc, "trailing gap") && !strings.Contains(doc, "leading gap") {
		t.Errorf("coverage gaps are not visible in the regenerated document")
	}

	// no raw observer list may be LABELED as vantages anywhere in the document —
	// the flat probe observer list includes collectors (api) and unclassified
	// sources (prober); only the accounting block's classified split may use the
	// word. (Found by the 2026-07-16 page-by-page inspection: the NOC quick read
	// and Signal measurements still said "Affected vantages: api, …".)
	if strings.Contains(doc, "Affected vantages") {
		t.Errorf(`rendered document still labels the raw observer list "Affected vantages"`)
	}

	// the Unavailable reason for executions renders once, never twice ("… ·
	// Unavailable — … failed" was the inspection's other finding).
	if n := strings.Count(doc, "per-execution lineage not joined"); n > 1 {
		t.Errorf("execution unavailability reason rendered %d times, want 1", n)
	}

	// zero blockers — the corrected document ships as a full assessment, not a draft.
	if !rep.Quality.Passed {
		t.Fatalf("regenerated P-027379 still trips blockers: %+v", rep.Quality.Errors)
	}
	if strings.HasPrefix(rep.ReportType, "Draft") {
		t.Errorf("report downgraded to draft: %s", rep.ReportType)
	}
}

// TestEmitP027379HTML writes the regenerated P-027379 report HTML to a file for
// PDF rendering + visual inspection. Inert in CI (writes only when RCA_EMIT_P027379
// is set to an output path).
func TestEmitP027379HTML(t *testing.T) {
	out := os.Getenv("RCA_EMIT_P027379")
	if out == "" {
		t.Skip("set RCA_EMIT_P027379=/path/to/out.html to emit")
	}
	rep := buildP027379Report(t)
	html, err := renderRcaReportHTML(rep)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if err := os.WriteFile(out, html, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Logf("wrote %d bytes to %s (quality passed=%v type=%q impactRU=%q)",
		len(html), out, rep.Quality.Passed, rep.ReportType, rep.States.ImpactRealUser)
	// also dump the after-state accounting + coverage tables (markdown) alongside.
	fmt.Println(p027379AfterTables(rep))
}

// p027379AfterTables renders the AFTER-state accounting + coverage tables (mirror
// of the Phase A audit §2 before-tables) as markdown, for the deliverable doc.
func p027379AfterTables(rep rcaReport) string {
	var b strings.Builder
	b.WriteString("\n### P-027379 AFTER — evidence accounting\n\n")
	fmt.Fprintf(&b, "- Evidence groups: %d\n", rep.Accounting.EvidenceGroups)
	fmt.Fprintf(&b, "- Logical vantages: %s\n", orNone(rep.Accounting.LogicalVantages))
	fmt.Fprintf(&b, "- Control-plane sources: %s\n", orNone(rep.Accounting.ControlPlaneSources))
	fmt.Fprintf(&b, "- Collectors (not vantages): %s\n", orNone(rep.Accounting.Collectors))
	fmt.Fprintf(&b, "- Independent confirming sources: %d (%s)\n",
		rep.Accounting.IndependentConfirmingSources, strings.Join(rep.Accounting.IndependentSourceIDs, ", "))
	fmt.Fprintf(&b, "- Configured tests: %s\n", rep.Accounting.ConfiguredTests)
	b.WriteString("\nReconciliation ladder:\n")
	for _, r := range rep.Accounting.Ladder {
		fmt.Fprintf(&b, "  - %s: %s\n", r.Label, r.Value)
	}
	b.WriteString("\n### P-027379 AFTER — coverage\n\n")
	b.WriteString("| Lane | Quality | State | Ratio | Leading | Trailing | Impact-elig |\n|---|---|---|---|---|---|---|\n")
	for _, l := range rep.Coverage {
		a := l.Assessment
		if a == nil {
			continue
		}
		ratio, lead, trail := "-", "-", "-"
		if a.RatioKnown {
			ratio = fmt.Sprintf("%.0f%%", a.CoverageRatio*100)
		}
		if a.LeadingGap != "" {
			lead = a.LeadingGap
		}
		if a.TrailingGap != "" {
			trail = a.TrailingGap
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %v |\n",
			l.Label, a.Quality, l.State, ratio, lead, trail, a.ImpactEligible)
	}
	fmt.Fprintf(&b, "\nImpact: overall=%s · synthetic=%s · real-user=%s · quality_passed=%v\n",
		rep.States.Impact, rep.States.ImpactSynthetic, rep.States.ImpactRealUser, rep.Quality.Passed)
	return b.String()
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}
