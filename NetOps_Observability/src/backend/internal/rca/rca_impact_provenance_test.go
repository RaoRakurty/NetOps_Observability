package rca

// rca_impact_provenance_test.go — Phase 1 quantified impact (spec §2): every
// value carries provenance; missing = not measured, never zero; user counts
// are never derived from synthetic/flow evidence.

import (
	"strings"
	"testing"
)

func provMeasure(t *testing.T, p rcaImpactProvenance, key string) rcaImpactMeasure {
	t.Helper()
	for _, m := range p.Measures {
		if m.Measure == key {
			return m
		}
	}
	t.Fatalf("measure %q missing from the provenance block (all measures must always be listed)", key)
	return rcaImpactMeasure{}
}

func TestImpactProvenanceListsFullVocabulary(t *testing.T) {
	p := buildImpactProvenance(rcaImpactInput{})
	if len(p.Measures) != len(rcaImpactMeasureOrder) {
		t.Fatalf("measures = %d, want %d (absence must be visible)", len(p.Measures), len(rcaImpactMeasureOrder))
	}
	for _, m := range p.Measures {
		if m.Status != impactNotMeasured {
			t.Fatalf("empty input measure %s = %q, want not_measured", m.Measure, m.Status)
		}
		if m.Value != nil {
			t.Fatalf("not_measured measure %s carries a value — missing must never be zero: %+v", m.Measure, m)
		}
		if m.Basis == "" {
			t.Fatalf("measure %s without basis", m.Measure)
		}
	}
	if !strings.Contains(p.Rule, "never zero") {
		t.Fatalf("rule missing: %q", p.Rule)
	}
}

func TestImpactProvenanceSyntheticMeasuredNeverUsers(t *testing.T) {
	p := buildImpactProvenance(rcaImpactInput{
		Probe:             &rcaProbeSummary{Observations: 40, Failed: 10},
		SyntheticFailures: 10,
	})
	syn := provMeasure(t, p, "synthetic_failure_rate")
	if syn.Status != impactMeasured || syn.Value == nil || *syn.Value != 25 {
		t.Fatalf("synthetic rate = %+v, want measured 25%%", syn)
	}
	if syn.Denominator == "" || syn.Source == "" || syn.Coverage == "" || syn.Confidence == "" {
		t.Fatalf("synthetic measure missing provenance: %+v", syn)
	}
	// Synthetic evidence NEVER yields user counts.
	for _, key := range []string{"active_users", "sessions", "transactions", "user_minutes", "transaction_failures"} {
		m := provMeasure(t, p, key)
		if m.Status != impactNotMeasured || m.Value != nil {
			t.Fatalf("%s derived from synthetic evidence: %+v", key, m)
		}
		if !strings.Contains(m.Basis, "never derived") {
			t.Fatalf("%s basis must state the derivation prohibition: %q", key, m.Basis)
		}
	}
}

func TestImpactProvenanceFlowIsIndicatorNeverUsers(t *testing.T) {
	p := buildImpactProvenance(rcaImpactInput{FlowAnomalies: 7})
	flow := provMeasure(t, p, "flow_volume_change")
	if flow.Status != impactMeasured || !strings.Contains(flow.Basis, "INDICATOR") {
		t.Fatalf("flow measure = %+v", flow)
	}
	users := provMeasure(t, p, "active_users")
	if users.Status != impactNotMeasured || users.Value != nil {
		t.Fatalf("user count derived from flow evidence: %+v", users)
	}
}

// Real-user impact EVIDENCE still never quantifies user counts (detection is
// not quantification — no identity/transaction mapping exists).
func TestImpactProvenanceDetectedRealUserStillNotQuantified(t *testing.T) {
	p := buildImpactProvenance(rcaImpactInput{RealUserSignals: 3, ImpactRU: "detected"})
	users := provMeasure(t, p, "active_users")
	if users.Status != impactNotMeasured || users.Value != nil {
		t.Fatalf("real-user detection quantified without mapping: %+v", users)
	}
	if !strings.Contains(users.Basis, "evidence exists") {
		t.Fatalf("basis must acknowledge the evidence while refusing the count: %q", users.Basis)
	}
}

func TestImpactProvenanceScopeCountsAreMeasured(t *testing.T) {
	p := buildImpactProvenance(rcaImpactInput{
		Scope: rcaReportScope{Services: []string{"crm", "vpn"}, Sites: []string{"fra-1"}},
	})
	apps := provMeasure(t, p, "affected_applications")
	if apps.Status != impactMeasured || apps.Value == nil || *apps.Value != 2 {
		t.Fatalf("affected applications = %+v", apps)
	}
	sites := provMeasure(t, p, "affected_sites")
	if sites.Status != impactMeasured || sites.Value == nil || *sites.Value != 1 {
		t.Fatalf("affected sites = %+v", sites)
	}
}

// The report builder wires provenance end-to-end: P-3335CF-shaped input
// (synthetic confirmed, real-user unknown) yields synthetic measured +
// real-user not measured.
func TestReportImpactProvenanceWiring(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.wan-edge.bgp-peer-down",
		testHyp("sig.ent.wan-edge.bgp-peer-down", 0.9, "confirmed",
			[]string{"probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->10.0.0.1", "crit", "2026-07-12 18:12:30", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildTestReport(t, meta, sigs)
	syn := provMeasure(t, rep.ImpactProvenance, "synthetic_failure_rate")
	if syn.Status != impactMeasured {
		t.Fatalf("synthetic axis = %+v", syn)
	}
	users := provMeasure(t, rep.ImpactProvenance, "active_users")
	if users.Status != impactNotMeasured {
		t.Fatalf("real-user axis = %+v", users)
	}
}
