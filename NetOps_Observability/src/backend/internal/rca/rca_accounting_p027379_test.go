package rca

import (
	"fmt"
	"testing"
)

// TestAccounting_P027379_Fixture reproduces the P-027379 evidence structure from
// the Phase A audit and asserts the derived accounting reconciles at every layer:
//
//	147 window observations
//	  → 8 case-linked signals (7 anomalous + 1 attached recovery)
//	    → 4 evidence groups
//	      → 4 anomaly observers
//	        → 3 independence groups (api+prober co-located)
//	          → 2 provenance-independent confirming sources (ipsec × lan-vantage-1)
//	  → 4 recovery observations
//	  configured tests: Unavailable (historical)
//
// The independent-source count (2) must AGREE with the audited verdicts.py gate
// pair, and be DERIVED — never hardcoded — from provenance + confirm-eligibility.
func TestAccounting_P027379_Fixture(t *testing.T) {
	var sigs []map[string]any
	add := func(o accSigOpt) { sigs = append(sigs, accSig(o)) }

	// 7 anomalous, attached signals across 4 (observer, entity) evidence groups.
	// group 1 — control-plane tunnel-down (ipsec:lab-vpn-edge)
	add(accSigOpt{signalID: "an-ipsec", observerID: "ipsec:lab-vpn-edge", entityID: "tunnel:lab-vpn",
		kind: "ipsec_tunnel_down", modality: "control_plane", attached: true, severity: "crit"})
	// group 2 — prober rtt + loss + a retry (co-located on the lab host)
	add(accSigOpt{signalID: "an-prtt", observerID: "prober", entityID: "path:prober->tunnel",
		kind: "probe_rtt_anomaly", attached: true, probeAuth: "low", agentHost: "lab-host",
		sourceEgress: "203.0.113.9", scheduleID: "sch-prober", target: "tunnel"})
	add(accSigOpt{signalID: "an-ploss", observerID: "prober", entityID: "path:prober->tunnel",
		kind: "probe_loss", attached: true, probeAuth: "low", agentHost: "lab-host",
		sourceEgress: "203.0.113.9", scheduleID: "sch-prober", target: "tunnel"})
	add(accSigOpt{signalID: "an-ploss2", observerID: "prober", entityID: "path:prober->tunnel",
		kind: "probe_loss", attached: true, probeAuth: "low", agentHost: "lab-host",
		sourceEgress: "203.0.113.9", scheduleID: "sch-prober", target: "tunnel"})
	// group 3 — lan-vantage-1 rtt (trusted vantage on its own host)
	add(accSigOpt{signalID: "an-lrtt", observerID: "lan-vantage-1", entityID: "path:lan->tunnel",
		kind: "probe_rtt_anomaly", attached: true, probeAuth: "high", agentHost: "lan-vantage-host",
		sourceEgress: "198.51.100.4", scheduleID: "sch-lan", target: "tunnel"})
	// group 4 — api rtt + loss (co-located with prober on the lab host/egress)
	add(accSigOpt{signalID: "an-artt", observerID: "api", observerType: "vantage_agent",
		entityID: "path:api->tunnel", kind: "probe_rtt_anomaly", attached: true, probeAuth: "low",
		agentHost: "lab-host", sourceEgress: "203.0.113.9", scheduleID: "sch-api", target: "tunnel"})
	add(accSigOpt{signalID: "an-aloss", observerID: "api", observerType: "vantage_agent",
		entityID: "path:api->tunnel", kind: "probe_loss", attached: true, probeAuth: "low",
		agentHost: "lab-host", sourceEgress: "203.0.113.9", scheduleID: "sch-api", target: "tunnel"})

	// 4 recovery signals: 1 attached (counts toward case-linked=8) + 3 unattached.
	add(accSigOpt{signalID: "rc-1", observerID: "prober", entityID: "path:prober->tunnel",
		kind: "probe_loss_clear", attached: true, probeAuth: "low", agentHost: "lab-host"})
	for i := 0; i < 3; i++ {
		add(accSigOpt{signalID: fmt.Sprintf("rc-u%d", i), observerID: "prober",
			entityID: "path:prober->tunnel", kind: "rtt_anomaly_clear", attached: false, agentHost: "lab-host"})
	}

	// Pad to 147 window observations with unattached, non-recovery filler.
	for len(sigs) < 147 {
		add(accSigOpt{signalID: fmt.Sprintf("fill-%d", len(sigs)), observerID: "prober",
			entityID: "path:prober->tunnel", kind: "probe_ok", attached: false, probeAuth: "low"})
	}

	// Verdict gate named ipsec × lan-vantage-1 (the audited independent pair).
	hb := decodeHypotheses(map[string]any{
		"hypotheses": `{"ranking":{"hypotheses":[{"id":"sig.ent.cloud.ipsec-tunnel-down","verdict":{"verdict_tier":"confirmed","independent_pair":["ipsec:lab-vpn-edge","lan-vantage-1"]}}]}}`,
	})

	acc, err := buildEvidenceAccounting(accountingInput{
		TenantID: "global", CorrelationID: "02737923-1f7a-57a2-ae88-6d650c608b51",
		Signals: sigs, Hyp: hb,
	})
	if err != nil {
		t.Fatalf("P-027379 accounting invariant error: %v", err)
	}

	want := []struct {
		name string
		got  int
		exp  int
	}{
		{"window observations", acc.WindowObservationCount(), 147},
		{"case-linked signals", acc.CaseLinkedSignalCount(), 8},
		{"anomalous signals", acc.AnomalousSignalCount(), 7},
		{"evidence groups", acc.CaseLinkedEvidenceGroupCount(), 4},
		{"anomaly observers", acc.AnomalyObserverCount(), 4},
		{"independence groups", acc.IndependenceGroupCount(), 3},
		{"independent confirming sources", acc.IndependentObserverCount(), 2},
		{"recovery observations", acc.RecoveryObservationCount(), 4},
	}
	for _, w := range want {
		if w.got != w.exp {
			t.Errorf("%s = %d, want %d", w.name, w.got, w.exp)
		}
	}

	// configured tests: historically Unavailable, with a reason (constraint 4).
	if acc.ConfiguredTests.Available || acc.ConfiguredTests.Unavailable == nil {
		t.Errorf("configured tests should be Unavailable with a reason for P-027379")
	}

	// The two independent sources are exactly the verdict-gate pair.
	got := map[string]bool{}
	for _, g := range acc.IndependentGroups {
		for _, oid := range g.ObserverIDs {
			got[oid] = true
		}
	}
	for _, oid := range []string{"ipsec:lab-vpn-edge", "lan-vantage-1"} {
		if !got[oid] {
			t.Errorf("independent source %q missing from confirm-eligible groups", oid)
		}
	}
	// api must never be classified as a logical vantage.
	for _, o := range acc.AnomalyObservers {
		if o.ObserverID == "api" && o.Kind == KindLogicalVantage {
			t.Errorf("api classified as logical_vantage in P-027379")
		}
	}
}
