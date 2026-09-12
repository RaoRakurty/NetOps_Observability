// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

import (
	"encoding/json"
	"fmt"
	"testing"
)

// accSig builds a corr_signals-shaped map the accounting constructor reads. attrs
// is marshaled to the JSON string the real read path produces.
type accSigOpt struct {
	signalID     string
	observerID   string
	observerType string
	entityID     string
	kind         string
	modality     string
	ts           string
	attached     bool
	probeAuth    string
	agentHost    string
	sourceEgress string
	scheduleID   string
	seamID       string
	target       string
	executionID  string
	severity     string
}

func accSig(o accSigOpt) map[string]any {
	attrs := map[string]any{}
	if o.agentHost != "" {
		attrs["agent_host"] = o.agentHost
	}
	if o.sourceEgress != "" {
		attrs["source_egress"] = o.sourceEgress
	}
	if o.scheduleID != "" {
		attrs["schedule_id"] = o.scheduleID
	}
	if o.seamID != "" {
		attrs["seam_id"] = o.seamID
	}
	if o.target != "" {
		attrs["target"] = o.target
	}
	if o.executionID != "" {
		attrs["execution_id"] = o.executionID
	}
	b, _ := json.Marshal(attrs)
	sev := o.severity
	if sev == "" {
		sev = "warn"
	}
	mod := o.modality
	if mod == "" {
		mod = "active_probe"
	}
	ts := o.ts
	if ts == "" {
		ts = "2026-07-15 20:25:00"
	}
	return map[string]any{
		"signal_id":       o.signalID,
		"observer_id":     o.observerID,
		"observer_type":   o.observerType,
		"entity_id":       o.entityID,
		"kind":            o.kind,
		"modality_class":  mod,
		"ts":              ts,
		"attached":        o.attached,
		"probe_authority": o.probeAuth,
		"severity":        sev,
		"attrs":           string(b),
	}
}

// ── Spec family 1: one execution, many signals → one group/observer ──────────

func TestAccounting_OneExecutionManySignals_CollapseToOneGroup(t *testing.T) {
	var sigs []map[string]any
	// One observer, one entity, many kinds + retries (different execution_ids).
	for i, k := range []string{"probe_rtt_anomaly", "probe_loss", "probe_rtt_anomaly", "probe_loss"} {
		sigs = append(sigs, accSig(accSigOpt{
			signalID: fmt.Sprintf("s%d", i), observerID: "probeA", entityID: "path:probeA->tgt",
			kind: k, attached: true, probeAuth: "high", agentHost: "hostA",
			scheduleID: "sch-1", target: "tgt", executionID: fmt.Sprintf("exec-%d", i),
		}))
	}
	acc, err := buildEvidenceAccounting(accountingInput{TenantID: "t1", Signals: sigs})
	if err != nil {
		t.Fatalf("unexpected invariant error: %v", err)
	}
	if got := acc.AnomalyObserverCount(); got != 1 {
		t.Errorf("anomaly observers = %d, want 1", got)
	}
	if got := acc.CaseLinkedEvidenceGroupCount(); got != 1 {
		t.Errorf("evidence groups = %d, want 1", got)
	}
	if got := acc.IndependenceGroupCount(); got != 1 {
		t.Errorf("independence groups = %d, want 1 (execution_id must NEVER separate)", got)
	}
	if got := acc.AnomalousSignalCount(); got != 4 {
		t.Errorf("anomalous signals = %d, want 4 (volume is preserved; only dedup collapses)", got)
	}
}

// ── Spec family 2: api → NEVER a logical vantage ─────────────────────────────

func TestAccounting_ApiNeverVantage(t *testing.T) {
	reg := NewObserverRegistry(nil)
	// Even mis-stamped as a high-authority vantage_agent, api can never be a vantage.
	k := reg.Classify("t1", ObserverFacts{
		ObserverID: "api", ObserverType: "vantage_agent", Modality: "active_probe", ProbeAuthority: "high",
	})
	if k == KindLogicalVantage {
		t.Fatalf("api classified as logical_vantage — hard rule violated")
	}
	if k != KindCollector {
		t.Errorf("api kind = %q, want collector", k)
	}
	// Even a tenant policy that TRIES to make api a vantage is downgraded.
	reg2 := NewObserverRegistry(map[string]map[string]ObserverKind{
		"t1": {"api": KindLogicalVantage},
	})
	if got := reg2.Classify("t1", ObserverFacts{ObserverID: "api", Modality: "active_probe"}); got == KindLogicalVantage {
		t.Errorf("policy override made api a vantage — hard rule must win, got %q", got)
	}
}

// ── Spec family 3: control-plane + probe → 2 independent confirming sources ───

func TestAccounting_ControlPlanePlusProbe_TwoIndependent(t *testing.T) {
	sigs := []map[string]any{
		accSig(accSigOpt{signalID: "c1", observerID: "ipsec:edge", entityID: "tunnel-1",
			kind: "ipsec_tunnel_down", modality: "control_plane", attached: true, severity: "crit"}),
		accSig(accSigOpt{signalID: "p1", observerID: "lan-vantage-1", entityID: "path:lan->tunnel",
			kind: "probe_loss", attached: true, probeAuth: "high", agentHost: "lan-host"}),
	}
	acc, err := buildEvidenceAccounting(accountingInput{TenantID: "t1", Signals: sigs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := acc.IndependentObserverCount(); got != 2 {
		t.Fatalf("independent sources = %d, want 2", got)
	}
	for _, g := range acc.IndependentGroups {
		if !g.ConfirmEligible {
			t.Errorf("independent group %v not confirm-eligible", g.ObserverIDs)
		}
	}
}

// A LOW-authority probe next to a control-plane source is NOT a 2nd independent
// confirming source (mirrors verdicts.py trusted rule).
func TestAccounting_LowAuthProbe_NotConfirmEligible(t *testing.T) {
	sigs := []map[string]any{
		accSig(accSigOpt{signalID: "c1", observerID: "ipsec:edge", entityID: "tunnel-1",
			kind: "ipsec_tunnel_down", modality: "control_plane", attached: true, severity: "crit"}),
		accSig(accSigOpt{signalID: "p1", observerID: "prober", entityID: "path:prober->tunnel",
			kind: "probe_loss", attached: true, probeAuth: "low", agentHost: "lab-host"}),
	}
	acc, err := buildEvidenceAccounting(accountingInput{TenantID: "t1", Signals: sigs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := acc.IndependentObserverCount(); got != 1 {
		t.Errorf("independent sources = %d, want 1 (low-authority probe supports, never confirms)", got)
	}
}

// ── Spec family 4: retry / co-located sources dedup ──────────────────────────

func TestAccounting_CoLocatedProbesShareFate(t *testing.T) {
	// api + prober on the same host / NAT egress → one independence group.
	sigs := []map[string]any{
		accSig(accSigOpt{signalID: "a1", observerID: "api", observerType: "vantage_agent",
			entityID: "path:api->x", kind: "probe_loss", attached: true, probeAuth: "low",
			agentHost: "lab-host", sourceEgress: "203.0.113.9"}),
		accSig(accSigOpt{signalID: "b1", observerID: "prober", entityID: "path:prober->x",
			kind: "probe_loss", attached: true, probeAuth: "low",
			agentHost: "lab-host", sourceEgress: "203.0.113.9"}),
	}
	acc, err := buildEvidenceAccounting(accountingInput{TenantID: "t1", Signals: sigs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := acc.AnomalyObserverCount(); got != 2 {
		t.Errorf("anomaly observers = %d, want 2", got)
	}
	if got := acc.IndependenceGroupCount(); got != 1 {
		t.Errorf("independence groups = %d, want 1 (co-located api+prober share fate)", got)
	}
}

// ── Spec family 15: legacy case → explicit partial accounting ────────────────

func TestAccounting_LegacyCase_ExecutionCountsUnavailable(t *testing.T) {
	sigs := []map[string]any{
		accSig(accSigOpt{signalID: "p1", observerID: "prober", entityID: "path:prober->x",
			kind: "probe_loss", attached: true, probeAuth: "low", agentHost: "lab-host"}),
	}
	acc, err := buildEvidenceAccounting(accountingInput{TenantID: "t1", Signals: sigs})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if acc.ConfiguredTests.Available {
		t.Errorf("configured tests should be Unavailable for a legacy case")
	}
	if acc.ConfiguredTests.Unavailable == nil || acc.ConfiguredTests.Unavailable.Reason == "" {
		t.Errorf("Unavailable must carry a reason (constraint 4)")
	}
	if acc.TestExecutions.Available {
		t.Errorf("test executions should be Unavailable when no per-execution records joined")
	}
	// Go-forward: with joined execution records the counts become Available.
	acc2, err := buildEvidenceAccounting(accountingInput{TenantID: "t1", Signals: sigs,
		ProbeExecutions: []probeExecutionRecord{
			{ExecutionID: "e1", Failed: true}, {ExecutionID: "e2", Failed: true}, {ExecutionID: "e3"},
		}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !acc2.TestExecutions.Available || acc2.TestExecutions.Value != 3 {
		t.Errorf("test executions = %+v, want Available value 3", acc2.TestExecutions)
	}
	if !acc2.FailedTestExecutions.Available || acc2.FailedTestExecutions.Value != 2 {
		t.Errorf("failed executions = %+v, want Available value 2", acc2.FailedTestExecutions)
	}
}

// ── Spec family 16: tenant isolation for registry policy ─────────────────────

func TestAccounting_RegistryPolicyTenantIsolation(t *testing.T) {
	reg := NewObserverRegistry(map[string]map[string]ObserverKind{
		"tenant-a": {"site-probe-1": KindLogicalVantage},
	})
	facts := ObserverFacts{ObserverID: "site-probe-1", Modality: "active_probe", ProbeAuthority: "low"}
	// tenant-a policy elevates a low-authority probe to a vantage…
	if got := reg.Classify("tenant-a", facts); got != KindLogicalVantage {
		t.Errorf("tenant-a classify = %q, want logical_vantage (its policy)", got)
	}
	// …tenant-b, with no policy, must NOT see it — structural default = unknown.
	if got := reg.Classify("tenant-b", facts); got != KindUnknown {
		t.Errorf("tenant-b classify = %q, want unknown (no policy leak across tenants)", got)
	}
}

// Unclassified observers render explicitly unknown (constraint 1).
func TestAccounting_UnclassifiedIsUnknownNotCollector(t *testing.T) {
	reg := NewObserverRegistry(nil)
	got := reg.Classify("t1", ObserverFacts{ObserverID: "mystery-src", Modality: "active_probe", ProbeAuthority: "low"})
	if got != KindUnknown {
		t.Errorf("unclassified low-authority probe = %q, want unknown", got)
	}
}

// ── Spec family 5: count-reconciliation invariants (property test) ───────────

func TestAccounting_ReconciliationInvariants_Property(t *testing.T) {
	// Deterministic pseudo-random generator over many synthetic cases; every one
	// must satisfy the ladder invariants (constructor returns no error) and the
	// descending-count relationships must hold.
	seed := uint64(0x9e3779b97f4a7c15)
	next := func() uint64 { seed ^= seed << 13; seed ^= seed >> 7; seed ^= seed << 17; return seed }
	observers := []string{"api", "prober", "lan-vantage-1", "ipsec:edge", "leaf1", "flow-exp", "site-probe-2"}
	mods := []string{"active_probe", "control_plane", "device_telemetry", "passive_flow"}
	auths := []string{"high", "medium", "low", "debug_only", ""}
	hosts := []string{"", "hostA", "hostB", "lab-host"}

	for c := 0; c < 400; c++ {
		n := int(next()%12) + 1
		var sigs []map[string]any
		for i := 0; i < n; i++ {
			obs := observers[next()%uint64(len(observers))]
			mod := mods[next()%uint64(len(mods))]
			attached := next()%3 != 0
			recovery := next()%7 == 0
			kind := "probe_loss"
			sev := "warn"
			if recovery {
				kind = "probe_loss_clear"
			}
			sigs = append(sigs, accSig(accSigOpt{
				signalID: fmt.Sprintf("c%d-s%d", c, i), observerID: obs, entityID: "e:" + obs,
				kind: kind, modality: mod, attached: attached, severity: sev,
				probeAuth:   auths[next()%uint64(len(auths))],
				agentHost:   hosts[next()%uint64(len(hosts))],
				executionID: fmt.Sprintf("ex-%d", next()%5),
			}))
		}
		acc, err := buildEvidenceAccounting(accountingInput{TenantID: "t1", Signals: sigs})
		if err != nil {
			t.Fatalf("case %d: invariant error on well-formed input: %v", c, err)
		}
		// Explicit ladder relationships.
		checks := []struct {
			name   string
			lo, hi int
		}{
			{"case_linked<=window", acc.CaseLinkedSignalCount(), acc.WindowObservationCount()},
			{"anomalous<=case_linked", acc.AnomalousSignalCount(), acc.CaseLinkedSignalCount()},
			{"groups<=anomalous", acc.CaseLinkedEvidenceGroupCount(), acc.AnomalousSignalCount()},
			{"observers<=anomalous", acc.AnomalyObserverCount(), acc.AnomalousSignalCount()},
			{"indep_groups<=observers", acc.IndependenceGroupCount(), acc.AnomalyObserverCount()},
			{"independent<=indep_groups", acc.IndependentObserverCount(), acc.IndependenceGroupCount()},
			{"independent<=observers", acc.IndependentObserverCount(), acc.AnomalyObserverCount()},
		}
		for _, ck := range checks {
			if ck.lo > ck.hi {
				t.Fatalf("case %d: %s violated (%d > %d)", c, ck.name, ck.lo, ck.hi)
			}
		}
	}
}

// A constructed contradiction must surface as an error (feeds the Phase E gate):
// a verdict names an independent source the accounting cannot confirm-qualify.
func TestAccounting_VerdictDisagreement_IsError(t *testing.T) {
	sigs := []map[string]any{
		// only low-authority probes attached → no confirm-eligible source…
		accSig(accSigOpt{signalID: "p1", observerID: "prober", entityID: "path:prober->x",
			kind: "probe_loss", attached: true, probeAuth: "low", agentHost: "lab-host"}),
	}
	// The verdict blob is authored via JSON (the real read path) so this test is
	// robust to the rcaHypBlob struct shape.
	hb := decodeHypotheses(map[string]any{
		"hypotheses": `{"ranking":{"hypotheses":[{"id":"h1","verdict":{"independent_pair":["prober","ghost-observer"]}}]}}`,
	})
	if len(hb.Ranking.Hypotheses) != 1 || len(hb.Ranking.Hypotheses[0].Verdict.IndependentPair) != 2 {
		t.Fatalf("test setup: verdict blob did not decode as expected: %+v", hb)
	}
	_, err := buildEvidenceAccounting(accountingInput{TenantID: "t1", Signals: sigs, Hyp: hb})
	if err == nil {
		t.Fatalf("expected an invariant error for a verdict/accounting disagreement")
	}
}
