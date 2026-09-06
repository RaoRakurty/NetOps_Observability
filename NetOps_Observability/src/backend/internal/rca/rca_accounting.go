// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_accounting.go — the EvidenceAccounting model (Phase B).
//
// ONE place derives every canonical evidence count for a case, from real stored
// records, with explicit layer semantics — so no two pages of a report can
// disagree (the P-027379 root defect: counts recomputed ad-hoc in the render
// layer). Renderers (HTML/PDF/NOC/API — Phase D) and the quality gate (Phase E)
// consume THIS struct; they never re-count.
//
// Design rules (rca-evidence-accounting-plan.md, binding owner constraints):
//   - Derive, never invent. Every count is len() of an enumerable record slice
//     held on the struct — `IndependentObserverCount() == len(IndependentGroups)`
//     holds by construction, not by coincidence.
//   - Constraint 4/9: a field with no supporting records for a historical case is
//     rendered Unavailable{Reason}, NEVER a fabricated number.
//   - Constraint 2: execution_id ALONE never establishes independence (see
//     rca_independence.go — this file never separates observers by execution_id).
//   - Constraint 10: a layer-by-layer ReconciliationLadder is produced (totals →
//     case-linked → deduped groups → confidence-eligible → impact-eligible). The
//     eligibility rungs are stubbed `not_yet_assessed` until Phase C — we do not
//     invent an eligibility verdict this phase.
//   - Invariants are enforced in the constructor; a violation returns an error the
//     caller surfaces (feeds the Phase E quality gate).

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Unavailable marks a count that cannot be derived from stored records — with the
// reason, so the report can say WHY (constraint 4). It is never a stand-in for 0.
type Unavailable struct {
	Reason string `json:"reason"`
}

// accountedCount is either a derived integer (Available) or explicitly Unavailable.
// When Available, Value is backed by RecordCount enumerable records.
type accountedCount struct {
	Value       int          `json:"value,omitempty"`
	RecordCount int          `json:"record_count,omitempty"`
	Available   bool         `json:"available"`
	Unavailable *Unavailable `json:"unavailable,omitempty"`
}

func availableCount(n int) accountedCount {
	return accountedCount{Value: n, RecordCount: n, Available: true}
}
func unavailableCount(reason string) accountedCount {
	return accountedCount{Unavailable: &Unavailable{Reason: reason}}
}

// observationRecord is one signal at the window/case-linked layer.
type observationRecord struct {
	SignalID   string `json:"signal_id"`
	ObserverID string `json:"observer_id"`
	EntityID   string `json:"entity_id"`
	Kind       string `json:"kind"`
	Modality   string `json:"modality_class"`
	TS         string `json:"ts"`
	Attached   bool   `json:"attached"`
	Recovery   bool   `json:"recovery"` // a _clear kind or a semantic recovery-state event
}

// evidenceGroupRecord is one deduplicated (observer, entity) measurement source
// among the anomalous evidence — many kinds from one source count once (P1.7).
type evidenceGroupRecord struct {
	Key        string   `json:"key"` // observer_id|entity_id
	ObserverID string   `json:"observer_id"`
	EntityID   string   `json:"entity_id"`
	SignalIDs  []string `json:"signal_ids"`
}

// observerRecord is one distinct anomaly observer, classified + provenance-tagged.
type observerRecord struct {
	ObserverID      string       `json:"observer_id"`
	Modality        string       `json:"modality_class"`
	Kind            ObserverKind `json:"kind"`
	AgentHost       string       `json:"agent_host,omitempty"`
	ProbeAuthority  string       `json:"probe_authority,omitempty"`
	ConfirmEligible bool         `json:"confirm_eligible"`
}

// ladderRung is one layer of the reconciliation ladder (constraint 10).
type ladderRung struct {
	Layer       string       `json:"layer"`
	Label       string       `json:"label"`
	Count       int          `json:"count,omitempty"`
	Unavailable *Unavailable `json:"unavailable,omitempty"`
	// Status: for eligibility rungs not computed until Phase C → "not_yet_assessed".
	Status string `json:"status,omitempty"`
}

// ReconciliationLadder is the explicit descent from raw totals to the numbers a
// verdict actually rests on. Rendered (Phase D) so every page reconciles.
type ReconciliationLadder struct {
	Rungs []ladderRung `json:"rungs"`
}

// EvidenceAccounting is the canonical evidence-count model for one case. Every
// count is the length of the corresponding record slice (or an accountedCount for
// the execution-layer fields, which may be historically Unavailable).
type EvidenceAccounting struct {
	TenantID      string `json:"tenant_id"`
	CorrelationID string `json:"correlation_id"`

	// Raw window layer — every lane observation in the window slice.
	WindowObservations []observationRecord `json:"-"`
	// Case-linked layer — signals attached to the case (excludes recovery/clears).
	CaseLinkedSignals []observationRecord `json:"-"`
	// Anomalous layer — attached, non-recovery signals (the evidence).
	AnomalousSignals []observationRecord `json:"-"`
	// Recovery layer — _clear kinds + semantic recovery-state events in the window.
	RecoverySignals []observationRecord `json:"-"`
	// Deduplicated evidence groups — distinct (observer, entity) among anomalies.
	EvidenceGroups []evidenceGroupRecord `json:"evidence_groups"`
	// Distinct anomaly observers (the raw source set before independence dedup).
	AnomalyObservers []observerRecord `json:"anomaly_observers"`
	// Independence groups — anomaly sources collapsed by shared fate (provenance).
	IndependenceGroups []IndependenceGroup `json:"independence_groups"`
	// Independent confirming sources — confirm-eligible independence groups. This
	// is the number a confirmed verdict rests on; must agree with the verdict gate.
	IndependentGroups []IndependenceGroup `json:"independent_groups"`

	// Execution layer — path_observations / execution_id backed. Historically
	// Unavailable (constraint 4): pre-model cases stored no configured-test or
	// per-execution lineage at the report layer.
	ConfiguredTests      accountedCount `json:"configured_test_count"`
	TestExecutions       accountedCount `json:"test_execution_count"`
	FailedTestExecutions accountedCount `json:"failed_test_execution_count"`

	Ladder ReconciliationLadder `json:"reconciliation_ladder"`

	// VerdictIndependentPair — the observer pair the audited verdict gate named
	// (verdicts.py), when present. Used to CROSS-CHECK the derived independent count.
	VerdictIndependentPair []string `json:"verdict_independent_pair,omitempty"`
}

// Canonical count accessors — each is len() of its backing slice, by construction.
func (a EvidenceAccounting) WindowObservationCount() int       { return len(a.WindowObservations) }
func (a EvidenceAccounting) CaseLinkedSignalCount() int        { return len(a.CaseLinkedSignals) }
func (a EvidenceAccounting) AnomalousSignalCount() int         { return len(a.AnomalousSignals) }
func (a EvidenceAccounting) RecoveryObservationCount() int     { return len(a.RecoverySignals) }
func (a EvidenceAccounting) CaseLinkedEvidenceGroupCount() int { return len(a.EvidenceGroups) }
func (a EvidenceAccounting) AnomalyObserverCount() int         { return len(a.AnomalyObservers) }
func (a EvidenceAccounting) IndependenceGroupCount() int       { return len(a.IndependenceGroups) }
func (a EvidenceAccounting) IndependentObserverCount() int     { return len(a.IndependentGroups) }

// accountingInput is what the report layer feeds the constructor: the window
// slice (attached flags already stamped by mergeTimelineEvidence), the hypothesis
// blob (for the verdict cross-check), the tenant/case ids, the classification
// registry, and — when the report layer has joined them — path_observations-backed
// execution records. Everything is derived from these; nothing is invented.
type accountingInput struct {
	TenantID      string
	CorrelationID string
	Signals       []map[string]any
	Hyp           rcaHypBlob
	Registry      *ObserverRegistry
	// ProbeExecutions: distinct probe/synthetic executions the report layer already
	// has (run_id/vantage/status). Nil/empty when not joined → execution counts are
	// rendered Unavailable rather than fabricated.
	ProbeExecutions []probeExecutionRecord
	// ConfiguredTestsKnown: set true ONLY when the current schedule registry was
	// consulted for this case. False (default) → configured_test_count Unavailable.
	ConfiguredTestsKnown  bool
	ConfiguredTestRecords []configuredTestRecord
}

// probeExecutionRecord is one test execution (a path run / synthetic check).
type probeExecutionRecord struct {
	ExecutionID string
	VantageID   string
	Failed      bool
}

// configuredTestRecord is one configured synthetic test/check from the schedule
// registry (go-forward; empty for pre-model cases).
type configuredTestRecord struct {
	ScheduleID string
	Target     string
}

// sigAttrs holds the provenance attributes parsed out of a signal's attrs JSON.
type sigAttrs struct {
	AgentHost    string `json:"agent_host"`
	AgentID      string `json:"agent_id"`
	HostID       string `json:"host_id"`
	SourceEgress string `json:"source_egress"`
	EgressIP     string `json:"egress_ip"`
	SeamID       string `json:"seam_id"`
	ScheduleID   string `json:"schedule_id"`
	Target       string `json:"target"`
}

func parseSigAttrs(sig map[string]any) sigAttrs {
	var a sigAttrs
	if s, ok := sig["attrs"].(string); ok && s != "" {
		_ = json.Unmarshal([]byte(s), &a) // best-effort: malformed attrs yields empty
	}
	return a
}

// agentHost resolves the co-location host key from attrs (agent_host → agent_id →
// host_id), matching the Python fate model (verdicts._fate_of). Empty when the
// signal carries no host identity — absence never fabricates co-location.
func (a sigAttrs) agentHost() string {
	for _, v := range []string{a.AgentHost, a.AgentID, a.HostID} {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func (a sigAttrs) sourceEgress() string {
	for _, v := range []string{a.SourceEgress, a.EgressIP} {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// probeTarget mirrors verdicts._probe_target for active_probe entity ids ("a->b").
func probeTarget(entityID, attrTarget string) string {
	if t := strings.TrimSpace(attrTarget); t != "" {
		return strings.ToLower(t)
	}
	if i := strings.Index(entityID, "->"); i >= 0 {
		return strings.ToLower(strings.TrimSpace(entityID[i+2:]))
	}
	return strings.ToLower(strings.TrimSpace(entityID))
}

// buildEvidenceAccounting derives the full EvidenceAccounting from stored records.
// Returns an error if any invariant is violated — the document is internally
// inconsistent and the caller must not ship it as final (Phase E gate).
func buildEvidenceAccounting(in accountingInput) (EvidenceAccounting, error) {
	reg := in.Registry
	if reg == nil {
		reg = NewObserverRegistry(nil)
	}
	a := EvidenceAccounting{TenantID: in.TenantID, CorrelationID: in.CorrelationID}

	// ---- window / case-linked / anomalous / recovery layers -------------------
	for _, sig := range in.Signals {
		kind := fmt.Sprintf("%v", sig["kind"])
		rec := observationRecord{
			SignalID:   fmt.Sprintf("%v", sig["signal_id"]),
			ObserverID: sigStr(sig, "observer_id"),
			EntityID:   fmt.Sprintf("%v", sig["entity_id"]),
			Kind:       kind,
			Modality:   fmt.Sprintf("%v", sig["modality_class"]),
			TS:         fmt.Sprintf("%v", sig["ts"]),
		}
		rec.Recovery = strings.HasSuffix(kind, "_clear") || rcaIsRecoveryStateSignal(sig)
		rec.Attached, _ = sig["attached"].(bool)
		a.WindowObservations = append(a.WindowObservations, rec)
		if rec.Recovery {
			a.RecoverySignals = append(a.RecoverySignals, rec)
		}
		if rec.Attached {
			// Case-linked = every signal tied to the case (matches
			// signal_summary.attached / corr_current.signal_count); it includes an
			// attached recovery/clear. Anomalous excludes recovery — recovery is
			// evidence of healing, not of the fault.
			a.CaseLinkedSignals = append(a.CaseLinkedSignals, rec)
			if !rec.Recovery {
				a.AnomalousSignals = append(a.AnomalousSignals, rec)
			}
		}
	}

	// ---- evidence groups: distinct (observer, entity) among anomalies (P1.7) --
	groupIdx := map[string]int{}
	for _, rec := range a.AnomalousSignals {
		key := rec.ObserverID + "|" + rec.EntityID
		if i, ok := groupIdx[key]; ok {
			a.EvidenceGroups[i].SignalIDs = append(a.EvidenceGroups[i].SignalIDs, rec.SignalID)
			continue
		}
		groupIdx[key] = len(a.EvidenceGroups)
		a.EvidenceGroups = append(a.EvidenceGroups, evidenceGroupRecord{
			Key: key, ObserverID: rec.ObserverID, EntityID: rec.EntityID,
			SignalIDs: []string{rec.SignalID},
		})
	}

	// ---- distinct anomaly observers + classification + provenance -------------
	obsIdx := map[string]int{}
	var provByObserver = map[string]SourceProvenance{}
	for _, sig := range in.Signals {
		if attached, _ := sig["attached"].(bool); !attached {
			continue
		}
		kind := fmt.Sprintf("%v", sig["kind"])
		if strings.HasSuffix(kind, "_clear") || rcaIsRecoveryStateSignal(sig) {
			continue
		}
		oid := sigStr(sig, "observer_id")
		if oid == "" {
			continue
		}
		modality := fmt.Sprintf("%v", sig["modality_class"])
		probeAuth := sigStr(sig, "probe_authority")
		at := parseSigAttrs(sig)
		facts := ObserverFacts{
			ObserverID: oid, ObserverType: sigStr(sig, "observer_type"),
			Modality: modality, ProbeAuthority: probeAuth,
		}
		ok := reg.Classify(in.TenantID, facts)
		prov := SourceProvenance{
			ObserverID: oid, AgentHost: at.agentHost(), SourceEgress: at.sourceEgress(),
			Modality: modality, SeamID: strings.TrimSpace(at.SeamID),
			Target:     probeTarget(fmt.Sprintf("%v", sig["entity_id"]), at.Target),
			ScheduleID: strings.TrimSpace(at.ScheduleID),
			Kind:       ok, ProbeAuthority: probeAuth,
		}
		if i, seen := obsIdx[oid]; seen {
			// enrich provenance for grouping; keep the strongest authority/kind.
			cur := provByObserver[oid]
			if cur.AgentHost == "" {
				cur.AgentHost = prov.AgentHost
			}
			if cur.SourceEgress == "" {
				cur.SourceEgress = prov.SourceEgress
			}
			if authRank(prov.ProbeAuthority) > authRank(cur.ProbeAuthority) {
				cur.ProbeAuthority = prov.ProbeAuthority
			}
			provByObserver[oid] = cur
			if a.AnomalyObservers[i].AgentHost == "" {
				a.AnomalyObservers[i].AgentHost = prov.AgentHost
			}
			continue
		}
		obsIdx[oid] = len(a.AnomalyObservers)
		provByObserver[oid] = prov
		a.AnomalyObservers = append(a.AnomalyObservers, observerRecord{
			ObserverID: oid, Modality: modality, Kind: ok,
			AgentHost: prov.AgentHost, ProbeAuthority: probeAuth,
			ConfirmEligible: prov.ConfirmEligible(),
		})
	}

	// ---- independence grouping (provenance dedup) -----------------------------
	provs := make([]SourceProvenance, 0, len(provByObserver))
	for _, oid := range sortedKeys(provByObserver) {
		provs = append(provs, provByObserver[oid])
	}
	a.IndependenceGroups = GroupIndependence(provs)
	a.IndependentGroups = ConfirmEligibleGroups(a.IndependenceGroups)
	// keep ConfirmEligible flags on the observer records consistent with grouping
	for i := range a.AnomalyObservers {
		p := provByObserver[a.AnomalyObservers[i].ObserverID]
		a.AnomalyObservers[i].ConfirmEligible = p.ConfirmEligible()
	}

	// ---- verdict-gate cross-check (agree with the audited Python gate) --------
	if len(in.Hyp.Ranking.Hypotheses) > 0 {
		if pair := in.Hyp.Ranking.Hypotheses[0].Verdict.IndependentPair; len(pair) == 2 {
			a.VerdictIndependentPair = append([]string{}, pair...)
		}
	}

	// ---- execution layer (may be Unavailable for historical cases) ------------
	a.ConfiguredTests = deriveConfiguredTests(in)
	a.TestExecutions, a.FailedTestExecutions = deriveExecutions(in)

	// ---- reconciliation ladder (constraint 10) --------------------------------
	a.Ladder = a.buildLadder()

	if err := a.checkInvariants(); err != nil {
		return a, err
	}
	return a, nil
}

// authRank orders probe authorities so the strongest wins when an observer emits
// several signals.
func authRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "debug_only":
		return 1
	}
	return 0
}

func sigStr(sig map[string]any, key string) string {
	v, ok := sig[key]
	if !ok || v == nil {
		return ""
	}
	s := fmt.Sprintf("%v", v)
	if s == "<nil>" {
		return ""
	}
	return strings.TrimSpace(s)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// deriveConfiguredTests: the number of configured synthetic tests. Only derivable
// when the schedule registry was consulted for this case (go-forward). For a
// pre-model / historical case it is Unavailable with a reason — never fabricated.
func deriveConfiguredTests(in accountingInput) accountedCount {
	if !in.ConfiguredTestsKnown {
		return unavailableCount("configured-test inventory not stored for this case " +
			"(predates the accounting model; the prober schedule registry is current-state only)")
	}
	seen := map[string]bool{}
	for _, c := range in.ConfiguredTestRecords {
		if id := strings.TrimSpace(c.ScheduleID); id != "" {
			seen[id] = true
		}
	}
	return availableCount(len(seen))
}

// deriveExecutions: distinct test executions + failed subset, from
// path_observations-backed records the report layer joined. Unavailable when no
// such records were provided (the derived-anomaly lanes carry no per-execution
// lineage — constraint 4 forbids inventing a total from partial identity).
func deriveExecutions(in accountingInput) (total, failed accountedCount) {
	if len(in.ProbeExecutions) == 0 {
		reason := "per-execution lineage not joined at the report layer for this case " +
			"(derived anomaly observations carry no execution_id; counts are not fabricated)"
		return unavailableCount(reason), unavailableCount(reason)
	}
	seen := map[string]bool{}
	failedIDs := map[string]bool{}
	for _, e := range in.ProbeExecutions {
		id := strings.TrimSpace(e.ExecutionID)
		if id == "" {
			continue
		}
		seen[id] = true
		if e.Failed {
			failedIDs[id] = true
		}
	}
	return availableCount(len(seen)), availableCount(len(failedIDs))
}

// buildLadder renders the layer-by-layer reconciliation (constraint 10). The two
// eligibility rungs are stubbed not_yet_assessed — Phase C computes them.
func (a EvidenceAccounting) buildLadder() ReconciliationLadder {
	rungs := []ladderRung{
		{Layer: "window_total", Label: "Window observations (all lanes)", Count: a.WindowObservationCount()},
		{Layer: "case_linked", Label: "Case-linked observations", Count: a.CaseLinkedSignalCount()},
		{Layer: "anomalous", Label: "Anomalous observations", Count: a.AnomalousSignalCount()},
		{Layer: "evidence_groups", Label: "Deduplicated evidence groups", Count: a.CaseLinkedEvidenceGroupCount()},
		{Layer: "anomaly_observers", Label: "Distinct anomaly observers", Count: a.AnomalyObserverCount()},
		{Layer: "independence_groups", Label: "Independence groups (fate-deduped)", Count: a.IndependenceGroupCount()},
		{Layer: "independent_sources", Label: "Independent confirming sources", Count: a.IndependentObserverCount()},
	}
	// Confidence/impact eligibility — Phase C (do not invent a verdict here).
	rungs = append(rungs,
		ladderRung{Layer: "confidence_eligible", Label: "Confidence-eligible groups", Status: "not_yet_assessed"},
		ladderRung{Layer: "impact_eligible", Label: "Impact-eligible groups", Status: "not_yet_assessed"},
	)
	// Recovery is a parallel track, shown for completeness.
	rungs = append(rungs, ladderRung{Layer: "recovery", Label: "Recovery observations", Count: a.RecoveryObservationCount()})
	return ReconciliationLadder{Rungs: rungs}
}

// checkInvariants enforces the count relationships. A violation means the model
// derived contradictory numbers — a bug, not a data condition — so it errors and
// the caller (Phase E) blocks the report.
func (a EvidenceAccounting) checkInvariants() error {
	if a.CaseLinkedSignalCount() > a.WindowObservationCount() {
		return fmt.Errorf("accounting invariant: case-linked (%d) > window total (%d)",
			a.CaseLinkedSignalCount(), a.WindowObservationCount())
	}
	if a.AnomalousSignalCount() > a.CaseLinkedSignalCount() {
		return fmt.Errorf("accounting invariant: anomalous (%d) > case-linked (%d)",
			a.AnomalousSignalCount(), a.CaseLinkedSignalCount())
	}
	if a.CaseLinkedEvidenceGroupCount() > a.AnomalousSignalCount() {
		return fmt.Errorf("accounting invariant: evidence groups (%d) > anomalous signals (%d)",
			a.CaseLinkedEvidenceGroupCount(), a.AnomalousSignalCount())
	}
	if a.AnomalyObserverCount() > a.AnomalousSignalCount() {
		return fmt.Errorf("accounting invariant: anomaly observers (%d) > anomalous signals (%d)",
			a.AnomalyObserverCount(), a.AnomalousSignalCount())
	}
	if a.IndependenceGroupCount() > a.AnomalyObserverCount() {
		return fmt.Errorf("accounting invariant: independence groups (%d) > anomaly observers (%d)",
			a.IndependenceGroupCount(), a.AnomalyObserverCount())
	}
	if a.IndependentObserverCount() > a.IndependenceGroupCount() {
		return fmt.Errorf("accounting invariant: independent sources (%d) > independence groups (%d)",
			a.IndependentObserverCount(), a.IndependenceGroupCount())
	}
	if a.IndependentObserverCount() > a.AnomalyObserverCount() {
		return fmt.Errorf("accounting invariant: independent sources (%d) > raw observers (%d)",
			a.IndependentObserverCount(), a.AnomalyObserverCount())
	}
	if a.FailedTestExecutions.Available && a.TestExecutions.Available &&
		a.FailedTestExecutions.Value > a.TestExecutions.Value {
		return fmt.Errorf("accounting invariant: failed executions (%d) > executions (%d)",
			a.FailedTestExecutions.Value, a.TestExecutions.Value)
	}
	// Cross-check the verdict gate: every observer the audited Python gate named as
	// an independent confirming source must appear in a confirm-eligible group here.
	// A disagreement means the accounting under-counts what the verdict relied on.
	if len(a.VerdictIndependentPair) == 2 {
		eligible := map[string]bool{}
		for _, g := range a.IndependentGroups {
			for _, oid := range g.ObserverIDs {
				eligible[oid] = true
			}
		}
		for _, oid := range a.VerdictIndependentPair {
			if !eligible[oid] {
				return fmt.Errorf("accounting invariant: verdict-gate independent source %q "+
					"is not a confirm-eligible source in the accounting (gate/accounting disagreement)", oid)
			}
		}
	}
	return nil
}
