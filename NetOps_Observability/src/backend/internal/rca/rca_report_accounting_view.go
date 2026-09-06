// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_report_accounting_view.go — Phase D presentation of the Phase B
// EvidenceAccounting and the Phase C coverage eligibility. The renderers
// (HTML/PDF/NOC/API) consume THESE derived views; they never recompute a count
// or a coverage verdict. "Derive, never recompute in the renderer" (plan §1).
//
// Two audiences (plan §1 Presentation bullet):
//   - customer view: canonical evidence groups, logical vantages, control-plane
//     sources, independent confirming sources — the numbers a verdict rests on.
//   - operator/debug appendix: the full lineage ladder (audit §5 — totals →
//     case-linked → dedup groups → confidence-eligible → impact-eligible).

import (
	"fmt"
	"sort"
	"strings"
)

// rcaAccountingLadderRow is one operator-appendix reconciliation rung.
type rcaAccountingLadderRow struct {
	Label string `json:"label"`
	// Value is a count, or "Unavailable — reason", or a status like "not assessed".
	Value string `json:"value"`
}

// rcaAccountingView is the customer-facing evidence-accounting block PLUS the
// operator/debug lineage ladder. Derived once from EvidenceAccounting (never
// recomputed by any renderer).
type rcaAccountingView struct {
	// ---- customer view -------------------------------------------------------
	// EvidenceGroups: distinct (measurement source, entity) among the anomalies —
	// many kinds from one source count once.
	EvidenceGroups int `json:"evidence_groups"`
	// LogicalVantages: real measurement origins (probe/synthetic agents at a real
	// location). NEVER the platform API container or a collector (Phase B hard rule).
	LogicalVantages []string `json:"logical_vantages,omitempty"`
	// ControlPlaneSources: devices/controllers reporting protocol / tunnel / routing state.
	ControlPlaneSources []string `json:"control_plane_sources,omitempty"`
	// Collectors: the platform's own data-collection identities (api, exporters,
	// pollers). Legitimate evidence sources, but not vantages.
	Collectors []string `json:"collectors,omitempty"`
	// UnknownSources: identity/kind could not be established (rendered explicitly,
	// never silently a vantage or a collector — owner constraint 1).
	UnknownSources []string `json:"unknown_sources,omitempty"`
	// IndependentConfirmingSources: confirm-eligible independence groups — the
	// number a confirmed verdict actually rests on (agrees with the verdict gate).
	IndependentConfirmingSources int      `json:"independent_confirming_sources"`
	IndependentSourceIDs         []string `json:"independent_source_ids,omitempty"`

	// ---- execution layer (may be historically Unavailable) -------------------
	ConfiguredTests  string `json:"configured_tests"`
	TestExecutions   string `json:"test_executions"`
	FailedExecutions string `json:"failed_executions"`
	// FailedExecutionsBrief: the bare failed count for inline HTML rendering —
	// empty when unavailable so the (identical) unavailability reason is not
	// rendered twice next to TestExecutions. JSON keeps FailedExecutions intact.
	FailedExecutionsBrief string `json:"-"`

	// ---- operator/debug appendix --------------------------------------------
	Ladder []rcaAccountingLadderRow `json:"reconciliation_ladder"`
}

// buildAccountingView derives the presentation view from the canonical
// EvidenceAccounting (Phase B) and the per-lane coverage assessments (Phase C).
// It classifies the distinct anomaly observers by kind, lists the independent
// confirming sources, and fills the two eligibility rungs of the reconciliation
// ladder from the coverage assessments (Phase B stubbed them not-yet-assessed).
func buildAccountingView(a EvidenceAccounting, lanes []rcaEvidenceLane) rcaAccountingView {
	v := rcaAccountingView{
		EvidenceGroups:               a.CaseLinkedEvidenceGroupCount(),
		IndependentConfirmingSources: a.IndependentObserverCount(),
	}
	for _, o := range a.AnomalyObservers {
		switch o.Kind {
		case KindLogicalVantage:
			v.LogicalVantages = append(v.LogicalVantages, o.ObserverID)
		case KindControlPlaneSource:
			v.ControlPlaneSources = append(v.ControlPlaneSources, o.ObserverID)
		case KindCollector:
			v.Collectors = append(v.Collectors, o.ObserverID)
		default:
			v.UnknownSources = append(v.UnknownSources, o.ObserverID)
		}
	}
	v.LogicalVantages = uniqueSortedStrings(v.LogicalVantages)
	v.ControlPlaneSources = uniqueSortedStrings(v.ControlPlaneSources)
	v.Collectors = uniqueSortedStrings(v.Collectors)
	v.UnknownSources = uniqueSortedStrings(v.UnknownSources)

	idSet := map[string]bool{}
	for _, g := range a.IndependentGroups {
		for _, oid := range g.ObserverIDs {
			idSet[oid] = true
		}
	}
	for oid := range idSet {
		v.IndependentSourceIDs = append(v.IndependentSourceIDs, oid)
	}
	v.IndependentSourceIDs = uniqueSortedStrings(v.IndependentSourceIDs)

	v.ConfiguredTests = accountedText(a.ConfiguredTests)
	v.TestExecutions = accountedText(a.TestExecutions)
	v.FailedExecutions = accountedText(a.FailedTestExecutions)
	if a.FailedTestExecutions.Available {
		v.FailedExecutionsBrief = fmt.Sprintf("%d", a.FailedTestExecutions.Value)
	}

	// eligibility rungs, computed from the coverage assessments (Phase C).
	confEligible, impactEligible := 0, 0
	for _, l := range lanes {
		if l.Assessment == nil {
			continue
		}
		if l.Assessment.ConfidenceEligible {
			confEligible++
		}
		if l.Assessment.ImpactEligible {
			impactEligible++
		}
	}
	for _, r := range a.Ladder.Rungs {
		row := rcaAccountingLadderRow{Label: r.Label, Value: ladderRowValue(r)}
		switch r.Layer {
		case "confidence_eligible":
			row.Label = "Confidence-eligible evidence classes"
			row.Value = fmt.Sprintf("%d", confEligible)
		case "impact_eligible":
			row.Label = "Impact-eligible evidence classes"
			row.Value = fmt.Sprintf("%d", impactEligible)
		}
		v.Ladder = append(v.Ladder, row)
	}
	return v
}

// accountedText renders an accountedCount for display: a number when Available,
// otherwise "Unavailable — <reason>" (owner constraint 4 — never a bare 0).
func accountedText(c accountedCount) string {
	if c.Available {
		return fmt.Sprintf("%d", c.Value)
	}
	if c.Unavailable != nil && c.Unavailable.Reason != "" {
		return "Unavailable — " + c.Unavailable.Reason
	}
	return "Unavailable"
}

// ladderRowValue renders one reconciliation rung's value: a count, an
// Unavailable-with-reason, or a status token humanized.
func ladderRowValue(r ladderRung) string {
	if r.Unavailable != nil && r.Unavailable.Reason != "" {
		return "Unavailable — " + r.Unavailable.Reason
	}
	if r.Status != "" {
		return strings.ReplaceAll(r.Status, "_", " ")
	}
	return fmt.Sprintf("%d", r.Count)
}

// uniqueSortedStrings returns the distinct, sorted, non-empty members.
func uniqueSortedStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// ---- coverage eligibility helpers (single source for the impact renderers) ----

// laneAssessment returns the Phase C coverage assessment for a lane class, or nil.
func laneAssessment(lanes []rcaEvidenceLane, class string) *CoverageAssessment {
	for i := range lanes {
		if lanes[i].Class == class {
			return lanes[i].Assessment
		}
	}
	return nil
}

// coverageImpactEligible reports whether a lane may support a DEFINITIVE impact
// statement (a negative "none detected" claim requires complete coverage — Phase
// C ImpactEligible). This is the single gate BOTH impact renderers consume, so
// the NOC "Real-user impact" line and the management summary can never disagree
// (kills the false "none detected" on the P-027379 flow lane, 78.8% + 2m13s gap).
func coverageImpactEligible(lanes []rcaEvidenceLane, class string) bool {
	a := laneAssessment(lanes, class)
	return a != nil && a.ImpactEligible
}
