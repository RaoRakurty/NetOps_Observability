// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_impact_provenance.go — Phase 1 quantified impact (spec §2,
// docs/design/rca-postmortem-enhancements-spec.md).
//
// Every impact value retains: value · unit · scope+denominator · source ·
// coverage · confidence · measured/estimated/inferred status. The full measure
// vocabulary is ALWAYS listed so absence is visible: a measure the platform
// cannot source is "not measured" — never zero, never invented. Synthetic
// failures, flow changes and network events are NEVER converted into
// affected-user counts without a valid identity or transaction mapping.

import "fmt"

// Impact-measure status vocabulary.
const (
	impactMeasured    = "measured"
	impactEstimated   = "estimated"
	impactInferred    = "inferred"
	impactNotMeasured = "not_measured"
)

// rcaImpactMeasure is one provenance-carrying impact value.
type rcaImpactMeasure struct {
	Measure string `json:"measure"`
	Label   string `json:"label"`
	// Status: measured | estimated | inferred | not_measured. A value is
	// present ONLY when status is not not_measured.
	Status      string   `json:"status"`
	Value       *float64 `json:"value,omitempty"`
	Unit        string   `json:"unit,omitempty"`
	Scope       string   `json:"scope,omitempty"`
	Denominator string   `json:"denominator,omitempty"`
	Source      string   `json:"source,omitempty"`
	Coverage    string   `json:"coverage,omitempty"`
	Confidence  string   `json:"confidence,omitempty"`
	// Basis: the honest sentence — what this number is, or why it is absent.
	Basis string `json:"basis"`
}

// rcaImpactProvenance is the report's impact block: the complete measure
// vocabulary with per-measure provenance, plus the derivation rule it enforces.
type rcaImpactProvenance struct {
	Rule     string             `json:"rule"`
	Measures []rcaImpactMeasure `json:"measures"`
}

const rcaImpactRule = "Impact values carry provenance and are never derived across evidence classes: synthetic failures, flow-volume changes and network events are never converted into affected-user counts without a valid identity or transaction mapping. A missing measure is stated as not measured — never zero."

// The supported measure vocabulary (spec §2), canonical order.
var rcaImpactMeasureOrder = []struct{ key, label string }{
	{"affected_applications", "Affected applications"},
	{"affected_sites", "Affected sites"},
	{"active_users", "Active users affected"},
	{"sessions", "Sessions affected"},
	{"transactions", "Transactions affected"},
	{"user_minutes", "User-minutes lost"},
	{"site_minutes", "Site-minutes lost"},
	{"transaction_failures", "Transaction failures (real users)"},
	{"synthetic_failure_rate", "Synthetic failure rate"},
	{"flow_volume_change", "Flow-volume change"},
	{"voice_impairment", "Voice impairment"},
	{"slo_error_budget", "SLO / error-budget consumption"},
}

// rcaImpactInput carries the builder's already-derived locals — provenance is a
// PROJECTION of what was measured, never a re-measurement.
type rcaImpactInput struct {
	Scope             rcaReportScope
	Probe             *rcaProbeSummary // nil when no active-probe evidence
	SyntheticFailures int              // customer-path synthetic failure observations
	FlowAnomalies     int              // anomalous passive-flow observations
	RealUserSignals   int              // real-user impact-kind observations
	ImpactRU          string           // real-user impact axis state
	Validation        bool
}

func fptr(v float64) *float64 { return &v }

// buildImpactProvenance derives the provenance block from the builder's locals.
func buildImpactProvenance(in rcaImpactInput) rcaImpactProvenance {
	byKey := map[string]rcaImpactMeasure{}

	// -- population measures the platform can genuinely count -----------------
	if n := len(in.Scope.Services); n > 0 {
		byKey["affected_applications"] = rcaImpactMeasure{
			Status: impactMeasured, Value: fptr(float64(n)), Unit: "applications",
			Scope:      "applications named by the attached evidence",
			Source:     "attached evidence scope (service identifiers on the correlated observations)",
			Coverage:   "only applications with attached evidence — unobserved applications are not counted absent",
			Confidence: "High",
			Basis:      fmt.Sprintf("%d application(s) appear in the attached evidence. This counts observed applications, not all potentially affected ones.", n),
		}
	}
	if n := len(in.Scope.Sites); n > 0 {
		byKey["affected_sites"] = rcaImpactMeasure{
			Status: impactMeasured, Value: fptr(float64(n)), Unit: "sites",
			Scope:      "sites named by the attached evidence",
			Source:     "attached evidence scope (site identifiers on the correlated observations)",
			Coverage:   "only sites with attached evidence",
			Confidence: "High",
			Basis:      fmt.Sprintf("%d site(s) appear in the attached evidence.", n),
		}
	}

	// -- synthetic axis --------------------------------------------------------
	if in.Probe != nil && in.Probe.Observations > 0 {
		rate := 100 * float64(in.Probe.Failed) / float64(in.Probe.Observations)
		byKey["synthetic_failure_rate"] = rcaImpactMeasure{
			Status: impactMeasured, Value: fptr(rate), Unit: "%",
			Scope:       "the configured synthetic checks that took part in this case",
			Denominator: fmt.Sprintf("%d synthetic check observations in the window", in.Probe.Observations),
			Source:      "active-probe observers (customer-path checks)",
			Coverage:    "the configured check targets and vantages only — a synthetic failure proves the configured transaction failed from that vantage, nothing more",
			Confidence:  "High",
			Basis:       fmt.Sprintf("%d of %d synthetic check observations failed (directly measured).", in.Probe.Failed, in.Probe.Observations),
		}
	} else if in.SyntheticFailures > 0 {
		byKey["synthetic_failure_rate"] = rcaImpactMeasure{
			Status: impactMeasured, Value: fptr(float64(in.SyntheticFailures)), Unit: "failed synthetic observations",
			Scope:      "the configured synthetic checks that took part in this case",
			Source:     "active-probe observers (customer-path checks)",
			Coverage:   "failure observations only — the total observation denominator was not captured, so no rate is computed",
			Confidence: "High",
			Basis:      fmt.Sprintf("%d customer-path synthetic failure observation(s); denominator not captured — reported as a count, never converted to a rate.", in.SyntheticFailures),
		}
	}

	// -- real-traffic indicator ------------------------------------------------
	if in.FlowAnomalies > 0 {
		byKey["flow_volume_change"] = rcaImpactMeasure{
			Status: impactMeasured, Value: fptr(float64(in.FlowAnomalies)), Unit: "anomalous flow observations",
			Scope:      "the exporters/interfaces that raised flow anomalies",
			Source:     "passive-flow telemetry",
			Coverage:   "observed flow telemetry only",
			Confidence: "Medium",
			Basis:      "A flow-volume change shows real traffic behaved differently; it is an INDICATOR — demand shifts, routing changes and collection loss produce the same delta. It is never converted into a user or transaction count.",
		}
	}

	// -- real-user measures: honest by construction ----------------------------
	// Real-user quantities require identity/transaction mapping the platform
	// does not have. Even when real-user impact EVIDENCE exists, the counts
	// stay "not measured" — detection is not quantification.
	realUserBasis := "No identity or transaction mapping exists for this case; this value is not measured. It is never derived from synthetic failures, flow deltas or network events."
	if in.RealUserSignals > 0 || in.ImpactRU == "confirmed" || in.ImpactRU == "detected" {
		realUserBasis = "Real-user impact evidence exists (see the impact axes), but no identity or transaction mapping quantifies it — the count is not measured, and is never derived from synthetic failures or flow deltas."
	}
	for _, key := range []string{"active_users", "sessions", "transactions", "user_minutes", "site_minutes", "transaction_failures"} {
		byKey[key] = rcaImpactMeasure{Status: impactNotMeasured, Basis: realUserBasis}
	}

	// -- not yet sourced -------------------------------------------------------
	byKey["voice_impairment"] = rcaImpactMeasure{
		Status: impactNotMeasured,
		Basis:  "No voice-quality telemetry (MOS/jitter/loss scoring) is attached to this case.",
	}
	byKey["slo_error_budget"] = rcaImpactMeasure{
		Status: impactNotMeasured,
		Basis:  "No SLO is linked to this incident; error-budget consumption is not measured.",
	}

	out := rcaImpactProvenance{Rule: rcaImpactRule}
	for _, m := range rcaImpactMeasureOrder {
		row, ok := byKey[m.key]
		if !ok {
			row = rcaImpactMeasure{Status: impactNotMeasured, Basis: "Not measured — no evidence source for this measure took part in the case."}
		}
		row.Measure, row.Label = m.key, m.label
		if in.Validation && row.Status != impactNotMeasured {
			row.Basis += " Validation scenario: the value describes the injected/validation condition, never production impact."
		}
		out.Measures = append(out.Measures, row)
	}
	return out
}
