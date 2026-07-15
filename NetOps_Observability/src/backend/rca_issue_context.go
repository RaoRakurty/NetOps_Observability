package main

// rca_issue_context.go — the explicit IssueContextResolver (mission P1 item,
// audit follow-through). The resolver's function previously lived DISTRIBUTED
// across the action-family table (rca_actions.go), classifyServiceScope and
// rcaHypothesisType (rca_report.go); this consolidates it into one struct +
// constructor so every consumer (report builder, action planner, ownership)
// reads the SAME resolved context instead of re-deriving fragments.
//
// Pure derivation over already-classified slice facts — no I/O, no engine
// re-decision, no case/signature-specific conditionals. Behavior-preserving by
// construction: each field is computed by the exact rule its consumer used
// before the consolidation (the scenario suite is the proof).

import (
	"sort"
	"strings"
)

// rcaIssueContext is the resolved interpretation context for one incident.
type rcaIssueContext struct {
	// IssueFamily: the catalog domain of the leading hypothesis
	// ("cloud", "wan-edge", "app", …) or the dominant anomalous evidence lane
	// when no signature matched. Never a guess.
	IssueFamily string `json:"issue_family"`
	// ServiceClassification: what KIND of service the subject is (§12) —
	// customer-managed internal / public endpoint / external third-party.
	ServiceClassification string `json:"service_classification,omitempty"`
	// ActiveFailureStage: where in the measured transaction the failure sits
	// (DNS / TCP connect / TLS / HTTP / Packet loss / Latency), when active
	// checks participated.
	ActiveFailureStage string `json:"active_failure_stage,omitempty"`
	// TopologyDomain: the verdict's layer statement (e.g. "L3 (provider)").
	TopologyDomain string `json:"topology_domain,omitempty"`
	// ParticipatingModalities: anomalous evidence lanes, in canonical order.
	ParticipatingModalities []string `json:"participating_modalities,omitempty"`
	// PathType: customer_path when customer-path probes participated,
	// infrastructure_path for other active checks, "" when no probe evidence.
	PathType string `json:"path_type,omitempty"`
	// CloudProvider: the provider named by attached cloud change/audit events.
	CloudProvider string `json:"cloud_provider,omitempty"`
	// Environment: production | validation (§11 watermark).
	Environment string `json:"environment"`
	// RequiredConfirmationGates: the leading hypothesis's missing evidence,
	// humanized — what must be observed before the analysis may firm up.
	RequiredConfirmationGates []string `json:"required_confirmation_gates,omitempty"`
	// ProhibitedClaims: assertions this report MUST NOT make in its current
	// evidence state. Generic, state-derived — never a template conditional.
	ProhibitedClaims []string `json:"prohibited_claims,omitempty"`
	// ApplicableActions: the evidence families whose telemetry actually
	// participated — the only families action steps may interrogate (P1.13).
	ApplicableActions []string `json:"applicable_actions,omitempty"`

	// internal, behavior-preserving consumer hooks (not serialized)
	topIsSymptom bool
	applicable   map[string]bool
}

// familyApplicable reports whether an action family's evidence participated in
// this incident (the P1.13 gate the planner enforces).
func (c rcaIssueContext) familyApplicable(name string) bool { return c.applicable[name] }

// rcaIssueContextInput carries the already-classified slice facts the resolver
// interprets. All fields are derived upstream in buildRcaReport.
type rcaIssueContextInput struct {
	Analysis      string
	RecoveryState string
	ImpactRU      string
	Validation    bool
	Hyp           rcaHypBlob
	Targets       []string
	LaneAnomalous map[string]int
	KindCounts    map[string]int
	Anomalous     []map[string]any
	Changes       []rcaCloudChange
}

// resolveIssueContext is the constructor: one place that answers "what kind of
// issue is this, and what may/may not be said and done about it".
func resolveIssueContext(in rcaIssueContextInput) rcaIssueContext {
	ctx := rcaIssueContext{Environment: "production"}
	if in.Validation {
		ctx.Environment = "validation"
	}

	// ---- issue family + symptom split + topology domain + gates ------------
	topID := ""
	if len(in.Hyp.Ranking.Hypotheses) > 0 {
		h0 := in.Hyp.Ranking.Hypotheses[0]
		topID = h0.ID
		ctx.topIsSymptom = rcaHypothesisType(h0.ID) == "symptom classification"
		ctx.TopologyDomain = h0.Verdict.Layer
		ctx.RequiredConfirmationGates = humanizeClauses(h0.Missing)
	}
	if parts := strings.Split(topID, "."); len(parts) >= 3 && parts[0] == "sig" {
		// "sig.ent.<family>.<name>" — the catalog's domain segment.
		ctx.IssueFamily = parts[2]
	}
	if ctx.IssueFamily == "" {
		// no signature: the dominant anomalous lane names the family factually.
		dominant, best := "", 0
		for _, lane := range rcaLaneOrder {
			if n := in.LaneAnomalous[lane]; n > best {
				best, dominant = n, lane
			}
		}
		ctx.IssueFamily = orDefault(dominant, "undetermined")
	}

	// ---- service classification (§12) ---------------------------------------
	ctx.ServiceClassification = classifyServiceScope(in.Targets)

	// ---- participating modalities -------------------------------------------
	for _, lane := range rcaLaneOrder {
		if in.LaneAnomalous[lane] > 0 {
			ctx.ParticipatingModalities = append(ctx.ParticipatingModalities, lane)
		}
	}

	// ---- active failure stage + path type ------------------------------------
	kinds := make([]string, 0, len(in.KindCounts))
	for k := range in.KindCounts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds) // deterministic
	for _, k := range kinds {
		if st := rcaFailureStage(k); st != "" && ctx.ActiveFailureStage == "" {
			ctx.ActiveFailureStage = st
		}
	}
	for _, sig := range in.Anomalous {
		if asString(sig["modality_class"]) != "active_probe" {
			continue
		}
		if asString(sig["probe_scope"]) == "customer_path" {
			ctx.PathType = "customer_path"
			break
		}
		ctx.PathType = "infrastructure_path"
	}

	// ---- cloud provider --------------------------------------------------------
	for _, c := range in.Changes {
		if c.Attached && c.Provider != "" {
			ctx.CloudProvider = c.Provider
			break
		}
	}

	// ---- prohibited claims (state-derived, generic) ------------------------------
	// Root cause: no causal-mechanism/causal-object evidence class exists yet,
	// so the claim is prohibited in every evidence state (P1.3).
	ctx.ProhibitedClaims = append(ctx.ProhibitedClaims, "root_cause_identified")
	if in.RecoveryState != "explicitly_confirmed" {
		ctx.ProhibitedClaims = append(ctx.ProhibitedClaims, "recovery_claim")
	}
	if in.ImpactRU != "confirmed" {
		ctx.ProhibitedClaims = append(ctx.ProhibitedClaims, "customer_impact_confirmed")
	}
	if in.ImpactRU != "none_detected" {
		ctx.ProhibitedClaims = append(ctx.ProhibitedClaims, "no_customer_impact")
	}
	if len(in.Hyp.Ranking.Hypotheses) > 0 &&
		rcaExternalOwnerTeams[rcaOwnerTeam[in.Hyp.Ranking.Hypotheses[0].Verdict.Owner]] {
		// an external provider/carrier may never be handed accountability
		// before demarcation confirms the boundary (P1.10).
		ctx.ProhibitedClaims = append(ctx.ProhibitedClaims, "external_provider_accountability_without_demarcation")
	}
	if in.Validation {
		ctx.ProhibitedClaims = append(ctx.ProhibitedClaims, "production_severity")
	}

	// ---- applicable action families (P1.13 gate, from the family table) ---------
	ctx.applicable = map[string]bool{}
	for _, f := range rcaActionFamilies {
		if rcaFamilyEvidencePresent(f, in.KindCounts, in.LaneAnomalous) {
			ctx.applicable[f.Name] = true
			ctx.ApplicableActions = append(ctx.ApplicableActions, f.Name)
		}
	}
	return ctx
}
