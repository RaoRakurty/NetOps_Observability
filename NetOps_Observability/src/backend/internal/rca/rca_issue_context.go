package rca

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
	"fmt"
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

// ---- demarcation evidence contract (P1.10 promotion, audit D8) -----------------
//
// An external provider/carrier may be handed escalation accountability ONLY
// when the demarcation evidence list is satisfied — BOTH of:
//
//  (a) a provider-side alarm/health declaration participating in the case.
//      Kind contract: `provider_alarm`, `carrier_alarm` (generic classes a
//      future correlation producer emits — none exist in the catalog today),
//      plus the EXISTING provider-declared health kinds `cloud_health` /
//      `cloud_resource_health`, which speak ONLY for the cloud provider.
//  (b) independent-vantage reachability evidence localizing the loss beyond
//      the customer boundary. Kind contract: `independent_vantage_probe`.
//
// Local checks alone, a hypothesis owner token, seam grounding or a confirmed
// verdict NEVER promote — carrier ownership without this list is prohibited.

// rcaProviderAlarmKinds: provider-side alarm evidence and the external teams
// each kind may speak for ("" key set = any external team).
var rcaProviderAlarmKinds = map[string]map[string]bool{
	"provider_alarm":        nil, // any external provider/carrier
	"carrier_alarm":         nil,
	"cloud_health":          {"Cloud provider": true},
	"cloud_resource_health": {"Cloud provider": true},
}

// rcaIndependentVantageKinds: beyond-boundary reachability evidence classes.
var rcaIndependentVantageKinds = map[string]bool{
	"independent_vantage_probe": true,
}

// assessDemarcation evaluates the demarcation evidence for one external
// candidate team over the case's participating anomalous evidence kinds.
// Returns (state, basis): provider_boundary_confirmed only when BOTH evidence
// classes participated; local_checks_pending otherwise, with a basis that
// names what is still missing.
func assessDemarcation(team string, kindCounts map[string]int) (string, string) {
	alarm, vantage := "", ""
	kinds := make([]string, 0, len(kindCounts))
	for k := range kindCounts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds) // deterministic evidence naming
	for _, k := range kinds {
		if teams, ok := rcaProviderAlarmKinds[k]; ok && alarm == "" {
			if teams == nil || teams[team] {
				alarm = k
			}
		}
		if rcaIndependentVantageKinds[k] && vantage == "" {
			vantage = k
		}
	}
	switch {
	case alarm != "" && vantage != "":
		return "provider_boundary_confirmed", fmt.Sprintf(
			"Demarcation confirmed by independent evidence: a provider-side alarm (%s) and independent-vantage reachability evidence (%s) localize the loss beyond the customer boundary.",
			strings.ReplaceAll(alarm, "_", " "), strings.ReplaceAll(vantage, "_", " "))
	case alarm != "":
		return "local_checks_pending", fmt.Sprintf(
			"A provider-side alarm (%s) participates, but independent-vantage reachability evidence has not localized the loss beyond the customer boundary — provider accountability stays pending.",
			strings.ReplaceAll(alarm, "_", " "))
	case vantage != "":
		return "local_checks_pending",
			"Independent-vantage evidence participates, but no provider-side alarm corroborates a provider-boundary fault — provider accountability stays pending."
	}
	return "local_checks_pending",
		"No demarcation evidence has been captured: local egress, route/neighbor state and independent-vantage reachability must localize the loss beyond the customer boundary before provider accountability is assigned."
}

// rcaIssueContextInput carries the already-classified slice facts the resolver
// interprets. All fields are derived upstream in BuildReport.
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
	if len(in.Hyp.Ranking.Hypotheses) > 0 {
		if team := OwnerTeam[in.Hyp.Ranking.Hypotheses[0].Verdict.Owner]; rcaExternalOwnerTeams[team] {
			// an external provider/carrier may never be handed accountability
			// before demarcation confirms the boundary (P1.10) — the promotion
			// path is the documented demarcation evidence contract.
			if dem, _ := assessDemarcation(team, in.KindCounts); dem != "provider_boundary_confirmed" {
				ctx.ProhibitedClaims = append(ctx.ProhibitedClaims, "external_provider_accountability_without_demarcation")
			}
		}
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
