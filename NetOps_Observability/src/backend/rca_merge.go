package main

// rca_merge.go — the generic merged-incident lifecycle model (truthfulness
// hardening 2026-07-15, P1 "merged incident lifecycle").
//
// A merged CHILD incident is not recovered and is not operationally closed. It
// is a TOMBSTONE that points at the surviving incident, which owns lifecycle,
// monitoring, ticketing, escalation and restoration actions from the merge
// forward. The child retains only its historical record: original detection
// time, the evidence it carried, its analysis snapshot, and the link to the
// survivor.
//
// The correlation engine (Python) writes the merge relationship in ClickHouse
// as state='merged' + merged_into (a UUID). Everything here is DERIVED at
// report-compose time from those two facts plus the survivor the handler
// resolved (resolveMergeChain, tenant-scoped) — so historical rows reconstruct
// with no migration. All functions are pure over already-tenant-scoped facts.

import (
	"fmt"
	"netops/backend/internal/noclabel"
	"strings"
)

// rcaLifecycleMerged / rcaLifecycleSuperseded — the canonical merged lifecycle
// states. The full lifecycle vocabulary (candidate, active, recovering,
// monitoring, resolved, closed, merged, superseded, duplicate) is documented in
// rcaCanonicalLifecycles; the report today derives merged/superseded from the
// engine's state column and the remaining values from the recovery/incident
// dimensions it already computes.
var rcaCanonicalLifecycles = []string{
	"candidate", "active", "recovering", "monitoring",
	"resolved", "closed", "merged", "superseded", "duplicate",
}

// rcaIncidentMerge is the structured merge record rendered on a merged source
// report. Absent fields (merge_reason, merge_actor, …) are honestly empty when
// the engine did not record them — never invented.
type rcaIncidentMerge struct {
	SourceIncidentID       string   `json:"source_incident_id"`
	SourceDisplayID        string   `json:"source_display_id"`
	SurvivingIncidentID    string   `json:"surviving_incident_id"`
	SurvivingDisplayID     string   `json:"surviving_display_id"`
	SurvivorResolved       bool     `json:"survivor_resolved"`
	MergedAt               string   `json:"merged_at,omitempty"`
	MergeReason            string   `json:"merge_reason,omitempty"`
	MergeConfidence        string   `json:"merge_confidence,omitempty"`
	SharedScope            []string `json:"shared_scope,omitempty"`
	TransferredEvidenceIDs []string `json:"transferred_evidence_ids,omitempty"`
	TransferredActions     bool     `json:"transferred_actions"`
	TransferredTicketRef   string   `json:"transferred_ticket_reference,omitempty"`
	TransferredMonitoring  bool     `json:"transferred_monitoring_state"`
	MergeActor             string   `json:"merge_actor,omitempty"`
	MergePolicyID          string   `json:"merge_policy_id,omitempty"`

	// ---- authoritative-state rules (P1 "merge ownership of state and side
	// effects"). After a merge exactly ONE incident is authoritative for
	// lifecycle, recovery, monitoring, ticketing, escalation, ownership, action
	// execution and communication. The merged source is never it.
	IsAuthoritative          bool   `json:"is_authoritative"`
	AuthoritativeIncidentID  string `json:"authoritative_incident_id"`
	AuthoritativeDisplayID   string `json:"authoritative_display_id"`
	SideEffectsTransferred   bool   `json:"side_effects_transferred"`
	TicketResponsibility     string `json:"ticket_responsibility"`     // surviving_incident | this_incident
	MonitoringResponsibility string `json:"monitoring_responsibility"` // surviving_incident | this_incident
	EscalationResponsibility string `json:"escalation_responsibility"` // surviving_incident | this_incident
	ActionResponsibility     string `json:"action_responsibility"`     // surviving_incident | this_incident

	// Statement — the customer-facing merge sentence (NOC wording standard).
	Statement string `json:"statement"`
	// ServiceRecoveryAtMerge — the reconciled service-recovery state carried into
	// the survivor at merge time ("failed_validation" / "not_observed" / …).
	ServiceRecoveryAtMerge string `json:"service_recovery_at_merge"`
}

// buildIncidentMerge derives the merge record. survivorID is the terminal
// surviving correlation id the handler resolved (empty in unit tests →
// falls back to the direct merged_into pointer). serviceRecovery is the
// reconciled service-scope recovery state at merge time. evidenceIDs is the set
// of anomalous evidence signal ids the survivor inherits.
func buildIncidentMerge(sourceID, mergedInto, survivorID, serviceRecovery string, scope rcaReportScope, evidenceIDs []string) *rcaIncidentMerge {
	survivor := survivorID
	if survivor == "" {
		survivor = mergedInto
	}
	m := &rcaIncidentMerge{
		SourceIncidentID:       sourceID,
		SourceDisplayID:        noclabel.ProblemDisplayID(sourceID),
		SurvivingIncidentID:    survivor,
		SurvivingDisplayID:     noclabel.ProblemDisplayID(survivor),
		SurvivorResolved:       survivor != "",
		SharedScope:            scope.Services,
		TransferredEvidenceIDs: evidenceIDs,
		ServiceRecoveryAtMerge: serviceRecovery,
		// A merged source transfers ALL operational side effects to the survivor
		// and is never itself authoritative (the invariant the gate enforces).
		IsAuthoritative:          false,
		SideEffectsTransferred:   survivor != "",
		TransferredActions:       true,
		TransferredMonitoring:    true,
		TicketResponsibility:     "surviving_incident",
		MonitoringResponsibility: "surviving_incident",
		EscalationResponsibility: "surviving_incident",
		ActionResponsibility:     "surviving_incident",
	}
	if survivor != "" {
		m.AuthoritativeIncidentID = survivor
		m.AuthoritativeDisplayID = noclabel.ProblemDisplayID(survivor)
	}
	m.Statement = rcaMergeStatement(m, serviceRecovery)
	return m
}

// rcaMergeStatement renders the NOC-standard merge sentence. It is honest about
// the service-recovery state at merge time and always names the survivor when
// resolved.
func rcaMergeStatement(m *rcaIncidentMerge, serviceRecovery string) string {
	if !m.SurvivorResolved {
		// The gate raises a P1 error separately; the prose stays honest about the
		// unresolved survivor rather than inventing one.
		return "This correlation object was merged, but the surviving incident could not be resolved. Lifecycle, monitoring, ticketing and restoration actions cannot be attributed until the surviving incident is identified."
	}
	recoveryClause := "End-to-end service recovery had not been confirmed at the time of the merge."
	switch serviceRecovery {
	case "explicitly_confirmed":
		recoveryClause = "End-to-end service recovery had been confirmed before the merge."
	case "not_applicable":
		recoveryClause = "No end-to-end service evidence participated before the merge."
	}
	return fmt.Sprintf(
		"This correlation object was merged into incident %s. %s The surviving incident owns lifecycle, monitoring, ticketing and restoration actions.",
		m.SurvivingDisplayID, recoveryClause)
}

// applyMergeToDecision transfers the source case's decision, ticket and
// escalation to the surviving incident (P1 merge ownership of side effects).
// The source neither monitors nor tickets nor escalates on its own.
func applyMergeToDecision(d *rcaDecision, m *rcaIncidentMerge) {
	survivor := "the surviving incident"
	if m != nil && m.SurvivorResolved {
		survivor = "surviving incident " + m.SurvivingDisplayID
	}
	d.Decision = "Track on surviving incident"
	d.Reason = "This case was merged; lifecycle, monitoring, ticketing and restoration are owned by " + survivor + "."
	if m != nil {
		d.Reason = m.Statement
	}
	// The source performs no side effects of its own.
	d.EscalationState = "transferred"
	d.EscalationAt = ""
	d.EscalateWhen = "handled on " + survivor + " (this source case does not escalate independently)"
	d.AutoCloseEligible = false
	d.TicketRecommended = "transferred"
	d.TicketRecommendReason = "Ticket responsibility transferred to " + survivor + "."
	d.TicketExecutionNote = "Ticket is managed by " + survivor + " — this source case does not open a separate ticket."
	if m != nil && !m.SurvivorResolved {
		// Unresolved survivor: the gate raises a P1 error; the copy stays honest.
		d.Reason = "This case was merged, but the surviving incident could not be resolved — lifecycle and side-effect ownership are unattributed."
		d.TicketExecutionNote = "Ticket responsibility is unattributed: the surviving incident could not be resolved."
	}
}

// rcaMergeIncidentState maps the engine's persisted state to the canonical
// merged lifecycle. "merged" and "superseded" both mean the source is a
// tombstone; anything else is not a merge.
func rcaMergeIncidentState(state string) (lifecycle string, merged bool) {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "merged":
		return "merged", true
	case "superseded":
		return "superseded", true
	}
	return "", false
}
