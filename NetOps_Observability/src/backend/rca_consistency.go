package main

// rca_consistency.go — the generic StateConsistencyValidator and
// ReportQualityGate (P1 gate, audit D11).
//
// The validator runs on the FINISHED report before it is emitted in any form
// (JSON, HTML, PDF). It is generic: every check is a cross-field invariant,
// never a case/signature/title match. Errors mean the document contradicts
// itself and must not ship as a final assessment — the gate downgrades the
// report type and the record travels inside the document (quality_gate_passed,
// errors, warnings, model/rule version, evaluated_at).
//
// The same banned-wording rules apply to all incident types; issue-family
// adapters cannot bypass them.

import (
	"fmt"
	"strings"
	"time"
)

const rcaConsistencyModelVersion = "rca-consistency/1"

type rcaQualityIssue struct {
	Code   string `json:"code"`
	Field  string `json:"field"`
	Detail string `json:"detail"`
}

type rcaReportQuality struct {
	Passed       bool              `json:"quality_gate_passed"`
	Errors       []rcaQualityIssue `json:"p1_errors,omitempty"`
	Warnings     []rcaQualityIssue `json:"p2_warnings,omitempty"`
	ModelVersion string            `json:"model_version"`
	EvaluatedAt  string            `json:"evaluated_at"`
}

// rcaBannedPhrases — the NOC wording standard's banned vocabulary. Checked
// against every customer-facing sentence the report carries.
var rcaBannedPhrases = []string{
	"went dark", "where it breaks", "real network issue",
	"matches this issue type", "evidence changed", "would be owned by",
	"check(s)", "signal(s)", "confirm or rule out the hypothesis",
}

// validateRcaReport is the pure StateConsistencyValidator.
func validateRcaReport(rep *rcaReport, now time.Time) rcaReportQuality {
	q := rcaReportQuality{ModelVersion: rcaConsistencyModelVersion, EvaluatedAt: fmtUTC(now)}
	errf := func(code, field, detail string, args ...any) {
		q.Errors = append(q.Errors, rcaQualityIssue{Code: code, Field: field, Detail: fmt.Sprintf(detail, args...)})
	}
	warnf := func(code, field, detail string, args ...any) {
		q.Warnings = append(q.Warnings, rcaQualityIssue{Code: code, Field: field, Detail: fmt.Sprintf(detail, args...)})
	}
	st := rep.States
	parse := func(s string) (time.Time, bool) {
		return parseChTS(strings.TrimSuffix(s, " UTC"))
	}

	// ---- merged-incident lifecycle (P1) -------------------------------------------
	// For a merged/superseded source, closure validation is replaced by MERGE
	// validation: the survivor must resolve, the source must not remain
	// authoritative, and no independent side effect may run on the source.
	merged := st.Incident == "merged" || st.Incident == "superseded"
	if merged {
		if rep.Merge == nil || rep.Merge.SurvivingIncidentID == "" {
			errf("merged_without_surviving_incident", "merge.surviving_incident_id",
				"a merged/superseded incident must resolve its surviving incident — merge target missing")
		}
		if rep.Merge != nil && rep.Merge.IsAuthoritative {
			errf("merged_source_remains_authoritative", "merge.is_authoritative",
				"a merged source incident cannot remain authoritative for lifecycle/side effects")
		}
		if rep.Merge != nil && !rep.Merge.SideEffectsTransferred && rep.Merge.SurvivorResolved {
			errf("merged_source_side_effects_not_transferred", "merge.side_effects_transferred",
				"a merged source with a resolved survivor must transfer ticket/monitoring/escalation/action ownership")
		}
		if st.Monitoring == "active" {
			errf("merged_source_monitoring_active", "states.monitoring",
				"a merged source cannot run its own monitoring window — monitoring belongs to the survivor")
		}
		if st.Ticket == "opened" {
			errf("merged_source_independent_ticket", "states.ticket",
				"a merged source cannot hold its own open ticket — ticket responsibility transfers to the survivor")
		}
		if rep.Decision.EscalationState == "triggered" {
			errf("merged_source_independent_escalation", "decision.escalation_state",
				"a merged source cannot trigger its own escalation — escalation is the survivor's")
		}
	}

	// ---- P1.1 lifecycle × recovery ------------------------------------------------
	closedLike := st.Incident == "closed" || st.Incident == "recovered"
	if closedLike && st.Recovery == "not_observed" {
		errf("closed_without_recovery", "states.incident",
			"incident is %q while recovery is not_observed — closure requires recovery evidence or an explicit no-longer-observed state", st.Incident)
	}
	if st.Incident == "recovered" && st.Recovery == "failed_validation" {
		errf("recovered_with_failed_validation", "states.recovery",
			"incident claims recovered while a recovery scope failed validation")
	}
	if st.Incident == "recovered" && st.Recovery == "component_only" {
		errf("component_recovery_presented_as_incident_recovery", "states.recovery",
			"component-level recovery must never recover the whole incident")
	}
	if closedLike && st.Monitoring == "active" {
		errf("closed_while_monitoring_active", "states.monitoring",
			"a closed incident cannot still be inside its monitoring window")
	}
	if rep.Times.MonitoringUntil != "" && !rep.Times.RecoveredCaptured {
		errf("monitoring_without_recovery_trigger", "times.monitoring_until",
			"a monitoring window exists without a valid recovery trigger")
	}
	// recovered_at must never precede the last qualifying anomaly
	if rep.Times.RecoveredCaptured {
		if rec, ok := parse(rep.Times.RecoveredAt); ok {
			if last, ok2 := parse(rep.Times.LastAnomalous); ok2 && rec.Before(last) {
				errf("recovered_before_last_anomaly", "times.recovered_at",
					"recovered_at %s precedes the last qualifying anomaly %s", rep.Times.RecoveredAt, rep.Times.LastAnomalous)
			}
		}
	}
	if rep.Times.DurationBasis == "to_recovery" && !rep.Times.RecoveredCaptured {
		errf("duration_claims_uncaptured_recovery", "times.duration_basis",
			"duration measures to_recovery but no recovery was captured")
	}
	if st.RecoveryService.State == "explicitly_confirmed" && rep.States.Incident == "active" {
		warnf("service_recovered_but_active", "states.recovery_service",
			"service recovery is confirmed while the incident is still active — verify scope completeness")
	}

	// ---- P1.3 fault vs root cause ---------------------------------------------------
	if st.RootCauseState == "confirmed" && (rep.RootCause.Mechanism == "" || rep.RootCause.Object == "") {
		errf("root_cause_without_mechanism_and_object", "states.root_cause_state",
			"root cause may be confirmed only with an identified causal mechanism AND causal object")
	}
	if rep.RootCause.Identified && (rep.RootCause.Mechanism == "" || rep.RootCause.Object == "") {
		errf("root_cause_identified_without_basis", "root_cause.identified",
			"root_cause.identified requires mechanism and object")
	}
	if st.RootCauseState != "confirmed" && strings.HasPrefix(rep.ReportType, "Root Cause Analysis") {
		errf("rca_title_without_confirmed_root_cause", "report_type",
			"the document may call itself an RCA only when the root cause concluded")
	}
	if strings.Contains(rep.FaultLocalization.ObjectType, "seam") && rep.RootCause.Object == rep.FaultLocalization.Object && rep.RootCause.Object != "" {
		errf("seam_promoted_to_root_cause", "root_cause.object",
			"a seam is a localization domain, never the root-cause object")
	}

	// ---- P1.5 impact observability ---------------------------------------------------
	if st.ImpactRealUser == "confirmed" && st.Analysis != "confirmed" {
		errf("real_user_impact_without_confirmed_analysis", "states.impact_real_user",
			"real-user impact confirmation requires confirmed corroborated evidence")
	}
	if st.Impact == "confirmed" && st.ImpactRealUser != "confirmed" {
		errf("impact_confirmed_without_real_user_evidence", "states.impact",
			"overall impact may be confirmed only when real-user impact is confirmed; a synthetic failure proves only its own scope")
	}
	// P1.6: a "no impact" CLAIM requires sufficient multi-class coverage — every
	// impact-relevant axis observed the window and none carried an anomaly. One
	// covering class is partial coverage; one anomalous class is an indicator.
	if st.Impact == "none_detected" && (st.ImpactSynthetic != "none_detected" || st.ImpactRealUser != "none_detected") {
		errf("no_impact_claim_without_sufficient_coverage", "states.impact",
			"impact none_detected requires every impact axis to have covered the window cleanly (synthetic=%s, real_user=%s)",
			st.ImpactSynthetic, st.ImpactRealUser)
	}
	// P1.5 residue: monitoring/decision copy may claim "has recovered" ONLY on
	// observed, reconciled recovery evidence — a quiesced window never recovered.
	if strings.Contains(strings.ToLower(rep.Decision.Reason), "has recovered") && st.Recovery != "explicitly_confirmed" {
		errf("recovery_claim_without_evidence", "decision.reason",
			"decision/monitoring copy claims recovery while recovery is %q", st.Recovery)
	}

	// ---- P1.9 hypothesis taxonomy ------------------------------------------------------
	for i, h := range rep.Hypotheses {
		if h.Contradicted && strings.EqualFold(h.Label, "confirmed") {
			errf("hypothesis_confirmed_and_ruled_out", fmt.Sprintf("hypotheses[%d]", i),
				"a hypothesis cannot render a live confirmed label while ruled out — use observation_state × causal_role")
		}
		if h.Type == "symptom classification" && (h.CausalRole == "possible_origin" || h.CausalRole == "probable_origin" || h.CausalRole == "confirmed_origin") {
			errf("symptom_ranked_as_cause", fmt.Sprintf("hypotheses[%d]", i),
				"a symptom classification must not be ranked as a causal origin")
		}
		// P1 issue-family confirmation gate: a hypothesis whose required evidence is
		// still outstanding cannot render as CONFIRMED (observed).
		if h.ObservationState == "confirmed" && len(h.Missing) > 0 {
			errf("hypothesis_confirmed_with_missing_evidence", fmt.Sprintf("hypotheses[%d]", i),
				"a hypothesis cannot be confirmed while its required confirmation evidence is still missing")
		}
	}

	// ---- P1.10 ownership / demarcation -------------------------------------------------
	if rcaExternalOwnerTeams[rep.Ownership.EscalationOwner] &&
		rep.Ownership.Demarcation != "provider_boundary_confirmed" {
		errf("external_owner_without_demarcation", "ownership.escalation_owner",
			"an external provider/carrier cannot own escalation before demarcation is confirmed")
	}

	// ---- P1.11 severity ------------------------------------------------------------------
	if st.SeverityIncident == "crit" {
		single := false
		for _, c := range st.SeverityReasonCodes {
			if c == "single_evidence_class" || c == "single_observer" {
				single = true
			}
		}
		if single {
			errf("crit_from_single_uncorroborated_stream", "states.severity_incident",
				"a CRIT incident severity cannot rest on a single uncorroborated evidence stream")
		}
	}
	if rep.Validation && st.SeverityIncident != "not_applicable" {
		errf("validation_with_production_severity", "states.severity_incident",
			"a validation scenario carries no production severity")
	}

	// ---- P1.12 ticket / escalation consistency ---------------------------------------------
	if rep.Decision.EscalationState == "triggered" &&
		(st.Ticket == "not_opened" || st.Ticket == "held") && rep.Decision.TicketExecutionNote == "" {
		errf("ticket_escalation_contradiction_unexplained", "decision.ticket_execution_note",
			"escalation triggered while the ticket is %s and no explanation is rendered", st.Ticket)
	}
	if rep.Validation && st.Ticket == "opened" {
		warnf("validation_scenario_opened_ticket", "states.ticket",
			"a validation scenario has an open production ticket — verify the tenant opted in (policy allow_validation_scenarios)")
	}

	// ---- P1.13 action applicability -----------------------------------------------------------
	for i, a := range rep.Actions {
		if a.OperationalPriority != "P1" && a.OperationalPriority != "P2" {
			errf("action_missing_operational_priority", fmt.Sprintf("next_actions[%d]", i),
				"every action carries an operational priority (P1/P2), separate from incident severity")
		}
		// instruction ↔ expected-output family agreement: an expected output
		// whose protocol family is absent from the instruction's families is
		// cross-issue contamination (the IKE-output-on-flow-action defect).
		stepFams := map[string]bool{}
		for _, f := range rcaStepFamilies(a.Action) {
			stepFams[f.Name] = true
		}
		outFams := rcaStepFamilies(a.ExpectedResult)
		if len(stepFams) > 0 && len(outFams) > 0 {
			match := false
			for _, f := range outFams {
				if stepFams[f.Name] {
					match = true
					break
				}
			}
			// generic transaction-forensics outputs legitimately span several
			// protocol stages; require agreement only when both sides are
			// single-family and disjoint.
			if !match && len(outFams) == 1 && !stepFams[outFams[0].Name] {
				errf("action_output_family_mismatch", fmt.Sprintf("next_actions[%d]", i),
					"expected output interrogates %q but the instruction does not", outFams[0].Name)
			}
		}
	}

	// ---- wording standard -------------------------------------------------------------------------
	scan := func(field, text string) {
		l := strings.ToLower(text)
		for _, banned := range rcaBannedPhrases {
			if strings.Contains(l, banned) {
				errf("banned_wording", field, "banned phrase %q in customer-facing text", banned)
			}
		}
	}
	// ---- management-summary length discipline (P2) --------------------------------
	if rep.mgmtTrimmed {
		warnf("management_summary_trimmed", "summary.management",
			"summary exceeded the %d-word cap; lower-priority sentences were dropped", rcaMgmtWordCap)
	}
	if n := len(strings.Fields(rep.Summary.Management)); n > rcaMgmtWordCap {
		warnf("management_summary_over_length", "summary.management",
			"summary is %d words after trimming (cap %d) — protected sentences alone exceed the cap", n, rcaMgmtWordCap)
	}

	scan("summary.management", rep.Summary.Management)
	for _, kv := range rep.Summary.Noc {
		scan("summary.noc", kv.V)
	}
	for i, a := range rep.Actions {
		scan(fmt.Sprintf("next_actions[%d]", i), a.Action+" "+a.ExpectedResult)
	}
	scan("topology.drop_point", rep.Topology.DropPoint)
	scan("root_cause.statement", rep.RootCause.Statement)
	scan("fault_localization.statement", rep.FaultLocalization.Statement)
	// P1: customer-facing fault-localization evidence must be ACTUAL case evidence,
	// never a humanized signature CLAUSE — a Boolean rule expression ("… or …")
	// among the localizing evidence is the matching rule leaking through.
	for i, e := range rep.FaultLocalization.Evidence {
		scan(fmt.Sprintf("fault_localization.evidence[%d]", i), e)
		if strings.Contains(e, " or ") {
			errf("rule_expression_in_fault_localization", fmt.Sprintf("fault_localization.evidence[%d]", i),
				"localizing evidence %q reads as a Boolean rule expression, not measured case evidence", e)
		}
	}

	q.Passed = len(q.Errors) == 0
	return q
}

// ticketFactConsistencyIssues is the EMITTER-side consistency gate (P1 gate at
// the sweeper/notify boundary): a cheap, single-pass validation of the already-
// loaded facts an RCA-derived external message would be built from. It never
// recomposes the report — it checks the same P1 invariants the report gate
// enforces, at the fidelity the raw slice offers. A non-empty result means the
// composed state contradicts itself and MUST NOT be emitted to an external
// system; callers suppress with an observable, structured reason — never a
// silent drop. Generic: cross-field invariants only, no case/signature matches.
func ticketFactConsistencyIssues(state string, sigRows []map[string]any) []string {
	var (
		firstAnomaly, lastAnomaly time.Time
		lastRecovery              time.Time
		stateUpTimes              []time.Time
		anomalous                 int
	)
	for _, sig := range sigRows {
		kind := fmt.Sprintf("%v", sig["kind"])
		ts, tsOK := parseChTS(fmt.Sprintf("%v", sig["ts"]))
		if rcaIsRecoveryStateSignal(sig) {
			if tsOK {
				stateUpTimes = append(stateUpTimes, ts)
			}
			continue
		}
		if strings.HasSuffix(kind, "_clear") {
			ct, ok := parseChTS(fmt.Sprintf("%v", sig["clear_ts"]))
			if !ok {
				ct, ok = ts, tsOK
			}
			if ok && ct.After(lastRecovery) {
				lastRecovery = ct
			}
			continue
		}
		if attached, _ := sig["attached"].(bool); !attached {
			continue
		}
		anomalous++
		if tsOK {
			if firstAnomaly.IsZero() || ts.Before(firstAnomaly) {
				firstAnomaly = ts
			}
			if ts.After(lastAnomaly) {
				lastAnomaly = ts
			}
		}
	}
	// a semantic up-state is recovery evidence only AFTER the first anomaly —
	// the same rule the report builder applies (§17).
	for _, t := range stateUpTimes {
		if !firstAnomaly.IsZero() && t.After(firstAnomaly) && t.After(lastRecovery) {
			lastRecovery = t
		}
	}
	var issues []string
	// P1.1: a closed object whose recovery evidence PRECEDES later anomalies
	// carries a recovery claim its own evidence contradicts.
	if state == "closed" && !lastRecovery.IsZero() && lastAnomaly.After(lastRecovery) {
		issues = append(issues, fmt.Sprintf(
			"recovered_before_last_anomaly: closure recovery evidence at %s precedes anomalous evidence through %s",
			fmtUTC(lastRecovery), fmtUTC(lastAnomaly)))
	}
	return issues
}

// applyReportQualityGate runs the validator and downgrades a contradictory
// document: P1 errors block "final" status — the report renders as a draft
// assessment with its quality record attached, and downstream emitters
// (ticketing, notification) can refuse on q.Passed == false.
func applyReportQualityGate(rep *rcaReport, now time.Time) {
	rep.Quality = validateRcaReport(rep, now)
	if !rep.Quality.Passed {
		rep.ReportType = "Draft Incident Assessment — Consistency Review"
		if rep.Subtitle != "" {
			rep.Subtitle += " · "
		}
		rep.Subtitle += countNoun(len(rep.Quality.Errors), "consistency error") + " held this document at draft"
	}
}
