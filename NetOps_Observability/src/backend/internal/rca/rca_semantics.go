package rca

// rca_semantics.go — Phase 1 of the RCA postmortem enhancements
// (docs/design/rca-postmortem-enhancements-spec.md, APPROVED 2026-07-19; gap
// analysis: docs/design/rca-postmortem-phase1-gaps.md).
//
// Two bounded models live here:
//
//  1. ARTIFACT CLASS / REPORT MATURITY — the spec's five artifact classes as
//     an explicit, honestly-derived field. The class is about the DOCUMENT's
//     standing (operational note vs formal postmortem), independent of the
//     analytic report type (`reportTypeFor`), which stays about evidence
//     maturity. A validation scenario is never allowed to resemble a
//     production postmortem; lessons-learned editing exists only for the
//     promoted classes.
//
//  2. SEMANTIC MODEL — trigger, root cause, contributing factors, symptoms
//     and impact as SEPARATE concepts (spec §1), populated only where the
//     engine genuinely distinguishes them today, "not determined" otherwise —
//     the leading hypothesis is never forced into a root-cause field. Plus
//     the detection-milestone set, each stamp carrying its source lineage;
//     comparative durations exist ONLY when both endpoints and their lineage
//     are present.

import (
	"fmt"
	"strings"
	"time"

	"netops/backend/timeintel"
)

// ---- artifact classes / report maturity --------------------------------------

// The five artifact classes (spec "Artifact classes & maturity" — preserve,
// never conflate).
const (
	rcaClassOperational = "operational_assessment"
	rcaClassValidation  = "validation_assessment"
	rcaClassPreliminary = "preliminary_rca"
	rcaClassInterim     = "interim_rca"
	rcaClassFinal       = "final_postmortem"
)

var rcaClassLabels = map[string]string{
	rcaClassOperational: "Operational incident assessment",
	rcaClassValidation:  "Validation incident assessment — nonproduction",
	rcaClassPreliminary: "Preliminary formal RCA",
	rcaClassInterim:     "Interim formal RCA",
	rcaClassFinal:       "Final RCA / postmortem",
}

// rcaHumanStages are the human lifecycle advances (Phase 3 workflow) a promoted
// case may carry. Modeled now so the states exist; nothing sets them yet.
var rcaHumanStages = map[string]string{
	"":        rcaClassPreliminary,
	"interim": rcaClassInterim,
	"final":   rcaClassFinal,
}

// rcaReportMaturity is the explicit artifact-class block on every report.
type rcaReportMaturity struct {
	Class string `json:"class"`
	Label string `json:"label"`
	Basis string `json:"basis"` // how the class was derived — never a bare label
	// Watermark: the rendered document must carry a nonproduction watermark.
	Watermark bool `json:"watermark"`
	// LessonsEditable: lessons learned / human-approved organizational
	// conclusions belong ONLY to the promoted postmortem workflow (classes 3–5).
	LessonsEditable bool `json:"lessons_editable"`
	// WithheldSections: sections this class must NOT render (spec: a validation
	// assessment never resembles a production postmortem; operational
	// assessments carry no lessons-learned narrative).
	WithheldSections []string `json:"withheld_sections,omitempty"`
	// HumanStage: the Phase 3 human lifecycle stage ("", "interim", "final").
	// Recorded so advancing is a data change, never a code change.
	HumanStage string `json:"human_stage,omitempty"`
}

// deriveReportMaturity computes the artifact class honestly:
//
//	validation scenario      → validation assessment (regardless of promotion)
//	unpromoted (incl. active) → operational assessment
//	promoted                 → preliminary RCA; human lifecycle actions
//	                           (Phase 3) advance interim → final.
func deriveReportMaturity(validation, promoted bool, humanStage string) rcaReportMaturity {
	switch {
	case validation:
		return rcaReportMaturity{
			Class:     rcaClassValidation,
			Label:     rcaClassLabels[rcaClassValidation],
			Basis:     "every anomalous observation declares a non-production purpose — this artifact documents a validation scenario and must never resemble a production postmortem",
			Watermark: true,
			WithheldSections: []string{
				"lessons_learned", "production_severity", "corrective_action_commitments",
			},
		}
	case !promoted:
		return rcaReportMaturity{
			Class:            rcaClassOperational,
			Label:            rcaClassLabels[rcaClassOperational],
			Basis:            "unpromoted candidate — an operational assessment may exist while the incident is active; suspected/undetermined findings are allowed and lessons-learned editing is not",
			WithheldSections: []string{"lessons_learned"},
		}
	default:
		class, ok := rcaHumanStages[humanStage]
		basis := "promoted real outage — formal RCA tier; lessons learned and organizational conclusions are editable in this workflow"
		if !ok {
			// An unknown stage never invents a class — it stays preliminary and
			// says why (§10: no silent failures).
			class = rcaClassPreliminary
			basis += fmt.Sprintf(" (unknown human stage %q ignored — kept preliminary)", humanStage)
			humanStage = ""
		} else if humanStage != "" {
			basis += fmt.Sprintf("; advanced to %s by a human lifecycle action", strings.ReplaceAll(class, "_", " "))
		}
		return rcaReportMaturity{
			Class:           class,
			Label:           rcaClassLabels[class],
			Basis:           basis,
			LessonsEditable: true,
			HumanStage:      humanStage,
		}
	}
}

// StampReportMaturity (re)stamps the artifact class after promotion is known
// (the HTTP layer owns the promotion store; the builder pre-stamps the
// promotion-independent classes). It also keeps the lessons-learned gate and
// the validation title discipline in one place.
func StampReportMaturity(rep *Report, humanStage string) {
	rep.Maturity = deriveReportMaturity(rep.Validation, rep.Promotion.Promoted, humanStage)
	rep.LessonsLearned.Editable = rep.Maturity.LessonsEditable
	if !rep.Maturity.LessonsEditable {
		rep.LessonsLearned.Note = "Lessons learned belong to the promoted postmortem workflow (preliminary/interim/final) — not editable on a " +
			strings.ReplaceAll(rep.Maturity.Class, "_", " ") + "."
	} else {
		rep.LessonsLearned.Note = "Editable in the promoted postmortem workflow (Phase 3). Correlix may offer fact-based prompts but never authors subjective lessons or assigns blame."
	}
}

// ---- lessons learned (schema now — editing is Phase 3) ------------------------

// rcaLessonsLearned is the spec-§6 schema. Phase 1 models it (so the fixtures
// can assert the editing gate); the editing workflow, reviewers and approvals
// arrive in Phase 3. Correlix never authors subjective lessons.
type rcaLessonsLearned struct {
	Editable bool   `json:"editable"`
	Note     string `json:"note"`

	WhatWorkedWell             []string `json:"what_worked_well,omitempty"`
	WhatDidNotWorkAsIntended   []string `json:"what_did_not_work_as_intended,omitempty"`
	WhereDefensesLimitedImpact []string `json:"where_defenses_limited_impact,omitempty"`
	AssumptionsProvedIncorrect []string `json:"assumptions_proved_incorrect,omitempty"`
	DetectionGaps              []string `json:"detection_gaps,omitempty"`
	ResponseGaps               []string `json:"response_gaps,omitempty"`

	PostmortemOwner string   `json:"postmortem_owner,omitempty"`
	Reviewers       []string `json:"reviewers,omitempty"`
	ApprovedBy      []string `json:"approved_by,omitempty"`
	UpdatedAt       string   `json:"updated_at,omitempty"`
}

// ---- semantic model -----------------------------------------------------------

// rcaSemanticClaim is one of the separated postmortem concepts with its honest
// determination state. Determined=false renders "not determined" — never a
// leading hypothesis promoted into the slot.
type rcaSemanticClaim struct {
	Determined    bool   `json:"determined"`
	Statement     string `json:"statement"`
	SourceLineage string `json:"source_lineage,omitempty"`
}

// rcaSemanticSymptom is one distinct observed manifestation (projected from the
// evidence summary — the one place the engine genuinely distinguishes symptoms).
type rcaSemanticSymptom struct {
	Label         string `json:"label"`
	Kind          string `json:"kind"`
	SourceLineage string `json:"source_lineage"`
	First         string `json:"first,omitempty"`
	Last          string `json:"last,omitempty"`
}

// rcaContributingFactor — modeled now; the engine does not yet distinguish
// contributing factors from alternatives, so Phase 1 never populates it.
type rcaContributingFactor struct {
	Statement     string `json:"statement"`
	SourceLineage string `json:"source_lineage"`
}

// rcaDetectionMilestone is one detection-track stamp: timestamp + the lineage
// of where that timestamp came from. A milestone with no source is ABSENT from
// the list, never invented.
type rcaDetectionMilestone struct {
	Key           string `json:"key"`
	Label         string `json:"label"`
	TS            string `json:"ts"`
	SourceLineage string `json:"source_lineage"`
}

// rcaMilestoneComparison is a comparative duration between two milestones —
// computed ONLY when both endpoints exist WITH lineage (spec §1: never compute
// comparative statements otherwise).
type rcaMilestoneComparison struct {
	Name       string `json:"name"`
	FromKey    string `json:"from"`
	ToKey      string `json:"to"`
	DurationMS int64  `json:"duration_ms"`
	Basis      string `json:"basis"`
}

// The milestone vocabulary (spec §1 detection tracks), in canonical order.
const (
	msFirstCredibleFailure = "first_credible_failure"
	msFirstServiceImpact   = "first_service_impact"
	msFirstDetection       = "first_correlix_detection"
	msFirstAlert           = "first_alert"
	msFirstAck             = "first_acknowledgement"
	msFirstUserReport      = "first_user_report"
	msFirstMitigation      = "first_mitigation"
	msServiceRestoration   = "service_restoration"
	msRecoveryValidation   = "recovery_validation"
)

var rcaMilestoneOrder = []string{
	msFirstCredibleFailure, msFirstServiceImpact, msFirstDetection, msFirstAlert,
	msFirstAck, msFirstUserReport, msFirstMitigation, msServiceRestoration, msRecoveryValidation,
}

var rcaMilestoneLabels = map[string]string{
	msFirstCredibleFailure: "First credible failure",
	msFirstServiceImpact:   "First service impact",
	msFirstDetection:       "First Correlix detection",
	msFirstAlert:           "First alert",
	msFirstAck:             "First acknowledgement",
	msFirstUserReport:      "First user/help-desk report",
	msFirstMitigation:      "First mitigation",
	msServiceRestoration:   "Service restoration",
	msRecoveryValidation:   "Recovery validation",
}

// rcaSemantics is the separated-concepts block on the report.
type rcaSemantics struct {
	// Trigger: the event/change that set the incident off. The engine does not
	// distinguish it from the earliest symptom today — always "not determined"
	// in Phase 1. The triggering OBSERVATION (the signal that opened the case)
	// is a different, genuinely-known detection fact and is carried separately.
	Trigger               rcaSemanticClaim         `json:"trigger"`
	TriggeringObservation *rcaDetectionMilestone   `json:"triggering_observation,omitempty"`
	RootCause             rcaSemanticClaim         `json:"root_cause"`
	ContributingFactors   []rcaContributingFactor  `json:"contributing_factors"`
	ContributingNote      string                   `json:"contributing_note"`
	Symptoms              []rcaSemanticSymptom     `json:"symptoms"`
	Impact                rcaSemanticClaim         `json:"impact"`
	Milestones            []rcaDetectionMilestone  `json:"detection_milestones"`
	MilestonesAbsent      []string                 `json:"detection_milestones_absent,omitempty"`
	Comparisons           []rcaMilestoneComparison `json:"comparisons,omitempty"`
}

// rcaSemanticsInput carries exactly what the semantic builder needs from the
// report builder's locals — no re-derivation, no engine re-decision.
type rcaSemanticsInput struct {
	Root      RootCause
	Evidence  rcaEvidenceSummary
	Impact    string // overall impact axis summary
	ImpactSyn string
	ImpactRU  string

	FirstObs        time.Time // earliest attached anomalous observation
	FirstRealUserTS time.Time // earliest real-user impact-kind observation (zero = none)
	TriggerSignalID string    // meta trigger_signal (may match nothing in the slice)
	Signals         []map[string]any

	Times      rcaReportTimes
	Monitoring string
	Lifecycle  timeintel.Lifecycle // manual/ITSM lifecycle stamps (nil = none loaded)
}

// buildRcaSemantics derives the separated semantic block. Population rule:
// only what the engine genuinely distinguishes; absent = absent.
func buildRcaSemantics(in rcaSemanticsInput) rcaSemantics {
	sem := rcaSemantics{
		Trigger: rcaSemanticClaim{
			Determined: false,
			Statement:  "Not determined. The engine does not distinguish the incident trigger (the event or change that set the failure off) from the earliest observed symptom, and no trigger has been causally established.",
		},
		ContributingFactors: []rcaContributingFactor{},
		ContributingNote:    "Not determined. The engine does not yet separate contributing factors from alternative hypotheses; alternatives are listed under hypotheses and are never relabeled as contributing factors.",
	}

	// Root cause: mirror the honest root-cause object — never restated stronger.
	sem.RootCause = rcaSemanticClaim{Determined: in.Root.Identified, Statement: in.Root.Statement}
	if in.Root.Identified {
		sem.RootCause.SourceLineage = "established causal mechanism and causal object (" + in.Root.Mechanism + " on " + in.Root.Object + ")"
	}

	// Symptoms: the evidence summary's distinct manifestations — the one place
	// the engine genuinely distinguishes symptom rows.
	for _, s := range in.Evidence.Symptoms {
		sem.Symptoms = append(sem.Symptoms, rcaSemanticSymptom{
			Label: s.Label, Kind: s.Kind,
			SourceLineage: "observed by " + orDefault(s.Source, "an attached evidence source") + " (evidence summary)",
			First:         s.First, Last: s.Last,
		})
	}

	// Impact: a pointer-claim — the numbers live in the provenance block.
	switch {
	case in.ImpactRU == "confirmed":
		sem.Impact = rcaSemanticClaim{Determined: true,
			Statement:     "Real-user impact confirmed by real-traffic/serving-infrastructure evidence. Quantities carry provenance in the impact block; unmeasured values are stated as not measured, never zero.",
			SourceLineage: "real-user impact evidence (impact provenance block)"}
	case in.ImpactSyn == "confirmed":
		sem.Impact = rcaSemanticClaim{Determined: true,
			Statement:     "Synthetic-transaction impact confirmed: the configured checks failed from their vantages. Real-user impact is a separate axis (" + strings.ReplaceAll(in.ImpactRU, "_", " ") + ") and is never derived from synthetic failures.",
			SourceLineage: "customer-path synthetic check failures (impact provenance block)"}
	default:
		sem.Impact = rcaSemanticClaim{Determined: false,
			Statement: "Not determined — impact axes: synthetic " + strings.ReplaceAll(in.ImpactSyn, "_", " ") +
				", real-user " + strings.ReplaceAll(in.ImpactRU, "_", " ") + ". Missing measurement is not evidence of no impact."}
	}

	sem.Milestones, sem.MilestonesAbsent, sem.TriggeringObservation = buildDetectionMilestones(in)
	sem.Comparisons = buildMilestoneComparisons(sem.Milestones)
	return sem
}

// lifecycleLineage names where a manual/ITSM stamp came from.
func lifecycleLineage(st timeintel.EventStamp) string {
	switch st.Source {
	case timeintel.SrcUserEntered:
		return "operator-entered lifecycle event (audited manual entry)"
	case timeintel.SrcITSM:
		return "ITSM-sourced lifecycle event"
	case timeintel.SrcObserved:
		return "engine-observed lifecycle event"
	default:
		return "lifecycle event (source: " + string(st.Source) + ")"
	}
}

// buildDetectionMilestones populates what exists and lists what is absent —
// absence is disclosed, never filled.
func buildDetectionMilestones(in rcaSemanticsInput) ([]rcaDetectionMilestone, []string, *rcaDetectionMilestone) {
	byKey := map[string]rcaDetectionMilestone{}
	put := func(key string, ts time.Time, lineage string) {
		if ts.IsZero() || lineage == "" {
			return
		}
		if cur, ok := byKey[key]; ok {
			if ct, okc := parseChTS(strings.TrimSuffix(cur.TS, " UTC")); okc && !ts.Before(ct) {
				return // keep the earliest stamp for a "first_*" milestone
			}
		}
		byKey[key] = rcaDetectionMilestone{Key: key, Label: rcaMilestoneLabels[key], TS: FmtUTC(ts), SourceLineage: lineage}
	}

	if !in.FirstObs.IsZero() {
		put(msFirstCredibleFailure, in.FirstObs, "earliest attached anomalous observation in the correlation window (observed)")
	}
	if !in.FirstRealUserTS.IsZero() {
		put(msFirstServiceImpact, in.FirstRealUserTS, "earliest real-user impact evidence (real-traffic / serving-infrastructure kinds); synthetic failures never populate this milestone")
	}

	// First Correlix detection: the trigger signal's own observation, when that
	// signal is present in the slice. No created-at fallback — a milestone the
	// platform cannot source stays absent.
	var trig *rcaDetectionMilestone
	if in.TriggerSignalID != "" && in.TriggerSignalID != "<nil>" {
		for _, sig := range in.Signals {
			if fmt.Sprintf("%v", sig["signal_id"]) != in.TriggerSignalID {
				continue
			}
			if ts, ok := parseChTS(fmt.Sprintf("%v", sig["ts"])); ok {
				kind := strings.ReplaceAll(fmt.Sprintf("%v", sig["kind"]), "_", " ")
				m := rcaDetectionMilestone{
					Key: msFirstDetection, Label: rcaMilestoneLabels[msFirstDetection], TS: FmtUTC(ts),
					SourceLineage: "correlation trigger observation (" + kind + ") — the evidence that opened this case",
				}
				byKey[msFirstDetection] = m
				trig = &m
			}
			break
		}
	}

	// Manual / ITSM lifecycle stamps (tenant-scoped store; loaded by the HTTP
	// layer). Engine-owned phases are excluded from manual entry upstream.
	if in.Lifecycle != nil {
		if st, ok := in.Lifecycle[timeintel.EvAcknowledged]; ok {
			put(msFirstAck, st.At, lifecycleLineage(st))
		}
		if st, ok := in.Lifecycle[timeintel.EvMitigationStarted]; ok {
			put(msFirstMitigation, st.At, lifecycleLineage(st))
		} else if st, ok := in.Lifecycle[timeintel.EvMitigated]; ok {
			put(msFirstMitigation, st.At, lifecycleLineage(st)+" (mitigation completion — start was not recorded)")
		}
		if st, ok := in.Lifecycle[timeintel.EvRecovered]; ok {
			put(msServiceRestoration, st.At, lifecycleLineage(st))
		}
	}

	// Service restoration from the recovery reconciler wins over a manual stamp
	// (observed evidence over recollection) — it is the stricter gate.
	if in.Times.RecoveredCaptured {
		if ts, ok := parseChTS(strings.TrimSuffix(in.Times.RecoveredAt, " UTC")); ok {
			byKey[msServiceRestoration] = rcaDetectionMilestone{
				Key: msServiceRestoration, Label: rcaMilestoneLabels[msServiceRestoration], TS: FmtUTC(ts),
				SourceLineage: "recovery reconciler: observed recovery evidence at/after the final qualifying anomaly in every participating scope",
			}
		}
	}
	if in.Monitoring == "completed_no_recurrence" && in.Times.MonitoringUntil != "" {
		if ts, ok := parseChTS(strings.TrimSuffix(in.Times.MonitoringUntil, " UTC")); ok {
			byKey[msRecoveryValidation] = rcaDetectionMilestone{
				Key: msRecoveryValidation, Label: rcaMilestoneLabels[msRecoveryValidation], TS: FmtUTC(ts),
				SourceLineage: "policy monitoring window completed without recurrence",
			}
		}
	}

	var out []rcaDetectionMilestone
	var absent []string
	for _, key := range rcaMilestoneOrder {
		if m, ok := byKey[key]; ok {
			out = append(out, m)
		} else {
			absent = append(absent, key)
		}
	}
	return out, absent, trig
}

// buildMilestoneComparisons — only when BOTH endpoints exist with lineage.
func buildMilestoneComparisons(ms []rcaDetectionMilestone) []rcaMilestoneComparison {
	byKey := map[string]rcaDetectionMilestone{}
	for _, m := range ms {
		if m.TS != "" && m.SourceLineage != "" {
			byKey[m.Key] = m
		}
	}
	var out []rcaMilestoneComparison
	pair := func(name, from, to string) {
		a, okA := byKey[from]
		b, okB := byKey[to]
		if !okA || !okB {
			return
		}
		ta, okTA := parseChTS(strings.TrimSuffix(a.TS, " UTC"))
		tb, okTB := parseChTS(strings.TrimSuffix(b.TS, " UTC"))
		if !okTA || !okTB || tb.Before(ta) {
			return // a negative comparative duration is a data problem, not a statement
		}
		out = append(out, rcaMilestoneComparison{
			Name: name, FromKey: from, ToKey: to, DurationMS: tb.Sub(ta).Milliseconds(),
			Basis: fmt.Sprintf("%s [%s] → %s [%s]", a.Label, a.SourceLineage, b.Label, b.SourceLineage),
		})
	}
	pair("detection lag", msFirstCredibleFailure, msFirstDetection)
	pair("time to acknowledgement", msFirstDetection, msFirstAck)
	pair("time to mitigation", msFirstCredibleFailure, msFirstMitigation)
	pair("time to restoration", msFirstCredibleFailure, msServiceRestoration)
	return out
}
