package rca

// rca_semantics_test.go — Phase 1 semantic models + report maturity
// (docs/design/rca-postmortem-enhancements-spec.md §1 + artifact classes).

import (
	"netops/backend/internal/ticketing"
	"strings"
	"testing"
	"time"

	"netops/backend/timeintel"
)

// ---- artifact classes ---------------------------------------------------------

func TestMaturityDerivation(t *testing.T) {
	cases := []struct {
		name                 string
		validation, promoted bool
		stage                string
		wantClass            string
		wantWatermark        bool
		wantLessons          bool
	}{
		{"active unpromoted", false, false, "", rcaClassOperational, false, false},
		{"validation unpromoted", true, false, "", rcaClassValidation, true, false},
		{"validation even when promoted", true, true, "", rcaClassValidation, true, false},
		{"promoted preliminary", false, true, "", rcaClassPreliminary, false, true},
		{"promoted interim", false, true, "interim", rcaClassInterim, false, true},
		{"promoted final", false, true, "final", rcaClassFinal, false, true},
		{"unknown stage stays preliminary", false, true, "banana", rcaClassPreliminary, false, true},
	}
	for _, c := range cases {
		m := deriveReportMaturity(c.validation, c.promoted, c.stage)
		if m.Class != c.wantClass {
			t.Fatalf("%s: class = %q, want %q", c.name, m.Class, c.wantClass)
		}
		if m.Watermark != c.wantWatermark {
			t.Fatalf("%s: watermark = %v", c.name, m.Watermark)
		}
		if m.LessonsEditable != c.wantLessons {
			t.Fatalf("%s: lessons_editable = %v", c.name, m.LessonsEditable)
		}
		if m.Basis == "" || m.Label == "" {
			t.Fatalf("%s: class must carry label + basis: %+v", c.name, m)
		}
	}
}

func TestMaturityValidationWithholdsPostmortemSections(t *testing.T) {
	m := deriveReportMaturity(true, true, "")
	joined := strings.Join(m.WithheldSections, ",")
	for _, want := range []string{"lessons_learned", "production_severity"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("validation class must withhold %q: %v", want, m.WithheldSections)
		}
	}
}

// The builder pre-stamps the unpromoted classes; the report type and title of a
// validation scenario must never resemble a production artifact.
func TestReportValidationScenarioNeverResemblesProduction(t *testing.T) {
	meta := testMeta("open", "confirmed", "sig.ent.cloud.ipsec-tunnel-down",
		testHyp("sig.ent.cloud.ipsec-tunnel-down", 0.9, "confirmed",
			[]string{"ipsec_tunnel_status"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("ipsec_tunnel_status", "control_plane", "gw-1", "seam", "sm-1", "crit", "2026-07-12 18:00:00", true,
			map[string]any{"attrs": `{"state":"down","signal_purpose":"fault_injection"}`}),
	}
	rep := buildTestReport(t, meta, sigs)
	if !rep.Validation {
		t.Fatal("validation not detected")
	}
	if rep.Maturity.Class != rcaClassValidation || !rep.Maturity.Watermark {
		t.Fatalf("maturity = %+v", rep.Maturity)
	}
	if !strings.Contains(rep.ReportType, "Validation") || !strings.Contains(rep.ReportType, "Nonproduction") {
		t.Fatalf("report type %q must name the validation class", rep.ReportType)
	}
	if !strings.HasPrefix(rep.Title, "Validation scenario — ") {
		t.Fatalf("title %q must carry the validation class", rep.Title)
	}
	if rep.LessonsLearned.Editable {
		t.Fatal("lessons learned must never be editable on a validation assessment")
	}
	for _, banned := range []string{"Root Cause Analysis", "Postmortem", "Incident Analysis"} {
		if strings.Contains(rep.ReportType, banned) {
			t.Fatalf("validation report type %q resembles a production artifact", rep.ReportType)
		}
	}
}

func TestReportUnpromotedIsOperationalAssessment(t *testing.T) {
	meta := testMeta("open", "suspected", "undetermined",
		testHyp("sig.x", 0.4, "suspected", []string{"probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildTestReport(t, meta, sigs)
	if rep.Maturity.Class != rcaClassOperational {
		t.Fatalf("unpromoted candidate class = %q, want operational", rep.Maturity.Class)
	}
	if rep.LessonsLearned.Editable {
		t.Fatal("operational assessment must not allow lessons-learned editing")
	}
}

// Promotion advances the class — the same report, re-stamped, becomes a
// preliminary formal RCA; validation never does.
func TestStampMaturityFollowsPromotion(t *testing.T) {
	rep := promoReport("confirmed", "confirmed", 10*time.Minute, false)
	rep.Promotion = EvaluatePromotion(&rep, nil)
	StampReportMaturity(&rep, "")
	if !rep.Promotion.Promoted || rep.Maturity.Class != rcaClassPreliminary {
		t.Fatalf("promoted real outage class = %q (promoted=%v), want preliminary", rep.Maturity.Class, rep.Promotion.Promoted)
	}
	if !rep.LessonsLearned.Editable {
		t.Fatal("promoted preliminary RCA must open the lessons workflow gate")
	}
}

// ---- semantic separation ------------------------------------------------------

// The trigger and contributing factors are NOT distinguished by the engine
// today — the semantic block must say "not determined", never promote the
// leading hypothesis into those slots.
func TestSemanticsNeverForcesHypothesisIntoTriggerOrRootCause(t *testing.T) {
	meta := testMeta("open", "suspected", "sig.ent.wan.bgp-peer-down",
		testHyp("sig.ent.wan.bgp-peer-down", 0.6, "suspected",
			[]string{"bgp_adjacency_change"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("bgp_adjacency_change", "control_plane", "wan-r2", "device", "wan-r2", "crit", "2026-07-12 18:12:00", true, nil),
	}
	rep := buildTestReport(t, meta, sigs)
	sem := rep.Semantics
	if sem.Trigger.Determined {
		t.Fatalf("trigger must not be determined: %+v", sem.Trigger)
	}
	if !strings.Contains(sem.Trigger.Statement, "Not determined") {
		t.Fatalf("trigger statement must say not determined: %q", sem.Trigger.Statement)
	}
	if sem.RootCause.Determined {
		t.Fatalf("root cause must not be determined for a suspected case: %+v", sem.RootCause)
	}
	if len(sem.ContributingFactors) != 0 || !strings.Contains(sem.ContributingNote, "Not determined") {
		t.Fatalf("contributing factors must be honestly empty: %+v / %q", sem.ContributingFactors, sem.ContributingNote)
	}
	// Symptoms ARE genuinely distinguished — they must be present with lineage.
	if len(sem.Symptoms) == 0 {
		t.Fatal("symptoms missing — the evidence summary distinguishes them")
	}
	for _, s := range sem.Symptoms {
		if s.SourceLineage == "" {
			t.Fatalf("symptom without source lineage: %+v", s)
		}
	}
}

// ---- detection milestones -----------------------------------------------------

func TestMilestonesPopulateOnlyWhatExists(t *testing.T) {
	meta := testMeta("open", "suspected", "undetermined",
		testHyp("sig.x", 0.4, "suspected", []string{"probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	rep := buildTestReport(t, meta, sigs)
	got := map[string]rcaDetectionMilestone{}
	for _, m := range rep.Semantics.Milestones {
		got[m.Key] = m
		if m.TS == "" || m.SourceLineage == "" {
			t.Fatalf("milestone without ts+lineage: %+v", m)
		}
	}
	if _, ok := got[msFirstCredibleFailure]; !ok {
		t.Fatal("first credible failure must come from the earliest anomalous observation")
	}
	// No real-user evidence, no lifecycle, no recovery → these must be ABSENT.
	for _, absentKey := range []string{msFirstServiceImpact, msFirstAck, msFirstUserReport, msFirstMitigation, msServiceRestoration, msRecoveryValidation} {
		if _, ok := got[absentKey]; ok {
			t.Fatalf("milestone %s fabricated", absentKey)
		}
	}
	// Absence is disclosed, never silently dropped.
	absent := strings.Join(rep.Semantics.MilestonesAbsent, ",")
	if !strings.Contains(absent, msFirstUserReport) {
		t.Fatalf("absent milestones must be disclosed: %v", rep.Semantics.MilestonesAbsent)
	}
}

func TestMilestonesFromLifecycleCarryLineage(t *testing.T) {
	meta := testMeta("open", "suspected", "undetermined",
		testHyp("sig.x", 0.4, "suspected", []string{"probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true,
			map[string]any{"probe_scope": "customer_path"}),
	}
	ack := time.Date(2026, 7, 12, 18, 20, 0, 0, time.UTC)
	rep := BuildReport(ReportInput{
		ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Meta: meta, Signals: sigs,
		Policy: ticketing.DefaultIncidentPolicy("t1"), Now: rcaTestNow,
		Lifecycle: timeintel.Lifecycle{
			timeintel.EvAcknowledged: {At: ack, Source: timeintel.SrcUserEntered, Confidence: 1},
		},
	})
	var found *rcaDetectionMilestone
	for i, m := range rep.Semantics.Milestones {
		if m.Key == msFirstAck {
			found = &rep.Semantics.Milestones[i]
		}
	}
	if found == nil {
		t.Fatal("acknowledgement milestone missing despite lifecycle stamp")
	}
	if !strings.Contains(found.SourceLineage, "operator-entered") {
		t.Fatalf("ack lineage must name the source: %q", found.SourceLineage)
	}
}

// Comparative durations exist ONLY when both endpoints (with lineage) exist.
func TestComparisonsRequireBothEndpoints(t *testing.T) {
	ms := []rcaDetectionMilestone{
		{Key: msFirstCredibleFailure, Label: "First credible failure", TS: "2026-07-12 18:10:00 UTC", SourceLineage: "observed"},
	}
	if got := buildMilestoneComparisons(ms); len(got) != 0 {
		t.Fatalf("comparison fabricated with one endpoint: %+v", got)
	}
	ms = append(ms, rcaDetectionMilestone{Key: msServiceRestoration, Label: "Service restoration", TS: "2026-07-12 18:40:00 UTC", SourceLineage: "recovery reconciler"})
	got := buildMilestoneComparisons(ms)
	if len(got) != 1 || got[0].Name != "time to restoration" || got[0].DurationMS != 30*60*1000 {
		t.Fatalf("time to restoration = %+v", got)
	}
	if !strings.Contains(got[0].Basis, "observed") || !strings.Contains(got[0].Basis, "recovery reconciler") {
		t.Fatalf("comparison basis must carry both lineages: %q", got[0].Basis)
	}
	// A milestone missing its lineage never grounds a comparison.
	ms[1].SourceLineage = ""
	if got := buildMilestoneComparisons(ms); len(got) != 0 {
		t.Fatalf("comparison computed from a lineage-less endpoint: %+v", got)
	}
}

// Recovery evidence populates service restoration with the reconciler lineage.
func TestMilestoneServiceRestorationFromReconciler(t *testing.T) {
	meta := testMeta("closed", "suspected", "undetermined",
		testHyp("sig.x", 0.4, "suspected", []string{"probe_loss"}, nil, nil, "netops", false))
	sigs := []map[string]any{
		testSig("probe_loss", "active_probe", "prober", "path", "prober->svc", "high", "2026-07-12 18:12:00", true, nil),
		testSig("probe_loss_clear", "active_probe", "prober", "path", "prober->svc", "info", "2026-07-12 18:15:15", false,
			map[string]any{"clear_ts": "2026-07-12 18:15:15"}),
	}
	rep := buildTestReport(t, meta, sigs)
	var rest *rcaDetectionMilestone
	for i, m := range rep.Semantics.Milestones {
		if m.Key == msServiceRestoration {
			rest = &rep.Semantics.Milestones[i]
		}
	}
	if rest == nil {
		t.Fatal("service restoration milestone missing despite captured recovery")
	}
	if !strings.Contains(rest.SourceLineage, "recovery reconciler") {
		t.Fatalf("restoration lineage = %q", rest.SourceLineage)
	}
}
