// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// severity_test.go — the cap that stops a flapping synthetic check from paging
// a human. The rule is only worth having if it survives the OTHER things that
// land in an incident's evidence, so these tests build the bundle the way
// buildIncident builds it: with the window's changes attached.

import (
	"testing"
	"time"
)

// flakyCheckIncident builds the one incident a failing critical journey raises,
// with a single flapping synthetic supporting it plus whatever the caller adds.
func flakyCheckIncident(t *testing.T, extra []EvidenceItem, changes []ChangeEvent,
	rel map[string]SyntheticReliability) ExperienceIncident {

	t.Helper()
	j := checkoutJourney()
	health := ComputeJourneyHealth(j, "1h", map[string]StepMeasurement{
		"browse": {Measured: true, SuccessPct: 100, Samples: 50},
		"cart":   {Measured: true, SuccessPct: 100, Samples: 50},
		"pay":    {Measured: true, SuccessPct: 50, Samples: 50},
	})
	check := ev("flap", ModalityActiveProbe, "prober@branch-1", -10*time.Minute)
	check.Entity = "def-1"
	check.JourneyID = j.ID
	items := append([]EvidenceItem{check}, extra...)

	got := Detect(Bundle{
		TenantID: "acme", Window: testWindow(), Now: testNow,
		Journeys: []JourneyDefinition{j}, JourneyHealth: []JourneyHealth{health},
		Evidence: items, Changes: changes, Reliability: rel,
	})
	if len(got) != 1 {
		t.Fatalf("expected one incident, got %d: %+v", len(got), got)
	}
	return got[0]
}

// flakyDef1 is a check that flipped success/failure on every run, which is the
// definition of one nobody should be woken up for.
func flakyDef1(t *testing.T) map[string]SyntheticReliability {
	t.Helper()
	rel := GradeReliability("def-1", runSeq("def-1", "SFSFSFSFSFSFSFSF", "prober@branch-1"))
	if rel.Grade != ReliabilityFlaky || rel.Trustworthy() {
		t.Fatalf("the fixture check was not graded flaky: %+v", rel)
	}
	return map[string]SyntheticReliability{"def-1": rel}
}

// deployChange is the routine release that used to disarm the cap: same app,
// inside the change lookback, before first impact.
func deployChange() ChangeEvent {
	return ChangeEvent{
		ID: "chg-" + "0000000000000000000000000000000d", TenantID: "acme",
		Type: ChangeApplicationDeploy, Actor: "ci", Object: "checkout-api",
		ObjectKind: "service", Summary: "checkout-api v42 deployed to production",
		ReleaseID: "v42", RollbackRef: "v41", App: "checkout",
		Cohort:     Cohort{AppVersion: "v42"},
		Provenance: prov(SourceConfigDrift, -32*time.Minute),
	}
}

// TestAChangeRecordDoesNotDisarmTheFlakySyntheticCap is the regression. A
// change record is attached to the incident as SUPPORTING evidence before the
// severity is graded, so a predicate that only asked "is this an active probe?"
// let any deploy in the window lift the cap. A flapping check plus a routine
// release then paged a human.
func TestAChangeRecordDoesNotDisarmTheFlakySyntheticCap(t *testing.T) {
	inc := flakyCheckIncident(t, nil, []ChangeEvent{deployChange()}, flakyDef1(t))

	// The test is only meaningful if the change really did become supporting
	// evidence, so assert that before asserting the severity.
	var attached bool
	for _, it := range inc.Evidence {
		if it.IndependenceGroup == ModalityChangeRecord && it.Stance == StanceSupports {
			attached = true
		}
	}
	if !attached {
		t.Fatalf("the change was not attached as supporting evidence, so this test proves nothing: %+v", inc.Evidence)
	}
	if inc.Severity != SeverityLow {
		t.Fatalf("a flapping check plus one deploy graded %q — a change record is not a measurement "+
			"of the experience and must never lift the flaky-synthetic cap", inc.Severity)
	}
}

// TestASecondInstrumentDoesDisarmTheFlakySyntheticCap is the other half: the
// cap must not swallow a real incident. A passive-flow observation of the same
// failure is an independent measurement, so the journey's own importance takes
// over again.
func TestASecondInstrumentDoesDisarmTheFlakySyntheticCap(t *testing.T) {
	flow := ev("flow-1", ModalityPassiveFlow, "flow:edge-1", -9*time.Minute)
	flow.Kind = KindServiceHealth
	flow.Entity = "checkout-api"
	flow.JourneyID = checkoutJourney().ID
	inc := flakyCheckIncident(t, []EvidenceItem{flow}, []ChangeEvent{deployChange()}, flakyDef1(t))
	if inc.Severity != SeverityCritical {
		t.Fatalf("a flow observation of the same failure graded %q — a genuine second instrument "+
			"must lift the cap, or the cap hides real outages", inc.Severity)
	}
}

// TestAnUngradedCheckDoesNotDisarmTheFlakySyntheticCap settles the branch the
// cap's own call site already documented: a definition with no runs is ABSENT
// from the reliability map, and absent means "not established as trustworthy",
// not "trustworthy". Reading it the other way let a brand-new check page
// someone on its first failure.
func TestAnUngradedCheckDoesNotDisarmTheFlakySyntheticCap(t *testing.T) {
	inc := flakyCheckIncident(t, nil, nil, map[string]SyntheticReliability{})
	if inc.Severity != SeverityLow {
		t.Fatalf("an incident resting on an UNGRADED check graded %q, want low — "+
			"severityFor must treat a missing grade and an untrustworthy one identically", inc.Severity)
	}

	// An `unknown` grade is the same answer by a different route: too few runs
	// to judge is still not a reason to page.
	thin := GradeReliability("def-1", runSeq("def-1", "F", "prober@branch-1"))
	if thin.Grade != ReliabilityUnknown {
		t.Fatalf("one run graded %q, want unknown: %+v", thin.Grade, thin)
	}
	inc = flakyCheckIncident(t, nil, nil, map[string]SyntheticReliability{"def-1": thin})
	if inc.Severity != SeverityLow {
		t.Fatalf("an incident resting on an UNKNOWN-grade check graded %q, want low", inc.Severity)
	}

	// And the check that IS graded trustworthy still raises the incident the
	// journey's importance calls for, so the cap has not become a blanket.
	solid := GradeReliability("def-1", runSeq("def-1", "FFFFFFFFFFFFFFFF", "prober@branch-1"))
	if !solid.Trustworthy() {
		t.Fatalf("a check that failed consistently was not trustworthy: %+v", solid)
	}
	inc = flakyCheckIncident(t, nil, nil, map[string]SyntheticReliability{"def-1": solid})
	if inc.Severity != SeverityCritical {
		t.Fatalf("a trustworthy check breaking a critical journey graded %q", inc.Severity)
	}
}
