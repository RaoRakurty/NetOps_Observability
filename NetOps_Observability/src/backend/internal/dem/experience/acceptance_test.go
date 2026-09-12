// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// acceptance_test.go — THE PHASE T ACCEPTANCE SCENARIO, encoded.
//
// From the owner's design (docs/design/research/DEM_OWNER_DESIGN_2026-09-05.md,
// Phase T) and §M.10 of the design of record:
//
//	A user attempts checkout from an affected network.
//	  Real-user telemetry:  checkout latency and failures rise.
//	  Synthetics:           checkout fails from the same network region.
//	  Network/path:         degradation between the ISP and the cloud.
//	  Backend:              checkout service healthy, database healthy.
//	  A nearby deployment exists — BUT healthy users on other ISPs run the
//	  same release, so the deployment evidence is CONTRADICTORY.
//
//	Expected: one incident, "Checkout … degraded"; impact shown; leading
//	hypothesis = ISP/transit degradation; confidence high enough to CONFIRM
//	only because the independence requirement is met; evidence = RUM +
//	synthetic + network path; contradictory evidence = backend healthy and the
//	same release healthy on the unaffected cohort; the affected hop implicated;
//	owner = the network/provider domain; a recommended action; and a recovery
//	plan that is not satisfied by the action merely completing.
//
// This test FAILED before this slice for the most direct reason there is: none
// of the types it names existed. It is the acceptance gate, and it is a table
// test rather than a lab booking precisely because everything it exercises is
// pure.

import (
	"strings"
	"testing"
	"time"
)

func acceptanceBundle() Bundle {
	j := checkoutJourney()
	affected := Cohort{Site: "branch-1", ISP: "ISP-A", AppVersion: "v42"}
	unaffected := Cohort{Site: "branch-7", ISP: "ISP-B", AppVersion: "v42"}

	health := ComputeJourneyHealth(j, "1h", map[string]StepMeasurement{
		"browse": {Measured: true, SuccessPct: 100, Samples: 60, P95Ms: 120},
		"cart":   {Measured: true, SuccessPct: 100, Samples: 60, P95Ms: 140},
		"pay":    {Measured: true, SuccessPct: 91.6, Samples: 60, P95Ms: 2400},
	})

	items := []EvidenceItem{
		// Real-user telemetry: the experience as it was actually had.
		{
			ID: "rum-checkout-errors", TenantID: "acme", Kind: KindRealUserMetric,
			Entity: "checkout", EntityKind: "service",
			Summary:           "checkout errors rose eightfold for users on ISP-A",
			Stance:            StanceSupports,
			IndependenceGroup: ModalityRealUser, Observer: "rum:browser",
			Reliability: 0.95, App: "checkout", Site: "branch-1", JourneyID: j.ID,
			Cohort:     affected,
			Provenance: prov(SourceRUM, -28*time.Minute),
		},
		// Synthetics from three vantages in the same region.
		ev("syn-branch-1", ModalityActiveProbe, "prober@branch-1", -27*time.Minute),
		ev("syn-branch-2", ModalityActiveProbe, "prober@branch-2", -26*time.Minute),
		ev("syn-branch-3", ModalityActiveProbe, "prober@branch-3", -25*time.Minute),
		// The path: degradation between the ISP and the cloud. THIS is the item
		// that names a cause, an entity and the seam that owns it.
		{
			ID: "path-isp-a", TenantID: "acme", Kind: KindPathDegradation,
			Entity: "hop-7", EntityKind: "hop",
			Summary:           "hop 7 (AS3356, ISP-A transit) lost 8% of probes and added 180 ms",
			Stance:            StanceSupports,
			IndependenceGroup: ModalityActiveProbe, Observer: "prober@branch-1",
			Reliability: 0.9, App: "checkout", Site: "branch-1", JourneyID: j.ID,
			Cohort:     affected,
			CauseClass: CauseTransitDegradation, CauseEntity: "AS3356 (ISP-A transit)",
			Seam: "wan-isp-a", Owner: "ISP A / carrier",
			Provenance: Provenance{
				Source: SourcePathGraph, SourceObject: "obs-91827", Producer: "prober@branch-1",
				EventAt: testNow.Add(-27 * time.Minute), ObservedAt: testNow.Add(-27 * time.Minute),
				Observation: ObservationObserved, DataClass: DataClassCustomerMetadata,
			},
		},
		// An independent control-plane observation of the same transit.
		{
			ID: "bgp-as3356", TenantID: "acme", Kind: KindCorrelation,
			Entity: "AS3356", EntityKind: "asn",
			Summary:           "the path to the checkout front door re-converged through AS3356 at the same minute",
			Stance:            StanceSupports,
			IndependenceGroup: ModalityControlPlane, Observer: "ripestat",
			Reliability: 0.85, App: "checkout", JourneyID: j.ID, Cohort: affected,
			CauseClass: CauseTransitDegradation, CauseEntity: "AS3356 (ISP-A transit)",
			Seam: "wan-isp-a", Owner: "ISP A / carrier",
			Provenance: prov(SourceBGP, -27*time.Minute),
		},
		// Backend healthy — CONTRADICTS the application-tier explanations.
		{
			ID: "svc-checkout-api", TenantID: "acme", Kind: KindServiceHealth,
			Entity: "checkout-api", EntityKind: "service",
			Summary:           "checkout-api p95 and error rate did not move, and its database is healthy",
			Stance:            StanceContradicts,
			IndependenceGroup: ModalityDeviceTelemetry, Observer: "svc:checkout-api",
			Reliability: 0.9, App: "checkout", JourneyID: j.ID,
			ContradictsCauses: []string{CauseApplicationRegress, CauseDependencyFailure},
			Provenance:        prov(SourceServiceHTTP, -26*time.Minute),
		},
		// The cohort contrast — the DECISIVE refutation of the deployment.
		{
			ID: "cohort-v42-healthy", TenantID: "acme", Kind: KindCohortComparison,
			Entity: "v42", EntityKind: "release",
			Summary: "users on ISP-B running the same v42 release completed checkout normally throughout",
			Stance:  StanceContradicts, Decisive: true,
			IndependenceGroup: ModalityRealUser, Observer: "rum:browser",
			Reliability: 0.95, App: "checkout", JourneyID: j.ID, Cohort: unaffected,
			ContradictsCauses: []string{CauseApplicationRegress},
			Provenance:        prov(SourceRUM, -24*time.Minute),
		},
	}
	for i := range items {
		items[i].App = "checkout"
		items[i].JourneyID = j.ID
	}

	changes := []ChangeEvent{{
		ID: "chg-" + "0000000000000000000000000000000d", TenantID: "acme",
		Type: ChangeApplicationDeploy, Actor: "ci", Object: "checkout-api",
		ObjectKind: "service", Summary: "checkout-api v42 deployed to production",
		ReleaseID: "v42", RollbackRef: "v41", App: "checkout",
		Cohort:     Cohort{AppVersion: "v42"},
		Provenance: prov(SourceConfigDrift, -32*time.Minute),
	}}

	return Bundle{
		TenantID: "acme", Window: testWindow(), Now: testNow,
		Journeys: []JourneyDefinition{j}, JourneyHealth: []JourneyHealth{health},
		Evidence: items, Changes: changes,
		// Two sources we expected and did not get. Neither could have anchored
		// the verdict (no producer is configured for them), so they lower
		// confidence without blocking confirmation — which is exactly the
		// distinction the design of record asks for.
		Missing: []MissingEvidence{
			// The flow producer EXISTS since tracker 252 (flow.go); in this
			// scenario no flow record reached the affected subject, which is a
			// different fact from "there is no producer" and is why the reason
			// is no_data rather than not_configured.
			{Source: SourceFlow, IndependenceGroup: ModalityPassiveFlow, Reason: MissingNoData,
				Detail: "no flow record touched the checkout subject in this window"},
			{Source: SourceAgent, IndependenceGroup: ModalityDeviceTelemetry, Reason: MissingNotConfigured,
				Detail: "no endpoint agent is deployed"},
		},
		Reliability: map[string]SyntheticReliability{},
	}
}

func TestPhaseTAcceptanceScenario(t *testing.T) {
	incidents := Detect(acceptanceBundle())
	if len(incidents) != 1 {
		t.Fatalf("the scenario produced %d incidents; the whole point is that it is ONE: %+v", len(incidents), incidents)
	}
	inc := incidents[0]

	// ── the incident ──
	if !strings.Contains(strings.ToLower(inc.Title), "checkout") {
		t.Fatalf("the incident is not named for the failing journey: %q", inc.Title)
	}
	if inc.Severity != SeverityCritical {
		t.Fatalf("a critical journey missing its objective by 7 points graded %q", inc.Severity)
	}

	// ── impact ──
	if inc.Impact.JourneySuccessPct == nil || *inc.Impact.JourneySuccessPct != 91.6 {
		t.Fatalf("journey success was not carried onto the impact: %+v", inc.Impact)
	}
	if len(inc.Impact.AffectedCohorts) == 0 || inc.Impact.AffectedCohorts[0].ISP != "ISP-A" {
		t.Fatalf("the affected cohort was not identified: %+v", inc.Impact.AffectedCohorts)
	}
	if len(inc.Impact.UnaffectedCohorts) == 0 || inc.Impact.UnaffectedCohorts[0].ISP != "ISP-B" {
		t.Fatalf("the UNAFFECTED cohort was not identified — it is what rules the deployment out: %+v", inc.Impact.UnaffectedCohorts)
	}
	if len(inc.Impact.NotMeasured) == 0 {
		t.Fatal("the impact claimed to be complete; affected users cannot be counted without real-user telemetry and the response must say so")
	}
	if inc.Impact.BusinessValueLost == nil || inc.Impact.Currency != "USD" {
		t.Fatalf("declared business value was not turned into an impact: %+v", inc.Impact)
	}

	// ── the leading hypothesis ──
	lead, ok := leadOf(inc)
	if !ok {
		t.Fatal("no leading hypothesis was reached")
	}
	if lead.CauseClass != CauseTransitDegradation {
		t.Fatalf("the leading hypothesis is %q, want transit degradation: %+v", lead.CauseClass, lead)
	}
	if lead.State != StateConfirmed {
		t.Fatalf("the transit hypothesis reached %s at %v, not CONFIRMED. Gate: %v",
			lead.State, lead.Confidence, lead.GateReasons)
	}
	if lead.VerdictTier != TierConfirmed {
		t.Fatalf("verdict tier is %q", lead.VerdictTier)
	}
	if lead.Confidence < ConfirmConfidence {
		t.Fatalf("confidence %v is below the confirmation bar %v", lead.Confidence, ConfirmConfidence)
	}
	if lead.Confidence >= 1 {
		t.Fatalf("confidence reached %v with two expected sources missing — missing telemetry must cost something", lead.Confidence)
	}
	if !lead.Independence.Satisfied() || len(lead.Independence.AnchorModalities) < 3 {
		t.Fatalf("confirmation was reached without three independent kinds of instrument: %+v", lead.Independence)
	}

	// ── ownership ──
	if inc.Seam != "wan-isp-a" || !strings.Contains(inc.Owner, "ISP A") {
		t.Fatalf("ownership was not attributed to the failing seam: seam=%q owner=%q", inc.Seam, inc.Owner)
	}

	// ── the contradicted deployment ──
	var deploy *Hypothesis
	for i := range inc.Hypotheses {
		if inc.Hypotheses[i].CauseClass == CauseApplicationRegress {
			deploy = &inc.Hypotheses[i]
		}
	}
	if deploy == nil {
		t.Fatal("the nearby deployment was never considered as a hypothesis — an explanation nobody weighed is not an explanation that was ruled out")
	}
	if deploy.State != StateRejected {
		t.Fatalf("the deployment was not rejected despite the same release being healthy on the unaffected cohort: %+v", deploy)
	}
	if len(deploy.ContradictingIDs) == 0 {
		t.Fatalf("the deployment was rejected without naming what refuted it: %+v", deploy)
	}

	// ── evidence, including the negative kind ──
	kinds := map[string]bool{}
	supporting, contradicting := 0, 0
	for _, e := range inc.Evidence {
		kinds[e.Kind] = true
		switch e.Stance {
		case StanceSupports:
			supporting++
		case StanceContradicts:
			contradicting++
		}
	}
	for _, want := range []string{KindRealUserMetric, KindSyntheticResult, KindPathDegradation, KindServiceHealth, KindCohortComparison} {
		if !kinds[want] {
			t.Fatalf("the incident is missing %q evidence; it must carry RUM, synthetic, path AND the contradictory backend/cohort evidence", want)
		}
	}
	if contradicting < 2 {
		t.Fatalf("only %d contradicting observations survived; negative evidence is first-class", contradicting)
	}
	if len(inc.MissingEvidence) != 2 {
		t.Fatalf("the missing sources were not carried onto the incident: %+v", inc.MissingEvidence)
	}

	// ── the affected hop ──
	if inc.PathObservationID != "obs-91827" {
		t.Fatalf("the immutable path observation was not referenced: %q", inc.PathObservationID)
	}

	// ── the change, ranked by correlation rather than by clock ──
	if len(inc.Changes) != 1 {
		t.Fatalf("the deployment did not appear in the change list: %+v", inc.Changes)
	}
	if !inc.Changes[0].Precedes {
		t.Fatal("the deployment was not recognised as preceding the first impact")
	}

	// ── the recommended action, and recovery that the action alone cannot satisfy ──
	if len(inc.RecommendedActions) == 0 {
		t.Fatal("a confirmed cause produced no recommended action")
	}
	act := inc.RecommendedActions[0]
	if act.Type != ActionTrafficShift {
		t.Fatalf("the recommended action for a transit fault is %q", act.Type)
	}
	if act.VerificationPlan == "" || act.RollbackPlan == "" {
		t.Fatalf("an action shipped without a verification or rollback plan: %+v", act)
	}
	if inc.Verification.Recovered {
		t.Fatal("the incident claimed recovery before anything was verified")
	}
	if len(inc.Verification.Checks) == 0 {
		t.Fatal("no recovery checks were planned, so recovery could only ever be a guess")
	}

	// ── one timeline, with observed and inferred distinguishable ──
	if len(inc.Timeline) < 5 {
		t.Fatalf("the timeline is too sparse to be the single view of the incident: %+v", inc.Timeline)
	}
	for _, e := range inc.Timeline {
		if e.Observation == "" {
			t.Fatalf("a timeline entry did not say whether it was observed or inferred: %+v", e)
		}
	}
}

// The derivation must not mutate its input. Evidence and path observations are
// immutable facts; a detector that rewrote them would make the same bundle
// yield different answers on a second read.
func TestDetectDoesNotMutateItsInput(t *testing.T) {
	b := acceptanceBundle()
	before := make([]EvidenceItem, len(b.Evidence))
	copy(before, b.Evidence)
	_ = Detect(b)
	for i := range before {
		if b.Evidence[i].Stance != before[i].Stance ||
			len(b.Evidence[i].SupportsHypotheses) != len(before[i].SupportsHypotheses) ||
			len(b.Evidence[i].ContradictsHypotheses) != len(before[i].ContradictsHypotheses) ||
			b.Evidence[i].EventAt != before[i].EventAt {
			t.Fatalf("Detect mutated evidence item %d: %+v", i, b.Evidence[i])
		}
	}
}

// The same bundle must always yield the same incident id, so a link an operator
// shares keeps working and two API calls never disagree about which incident is
// which.
func TestIncidentDerivationIsDeterministic(t *testing.T) {
	a := Detect(acceptanceBundle())
	c := Detect(acceptanceBundle())
	if len(a) != len(c) || a[0].ID != c[0].ID {
		t.Fatalf("the derivation is not deterministic: %v vs %v", a[0].ID, c[0].ID)
	}
	if a[0].Confidence != c[0].Confidence {
		t.Fatalf("the confidence is not deterministic: %v vs %v", a[0].Confidence, c[0].Confidence)
	}
}

func leadOf(inc ExperienceIncident) (Hypothesis, bool) {
	for _, h := range inc.Hypotheses {
		if h.ID == inc.LeadingHypothesisID {
			return h, true
		}
	}
	return Hypothesis{}, false
}
