package experience

// model_test.go — the rest of the Phase O backend list: the score (O-14), the
// branching journey (O-10), synthetic flakiness (O-11), the privacy
// classification (O-13), observed-vs-inferred (O-8), and the immutability of
// the path reference (O-9).

import (
	"strings"
	"testing"
	"time"
)

// ── the score (O-14: explainable AND versioned) ─────────────────────────────

func TestEmbeddedScorePolicyLoadsAndIsAuditable(t *testing.T) {
	p, err := EmbeddedScorePolicy()
	if err != nil {
		t.Fatalf("the SHIPPED score policy does not parse — no score could be published at all: %v", err)
	}
	if p.Version <= 0 || p.Name == "" {
		t.Fatalf("the shipped policy is unidentifiable: %+v", p)
	}
	if _, ok := p.Classes[DefaultAppClass]; !ok {
		t.Fatal("the shipped policy has no default class, so an unknown application class would score against nothing")
	}
	for _, class := range p.ClassNames() {
		sum := 0.0
		for dim, w := range p.Classes[class] {
			if !ValidDimension(dim) {
				t.Fatalf("class %q weights a dimension nothing computes: %q", class, dim)
			}
			sum += w
		}
		if sum < 1-weightSumTolerance || sum > 1+weightSumTolerance {
			t.Fatalf("class %q weights sum to %v", class, sum)
		}
	}
}

func TestScorePolicyRefusesWhatItCannotHonour(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"unknown dimension", "name: x\nversion: 1\nclasses:\n  default:\n    made_up: 1.0\n", "unknown dimension"},
		{"weights do not sum", "name: x\nversion: 1\nclasses:\n  default:\n    availability: 0.4\n", "sum to"},
		{"no default class", "name: x\nversion: 1\nclasses:\n  web:\n    availability: 1.0\n", "default"},
		{"no version", "name: x\nclasses:\n  default:\n    availability: 1.0\n", "version"},
		{"tabs", "name: x\nversion: 1\nclasses:\n\tdefault:\n", "tab"},
		{"unknown top-level key", "name: x\nversion: 1\nweights: 3\n", "unknown top-level key"},
	}
	for _, c := range cases {
		if _, err := ParseScorePolicy(c.src); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v, want an error mentioning %q", c.name, err, c.want)
		}
	}
}

func TestScoreIsDecomposableVersionedAndGated(t *testing.T) {
	policy, err := EmbeddedScorePolicy()
	if err != nil {
		t.Fatal(err)
	}
	// A window with only ONE measured dimension is below the evidence minimum
	// and must not be published at all — not as 0, and not as 100.
	thin := ComputeScore("acme", "tenant", "1h", AggWorstOf, policy, "web", map[string]DimensionInput{
		DimAvailability: {Measured: true, Points: 99, Samples: 60},
	}, nil)
	if thin.Measured || thin.Score != nil {
		t.Fatalf("a score was published from one dimension: %+v", thin)
	}
	if thin.Reason != ReasonScoreBelowMinimum || thin.Detail == "" {
		t.Fatalf("the unpublished score gave no usable reason: %+v", thin)
	}
	if thin.Band != BandNotMeasured {
		t.Fatalf("an unmeasured score carried the band %q", thin.Band)
	}

	prev := ComputeScore("acme", "tenant", "1h", AggWorstOf, policy, "web", map[string]DimensionInput{
		DimJourneySuccess: {Measured: true, Points: 99, Samples: 3},
		DimAvailability:   {Measured: true, Points: 99, Samples: 60},
		DimResponsiveness: {Measured: true, Points: 95, Samples: 60},
	}, nil)
	now := ComputeScore("acme", "tenant", "1h", AggWorstOf, policy, "web", map[string]DimensionInput{
		DimJourneySuccess: {Measured: true, Points: 60, Samples: 3, Detail: "Checkout success fell to 91.6%"},
		DimAvailability:   {Measured: true, Points: 99, Samples: 60},
		DimResponsiveness: {Measured: true, Points: 95, Samples: 60},
		DimNetworkQuality: {Reason: MissingNoData, Detail: "no forward path was observed"},
	}, &prev)

	if !now.Measured || now.Score == nil {
		t.Fatalf("a three-dimension window published no score: %+v", now)
	}
	if now.PolicyVersion != policy.Version || now.PolicyName != policy.Name {
		t.Fatalf("the score did not carry its policy version: %+v", now)
	}
	if now.PreviousScore == nil || now.Delta == nil || *now.Delta >= 0 {
		t.Fatalf("the fall was not expressed as a delta: %+v", now)
	}
	// The dimension that fell must own the fall.
	var js *DimensionScore
	for i := range now.Dimensions {
		if now.Dimensions[i].Name == DimJourneySuccess {
			js = &now.Dimensions[i]
		}
	}
	if js == nil || js.DeltaContribution == nil || *js.DeltaContribution >= 0 {
		t.Fatalf("journey_success did not report its contribution to the fall: %+v", js)
	}
	if js.Detail == "" {
		t.Fatal("the dimension gave no operator-readable reason for its value")
	}
	// The unmeasured dimension contributes nothing and its weight is
	// redistributed: the measured weights must still sum to 1.
	sum := 0.0
	for _, d := range now.Dimensions {
		if d.Measured {
			sum += d.Weight
		} else if d.Weight != 0 {
			t.Fatalf("an unmeasured dimension carried weight: %+v", d)
		}
	}
	if sum < 1-weightSumTolerance || sum > 1+weightSumTolerance {
		t.Fatalf("the measured weights sum to %v after redistribution", sum)
	}
	// Bands are fixed at 70/30 and never inverted.
	if Band(70) != BandGood || Band(69.9) != BandFair || Band(30) != BandPoor {
		t.Fatal("the score bands moved")
	}
}

// ── the journey (O-10: branching, optional steps and loops) ─────────────────

func TestBranchingJourneyIsRepresentedAndComposedMultiplicatively(t *testing.T) {
	j := checkoutJourney()
	// The fixture's `cart` step branches to `pay` AND back to `browse` — a loop,
	// which is legal and must not be flattened into a line.
	cart, ok := j.Step("cart")
	if !ok || len(cart.Next) != 2 {
		t.Fatalf("the branching step was not preserved: %+v", cart)
	}

	h := ComputeJourneyHealth(j, "1h", map[string]StepMeasurement{
		"browse": {Measured: true, SuccessPct: 100, Samples: 50},
		"cart":   {Measured: true, SuccessPct: 95, Samples: 50},
		"pay":    {Measured: true, SuccessPct: 90, Samples: 50},
	})
	// 1.00 × 0.95 × 0.90 = 0.855. The MEAN would be 95 and would hide the fact
	// that fewer than nine in ten people finish.
	if h.SuccessPct != 85.5 {
		t.Fatalf("journey success composed to %v, want the product 85.5", h.SuccessPct)
	}
	if h.FailingStepID != "cart" {
		t.Fatalf("the failing step is %q, want the FIRST required step that misses its objective", h.FailingStepID)
	}
	if h.MeetsSLO {
		t.Fatal("a journey at 85.5% met a 99% objective")
	}

	// A step nobody bound to a measurement is NOT MEASURED, never "fine".
	unbound := j
	unbound.Steps = append([]JourneyStep{}, j.Steps...)
	unbound.Steps[2].TargetID = ""
	uh := ComputeJourneyHealth(unbound, "1h", map[string]StepMeasurement{
		"browse": {Measured: true, SuccessPct: 100, Samples: 50},
		"cart":   {Measured: true, SuccessPct: 100, Samples: 50},
	})
	for _, s := range uh.Steps {
		if s.StepID == "pay" {
			if s.Measured || s.Reason != ReasonStepUnbound {
				t.Fatalf("an unbound step was reported as measured: %+v", s)
			}
		}
	}
	if uh.StepsMeasured != 2 || uh.StepsDeclared != 3 {
		t.Fatalf("the coverage behind the number was not exposed: %d of %d", uh.StepsMeasured, uh.StepsDeclared)
	}

	// Nothing measured at all ⇒ no success rate, with a reason.
	empty := ComputeJourneyHealth(j, "1h", map[string]StepMeasurement{})
	if empty.Measured || empty.Reason != ReasonJourneyNotMeasured || empty.Detail == "" {
		t.Fatalf("an unmeasured journey was not explained: %+v", empty)
	}
}

func TestJourneyValidationRefusesAnUnwalkableGraph(t *testing.T) {
	base := checkoutJourney()
	cases := []struct {
		name string
		fix  func(*JourneyDefinition)
		want string
	}{
		{"dangling edge", func(j *JourneyDefinition) { j.Steps[0].Next = []string{"nowhere"} }, "unknown step"},
		{"no success terminal", func(j *JourneyDefinition) { j.Steps[2].TerminalSuccess = false }, "success terminal"},
		{"entry not a step", func(j *JourneyDefinition) { j.EntryStepID = "ghost" }, "entry_step_id"},
		{"duplicate step id", func(j *JourneyDefinition) { j.Steps[1].ID = "browse" }, "duplicate step id"},
		{"both terminals", func(j *JourneyDefinition) { j.Steps[2].TerminalFailure = true }, "cannot be both"},
		{"value without currency", func(j *JourneyDefinition) { j.Currency = "" }, "currency"},
	}
	for _, c := range cases {
		j := base
		j.Steps = append([]JourneyStep{}, base.Steps...)
		c.fix(&j)
		if err := j.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: got %v, want an error mentioning %q", c.name, err, c.want)
		}
	}
}

// ── synthetic reliability (O-11: a flaky check must not create a P1) ────────

func TestFlakySyntheticCannotRaiseAHighSeverityIncident(t *testing.T) {
	runs := make([]SyntheticRun, 0, 20)
	for i := 0; i < 20; i++ {
		outcome := RunSuccess
		if i%2 == 1 {
			outcome = RunFailure
		}
		runs = append(runs, SyntheticRun{
			ID: "run", DefinitionID: "def-1", VantageID: "v1", Outcome: outcome,
			StartedAt: testNow.Add(time.Duration(-i) * time.Minute),
		})
	}
	rel := GradeReliability("def-1", runs)
	if rel.Grade != ReliabilityFlaky {
		t.Fatalf("a check that flipped on every run graded %q: %+v", rel.Grade, rel)
	}
	if rel.Trustworthy() {
		t.Fatal("a flaky check was called trustworthy")
	}

	// The incident built ONLY on that check must be capped at low severity even
	// though the journey it breaks is critical to the business.
	j := checkoutJourney()
	health := ComputeJourneyHealth(j, "1h", map[string]StepMeasurement{
		"browse": {Measured: true, SuccessPct: 100, Samples: 50},
		"cart":   {Measured: true, SuccessPct: 100, Samples: 50},
		"pay":    {Measured: true, SuccessPct: 50, Samples: 50},
	})
	item := ev("flap", ModalityActiveProbe, "prober@branch-1", -10*time.Minute)
	item.Entity = "def-1"
	item.JourneyID = j.ID
	inc := Detect(Bundle{
		TenantID: "acme", Window: testWindow(), Now: testNow,
		Journeys: []JourneyDefinition{j}, JourneyHealth: []JourneyHealth{health},
		Evidence:    []EvidenceItem{item},
		Reliability: map[string]SyntheticReliability{"def-1": rel},
	})
	if len(inc) != 1 {
		t.Fatalf("expected one incident, got %d", len(inc))
	}
	if inc[0].Severity != SeverityLow {
		t.Fatalf("an incident resting on a single flaky check graded %q — a flapping test must never page anyone", inc[0].Severity)
	}

	// The same failure, with the check graded solid, IS a critical incident.
	solid := rel
	solid.Grade = ReliabilitySolid
	inc = Detect(Bundle{
		TenantID: "acme", Window: testWindow(), Now: testNow,
		Journeys: []JourneyDefinition{j}, JourneyHealth: []JourneyHealth{health},
		Evidence:    []EvidenceItem{item},
		Reliability: map[string]SyntheticReliability{"def-1": solid},
	})
	if inc[0].Severity != SeverityCritical {
		t.Fatalf("a trustworthy check breaking a critical journey graded %q", inc[0].Severity)
	}
}

func TestReliabilityIsUnknownRatherThanGuessedOnTooFewRuns(t *testing.T) {
	rel := GradeReliability("def-1", []SyntheticRun{{Outcome: RunFailure, VantageID: "v1"}})
	if rel.Grade != ReliabilityUnknown || rel.Trustworthy() {
		t.Fatalf("one run produced a reliability verdict: %+v", rel)
	}
	if rel.Reason == "" {
		t.Fatal("the unknown grade gave no reason")
	}
}

// ── coverage ────────────────────────────────────────────────────────────────

func TestCoverageCallsAnUnmeasuredActionUntestedNotHealthy(t *testing.T) {
	j := checkoutJourney()
	defs := map[string][]SyntheticDefinition{
		j.ID + "/browse": {{ID: "d1", Kind: SynHTTP, Vantages: []string{"v1", "v2"}}},
		j.ID + "/cart":   {{ID: "d2", Kind: SynHTTP, Vantages: []string{"v1"}}},
		// "pay" is deliberately unprotected.
	}
	rep := BuildCoverage("1h", []JourneyDefinition{j}, defs,
		map[string]SyntheticReliability{
			"d1": {Grade: ReliabilitySolid}, "d2": {Grade: ReliabilitySolid},
		},
		map[string]time.Time{"d1": testNow, "d2": testNow})
	states := map[string]string{}
	for _, a := range rep.Actions {
		states[a.StepID] = a.State
	}
	if states["pay"] != CoverageUntested {
		t.Fatalf("an action nothing measures was graded %q", states["pay"])
	}
	if states["cart"] != CoverageThin {
		t.Fatalf("an action protected by one check from one vantage was graded %q", states["cart"])
	}
	if states["browse"] != CoverageProtected {
		t.Fatalf("an action protected by a check from two vantages was graded %q", states["browse"])
	}
	if rep.Untested != 1 || rep.CoveragePct == nil || *rep.CoveragePct >= 100 {
		t.Fatalf("coverage was overstated: %+v", rep)
	}

	// Zero declared actions is NOT 100% coverage.
	empty := BuildCoverage("1h", nil, nil, nil, nil)
	if empty.CoveragePct != nil {
		t.Fatalf("coverage of nothing was reported as %v", *empty.CoveragePct)
	}
	if !strings.Contains(empty.Detail, "not 100%") {
		t.Fatalf("the empty-coverage sentence is misleading: %q", empty.Detail)
	}
}

// ── data health (UNKNOWN and NO DATA are never HEALTHY) ─────────────────────

func TestDataHealthNeverCallsAbsenceHealthyAndGatesConfirmation(t *testing.T) {
	dh := BuildDataHealth("1h", []SourceHealth{
		{Source: SourceSynthetic, Configured: true, State: StateFlowing, CoverageTotal: 4, CoverageCovered: 3},
		{Source: SourcePathGraph, Configured: true, State: StateNoData},
		{Source: SourceRUM, State: StateOff},
	}, testNow)
	if dh.AnchorSourcesFlowing != 1 || dh.CanConfirm {
		t.Fatalf("one flowing anchor source claimed confirmation was possible: %+v", dh)
	}
	if dh.Explanation == "" {
		t.Fatal("the confirmation ceiling was not explained")
	}
	for _, s := range dh.Sources {
		if Healthy(s.State) != (s.State == StateFlowing) {
			t.Fatalf("state %q was misgraded as healthy=%v", s.State, Healthy(s.State))
		}
		if !Healthy(s.State) && s.ConfidenceInfluence == 0 {
			t.Fatalf("an absent source (%s/%s) had no effect on confidence", s.Source, s.State)
		}
	}
	// A source that is off but was never configured must not BLOCK a verdict —
	// only lower confidence. A configured anchor source that stopped must block.
	missing := dh.MissingFrom()
	byName := map[string]MissingEvidence{}
	for _, m := range missing {
		byName[m.Source] = m
	}
	if m, ok := byName[SourceRUM]; !ok || m.Required {
		t.Fatalf("an unconfigured source was treated as required: %+v", m)
	}
	if m, ok := byName[SourcePathGraph]; !ok || !m.Required {
		t.Fatalf("a CONFIGURED anchor source that stopped reporting did not block confirmation: %+v", m)
	}
	// Coverage is stated, never assumed.
	for _, s := range dh.Sources {
		if s.Source == SourceSynthetic {
			if s.Coverage == nil || *s.Coverage != 0.75 {
				t.Fatalf("coverage was not computed: %+v", s.Coverage)
			}
		}
		if s.Source == SourceRUM && s.Coverage != nil {
			t.Fatal("coverage was invented for a source with no denominator")
		}
	}
}

// ── changes ranked by correlation, not by clock ─────────────────────────────

func TestChangesAreRankedByCorrelationNotProximity(t *testing.T) {
	firstImpact := testNow.Add(-30 * time.Minute)
	affected := Cohort{Site: "branch-1", ISP: "ISP-A"}
	near := ChangeEvent{
		ID: "near", Type: ChangeConfig, Object: "sw-99", Summary: "unrelated switch VLAN edit",
		App: "billing", Site: "branch-9", Cohort: Cohort{Site: "branch-9", ISP: "ISP-B"},
		Provenance: prov(SourceConfigDrift, -31*time.Minute), // one minute before impact
	}
	relevant := ChangeEvent{
		ID: "relevant", Type: ChangeRoute, Object: "wan-isp-a", Summary: "transit preference changed",
		App: "checkout", Site: "branch-1", Seam: "wan-isp-a", Cohort: affected,
		Provenance: prov(SourceBGP, -60*time.Minute), // an hour before — much further away
	}
	ranked := RankChanges([]ChangeEvent{near, relevant}, affected, "checkout", "branch-1", "wan-isp-a",
		firstImpact, testWindow(), []string{CauseRoutingChange})
	if ranked[0].Change.ID != "relevant" {
		t.Fatalf("the nearer-in-time but unrelated change outranked the relevant one: %+v", ranked)
	}
	if ranked[1].TouchesAffectedCohort {
		t.Fatalf("a change whose cohort excludes the affected population was not marked: %+v", ranked[1])
	}
	for _, r := range ranked {
		if len(r.Reasons) == 0 {
			t.Fatalf("a ranked change gave no reasons: %+v", r)
		}
	}

	// A change AFTER the first impact is shown but can never lead.
	late := relevant
	late.ID = "late"
	late.Provenance = prov(SourceBGP, -10*time.Minute)
	ranked = RankChanges([]ChangeEvent{late}, affected, "checkout", "branch-1", "wan-isp-a",
		firstImpact, testWindow(), []string{CauseRoutingChange})
	if ranked[0].Precedes {
		t.Fatal("a change after the first impact was marked as preceding it")
	}
}

// ── privacy (O-13) ──────────────────────────────────────────────────────────

func TestPseudonymousUserReferencesAreEnforced(t *testing.T) {
	e := ExperienceEvent{
		ID: "e1", TenantID: "acme", App: "checkout", Type: EventPageView,
		UserRef: "alice@example.com", ActorType: ActorHuman,
		Provenance: prov(SourceRUM, 0),
	}
	if err := e.Validate(); err == nil || !strings.Contains(err.Error(), "pseudonymous") {
		t.Fatalf("a direct identifier was accepted as a user reference: %v", err)
	}
	// Default-closed: an event carrying a user reference that declares NO class
	// is classified pseudonymous, never "internal".
	e.UserRef = "u_9f2c1a"
	e.DataClass = ""
	if err := e.Validate(); err != nil {
		t.Fatalf("a pseudonymous reference was refused: %v", err)
	}
	if e.DataClass != DataClassPseudonymousUser {
		t.Fatalf("an event carrying a user reference was classified %q", e.DataClass)
	}
	// And a producer that classifies it BELOW that is refused rather than
	// silently upgraded: quietly rewriting a security classification would hide
	// the fact that a producer is mislabelling its data.
	for _, low := range []string{DataClassPublic, DataClassInternal, DataClassCustomerMetadata} {
		bad := e
		bad.DataClass = low
		if err := bad.Validate(); err == nil {
			t.Fatalf("an event with a user reference was accepted as %q", low)
		}
	}
	// The AI packet withholds anything above the class that may leave.
	if MayLeaveThePlatform(DataClassPII) || MayLeaveThePlatform(DataClassCredential) {
		t.Fatal("PII or a credential was permitted to leave the platform")
	}
	if !MayLeaveThePlatform(DataClassPseudonymousUser) {
		t.Fatal("a pseudonymous reference was withheld, which would make every AI answer thin for no benefit")
	}
	// An unknown class is treated as the MOST sensitive, never the least.
	if MayLeaveThePlatform("something_new") {
		t.Fatal("an unrecognised data class was permitted to leave the platform")
	}
}

// ── observed vs inferred (O-8) and the immutable path reference (O-9) ───────

func TestObservedAndInferredStayDistinguishable(t *testing.T) {
	inferred := ev("inferred", ModalityActiveProbe, "prober-1", -5*time.Minute)
	inferred.Observation = ObservationInferred
	if err := inferred.Validate(); err != nil {
		t.Fatal(err)
	}
	observed := ev("observed", ModalityActiveProbe, "prober-2", -5*time.Minute)
	if err := observed.Validate(); err != nil {
		t.Fatal(err)
	}
	if inferred.Observation == observed.Observation {
		t.Fatal("an inferred observation became indistinguishable from a measured one")
	}
	// A provenance that will not say which it is, is refused.
	bad := observed
	bad.Observation = "probably"
	if err := bad.Validate(); err == nil {
		t.Fatal("an evidence item with an unrecognised observation mode was accepted")
	}
	// And the distinction survives into the model briefing.
	inc := ExperienceIncident{ID: "exp-1", Evidence: []EvidenceItem{inferred, observed}}
	p := BuildPacket(inc, nil)
	modes := map[string]bool{}
	for _, e := range p.Evidence {
		modes[e.Observation] = true
	}
	if !modes[ObservationInferred] || !modes[ObservationObserved] {
		t.Fatalf("the packet flattened observed and inferred: %+v", p.Evidence)
	}
}

// ── the AI investigator's whitelist (Phase K) ───────────────────────────────

func TestInvestigatorRejectsInventedEvidenceAndCannotConfirm(t *testing.T) {
	inc := Detect(acceptanceBundle())[0]
	packet := BuildPacket(inc, nil)
	if len(packet.EvidenceIDs) == 0 {
		t.Fatal("the packet carried no evidence whitelist")
	}

	good := Investigation{
		Answer:                "The ISP-A transit segment is degrading checkout for the branch-1 cohort.",
		Confidence:            0.8,
		SupportingEvidenceIDs: []string{packet.EvidenceIDs[0]},
		Hypotheses:            []InvestigationHypothesis{{ID: packet.Hypotheses[0].ID, Cause: "transit", Confidence: 0.8}},
	}
	if _, err := ValidateInvestigation(good, packet); err != nil {
		t.Fatalf("a well-formed answer was rejected: %v", err)
	}

	invented := good
	invented.SupportingEvidenceIDs = []string{"ev-that-never-existed"}
	if _, err := ValidateInvestigation(invented, packet); err == nil {
		t.Fatal("an answer citing evidence it was never given was accepted")
	}

	inventedHyp := good
	inventedHyp.Hypotheses = []InvestigationHypothesis{{ID: "hyp-made-up", Cause: "x", Confidence: 0.5}}
	if _, err := ValidateInvestigation(inventedHyp, packet); err == nil {
		t.Fatal("an answer citing a hypothesis it was never given was accepted")
	}

	overreach := good
	overreach.Hypotheses = []InvestigationHypothesis{{ID: packet.Hypotheses[0].ID, Cause: "transit", Confidence: 0.99, State: StateConfirmed}}
	out, err := ValidateInvestigation(overreach, packet)
	if err != nil {
		t.Fatal(err)
	}
	if out.Hypotheses[0].State == StateConfirmed {
		t.Fatal("the model was allowed to mark a cause confirmed; only the evidence engine may")
	}
	if !out.Downgraded {
		t.Fatal("the downgrade was not recorded, so an operator could not see the model overreached")
	}
	if out.Attribution != AttributionLine {
		t.Fatalf("the attribution line was not stamped: %q", out.Attribution)
	}
}

func TestPacketWithholdsWhatMayNotLeaveAndSaysSo(t *testing.T) {
	secret := ev("secret", ModalityActiveProbe, "prober-1", -5*time.Minute)
	secret.DataClass = DataClassPII
	open := ev("open", ModalityRealUser, "rum", -5*time.Minute)
	p := BuildPacket(ExperienceIncident{ID: "exp-1", Evidence: []EvidenceItem{secret, open}}, nil)
	for _, e := range p.Evidence {
		if e.ID == "secret" {
			t.Fatal("a PII-classified item was placed in a model briefing")
		}
	}
	if len(p.Redacted) == 0 {
		t.Fatal("the redaction was silent; an operator must be able to see the briefing was trimmed")
	}
}
