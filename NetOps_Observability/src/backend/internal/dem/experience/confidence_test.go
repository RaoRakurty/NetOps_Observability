package experience

// confidence_test.go — the owner's Phase O backend list, items 2 to 7: what
// evidence does to a verdict.
//
// Each test states the RULE it protects, not just the numbers, because the
// numbers are allowed to be tuned and the rules are not.

import (
	"testing"
	"time"
)

// O-4 / O-5: independence is about DIFFERENT KINDS of instrument from DIFFERENT
// vantages. Repeating one source does not make it two opinions — that is the
// single most common way a dashboard manufactures false certainty.
func TestIndependenceCountsKindsNotCopies(t *testing.T) {
	same := []EvidenceItem{
		ev("a", ModalityActiveProbe, "prober-1", -10*time.Minute),
		ev("b", ModalityActiveProbe, "prober-1", -9*time.Minute),
		ev("c", ModalityActiveProbe, "prober-1", -8*time.Minute),
		ev("d", ModalityActiveProbe, "prober-1", -7*time.Minute),
	}
	ind := AssessIndependence(same)
	if ind.Satisfied() {
		t.Fatalf("four copies of one probe from one vantage satisfied the independence rule: %+v", ind)
	}
	if got := independenceFactor(ind); got != IndependenceSingleClass {
		t.Fatalf("independence factor for one class was %v, want %v", got, IndependenceSingleClass)
	}

	// Two vantages of the SAME modality are two samples, still one opinion.
	twoVantages := append([]EvidenceItem{}, same...)
	twoVantages = append(twoVantages, ev("e", ModalityActiveProbe, "prober-2", -6*time.Minute))
	if AssessIndependence(twoVantages).Satisfied() {
		t.Fatal("two vantages of the same modality satisfied the independence rule")
	}

	// A second MODALITY from a second observer does.
	mixed := append([]EvidenceItem{}, same...)
	mixed = append(mixed, ev("f", ModalityRealUser, "rum", -6*time.Minute))
	ind = AssessIndependence(mixed)
	if !ind.Satisfied() {
		t.Fatalf("a second modality from a second observer did not satisfy the rule: %+v", ind)
	}
	if got := independenceFactor(ind); got != IndependenceTwoClasses {
		t.Fatalf("independence factor for two classes was %v, want %v", got, IndependenceTwoClasses)
	}
}

// O-4: more independent kinds of evidence must RAISE confidence, and the rise
// must come from the independence factor rather than from sheer volume.
func TestIndependentVantagesRaiseConfidence(t *testing.T) {
	h := hyp("h1", CauseTransitDegradation, "AS3356", "wan-isp-a", "ISP A")
	single := []EvidenceItem{
		ev("a", ModalityActiveProbe, "prober-1", -10*time.Minute),
		ev("b", ModalityActiveProbe, "prober-1", -9*time.Minute),
		ev("c", ModalityActiveProbe, "prober-1", -8*time.Minute),
	}
	multi := []EvidenceItem{
		ev("a", ModalityActiveProbe, "prober-1", -10*time.Minute),
		ev("b", ModalityRealUser, "rum", -9*time.Minute),
		ev("c", ModalityControlPlane, "ripestat", -8*time.Minute),
	}
	lo := ComputeConfidence(h, single, nil, testWindow(), testNow)
	hi := ComputeConfidence(h, multi, nil, testWindow(), testNow)
	if !(hi.Score > lo.Score) {
		t.Fatalf("three independent kinds of evidence (%v) did not beat three copies of one (%v)", hi.Score, lo.Score)
	}
	// …and the reason must be legible, not just numeric.
	if factorValue(hi.Factors, "independence") <= factorValue(lo.Factors, "independence") {
		t.Fatalf("the independence factor did not rise: %+v vs %+v", hi.Factors, lo.Factors)
	}
}

// O-2: negative evidence is evidence. A contradicting observation must lower
// confidence — and it must be visible in the decomposition, not folded away.
func TestContradictingEvidenceLowersConfidence(t *testing.T) {
	h := hyp("h1", CauseApplicationRegress, "checkout-api", "app", "application team")
	support := []EvidenceItem{
		ev("a", ModalityActiveProbe, "prober-1", -10*time.Minute),
		ev("b", ModalityRealUser, "rum", -9*time.Minute),
	}
	clean := ComputeConfidence(h, support, nil, testWindow(), testNow)
	withContra := ComputeConfidence(h,
		append(append([]EvidenceItem{}, support...),
			contra("svc", ModalityDeviceTelemetry, "checkout-api", nil, -8*time.Minute)),
		nil, testWindow(), testNow)
	if !(withContra.Score < clean.Score) {
		t.Fatalf("a contradicting observation did not lower confidence: %v → %v", clean.Score, withContra.Score)
	}
	if factorValue(withContra.Factors, "contradiction") >= 1 {
		t.Fatalf("the contradiction factor stayed at 1: %+v", withContra.Factors)
	}
}

// O-3: missing telemetry is DATA. It lowers confidence, and when the missing
// source is one that could have anchored the verdict it BLOCKS confirmation
// outright — silence is never agreement.
func TestMissingTelemetryLowersConfidenceAndBlocksConfirmation(t *testing.T) {
	h := hyp("h1", CauseTransitDegradation, "AS3356", "wan-isp-a", "ISP A")
	items := []EvidenceItem{
		ev("a", ModalityActiveProbe, "prober-1", -10*time.Minute),
		ev("b", ModalityRealUser, "rum", -9*time.Minute),
		ev("c", ModalityControlPlane, "ripestat", -8*time.Minute),
	}
	full := h
	full.Grade(items, nil, testWindow(), testNow)
	if full.State != StateConfirmed {
		t.Fatalf("three independent kinds of evidence with nothing missing did not confirm: %s %v %v",
			full.State, full.Confidence, full.GateReasons)
	}

	gapped := h
	gapped.Grade(items, []MissingEvidence{
		{Source: SourceFlow, IndependenceGroup: ModalityPassiveFlow, Reason: MissingNoData, Required: true},
	}, testWindow(), testNow)
	if gapped.State == StateConfirmed {
		t.Fatal("a REQUIRED missing source did not block confirmation")
	}
	if gapped.Confidence >= full.Confidence {
		t.Fatalf("a missing source did not lower confidence: %v → %v", full.Confidence, gapped.Confidence)
	}
	found := false
	for _, r := range gapped.GateReasons {
		if containsSubstring(r, SourceFlow) {
			found = true
		}
	}
	if !found {
		t.Fatalf("the blocking gate reason did not name the missing source: %v", gapped.GateReasons)
	}
}

// O-6: a change that happened BEFORE the first impact can support a hypothesis…
// O-7: …but temporal proximity ALONE can never confirm one. A change record is
// not a measurement of the experience, so it can corroborate and never anchor.
func TestChangeBeforeEffectSupportsButNeverConfirms(t *testing.T) {
	h := hyp("h1", CauseApplicationRegress, "checkout-api", "app", "application team")
	change := EvidenceItem{
		ID: "chg-1", TenantID: "acme", Kind: KindChange, Entity: "checkout-api",
		Summary: "checkout-api v42 deployed", Stance: StanceSupports,
		IndependenceGroup: ModalityChangeRecord, Observer: "ci",
		Reliability: 0.9, App: "checkout",
		Provenance: prov(SourceConfigDrift, -32*time.Minute), // 2 minutes before first impact
	}
	graded := h
	graded.Grade([]EvidenceItem{change}, nil, testWindow(), testNow)
	if graded.Confidence <= 0 {
		t.Fatal("a change immediately before the impact contributed nothing")
	}
	if graded.State == StateConfirmed {
		t.Fatalf("temporal proximity alone confirmed a cause: %+v", graded)
	}
	reasonNames := false
	for _, r := range graded.GateReasons {
		if containsSubstring(r, "corroborate but never confirm") {
			reasonNames = true
		}
	}
	if !reasonNames {
		t.Fatalf("the gate did not explain why a change record cannot confirm: %v", graded.GateReasons)
	}

	// A change AFTER the first impact is not aligned at all: it cannot have
	// caused what had already started.
	after := change
	after.ID = "chg-2"
	after.Provenance = prov(SourceConfigDrift, -20*time.Minute) // after firstImpact (-30m)
	late := h
	late.Grade([]EvidenceItem{after}, nil, testWindow(), testNow)
	if late.Confidence >= graded.Confidence {
		t.Fatalf("a change AFTER the impact scored at least as well as one before it: %v vs %v",
			late.Confidence, graded.Confidence)
	}
}

// A DECISIVE contradiction rejects a hypothesis however much circumstantial
// support it has: a cause that demonstrably did not act is not a weak cause,
// it is the wrong cause.
func TestDecisiveContradictionRejects(t *testing.T) {
	h := hyp("h1", CauseApplicationRegress, "checkout-api", "app", "application team")
	items := []EvidenceItem{
		ev("a", ModalityActiveProbe, "prober-1", -10*time.Minute),
		ev("b", ModalityRealUser, "rum", -9*time.Minute),
		ev("c", ModalityControlPlane, "ripestat", -8*time.Minute),
	}
	dec := contra("cohort", ModalityRealUser, "rum-b", []string{CauseApplicationRegress}, -7*time.Minute)
	dec.Decisive = true
	dec.Summary = "the same release is healthy for every user on another ISP"
	graded := h
	graded.Grade(append(items, dec), nil, testWindow(), testNow)
	if graded.State != StateRejected {
		t.Fatalf("a decisive contradiction did not reject the hypothesis: %+v", graded)
	}
	if graded.VerdictTier != TierUndetermined {
		t.Fatalf("a rejected hypothesis reported verdict tier %q", graded.VerdictTier)
	}
}

// A rejected hypothesis is RANKED LAST but never dropped: "we considered the
// deploy and ruled it out" is one of the most valuable things we can say.
func TestRejectedHypothesesAreKeptAndRankedLast(t *testing.T) {
	items := []EvidenceItem{
		ev("a", ModalityActiveProbe, "prober-1", -10*time.Minute),
		ev("b", ModalityRealUser, "rum", -9*time.Minute),
	}
	dec := contra("cohort", ModalityRealUser, "rum-b", nil, -7*time.Minute)
	dec.Decisive = true
	dec.ContradictsHypotheses = []string{"h2"}
	ranked := RankHypotheses(
		[]Hypothesis{
			hyp("h2", CauseApplicationRegress, "checkout-api", "app", "application team"),
			hyp("h1", CauseTransitDegradation, "AS3356", "wan-isp-a", "ISP A"),
		},
		append(items, dec), nil, testWindow(), testNow)
	if len(ranked) != 2 {
		t.Fatalf("a hypothesis was dropped: %+v", ranked)
	}
	if ranked[len(ranked)-1].State != StateRejected {
		t.Fatalf("the rejected hypothesis did not sort last: %+v", ranked)
	}
	lead, ok := Leading(ranked)
	if !ok || lead.CauseClass != CauseTransitDegradation {
		t.Fatalf("the leading hypothesis was %+v (ok=%v)", lead, ok)
	}
}

// Freshness decays: an old observation weighs less than a fresh one, and one
// that has missed ten of its own intervals weighs nothing at all.
func TestFreshnessDecaysWithTheSourcesOwnCadence(t *testing.T) {
	item := ev("a", ModalityActiveProbe, "prober-1", 0)
	item.ExpectedIntervalSec = 60
	if got := item.Freshness(testNow); got != 1 {
		t.Fatalf("an observation inside its own interval was not fully fresh: %v", got)
	}
	item.Provenance = prov(SourceSynthetic, -5*time.Minute)
	mid := item.Freshness(testNow)
	if mid <= 0 || mid >= 1 {
		t.Fatalf("an observation five intervals old graded %v, want strictly between 0 and 1", mid)
	}
	item.Provenance = prov(SourceSynthetic, -30*time.Minute)
	if got := item.Freshness(testNow); got != 0 {
		t.Fatalf("an observation thirty intervals old still weighed %v", got)
	}
}

func factorValue(fs []Factor, name string) float64 {
	for _, f := range fs {
		if f.Name == name {
			return f.Value
		}
	}
	return -1
}

func containsSubstring(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
