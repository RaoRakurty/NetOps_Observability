// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

import (
	"strings"
	"testing"
	"time"
)

var clsNow = time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)

// vp builds one vantage point's observed path.
func vp(peer string, hops ...uint32) VantagePath { return VantagePath{Peer: peer, Path: hops} }

// healthy is the baseline observation: announced, fully visible, RPKI valid,
// two vantage points agreeing on the expected origin through a declared
// upstream. Every case below perturbs exactly one thing.
func healthy() Observation {
	return Observation{
		Prefix: "193.0.0.0/21", Measured: true,
		Announced: true, AnnouncedKnown: true,
		PeersSeeing: 300, PeersTotal: 320,
		Paths: []VantagePath{
			vp("rrc00-1", 3356, 64500, 64496),
			vp("rrc01-2", 1299, 64500, 64496),
		},
		RPKIState: "valid", RPKIOrigin: "AS64496",
		FetchedAt: clsNow,
	}
}

func policy() PolicyConfig {
	return PolicyConfig{ExpectedOrigins: []uint32{64496}, Upstreams: []uint32{64500}}
}

func TestClassifyHealthyIsNone(t *testing.T) {
	inc := Classify(healthy(), policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassNone {
		t.Fatalf("class=%s (%s), want none", inc.Class, inc.Summary)
	}
	if inc.Severity != SevInfo {
		t.Fatalf("severity=%s, want info", inc.Severity)
	}
}

// The §10 rule: "not measured" is NEVER "measured and fine".
func TestClassifyUnmeasuredIsUnknownNotNone(t *testing.T) {
	obs := Observation{Prefix: "193.0.0.0/21", Measured: false, Error: "upstream 502"}
	inc := Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassUnknown {
		t.Fatalf("class=%s, want unknown", inc.Class)
	}
	if inc.Error == "" || !strings.Contains(inc.Summary, "Not measured") {
		t.Fatalf("an unmeasured prefix must SAY so: %+v", inc)
	}
	if kindForClass(inc.Class) != "" {
		t.Fatal("ClassUnknown must not map to an evidence kind — it would ground a non-event")
	}
}

func TestClassifyOriginChangeNeedsCorroboration(t *testing.T) {
	// ONE collector holding a stale path with a foreign origin: NOT an incident.
	obs := healthy()
	obs.Paths = []VantagePath{
		vp("rrc00-1", 3356, 64500, 64496),
		vp("rrc01-2", 1299, 64500, 64496),
		vp("rrc02-9", 174, 65001), // a single stale vantage point
	}
	inc := Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class == ClassOriginChange {
		t.Fatalf("one vantage point must not assert an origin change: %+v", inc)
	}
	if inc.Shortfall == "" || !strings.Contains(inc.Shortfall, "AS65001") {
		t.Fatalf("the near-miss must be RECORDED, not silently dropped: %q", inc.Shortfall)
	}

	// TWO agreeing vantage points: now it is an incident.
	obs.Paths = append(obs.Paths, vp("rrc03-4", 174, 65001))
	inc = Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassOriginChange {
		t.Fatalf("class=%s, want origin_change", inc.Class)
	}
	if inc.Severity != SevCritical {
		t.Fatalf("severity=%s, want critical", inc.Severity)
	}
	if len(inc.Evidence.Vantages) != 2 {
		t.Fatalf("evidence must NAME the supporting vantage points: %+v", inc.Evidence)
	}
	if len(inc.Evidence.Paths) == 0 {
		t.Fatal("evidence must carry the supporting paths")
	}
}

func TestClassifyLearnsOriginWhenNotDeclaredAndSaysSo(t *testing.T) {
	cfg := PolicyConfig{} // nothing declared
	inc := Classify(healthy(), cfg, NewBogonSet(), clsNow)
	if !inc.LearnedOrigin {
		t.Fatal("with no declared origin the baseline is not declared and must be marked as such")
	}
	if inc.Class != ClassNone {
		t.Fatalf("the per-pass baseline must match the dominant observed origin, got %s", inc.Class)
	}
}

// ── H4: an undeclared baseline must not be reported as a check that passed ──
//
// Review 2026-09-08. With expected_origins undeclared (the shipped default) the
// baseline is re-derived from the CURRENT observation's dominant origin, and
// nothing persists one between passes. So a fully propagated origin change
// makes the hijacker the baseline in the same pass, the real origin drops below
// MinVantages and is filed as a shortfall, and the verdict was ClassNone with
// "Announced as expected; RPKI clean; visibility normal." That summary claims a
// comparison that never happened.
//
// The honesty fix does NOT change the class — the prefix really is announced,
// really is RPKI clean and really is visible, and inventing an incident out of
// a missing declaration would page people over every default install. What it
// changes is the claim.

// fullyPropagatedHijack is the case the classifier cannot see: AS65001 has won
// every vantage point except one straggler still holding the real origin.
func fullyPropagatedHijack() Observation {
	o := healthy()
	o.Paths = []VantagePath{
		vp("rrc00-1", 174, 65001),
		vp("rrc01-2", 174, 65001),
		vp("rrc02-9", 174, 65001),
		vp("rrc03-4", 3356, 64500, 64496), // the tenant's own origin, outvoted
	}
	return o
}

func TestClassifyUndeclaredBaselineDoesNotClaimAnOriginCheck(t *testing.T) {
	inc := Classify(fullyPropagatedHijack(), PolicyConfig{}, NewBogonSet(), clsNow)

	// The claim, not the class, is the defect.
	if strings.Contains(inc.Summary, "Announced as expected") {
		t.Fatalf("nothing declared an expectation, so the verdict must not say the prefix is announced as expected: %q", inc.Summary)
	}
	if !strings.Contains(inc.Summary, "NOT checked against a declared baseline") {
		t.Fatalf("the verdict must say the origin check did not happen: %q", inc.Summary)
	}
	if inc.BaselineNote == "" {
		t.Fatal("an undeclared baseline must carry the note that says what the check cannot see")
	}
	for _, want := range []string{"re-derived every pass", "MINORITY", "reaches every vantage point", "Declare the expected origin AS"} {
		if !strings.Contains(inc.BaselineNote, want) {
			t.Fatalf("the baseline note must contain %q: %q", want, inc.BaselineNote)
		}
	}
	// It names the baseline it actually used, so the operator can see it is the
	// hijacker's ASN and not their own.
	if !strings.Contains(inc.BaselineNote, "AS65001") {
		t.Fatalf("the note must name the origin it took as the baseline: %q", inc.BaselineNote)
	}
	if !strings.Contains(inc.Evidence.Detail, "re-derived every pass") {
		t.Fatalf("the evidence detail must carry the same limit, not the clean sentence: %q", inc.Evidence.Detail)
	}
}

// The over-correction guard, both directions.
func TestClassifyDeclaredBaselineIsNotHedged(t *testing.T) {
	inc := Classify(healthy(), policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassNone {
		t.Fatalf("class=%s, want none", inc.Class)
	}
	if inc.LearnedOrigin {
		t.Fatal("a declared origin must not be reported as undeclared")
	}
	if inc.BaselineNote != "" {
		t.Fatalf("a declared baseline carries no hedge: %q", inc.BaselineNote)
	}
	if !strings.Contains(inc.Summary, "Announced as expected") {
		t.Fatalf("a real check that passed must still say so plainly: %q", inc.Summary)
	}

	// And the honesty fix must not invent an incident where there is none: an
	// undeclared baseline on a healthy prefix is still class none, still info,
	// and still pages nobody.
	un := Classify(healthy(), PolicyConfig{}, NewBogonSet(), clsNow)
	if un.Class != ClassNone || un.Severity != SevInfo {
		t.Fatalf("a missing declaration is not an incident: class=%s severity=%s", un.Class, un.Severity)
	}
	if kindForClass(un.Class) != "" {
		t.Fatal("a missing declaration must not ground an evidence event")
	}
}

// The note rides along on a real incident too — a corroborated minority origin
// IS detected without a declaration, and the operator must still know the
// baseline it was measured against came from the same observation.
func TestClassifyBaselineNoteRidesOnARealIncident(t *testing.T) {
	obs := healthy()
	obs.Paths = []VantagePath{
		vp("rrc00-1", 3356, 64500, 64496),
		vp("rrc01-2", 1299, 64500, 64496),
		vp("rrc02-9", 174, 65001),
		vp("rrc03-4", 174, 65001),
	}
	inc := Classify(obs, PolicyConfig{}, NewBogonSet(), clsNow)
	if inc.Class != ClassOriginChange {
		t.Fatalf("a corroborated minority origin must still be detected, got %s", inc.Class)
	}
	if inc.BaselineNote == "" {
		t.Fatal("the incident must still say the baseline was not declared")
	}
}

// With no path at all there is no baseline and no origin check. That is an
// absent check, and it must not be reported as a passed one.
func TestClassifyNoPathsMeansNoOriginCheckAndSaysSo(t *testing.T) {
	obs := healthy()
	obs.Paths = nil
	inc := Classify(obs, PolicyConfig{}, NewBogonSet(), clsNow)
	if inc.LearnedOrigin {
		t.Fatal("no path means no baseline was derived at all")
	}
	if !strings.Contains(inc.BaselineNote, "no origin check ran") {
		t.Fatalf("the missing check must be stated: %q", inc.BaselineNote)
	}
}

func TestClassifyRPKIInvalid(t *testing.T) {
	obs := healthy()
	obs.RPKIState, obs.RPKIReason = "invalid", "origin_as"
	inc := Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassRPKIInvalid {
		t.Fatalf("class=%s, want rpki_invalid", inc.Class)
	}
	if !strings.Contains(inc.Evidence.Detail, "stale ROA") {
		t.Fatalf("the RPKI detail must not assert a hijack: %q", inc.Evidence.Detail)
	}
	// An "unavailable" verdict is NOT an invalid one.
	obs.RPKIState = "unavailable"
	if got := Classify(obs, policy(), NewBogonSet(), clsNow); got.Class == ClassRPKIInvalid {
		t.Fatal("an unavailable RPKI lookup must never be rendered as invalid")
	}
}

func TestClassifyVisibilityLoss(t *testing.T) {
	obs := healthy()
	obs.PeersSeeing, obs.PeersTotal = 40, 320 // 12.5%
	inc := Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassVisibilityLoss {
		t.Fatalf("class=%s, want visibility_loss", inc.Class)
	}
	if inc.Evidence.PeersSeeing != 40 || inc.Evidence.PeersTotal != 320 {
		t.Fatalf("the measured fraction must ride in the evidence: %+v", inc.Evidence)
	}

	// Not announced at all, with no peer counts, is still a visibility loss.
	gone := Observation{Prefix: "193.0.0.0/21", Measured: true, AnnouncedKnown: true, Announced: false}
	if got := Classify(gone, policy(), NewBogonSet(), clsNow); got.Class != ClassVisibilityLoss {
		t.Fatalf("a withdrawn prefix: class=%s, want visibility_loss", got.Class)
	}

	// A raised threshold makes the same measurement an incident.
	obs = healthy()
	strict := policy()
	strict.MinVisibility = 0.99
	if got := Classify(obs, strict, NewBogonSet(), clsNow); got.Class != ClassVisibilityLoss {
		t.Fatalf("93%% visibility under a 99%% threshold: class=%s", got.Class)
	}
}

func TestClassifyRouteLeakUnexpectedTransit(t *testing.T) {
	obs := healthy()
	// Two vantage points see the prefix reaching the world through AS65010,
	// which the tenant does not buy transit from.
	obs.Paths = []VantagePath{
		vp("rrc00-1", 3356, 65010, 64496),
		vp("rrc01-2", 1299, 65010, 64496),
	}
	inc := Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassRouteLeak {
		t.Fatalf("class=%s, want route_leak (%s)", inc.Class, inc.Summary)
	}
	if !strings.Contains(inc.Summary, "AS65010") {
		t.Fatalf("the leaking AS must be named: %q", inc.Summary)
	}
	if !strings.Contains(inc.Evidence.Detail, "DECLARED upstream set") {
		t.Fatalf("the leak verdict must state what it is derived from: %q", inc.Evidence.Detail)
	}
}

func TestClassifyRouteLeakNeedsCorroborationAndADeclaredSet(t *testing.T) {
	obs := healthy()
	obs.Paths = []VantagePath{
		vp("rrc00-1", 3356, 65010, 64496), // ONE vantage point only
		vp("rrc01-2", 1299, 64500, 64496),
	}
	inc := Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class == ClassRouteLeak {
		t.Fatal("one vantage point must not assert a route leak")
	}
	if !strings.Contains(inc.Shortfall, "AS65010") {
		t.Fatalf("the near-miss must be recorded: %q", inc.Shortfall)
	}

	// With NO declared upstream set the heuristic must not run at all —
	// guessing a transit set would be fabrication.
	noUp := PolicyConfig{ExpectedOrigins: []uint32{64496}}
	obs.Paths = []VantagePath{vp("a", 3356, 65010, 64496), vp("b", 1299, 65010, 64496)}
	if got := Classify(obs, noUp, NewBogonSet(), clsNow); got.Class == ClassRouteLeak {
		t.Fatal("with no declared upstreams there is nothing to call unexpected")
	}
}

func TestClassifyRouteLeakValleyThroughOurOwnTransit(t *testing.T) {
	obs := healthy()
	// Our declared upstream AS64500 appears on the path, but a third party
	// (AS65020) sits between it and us: our transit is carrying the prefix for
	// someone else.
	obs.Paths = []VantagePath{
		vp("rrc00-1", 3356, 64500, 65020, 64496),
		vp("rrc01-2", 1299, 64500, 65020, 64496),
	}
	inc := Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassRouteLeak {
		t.Fatalf("class=%s, want route_leak for the valley signature", inc.Class)
	}
	if !strings.Contains(inc.Evidence.Detail, "valley") {
		t.Fatalf("the valley signature must be named in the evidence: %q", inc.Evidence.Detail)
	}
}

func TestClassifyBogon(t *testing.T) {
	obs := healthy()
	obs.Prefix = "10.1.0.0/16"
	inc := Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassBogon {
		t.Fatalf("class=%s, want bogon", inc.Class)
	}
	if inc.Evidence.Bogon == nil || inc.Evidence.Bogon.Block != "10.0.0.0/8" {
		t.Fatalf("the matched block must be in the evidence: %+v", inc.Evidence.Bogon)
	}
	// A nil bogon set simply does not evaluate the rule (no panic, no verdict).
	if got := Classify(obs, policy(), nil, clsNow); got.Class == ClassBogon {
		t.Fatal("a nil bogon set must not produce a bogon verdict")
	}
}

// The headline class is the WORST one; the others are kept, never discarded.
func TestClassifyRanksWorstFirstAndKeepsTheRest(t *testing.T) {
	obs := healthy()
	obs.RPKIState = "invalid"
	obs.PeersSeeing = 10
	obs.Paths = append(obs.Paths, vp("x", 174, 65001), vp("y", 174, 65001))
	inc := Classify(obs, policy(), NewBogonSet(), clsNow)
	if inc.Class != ClassOriginChange {
		t.Fatalf("headline class=%s, want the worst (origin_change)", inc.Class)
	}
	got := map[IncidentClass]bool{}
	for _, c := range inc.Also {
		got[c] = true
	}
	for _, want := range []IncidentClass{ClassRPKIInvalid, ClassVisibilityLoss} {
		if !got[want] {
			t.Fatalf("class %s fired but was dropped from Also: %+v", want, inc.Also)
		}
	}
}

func TestPolicyThresholdDefaultsAndOverrideInheritance(t *testing.T) {
	p := TenantPolicy{
		Default:  PolicyConfig{MinVisibility: 0.8, MinVantages: 3},
		Prefixes: map[string]PolicyConfig{"193.0.0.0/21": {ExpectedOrigins: []uint32{64496}}},
	}
	got := p.For("193.0.0.0/21")
	if got.MinVisibility != 0.8 || got.MinVantages != 3 {
		t.Fatalf("a per-prefix override must INHERIT unset thresholds, got %+v", got)
	}
	if def := p.For("193.0.16.0/21"); def.MinVisibility != 0.8 {
		t.Fatalf("an unlisted prefix must take the tenant default, got %+v", def)
	}
	empty := TenantPolicy{}
	if d := empty.For("x"); d.MinVisibility != DefaultMinVisibility || d.MinVantages != DefaultMinVantages {
		t.Fatalf("an empty policy must take the shipped defaults, got %+v", d)
	}
}
