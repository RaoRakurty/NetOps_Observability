package experience

// confidence.go — THE CONFIDENCE MATHS, in one place, pure, and documented to
// the decimal (Phase J: "document confidence math").
//
// A confidence is a claim about EVIDENCE, not a feeling about a conclusion. It
// is the product of six factors, each in 0..1, each with an operator-readable
// sentence attached, so "0.71" is always decomposable into why:
//
//	confidence = support × independence × alignment × specificity
//	             × contradiction × completeness
//
//	support       how much fresh, reliable observation there is. Weight per
//	              item is reliability × freshness; the sum saturates at
//	              supportSaturation, so a third strong observation adds
//	              nothing a fourth would not. Linear-then-capped rather than
//	              exponential precisely so it can be explained on a tooltip.
//	independence  how many DIFFERENT kinds of instrument, from how many
//	              different vantages, agree. One class = 0.60; two anchor
//	              classes with two observers = 0.85; three or more = 1.00.
//	              Five copies of one source stay at 0.60 — that is the point.
//	alignment     how much of the supporting evidence falls inside the
//	              incident window (a change is aligned only when it precedes
//	              first impact: change-BEFORE-effect, never after).
//	specificity   whether the hypothesis names a concrete cause and a seam,
//	              or waves at a region. "Something upstream is slow" is a
//	              lead, not a diagnosis, and its ceiling says so.
//	contradiction each contradicting item removes a share of what is left;
//	              a DECISIVE contradiction does not merely lower this — it
//	              rejects the hypothesis outright (see Hypothesis.Grade).
//	completeness  every missing expected source costs a fixed slice, floored
//	              so that missing telemetry lowers confidence without ever
//	              pretending the remaining evidence is worthless.
//
// Nothing here reads a clock: `now` is always an argument, so every branch is a
// table test (docs/design/dem-evidence-confidence.md).

import (
	"sort"
	"time"
)

// The constants the maths is made of. They are exported so the API can publish
// them beside a score — a number whose constants are secret is not explainable.
const (
	// SupportSaturation is the summed weight at which support reaches 1.0.
	// Three fully-reliable, perfectly fresh observations saturate it.
	SupportSaturation = 3.0

	// Independence steps.
	IndependenceSingleClass = 0.60
	IndependenceTwoClasses  = 0.85
	IndependenceThreeOrMore = 1.00

	// SpecificityEntityAndSeam names both a cause entity and the seam that
	// owns it; SpecificityEntityOnly names the entity; SpecificityVague names
	// neither and is capped accordingly.
	SpecificityEntityAndSeam = 1.00
	SpecificityEntityOnly    = 0.80
	SpecificityVague         = 0.55

	// ContradictionShare is the fraction of the REMAINING confidence one
	// fully-weighted contradiction removes. Applied multiplicatively per item,
	// floored at ContradictionFloor so a hypothesis with real support never
	// silently vanishes — it is shown, weakened, with its contradictions named.
	ContradictionShare = 0.45
	ContradictionFloor = 0.15

	// MissingEvidenceCost is what one missing expected source costs;
	// MissingEvidenceFloor bounds the total penalty. Missing telemetry must
	// reduce confidence (Phase B rule H) without erasing what WAS measured.
	MissingEvidenceCost  = 0.10
	MissingEvidenceFloor = 0.60

	// ConfidenceFloor mirrors the correlation engine's CONFIDENCE_FLOOR: below
	// it a hypothesis is a CANDIDATE, not a diagnosis.
	ConfidenceFloor = 0.30
	// ConfirmConfidence is the minimum confidence for CONFIRMED. It is
	// necessary, never sufficient — the independence gate still rules.
	ConfirmConfidence = 0.70
)

// Factor is one named multiplier with its reason.
type Factor struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Reason string  `json:"reason"`
}

// Confidence is the decomposed result. Score is the product of every factor.
type Confidence struct {
	Score   float64  `json:"score"`
	Factors []Factor `json:"factors"`
	// SupportWeight is the raw summed evidence weight behind Support — the
	// honesty anchor, the way Component.Samples is in internal/dem.
	SupportWeight float64 `json:"support_weight"`
}

// ComputeConfidence grades one hypothesis's evidence at time now.
//
// items must be the evidence ALREADY filtered to this hypothesis (supporting
// and contradicting); neutral items are ignored by weight and are the caller's
// context, not the scorer's input.
func ComputeConfidence(h Hypothesis, items []EvidenceItem, missing []MissingEvidence, window Window, now time.Time) Confidence {
	var supportW, contraW float64
	aligned, alignable := 0.0, 0.0
	for _, it := range items {
		w := it.Weight(now)
		switch it.Stance {
		case StanceSupports:
			supportW += w
			alignable += w
			if window.Aligns(it, h.FirstImpactAt) {
				aligned += w
			}
		case StanceContradicts:
			contraW += w
		}
	}

	support := clamp01(supportW / SupportSaturation)
	ind := AssessIndependence(items)
	independence := independenceFactor(ind)
	alignment := 1.0
	alignReason := "no supporting evidence to place in time"
	if alignable > 0 {
		alignment = clamp01(aligned / alignable)
		alignReason = "share of supporting evidence that falls inside the incident window (a change counts only when it precedes first impact)"
	}
	spec := specificityFactor(h)
	contra := contradictionFactor(items, now)
	complete := completenessFactor(missing)

	score := support * independence * alignment * spec.Value * contra.Value * complete.Value
	return Confidence{
		Score:         round2(clamp01(score)),
		SupportWeight: round2(supportW),
		Factors: []Factor{
			{Name: "support", Value: round2(support), Reason: supportReason(supportW)},
			{Name: "independence", Value: round2(independence), Reason: independenceReason(ind)},
			{Name: "alignment", Value: round2(alignment), Reason: alignReason},
			spec, contra, complete,
		},
	}
}

func independenceFactor(i Independence) float64 {
	switch {
	case len(i.AnchorModalities) >= 3 && len(i.Observers) >= 2:
		return IndependenceThreeOrMore
	case i.Satisfied():
		return IndependenceTwoClasses
	default:
		return IndependenceSingleClass
	}
}

func independenceReason(i Independence) string {
	if i.Satisfied() {
		return "independent observations from " + joinWords(i.AnchorModalities) +
			" across " + plural(len(i.Observers), "observer", "observers")
	}
	if len(i.Reasons) > 0 {
		return i.Reasons[0]
	}
	return "one modality class observed it"
}

func supportReason(w float64) string {
	switch {
	case w <= 0:
		return "nothing fresh and reliable supports this"
	case w >= SupportSaturation:
		return "as much fresh, reliable observation as this measure counts"
	default:
		return "partial: the fresh, reliable observation behind this is below the point where more would stop adding"
	}
}

func specificityFactor(h Hypothesis) Factor {
	switch {
	case h.CauseEntity != "" && h.Seam != "":
		return Factor{Name: "specificity", Value: SpecificityEntityAndSeam,
			Reason: "names a concrete cause and the seam that owns it"}
	case h.CauseEntity != "":
		return Factor{Name: "specificity", Value: SpecificityEntityOnly,
			Reason: "names a concrete cause but no owning seam, so it cannot be handed to anyone yet"}
	default:
		return Factor{Name: "specificity", Value: SpecificityVague,
			Reason: "names no concrete cause — this is a lead, not a diagnosis"}
	}
}

func contradictionFactor(items []EvidenceItem, now time.Time) Factor {
	f := 1.0
	n := 0
	for _, it := range items {
		if it.Stance != StanceContradicts {
			continue
		}
		n++
		f *= 1 - ContradictionShare*it.Weight(now)
	}
	if f < ContradictionFloor {
		f = ContradictionFloor
	}
	if n == 0 {
		return Factor{Name: "contradiction", Value: 1, Reason: "nothing measured contradicts it"}
	}
	return Factor{Name: "contradiction", Value: round2(f),
		Reason: plural(n, "observation contradicts", "observations contradict") + " it"}
}

func completenessFactor(missing []MissingEvidence) Factor {
	if len(missing) == 0 {
		return Factor{Name: "completeness", Value: 1, Reason: "every source we expected reported"}
	}
	f := 1 - MissingEvidenceCost*float64(len(missing))
	if f < MissingEvidenceFloor {
		f = MissingEvidenceFloor
	}
	names := make([]string, 0, len(missing))
	for _, m := range missing {
		names = append(names, m.Source)
	}
	sort.Strings(names)
	return Factor{Name: "completeness", Value: round2(f),
		Reason: "expected but absent: " + joinWords(names) + " — missing telemetry is not agreement"}
}
