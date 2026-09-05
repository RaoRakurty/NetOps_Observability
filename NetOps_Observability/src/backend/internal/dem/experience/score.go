package experience

// score.go — THE PUBLISHED EXPERIENCE SCORE (§M.4, the owner's Phase I).
//
// Distinct from internal/dem's per-TARGET verdict, and deliberately so: that
// one answers "was this check healthy"; this one answers "was the EXPERIENCE
// good", over six dimensions, for a subject a business cares about (a journey,
// an application, a site, the tenant).
//
// Four rules, all of them the reason this file exists:
//
//  1. DECOMPOSABLE. A score always carries its dimensions, their weights,
//     their values, and each one's contribution to the CHANGE since the
//     previous score. "86, down from 97, because journey_success fell 5.8
//     points" is the product; "86" alone is a number nobody can act on.
//  2. VERSIONED. Weights are policy DATA with a version, and the version is
//     stored with every score. A weight change must never silently rewrite
//     yesterday's history.
//  3. GATED. A dimension that was NOT MEASURED contributes nothing and its
//     weight is redistributed. Below the evidence minimum the score is NOT
//     RENDERED — "not measured, and here is why" — never 0 and never 100.
//  4. BANDED, and the bands never move: Good ≥ 70, Fair 31–69, Poor ≤ 30.

import (
	"sort"
	"strings"
)

// Dimension names. Closed vocabulary: a policy naming a dimension this package
// does not compute is a policy that silently drops weight, so the loader
// refuses it.
const (
	DimJourneySuccess       = "journey_success"
	DimAvailability         = "availability"
	DimResponsiveness       = "responsiveness"
	DimErrorFreeInteraction = "error_free_interaction"
	DimNetworkQuality       = "network_quality"
	DimUserFriction         = "user_friction"
)

// Dimensions in canonical order — the order the UI renders and the order a
// tie-break falls back to.
var Dimensions = []string{
	DimJourneySuccess, DimAvailability, DimResponsiveness,
	DimErrorFreeInteraction, DimNetworkQuality, DimUserFriction,
}

// ValidDimension reports whether d is one of the six.
func ValidDimension(d string) bool {
	for _, v := range Dimensions {
		if v == d {
			return true
		}
	}
	return false
}

// Bands (§M.4). Fixed, and never inverted.
const (
	BandGood        = "good"
	BandFair        = "fair"
	BandPoor        = "poor"
	BandNotMeasured = "not_measured"

	BandGoodAt = 70.0
	BandPoorAt = 30.0
)

// Band maps a score to its band. Only ever called on a MEASURED score — an
// unmeasured one is BandNotMeasured and never passes through here.
func Band(score float64) string {
	switch {
	case score >= BandGoodAt:
		return BandGood
	case score <= BandPoorAt:
		return BandPoor
	default:
		return BandFair
	}
}

// Aggregation modes. A subject legitimately has one score per observer; which
// one is on screen must always be stated (§2 of the Correlix half).
const (
	AggWorstOf = "worst_of" // triage: the worst observer's view
	AggP95Of   = "p95_of"   // reporting: the 95th percentile of observers
)

// MinMeasuredDimensions is the evidence minimum. Below it the score is not
// rendered: one dimension is a metric, not an experience.
const MinMeasuredDimensions = 2

// Score not-measured reasons.
const (
	ReasonScoreNoDimensions = "no_dimensions_measured"
	ReasonScoreBelowMinimum = "below_evidence_minimum"
	ReasonScoreNoPolicy     = "no_score_policy"
)

// DimensionScore is one scored dimension.
type DimensionScore struct {
	Name string `json:"name"`
	// Measured is the honesty flag; when false, Points/Max/Weight are zero and
	// Reason carries the sentence.
	Measured bool   `json:"measured"`
	Reason   string `json:"reason,omitempty"`
	// Points is 0..100 on this dimension's own scale.
	Points float64 `json:"points"`
	// Weight is the share it carried AFTER redistribution; Max is the points it
	// could have contributed to the composite (weight × 100).
	Weight float64 `json:"weight"`
	Max    float64 `json:"max"`
	// Score is this dimension's contribution to the composite (points × weight).
	Score float64 `json:"score"`
	// DeltaContribution is how many composite points this dimension is
	// responsible for since the previous score. Negative = it pulled the score
	// down. Absent when there is no previous score to compare with.
	DeltaContribution *float64 `json:"delta_contribution,omitempty"`
	// Detail is the operator sentence: "Checkout success fell to 91.6%".
	Detail string `json:"detail,omitempty"`
	// Samples is the observation count behind Points — the honesty anchor.
	Samples int `json:"samples"`
	// EvidenceRef links the dimension to the evidence that produced it, so
	// every dimension is clickable through to what it is made of (§M.4).
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// ExperienceScore is the published, decomposable score for one subject.
type ExperienceScore struct {
	Subject     string `json:"subject"`
	SubjectKind string `json:"subject_kind"` // tenant | app | site | journey
	Window      string `json:"window"`
	AppClass    string `json:"app_class"`
	Aggregation string `json:"aggregation"`

	Measured bool     `json:"measured"`
	Reason   string   `json:"reason,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Score    *float64 `json:"score,omitempty"`
	Band     string   `json:"band"`

	PreviousScore *float64 `json:"previous_score,omitempty"`
	Delta         *float64 `json:"delta,omitempty"`

	Dimensions []DimensionScore `json:"dimensions"`

	// PolicyVersion is stored WITH the score. A score whose weights cannot be
	// reconstructed is not auditable, and an unauditable score is not published.
	PolicyVersion int    `json:"policy_version"`
	PolicyName    string `json:"policy_name"`

	// MeasuredDimensions / DeclaredDimensions expose the gate's arithmetic.
	MeasuredDimensions int `json:"measured_dimensions"`
	DeclaredDimensions int `json:"declared_dimensions"`
}

// DimensionInput is one measured dimension handed to the scorer. Measured=false
// carries only a Reason — there is no way to supply a value for a dimension
// that was not measured, which is the point.
type DimensionInput struct {
	Measured    bool
	Reason      string
	Detail      string
	Points      float64 // 0..100
	Samples     int
	EvidenceRef string
}

// ComputeScore builds the published score for one subject. PURE.
//
// previous may be nil (no prior score); when present, each dimension's
// delta_contribution is its share of the composite change, so "why did it fall"
// is arithmetic rather than narrative.
func ComputeScore(subject, subjectKind, window, aggregation string, policy ScorePolicy,
	appClass string, in map[string]DimensionInput, previous *ExperienceScore) ExperienceScore {

	weights := policy.Weights(appClass)
	out := ExperienceScore{
		Subject: subject, SubjectKind: subjectKind, Window: window,
		AppClass: policy.ResolveClass(appClass), Aggregation: aggregation,
		Band: BandNotMeasured, PolicyVersion: policy.Version, PolicyName: policy.Name,
		Dimensions: make([]DimensionScore, 0, len(Dimensions)),
	}
	if len(weights) == 0 {
		out.Reason = ReasonScoreNoPolicy
		out.Detail = "no scoring policy is loaded for this application class, so no score can be published"
		return out
	}

	total, weightSum := 0.0, 0.0
	for _, name := range Dimensions {
		w, declared := weights[name]
		if !declared {
			continue
		}
		out.DeclaredDimensions++
		ds := DimensionScore{Name: name, Max: round2(w * 100)}
		d, has := in[name]
		switch {
		case !has:
			ds.Reason = ReasonScoreNoDimensions
			ds.Detail = "nothing produced this dimension in this window"
		case !d.Measured:
			ds.Reason = d.Reason
			ds.Detail = d.Detail
		default:
			ds.Measured = true
			ds.Points = round2(clamp100(d.Points))
			ds.Samples = d.Samples
			ds.Detail = d.Detail
			ds.EvidenceRef = d.EvidenceRef
			total += ds.Points * w
			weightSum += w
			out.MeasuredDimensions++
		}
		out.Dimensions = append(out.Dimensions, ds)
	}

	if out.MeasuredDimensions < MinMeasuredDimensions {
		out.Reason = ReasonScoreBelowMinimum
		out.Detail = "fewer than " + plural(MinMeasuredDimensions, "dimension was", "dimensions were") +
			" measured in this window, so no experience score is published — this is an absent result, not a good or a bad one"
		return out
	}

	// Redistribute: each measured dimension's weight becomes its share of the
	// weight that was actually available.
	score := round2(total / weightSum)
	out.Measured = true
	out.Score = &score
	out.Band = Band(score)
	for i := range out.Dimensions {
		d := &out.Dimensions[i]
		if !d.Measured {
			continue
		}
		w := weights[d.Name] / weightSum
		d.Weight = round2(w)
		d.Max = round2(w * 100)
		d.Score = round2(d.Points * w)
	}

	if previous != nil && previous.Measured && previous.Score != nil {
		prev := *previous.Score
		delta := round2(score - prev)
		out.PreviousScore, out.Delta = &prev, &delta
		prevByName := map[string]DimensionScore{}
		for _, d := range previous.Dimensions {
			prevByName[d.Name] = d
		}
		for i := range out.Dimensions {
			d := &out.Dimensions[i]
			p, ok := prevByName[d.Name]
			if !ok || !p.Measured || !d.Measured {
				continue
			}
			// The dimension's contribution to the CHANGE is the change in its
			// own weighted contribution. Summed over dimensions this is the
			// composite delta whenever the weight set did not move — and when
			// it did, the difference is visible instead of hidden.
			c := round2(d.Score - p.Score)
			d.DeltaContribution = &c
		}
	}
	return out
}

// ScorePolicy is the versioned weight set (§M.4). Weights are per application
// CLASS, because a real-time class and a thick client do not share a definition
// of "responsive".
type ScorePolicy struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	// Classes maps an application class to its dimension weights. The class
	// "default" is required and is used for any class not named.
	Classes map[string]map[string]float64 `json:"classes"`
	// Source records where the policy came from — "embedded" or a file path —
	// so an operator can tell a shipped policy from an overridden one.
	Source string `json:"source"`
}

// DefaultAppClass is the class applied when none is declared.
const DefaultAppClass = "default"

// ResolveClass returns the class whose weights will actually be used.
func (p ScorePolicy) ResolveClass(class string) string {
	c := labelSafe(strings.ToLower(class))
	if _, ok := p.Classes[c]; ok && c != "" {
		return c
	}
	return DefaultAppClass
}

// Weights returns the weight set for a class, falling back to "default".
func (p ScorePolicy) Weights(class string) map[string]float64 {
	if w, ok := p.Classes[p.ResolveClass(class)]; ok {
		return w
	}
	return nil
}

// ClassNames lists the declared classes, sorted.
func (p ScorePolicy) ClassNames() []string {
	out := make([]string, 0, len(p.Classes))
	for k := range p.Classes {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clamp100(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 100:
		return 100
	default:
		return v
	}
}
