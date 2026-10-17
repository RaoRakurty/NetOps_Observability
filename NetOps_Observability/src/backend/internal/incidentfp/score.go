// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package incidentfp

// score.go — how alike two incidents are, in [0,1], and why.
//
// Weights (they sum to 1; a test enforces it):
//
//	signature   .25  same engine hypothesis template
//	chain       .20  LCS of the causal-chain kinds / the longer chain
//	entities    .20  same root device = 1; else Jaccard(devices ∪ interfaces);
//	                 same site only = .5
//	seam        .15  same seam id = 1; else same seam type AND provider class = .5
//	symptoms    .10  Jaccard
//	path        .07  Jaccard
//	domain      .03  same owner domain
//
// HARD GATE: at least one of — same signature, chain LCS ≥ .5, same root
// device. Domain or provider overlap alone never makes a match.
//
// THRESHOLDS: Similar ≥ 0.55, Strong ≥ 0.75. Worked examples (pinned by test):
//
//	signature + provider class + domain           = .25+.075+.03 = .355 → not similar
//	signature + same root device + same seam      = .25+.20+.15  = .60  → similar
//	signature + chain + root device + seam + symptoms + domain
//	                                              = .25+.20+.20+.15+.10+.03 = .93 → strong

import "time"

const (
	wSignature = 0.25
	wChain     = 0.20
	wEntities  = 0.20
	wSeam      = 0.15
	wSymptoms  = 0.10
	wPath      = 0.07
	wDomain    = 0.03

	ThresholdSimilar = 0.55
	ThresholdStrong  = 0.75
)

// Match is one recalled incident and why it matched.
type Match struct {
	CorrelationID string    `json:"correlation_id"`
	Score         float64   `json:"score"`
	Strength      string    `json:"strength"` // similar | strong
	MatchedOn     []string  `json:"matched_on"`
	Differences   []string  `json:"differences,omitempty"`
	OccurredAt    time.Time `json:"occurred_at"`
	Signature     string    `json:"signature,omitempty"`
	Partial       bool      `json:"partial,omitempty"`
}

func jaccard(a, b []string) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	in := map[string]bool{}
	for _, x := range a {
		in[x] = true
	}
	inter, union := 0, len(a)
	for _, y := range b {
		if in[y] {
			inter++
		} else {
			union++
		}
	}
	if union == 0 {
		return 0
	}
	return float64(inter) / float64(union)
}

func lcsRatio(a, b []string) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	dp := make([][]int, len(a)+1)
	for i := range dp {
		dp[i] = make([]int, len(b)+1)
	}
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			switch {
			case a[i-1] == b[j-1]:
				dp[i][j] = dp[i-1][j-1] + 1
			case dp[i-1][j] >= dp[i][j-1]:
				dp[i][j] = dp[i-1][j]
			default:
				dp[i][j] = dp[i][j-1]
			}
		}
	}
	longer := len(a)
	if len(b) > longer {
		longer = len(b)
	}
	return float64(dp[len(a)][len(b)]) / float64(longer)
}

func first(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}

func overlap(a, b []string) bool { return jaccard(a, b) > 0 }

// Score compares a candidate to the subject. ok=false when the hard gate fails.
func Score(subject, cand Fingerprint) (float64, []string, []string, bool) {
	var s float64
	var on, diff []string
	sameSig := subject.Signature != "" && subject.Signature == cand.Signature
	if sameSig {
		s += wSignature
		on = append(on, "same signature")
	} else if subject.Signature != "" && cand.Signature != "" {
		diff = append(diff, "different signature")
	}
	chain := lcsRatio(subject.ChainKinds, cand.ChainKinds)
	if chain > 0 {
		s += wChain * chain
		on = append(on, "causal chain")
	}
	sameRoot := len(subject.Devices) > 0 && overlap(subject.Devices, cand.Devices) &&
		(first(subject.Devices) == first(cand.Devices) || jaccard(subject.Devices, cand.Devices) == 1)
	switch {
	case sameRoot:
		s += wEntities
		on = append(on, "same device")
	case overlap(append(append([]string{}, subject.Devices...), subject.Interfaces...), append(append([]string{}, cand.Devices...), cand.Interfaces...)):
		s += wEntities * jaccard(append(append([]string{}, subject.Devices...), subject.Interfaces...), append(append([]string{}, cand.Devices...), cand.Interfaces...))
		on = append(on, "shared devices")
	case overlap(subject.Sites, cand.Sites):
		s += wEntities * 0.5
		on = append(on, "same site")
	default:
		if len(subject.Devices) > 0 && len(cand.Devices) > 0 {
			diff = append(diff, "different devices")
		}
	}
	switch {
	case overlap(subject.Seams, cand.Seams):
		s += wSeam
		on = append(on, "same seam")
	case subject.SeamType != "" && subject.SeamType == cand.SeamType && subject.Provider != "" && subject.Provider == cand.Provider:
		s += wSeam * 0.5
		on = append(on, "same seam type and provider class")
	}
	if j := jaccard(subject.SymptomKinds, cand.SymptomKinds); j > 0 {
		s += wSymptoms * j
		on = append(on, "shared symptoms")
	}
	if j := jaccard(subject.Paths, cand.Paths); j > 0 {
		s += wPath * j
		on = append(on, "shared path")
	}
	if subject.OwnerDomain != "" && subject.OwnerDomain == cand.OwnerDomain {
		s += wDomain
		on = append(on, "same domain")
	}
	gate := sameSig || chain >= 0.5 || sameRoot
	if s > 1 {
		s = 1
	}
	return s, on, diff, gate
}
