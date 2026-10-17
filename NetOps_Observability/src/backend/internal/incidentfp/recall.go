// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package incidentfp

// recall.go — rank candidates and answer honestly.

import (
	"sort"
	"time"
)

// Verdicts (closed).
const (
	VerdictSimilar = "similar_incidents"
	VerdictNone    = "no_similar_incident"
)

// MaxMatches bounds the answer.
const MaxMatches = 5

// Result is the recall answer. Below the threshold Matches is EMPTY — the
// nearest weak candidate is not returned in any form.
type Result struct {
	Verdict    string  `json:"verdict"`
	Matches    []Match `json:"matches"`
	Examined   int     `json:"examined"`
	Incomplete int     `json:"incomplete"` // candidates scored without a chain or symptoms
	Window     string  `json:"window"`
	Note       string  `json:"note"`
	Caveat     string  `json:"caveat"`
}

// Caveat is said with every answer.
const Caveat = "Similar is not the same cause: past incidents are context, never confirmation of this one."

// Rank scores the candidates against the subject.
func Rank(subject Fingerprint, cands []Fingerprint, window string) Result {
	out := Result{Verdict: VerdictNone, Matches: []Match{}, Window: window, Caveat: Caveat}
	for _, c := range cands {
		if c.CorrelationID == "" || c.CorrelationID == subject.CorrelationID {
			continue
		}
		out.Examined++
		if c.Partial() {
			out.Incomplete++
		}
		score, on, diff, gate := Score(subject, c)
		if !gate || score < ThresholdSimilar {
			continue
		}
		strength := "similar"
		if score >= ThresholdStrong {
			strength = "strong"
		}
		out.Matches = append(out.Matches, Match{CorrelationID: c.CorrelationID, Score: round2(score), Strength: strength,
			MatchedOn: on, Differences: diff, OccurredAt: c.OccurredAt, Signature: c.Signature, Partial: c.Partial()})
	}
	sort.SliceStable(out.Matches, func(i, j int) bool {
		if out.Matches[i].Score != out.Matches[j].Score {
			return out.Matches[i].Score > out.Matches[j].Score
		}
		return out.Matches[i].OccurredAt.After(out.Matches[j].OccurredAt) // recency only breaks ties
	})
	if len(out.Matches) > MaxMatches {
		out.Matches = out.Matches[:MaxMatches]
	}
	switch {
	case len(out.Matches) > 0:
		out.Verdict = VerdictSimilar
		out.Note = "Earlier closed incidents that share this one's shape."
	case out.Examined == 0:
		out.Note = "No closed incidents in this window to compare with."
	default:
		out.Note = "Earlier incidents were compared, and none is similar enough to show."
	}
	return out
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }

// Windows (closed).
var windows = map[string]time.Duration{"30d": 30 * 24 * time.Hour, "90d": 90 * 24 * time.Hour, "180d": 180 * 24 * time.Hour, "365d": 365 * 24 * time.Hour}

// DefaultWindow is used when none is given.
const DefaultWindow = "180d"

// WindowFor validates a window name.
func WindowFor(name string) (time.Duration, bool) {
	if name == "" {
		name = DefaultWindow
	}
	d, ok := windows[name]
	return d, ok
}
