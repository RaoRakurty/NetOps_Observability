// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package noclabel

// confidence.go — the four fixed confidence phrases (owner decision D4,
// 2026-11-11) and the context-story test (decision D1). This is THE Go
// definition: the RCA view's server report, the PDF and Iris all read it, and
// the frontend mirror is rcaPhrases.ts. When one side changes, change the other.
//
// Strongest first:
//
//	Confirmed cause · Likely cause · Possibly because of X · Cause not determined
//
// The level comes from the engine's verdict tier and confidence_label, never
// from the ranking number (a heuristic rank, not a probability).

import "strings"

// ConfidenceLevel is the closed set of NOC confidence levels.
type ConfidenceLevel string

const (
	LevelConfirmed    ConfidenceLevel = "confirmed"
	LevelLikely       ConfidenceLevel = "likely"
	LevelSuspected    ConfidenceLevel = "suspected"
	LevelUndetermined ConfidenceLevel = "undetermined"
)

// The four phrases, verbatim. PhrasePossiblyBecauseOf is followed by the cause.
const (
	PhraseConfirmed         = "Confirmed cause"
	PhraseLikely            = "Likely cause"
	PhrasePossiblyBecauseOf = "Possibly because of"
	PhraseNotDetermined     = "Cause not determined"
)

// LevelFor maps the engine's verdict tier and confidence_label to a level:
// confirmed → confirmed; likely → likely; suspected → suspected; anything
// else (undetermined, empty, unknown words) → undetermined. A confirmed tier
// wins over the label, and a label never upgrades past the tier it came with
// except "likely", which the engine only emits on a suspected tier.
func LevelFor(tier, label string) ConfidenceLevel {
	t := strings.ToLower(strings.TrimSpace(tier))
	l := strings.ToLower(strings.TrimSpace(label))
	switch {
	case t == "confirmed":
		return LevelConfirmed
	case l == "likely":
		return LevelLikely
	case t == "suspected" || l == "suspected":
		return LevelSuspected
	case t == "" && l == "confirmed":
		// a label without a tier (pre-gate blobs) still names the gate result
		return LevelConfirmed
	}
	return LevelUndetermined
}

// LevelForAnalysis maps the RCA report's analysis vocabulary
// (confirmed | probable | suspected | observed | inconclusive) to a level.
func LevelForAnalysis(analysis string) ConfidenceLevel {
	switch strings.ToLower(strings.TrimSpace(analysis)) {
	case "confirmed":
		return LevelConfirmed
	case "probable", "likely":
		return LevelLikely
	case "suspected":
		return LevelSuspected
	}
	return LevelUndetermined
}

// PhraseFor renders a level as its fixed phrase. A suspected level needs the
// cause in NOC words; without one there is nothing to be "possibly because
// of", so it reads "Cause not determined" — never a dangling phrase.
func PhraseFor(level ConfidenceLevel, cause string) string {
	cause = strings.TrimRight(strings.TrimSpace(cause), ".")
	switch level {
	case LevelConfirmed:
		return PhraseConfirmed
	case LevelLikely:
		return PhraseLikely
	case LevelSuspected:
		if cause == "" {
			return PhraseNotDetermined
		}
		return PhrasePossiblyBecauseOf + " " + midSentence(cause)
	}
	return PhraseNotDetermined
}

// ConfidencePhrase is the one-call form: engine tier + label (+ the cause in
// NOC words for the suspected phrase) → the fixed phrase.
func ConfidencePhrase(tier, label, cause string) string {
	return PhraseFor(LevelFor(tier, label), cause)
}

// midSentence lowercases the first letter of a plain sentence-cased first word
// ("The IPsec tunnel…" → "the IPsec tunnel…") and leaves acronyms and proper
// names alone ("BGP peer…", "IPsec…").
func midSentence(s string) string {
	if s == "" {
		return s
	}
	first := s
	if i := strings.IndexAny(s, " \t"); i > 0 {
		first = s[:i]
	}
	if first[0] < 'A' || first[0] > 'Z' {
		return s
	}
	for i := 1; i < len(first); i++ {
		if first[i] >= 'A' && first[i] <= 'Z' {
			return s
		}
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// contextStoryFallbackIDs — the background-story templates persisted BEFORE the
// engine emitted `"context_story": true` on its hypotheses (owner D1). A
// standing posture or exposure finding has no onset and no mechanism, so it is
// background on the device, never the cause. The threat-signal story is NOT
// here: a dated detection with a mechanism may be a cause.
var contextStoryFallbackIDs = map[string]bool{
	"sig.ent.security.exposure-story":        true,
	"sig.ent.security.hardening-drift-story": true,
}

// IsContextStory reports whether a hypothesis is a background story: the
// engine's own flag, or (for objects persisted before the flag existed) one of
// the fallback template ids.
func IsContextStory(id string, flagged bool) bool {
	return flagged || contextStoryFallbackIDs[strings.TrimSpace(id)]
}
