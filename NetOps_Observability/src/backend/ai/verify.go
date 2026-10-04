// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"regexp"
	"strings"
)

// verify.go — the DETERMINISTIC (non-LLM) post-checks on the model's
// narrative, run before the answer is returned. Guardrails in code, not prompt
// instructions: the model can't talk its way past them, they're always-on and
// free (no verifier-model call), and neither one rejects an honest answer.
//
// Two checks live here:
//
//	VerifyGrounding (HLD Phase 5 / spec §11, §16) — fabricated grounding, i.e.
//	citing an evidence id that doesn't exist, is the worst LLM failure (fake
//	authority), so we STRIP it rather than trust the model.
//
//	enforceVerdictHonesty — the engine, not the model, decides whether a cause
//	is established. On a non-confirmed verdict the structured fields already
//	read "Undetermined" / "Not established" (quality.go), but Answer.Text is
//	model prose, and nothing stopped it from opening with "The root cause is a
//	BGP session reset on core-1". This check removes a sentence that asserts an
//	established cause under a verdict that has not established one, and
//	DISCLOSES the removal the way the citation strip does.

var (
	// A bracketed reference the model emitted, e.g. "[problem:abc]" / "[log:os:1]".
	reBracketRef = regexp.MustCompile(`\[([^\]]{1,160})\]`)
	// Cleanup of artifacts left after removing a reference.
	reDoubleSpace   = regexp.MustCompile(`[ \t]{2,}`)
	reSpaceBeforeP  = regexp.MustCompile(`\s+([.,;:!?])`)
	reSpaceBeforePr = regexp.MustCompile(`([([])\s+`)
)

// VerifyResult is the grounding-check outcome for a model narrative.
type VerifyResult struct {
	Text    string   // the cleaned narrative (fabricated references removed)
	Removed []string // the invented reference ids that were stripped (for audit)
}

// VerifyGrounding removes bracketed references the model INVENTED — tokens that
// look like an evidence citation (a "kind:detail" id) but aren't in the provided
// valid set. Legitimate ids and non-citation brackets (e.g. "[1]", "[note]") are
// left untouched, so a well-grounded answer is unchanged. Case-insensitive on ids.
func VerifyGrounding(text string, validIDs []string) VerifyResult {
	res := VerifyResult{Text: text}
	if strings.TrimSpace(text) == "" {
		return res
	}
	valid := make(map[string]bool, len(validIDs))
	for _, id := range validIDs {
		if s := strings.ToLower(strings.TrimSpace(id)); s != "" {
			valid[s] = true
		}
	}
	cleaned := reBracketRef.ReplaceAllStringFunc(text, func(m string) string {
		inner := strings.TrimSpace(m[1 : len(m)-1]) // drop the surrounding [ ]
		low := strings.ToLower(inner)
		// Only judge tokens shaped like an evidence citation id (kind:detail); a
		// bracket without a colon isn't a citation we vouch for, so leave it.
		if !strings.Contains(low, ":") {
			return m
		}
		if valid[low] {
			return m // real citation — keep it
		}
		res.Removed = append(res.Removed, inner) // fabricated — strip it
		return ""
	})
	if len(res.Removed) > 0 {
		cleaned = tidyAfterStrip(cleaned)
	}
	res.Text = strings.TrimSpace(cleaned)
	return res
}

// tidyAfterStrip cleans the whitespace/punctuation artifacts a removed "[id]"
// leaves behind ("loss . Next" → "loss. Next").
func tidyAfterStrip(s string) string {
	s = reSpaceBeforePr.ReplaceAllString(s, "$1")
	s = reSpaceBeforeP.ReplaceAllString(s, "$1")
	s = reDoubleSpace.ReplaceAllString(s, " ")
	return s
}

// bundleCitationIDs is the set of valid citation ids the model was given, used to
// verify the ids it cited actually exist.
func bundleCitationIDs(bundle []EvidenceItem) []string {
	out := make([]string, 0, len(bundle))
	for _, ev := range bundle {
		out = append(out, ev.CitationID)
	}
	return out
}

// citationRefIDs is the set of valid ids from a Citation slice (current-state /
// module answers keep Citations, not the raw bundle).
func citationRefIDs(cites []Citation) []string {
	out := make([]string, 0, len(cites))
	for _, c := range cites {
		out = append(out, c.ID)
	}
	return out
}

// verifyNarrative runs the grounding check and returns the cleaned text plus a
// badge/disclaimer when it stripped anything — so the operator sees the answer
// was verified and knows an unsupported reference was removed (transparency).
//
// It is a METHOD so that a firing can also be COUNTED (score.go). The count is
// the scorecard's unsupported-claim numerator, and it is raised here rather
// than at the four call sites for the same reason Ask wraps ask: one place to
// observe means no path can be instrumented and another forgotten. What crosses
// the seam is a name from a closed vocabulary and a COUNT — never the stripped
// text, which is untrusted model output.
func (o *Orchestrator) verifyNarrative(text string, validIDs, badges, disc []string) (string, []string, []string) {
	vr := VerifyGrounding(text, validIDs)
	if len(vr.Removed) > 0 {
		badges = append(badges, "Verified")
		disc = append(disc, plural(len(vr.Removed), "unsupported reference")+" removed (not in the evidence).")
		o.observeGuard(GuardFabricatedCitation, len(vr.Removed))
	}
	return vr.Text, badges, disc
}

// ---- overclaim post-check ----------------------------------------------------

var (
	// certaintyMarkers is a SMALL CLOSED vocabulary of phrases that assert an
	// established cause. It is deliberately closed rather than clever: a
	// guardrail that fires on prose nobody can predict would be untestable, and
	// this set is exactly what AgentDoctrine's WORDING contract already forbids
	// ("Never: certainly, definitely, root cause found, proven") plus the two
	// constructions the review actually observed. Growing it is a code change
	// with a test, never a regex that guesses.
	certaintyMarkers = []*regexp.Regexp{
		regexp.MustCompile(`\broot cause (?:is|was|are|were)\b`),
		regexp.MustCompile(`\broot cause (?:has been |had been |was |is |been )?(?:identified|determined|found|established|isolated)\b`),
		regexp.MustCompile(`\b(?:is|was|are|were|been|being) caused by\b`),
		regexp.MustCompile(`\bthe cause (?:is|was)\b`),
		regexp.MustCompile(`\bconfirm(?:ed|s)\b`),
		regexp.MustCompile(`\bdefinitely\b`),
		regexp.MustCompile(`\bcertainly\b`),
		regexp.MustCompile(`\bproven\b`),
	}

	// certaintyHedges exempt a sentence that already says it is NOT established
	// — "not confirmed", "possibly caused by X", "may be caused by X". These are
	// the words the RCA report itself uses when it hedges
	// (internal/rca/rca_report_wording.go: "possibly because of X (unconfirmed
	// best hypothesis)"), so a narrative written that way must survive intact.
	//
	// "likely" is NOT a hedge here. It is a CONFIDENCE label in the NOC voice
	// contract, and "likely caused by X" still names a cause the engine did not
	// establish — which is the exact sentence this check exists to catch.
	certaintyHedges = regexp.MustCompile(`\b(?:not|never|no|none|nothing|yet|cannot|unconfirmed|unproven|unclear|unknown|undetermined|possibly|possible|perhaps|may|might|could|appear|appears|seem|seems|suspect|suspected|hypothesis)\b|n't`)

	// Sentence split: a terminator followed by whitespace or end of text.
	reSentenceEnd = regexp.MustCompile(`[.!?]+(?:\s+|$)`)
)

// overclaims reports whether ONE sentence asserts an established cause without
// hedging it. Case-insensitive; the hedge exemption is scoped to the same
// sentence so "X is confirmed" in one sentence is not excused by "possibly" in
// another.
//
// The test reads the PROSE: bracketed citation ids are stripped first, because
// an id such as "hypothesis:ab12:0" contains the hedge word "hypothesis" and
// would otherwise exempt every overclaim that cites the engine's own evidence.
func overclaims(sentence string) bool {
	low := strings.ToLower(stripCitations(sentence))
	if certaintyHedges.MatchString(low) {
		return false
	}
	for _, re := range certaintyMarkers {
		if re.MatchString(low) {
			return true
		}
	}
	return false
}

// splitSentences breaks a narrative into sentences, keeping each terminator and
// its trailing space with the sentence it ends, so re-joining what survives
// reproduces the original prose exactly.
func splitSentences(text string) []string {
	locs := reSentenceEnd.FindAllStringIndex(text, -1)
	out := make([]string, 0, len(locs)+1)
	prev := 0
	for _, loc := range locs {
		out = append(out, text[prev:loc[1]])
		prev = loc[1]
	}
	if prev < len(text) {
		out = append(out, text[prev:])
	}
	return out
}

// enforceVerdictHonesty removes sentences that assert an established cause when
// the ENGINE's verdict has not established one, and discloses what it did.
//
// A confirmed verdict passes through untouched — the engine did the work, so
// the narrative may say so. Otherwise each sentence is judged on its own; the
// ones that overclaim are dropped, and if nothing usable survives the caller's
// deterministic evidence-only summary takes over (an honest short answer beats
// a confident wrong one). The badge + disclaimer mirror the citation strip:
// the operator is told the answer was changed and why, never silently handed a
// shortened one.
func enforceVerdictHonesty(text, verdict, fallback string, badges, disc []string) (string, []string, []string) {
	out, badges, disc, _ := verdictHonesty(text, verdict, fallback, badges, disc)
	return out, badges, disc
}

// enforceVerdictHonesty is the orchestrator's form of the gate: identical
// behaviour, plus one scorecard observation when it fires, so the uncertain-
// claim guard is counted exactly where it acts (score.go).
func (o *Orchestrator) enforceVerdictHonesty(text, verdict, fallback string, badges, disc []string) (string, []string, []string) {
	out, badges, disc, removed := verdictHonesty(text, verdict, fallback, badges, disc)
	if removed > 0 {
		o.observeGuard(GuardUncertainClaim, removed)
	}
	return out, badges, disc
}

// verdictHonesty is the gate's body; removed is how many overclaiming
// sentences it dropped (0 = it did not fire).
func verdictHonesty(text, verdict, fallback string, badges, disc []string) (string, []string, []string, int) {
	if strings.EqualFold(strings.TrimSpace(verdict), "confirmed") || strings.TrimSpace(text) == "" {
		return text, badges, disc, 0
	}
	kept := make([]string, 0, 8)
	removed := 0
	for _, s := range splitSentences(text) {
		if strings.TrimSpace(s) != "" && overclaims(s) {
			removed++
			continue
		}
		kept = append(kept, s)
	}
	if removed == 0 {
		return text, badges, disc, 0
	}
	out := strings.TrimSpace(strings.Join(kept, ""))
	note := plural(removed, "sentence") + " claiming an established cause was removed — Correlix has not identified a root cause for this incident (status: " +
		StatusLabel(verdict) + ")."
	if len(out) < 40 { // nothing usable left — fall back to the evidence-only summary
		out = strings.TrimSpace(fallback)
		note = "The AI narrative claimed a cause Correlix has not established (status: " + StatusLabel(verdict) +
			"), so it was replaced with the evidence-only summary."
	}
	return out, append(badges, "Verified"), append(disc, note), removed
}
