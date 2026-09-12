// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"regexp"
	"strings"
)

// verify.go — the unsupported-claim detector (HLD Phase 5 / spec §11, §16). A
// DETERMINISTIC (non-LLM) post-check on the model's narrative, run before the
// answer is returned. Fabricated grounding — citing an evidence id that doesn't
// exist — is the worst LLM failure (fake authority), so we STRIP it rather than
// trust the model. This is a guardrail in code, not a prompt instruction: the
// model can't talk its way past it. Being deterministic, it's always-on and free
// (no verifier-model call), and it never rejects a genuinely-grounded answer.

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
func verifyNarrative(text string, validIDs, badges, disc []string) (string, []string, []string) {
	vr := VerifyGrounding(text, validIDs)
	if len(vr.Removed) > 0 {
		badges = append(badges, "Verified")
		disc = append(disc, plural(len(vr.Removed), "unsupported reference")+" removed (not in the evidence).")
	}
	return vr.Text, badges, disc
}
