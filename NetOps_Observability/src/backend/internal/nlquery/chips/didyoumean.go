// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chips

// didyoumean.go — did-you-mean chips (hybrid NLU plan A7, owner decision D2).
//
// When a word was not understood and Iris has candidates for it — a name in
// the caller's own scope one typo away (resolver rung 6b), the start of a
// name (rung 6), or several equally close vocabulary words — the answer
// offers each candidate as a chip instead of "I don't understand". A chip is
// a SERVER-WRITTEN rephrasing of the question with that word replaced; the
// client shows the label and, when picked, asks the rephrased question. It is
// compiled again from scratch in the caller's scope, so a chip can never
// reach anything a typed question could not: an entity candidate is written
// as its canonical id, which resolves only if the caller can see it.

import (
	"regexp"
	"strings"

	"netops/backend/internal/nlquery/compile"
)

// Did-you-mean bounds.
const (
	MaxAsksPerWord = 3
	MaxAsks        = 6
)

// Ask is one did-you-mean chip.
type Ask struct {
	Word     string `json:"word"`
	Label    string `json:"label"`
	Question string `json:"question"`
}

// DidYouMean returns the chips for the suggestions of a compile result over
// the question as asked. Entity candidates are labelled by display (namer
// may be nil: the id is shown) and written into the question as their id.
func DidYouMean(question string, sugg []compile.Suggestion, namer func(entityID string) string) []Ask {
	var out []Ask
	for _, s := range sugg {
		re := wordRe(s.Word)
		if re == nil || !re.MatchString(question) {
			continue // the word is not in the question as typed: nothing to replace
		}
		n := 0
		add := func(label, with string) {
			if n == MaxAsksPerWord || len(out) == MaxAsks || with == "" {
				return
			}
			q := re.ReplaceAllLiteralString(question, with)
			if q == question {
				return
			}
			out = append(out, Ask{Word: s.Word, Label: clip(label, maxLabel), Question: q})
			n++
		}
		for _, r := range s.Refs {
			if !r.NeedsConfirmation {
				continue // a chip only ever confirms a candidate
			}
			label := r.EntityID
			if namer != nil {
				if nm := namer(r.EntityID); nm != "" {
					label = nm
				}
			}
			add(label, r.EntityID)
		}
		for _, w := range s.Words {
			add(w, w)
		}
	}
	return out
}

// wordRe matches the word as a whole, case-insensitively.
func wordRe(w string) *regexp.Regexp {
	w = strings.TrimSpace(w)
	if w == "" || len(w) > maxValue {
		return nil
	}
	return regexp.MustCompile(`(?i)(?:^|\b)` + regexp.QuoteMeta(w) + `(?:\b|$)`)
}
