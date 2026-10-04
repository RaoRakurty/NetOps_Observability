// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

import (
	"regexp"
	"sort"
	"strings"
)

// Coverage is the compiler's honesty rule: EVERY content word of the question
// must be explained — by the time phrase, the metric, a target or filter word,
// a number the grammar used, a resolved entity, or the fixed question
// vocabulary below. A word left over means the grammar did not understand
// part of the question, and answering the rest would answer a DIFFERENT
// question — "CPU on <a device you cannot see>" must never become "CPU on
// every device". Leftovers make the result Unparsed (model fallback or a
// clarifying question), carrying the words that were not understood.

// questionVocab is the closed set of words that carry no query meaning of
// their own (they frame the question).
var questionVocab = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`show list display give get see find tell view pull bring up what which who whom how when
		where why is are was were be been being do does did has have had any anything anywhere there it its currently now
		right please me us i we our my the a an of on in at to for from by per with across over during and or vs versus
		all every each happening happened going look looking like status level levels value values numbers trend trending
		graph chart plot report summary overview current can could would you whats what's that's there's lately recently
		so just also then too still again latest recent are ever much many count counts number anyone someone something
		seeing seen hitting had having see-ing been getting affected affecting impacting impacted our site sites locations
		up across between within about around near under past last previous this today yesterday week day days hour hours
		minute minutes min mins h d w m`) {
		questionVocab[w] = true
	}
	for w := range stopword {
		questionVocab[w] = true
	}
}

// eaten tracks which words of the question the grammar explained.
//
// required words (the lead word of a referential phrase: "it", "that", "there")
// are explained ONLY by binding them to a referent — framing vocabulary does
// not cover them — and a leftover one is reported as its whole phrase.
type eaten struct {
	words    map[string]bool
	required map[string]string // lead word → the phrase shown when unbound
	bound    map[string]bool
}

func newEaten() *eaten {
	return &eaten{words: map[string]bool{}, required: map[string]string{}, bound: map[string]bool{}}
}

func (e *eaten) require(word, phrase string) {
	if _, ok := e.required[word]; !ok {
		e.required[word] = phrase
	}
}

func (e *eaten) bind(word string) { e.bound[word] = true }

// phrase marks every word of a phrase explained.
func (e *eaten) phrase(p string) {
	for _, w := range strings.Fields(strings.ToLower(p)) {
		e.words[w] = true
	}
}

// re marks every match of re in text explained, and reports whether it matched.
func (e *eaten) re(re *regexp.Regexp, text string) bool {
	ms := re.FindAllString(text, -1)
	for _, m := range ms {
		e.phrase(m)
	}
	return len(ms) > 0
}

// leftovers returns the content words nothing explained, in order.
func (e *eaten) leftovers(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, w := range strings.Fields(text) {
		if phrase, req := e.required[w]; req && !e.bound[w] {
			if !seen[phrase] {
				seen[phrase] = true
				out = append(out, phrase)
			}
			continue
		}
		if e.words[w] || questionVocab[w] || seen[w] {
			continue
		}
		seen[w] = true
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}
