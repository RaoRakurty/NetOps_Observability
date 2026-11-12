// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

import (
	"testing"

	"netops/backend/internal/nlquery/lex"
)

// The grammar's vocabulary is larger than the router's (catalog aliases, rule
// words), so the audit of correctly spelt near-domain words runs here too:
// none of them is ever "corrected" into a sibling (live 2026-11-12:
// "connected" → "connector").
func TestGrammarNeverRewritesARealWord(t *testing.T) {
	v := Vocabulary(cat)
	for _, w := range lex.NearDomainWords() {
		if fix, ties := v.Correct(w); fix != "" || ties != nil {
			t.Errorf("grammar Correct(%q) = %q %v: a real word must be left as typed", w, fix, ties)
		}
	}
}
