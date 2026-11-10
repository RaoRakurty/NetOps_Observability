// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package validate

import (
	"sort"

	"netops/backend/internal/nlquery/lex"
)

// suggest returns up to 3 candidates within a Damerau–Levenshtein distance of
// max(2, len/4) of got — preferred candidates first, then by distance, then
// lexically, so the output is deterministic.
func suggest(got string, candidates []string, preferred map[string]bool) []string {
	limit := len(got) / 4
	if limit < 2 {
		limit = 2
	}
	type cand struct {
		s    string
		d    int
		pref bool
	}
	var cs []cand
	seen := map[string]bool{}
	for _, c := range candidates {
		if seen[c] {
			continue
		}
		seen[c] = true
		if d := lex.Distance(got, c); d <= limit {
			cs = append(cs, cand{c, d, preferred[c]})
		}
	}
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].pref != cs[j].pref {
			return cs[i].pref
		}
		if cs[i].d != cs[j].d {
			return cs[i].d < cs[j].d
		}
		return cs[i].s < cs[j].s
	})
	var out []string
	for i := 0; i < len(cs) && i < 3; i++ {
		out = append(out, cs[i].s)
	}
	return out
}
