// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package validate

import "sort"

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
		if d := osaDistance(got, c); d <= limit {
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

// osaDistance is the optimal-string-alignment (restricted Damerau–Levenshtein)
// distance over bytes — inputs are catalog names and short tokens.
func osaDistance(a, b string) int {
	la, lb := len(a), len(b)
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && a[i-1] == b[j-2] && a[i-2] == b[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[la][lb]
}
