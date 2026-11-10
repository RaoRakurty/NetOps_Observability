// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package resolve

import (
	"context"
	"testing"
)

// Rung 6b: a misspelt name the caller can see is OFFERED — confidence below
// every deciding rung, NeedsConfirmation, method fuzzy_name — never used.
func TestFuzzyNameNeedsConfirmation(t *testing.T) {
	rv := resolverFor(tenantA())
	for _, typo := range []string{"dalas", "Dallsa", "salesfroce"} {
		res := mustResolve(t, rv, typo, nil)
		if len(res.Refs) == 0 {
			t.Fatalf("%q: no candidate", typo)
		}
		for _, ref := range res.Refs {
			if ref.Method != MethodFuzzyName || !ref.NeedsConfirmation || ref.Confidence != confFuzzy || ref.Confidence >= confPartial {
				t.Fatalf("%q: a fuzzy candidate must be confirm-only: %+v", typo, ref)
			}
		}
	}
	if ids(mustResolve(t, rv, "dalas", nil)) != "site:dfw-hq" {
		t.Error("dalas must offer Dallas")
	}
}

// The guards: short keys, keys with a digit, a difference in a short word,
// two misspelt words, vocabulary words and names that are too far are never
// fuzzed; an exact name still decides at rung 3.
func TestFuzzyNameGuards(t *testing.T) {
	rv := resolverFor(tenantA())
	for _, text := range []string{
		"dfw",     // too short (< 5)
		"edge-3",  // a digit: a different device, not a typo of edge-1
		"edge3",   // same, squashed
		"latency", // a catalog word, not a name
		"dxllxs",  // two edits on a 6-character key
		"xallas",  // a different first letter counts double
	} {
		for _, ref := range mustResolve(t, rv, text, nil).Refs {
			if ref.Method == MethodFuzzyName {
				t.Errorf("%q must not be fuzzed: %+v", text, ref)
			}
		}
	}
	w := tenantA()
	w.inv = append(w.inv, Named{Type: "device", ID: "device:core-a", Names: []string{"core-a"}},
		Named{Type: "site", ID: "site:north-plant", Names: []string{"North Plant"}})
	for _, text := range []string{"core-b", "nort plnt"} { // a short word / two words differ
		for _, ref := range mustResolve(t, resolverFor(w), text, nil).Refs {
			if ref.Method == MethodFuzzyName {
				t.Errorf("%q must not be fuzzed: %+v", text, ref)
			}
		}
	}
	if res := mustResolve(t, resolverFor(w), "nort plant", nil); len(res.Refs) != 1 || res.Refs[0].EntityID != "site:north-plant" {
		t.Errorf("one misspelt word of a two-word name is offered: %+v", res)
	}
	if res := mustResolve(t, rv, "edge-1", nil); res.Refs[0].Method != MethodInventoryName {
		t.Errorf("an exact name decides at rung 3: %+v", res)
	}
}

// At most MaxSuggestions candidates, closest first.
func TestFuzzyNameCapsCandidates(t *testing.T) {
	w := tenantA()
	for _, n := range []string{"kearny", "kearns", "kearne", "kearnd", "kearnt"} {
		w.inv = append(w.inv, Named{Type: "site", ID: "site:" + n, Names: []string{n}})
	}
	res := mustResolve(t, resolverFor(w), "kearnx", []string{"site"})
	if len(res.Refs) == 0 || len(res.Refs) > MaxSuggestions {
		t.Fatalf("candidates = %d, want 1..%d", len(res.Refs), MaxSuggestions)
	}
}

// §3a: the candidate set is the caller's OWN aliases and inventory. A
// near-identical name that exists only in another tenant is never offered —
// not as a candidate, not under any rung — and the answer is the same as for a
// name that exists nowhere.
func TestFuzzyNameNeverCrossesTenants(t *testing.T) {
	w := tenantA()
	w.inv = []Named{{Type: "site", ID: "site:aus-hq", Names: []string{"Austin HQ"}}}
	w.aliases = nil
	w.foreign = append(w.foreign, Named{Type: "site", ID: "site:gx-dallas", Names: []string{"Dallas"}})
	rv := resolverFor(w)
	got := mustResolve(t, rv, "dalas", nil)
	if len(got.Refs) != 0 {
		t.Fatalf("a name only another tenant has must never be offered: %+v", got)
	}
	none := mustResolve(t, rv, "zzqqx", nil)
	if len(none.Refs) != len(got.Refs) || none.Ambiguous != got.Ambiguous {
		t.Fatal("foreign must answer exactly like missing")
	}
}

// An alias table that cannot be read surfaces as an error from the
// deterministic rungs; the fuzzy rung never turns it into "no candidates".
func TestFuzzyNameAliasErrorSurfaces(t *testing.T) {
	rv := Resolver{Cat: r.Cat, L: aliasErr{tenantA()}}
	if _, err := rv.Resolve(context.Background(), "dalas", nil); err == nil {
		t.Fatal("an alias failure must surface")
	}
}

type aliasErr struct{ world }

func (aliasErr) Aliases(context.Context) ([]Alias, error) { return nil, errAliases }

var errAliases = errorString("alias table unavailable")

type errorString string

func (e errorString) Error() string { return string(e) }
