// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chips

import (
	"testing"

	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/resolve"
)

func TestDidYouMeanChips(t *testing.T) {
	sugg := []compile.Suggestion{
		{Word: "dalas", Refs: []resolve.Ref{
			{EntityID: "site:dfw-hq", EntityType: "site", NeedsConfirmation: true},
			{EntityID: "site:dal-2", EntityType: "site", NeedsConfirmation: false}, // not a candidate: never a chip
		}},
		{Word: "chanbe", Words: []string{"chance", "change"}},
		{Word: "absent", Words: []string{"x"}}, // not in the question: nothing to replace
	}
	names := map[string]string{"site:dfw-hq": "Dallas HQ"}
	got := DidYouMean("Open incidents at Dalas with any chanbe", sugg, func(id string) string { return names[id] })
	want := []Ask{
		{Word: "dalas", Label: "Dallas HQ", Question: "Open incidents at site:dfw-hq with any chanbe"},
		{Word: "chanbe", Label: "chance", Question: "Open incidents at Dalas with any chance"},
		{Word: "chanbe", Label: "change", Question: "Open incidents at Dalas with any change"},
	}
	if len(got) != len(want) {
		t.Fatalf("asks = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ask %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// No namer: the id is the label. A word is replaced as a whole word only.
	got = DidYouMean("dalas-east and dalas", []compile.Suggestion{{Word: "dalas", Refs: []resolve.Ref{{EntityID: "site:x", NeedsConfirmation: true}}}}, nil)
	if len(got) != 1 || got[0].Label != "site:x" {
		t.Fatalf("no namer: %+v", got)
	}
	// Bounded: at most MaxAsksPerWord per word and MaxAsks overall.
	var many []resolve.Ref
	for _, id := range []string{"site:a", "site:b", "site:c", "site:d"} {
		many = append(many, resolve.Ref{EntityID: id, NeedsConfirmation: true})
	}
	got = DidYouMean("w1 w2 w3", []compile.Suggestion{{Word: "w1", Refs: many}, {Word: "w2", Refs: many}, {Word: "w3", Refs: many}}, nil)
	if len(got) != MaxAsks {
		t.Fatalf("asks = %d, want %d", len(got), MaxAsks)
	}
}
