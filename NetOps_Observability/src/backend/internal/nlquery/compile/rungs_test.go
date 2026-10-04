// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// rungs_test.go — how the compiler uses the N-C2 remainder rungs: a plural
// topology phrase narrows to EVERY neighbour (same type = OR); a singular one
// with several candidates asks; a neighbour that needs confirmation, a partial
// name and a model suggestion are NEVER applied — the words stay unexplained
// and the question is not answered as if they had been understood.

import (
	"context"
	"testing"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/resolve"
)

type topoWorld struct{}

func (topoWorld) Aliases(context.Context) ([]resolve.Alias, error) {
	return []resolve.Alias{{EntityType: "site", EntityID: "site:dfw-hq", Alias: "dallas"}}, nil
}
func (topoWorld) Inventory(_ context.Context, types []string) ([]resolve.Named, error) {
	var out []resolve.Named
	for _, n := range []resolve.Named{
		{Type: "device", ID: "device:core-1", Names: []string{"core-1"}, Role: "core-switch"},
		{Type: "device", ID: "device:edge-1", Names: []string{"edge-1"}, Role: "router"},
		{Type: "device", ID: "device:edge-2", Names: []string{"edge-2"}, Role: "router"},
		{Type: "device", ID: "device:sw-9", Names: []string{"sw-9"}},
	} {
		if contains(types, n.Type) {
			out = append(out, n)
		}
	}
	return out, nil
}
func (topoWorld) Visible(context.Context, string, string) (bool, error) { return false, nil }
func (w topoWorld) Neighbors(ctx context.Context, id string) ([]resolve.Named, error) {
	inv, _ := w.Inventory(ctx, []string{"device"})
	by := map[string]resolve.Named{}
	for _, n := range inv {
		by[n.ID] = n
	}
	adj := map[string][]string{
		"device:core-1": {"device:edge-1", "device:edge-2"},
		"device:edge-1": {"device:core-1"},
		"device:edge-2": {"device:core-1", "device:sw-9"},
	}
	var out []resolve.Named
	for _, x := range adj[id] {
		out = append(out, by[x])
	}
	return out, nil
}

// alwaysSuggests is a model that suggests a real, visible name for anything.
type alwaysSuggests struct{ calls *int }

func (a alwaysSuggests) SuggestNames(context.Context, string, []string) ([]string, error) {
	*a.calls++
	return []string{"edge-1", "Dallas"}, nil
}

func topoCompiler(sugg resolve.Suggester) Compiler {
	return Compiler{Cat: cat, R: resolve.Resolver{Cat: cat, L: topoWorld{}, Topo: topoWorld{}, Suggest: sugg}}
}

func compileWith(t *testing.T, comp Compiler, q string) Result {
	t.Helper()
	r, err := comp.Compile(context.Background(), q, cx)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPluralTopologyNarrowsToEveryNeighbour(t *testing.T) {
	r := compileWith(t, topoCompiler(nil), "cpu on the routers next to core-1 last hour")
	if r.AST == nil || r.Unparsed {
		t.Fatalf("not compiled: %+v", r)
	}
	want := []ast.EntityRef{{Type: "device", ID: "device:edge-1"}, {Type: "device", ID: "device:edge-2"}}
	if len(r.AST.Refs) != 2 || r.AST.Refs[0] != want[0] || r.AST.Refs[1] != want[1] || r.AST.Target != "device" || r.AST.Metric != "cpu_util_pct" {
		t.Fatalf("routers next to core-1 = %+v", r.AST)
	}
	for _, e := range r.Entities {
		if e.Method != resolve.MethodTopology {
			t.Fatalf("entity provenance lost: %+v", e)
		}
	}
}

func TestSingularTopologyWithTwoCandidatesAsks(t *testing.T) {
	r := compileWith(t, topoCompiler(nil), "cpu on the router next to core-1 last hour")
	if r.AST != nil || len(r.Clarify) != 2 {
		t.Fatalf("one router of two must be asked, got %+v", r)
	}
}

func TestUnconfirmedRungsAreNeverApplied(t *testing.T) {
	calls := 0
	comp := topoCompiler(alwaysSuggests{calls: &calls})
	for _, q := range []string{
		"cpu on the switch next to edge-2 last hour", // sw-9's role is unknown: confirm first
		"cpu on dalas last hour",                     // the model would say "Dallas": never applied
		"cpu on edgy-one last hour",                  // the model would say "edge-1": never applied
		"cpu on cor last hour",                       // a partial name: never applied
	} {
		r := compileWith(t, comp, q)
		if r.AST != nil {
			t.Errorf("%q compiled using an unconfirmed candidate: %+v", q, r.AST)
		}
		if !r.Unparsed || len(r.NotUnderstood) == 0 {
			t.Errorf("%q must be not-understood, with its words listed: %+v", q, r)
		}
		for _, e := range append(r.Entities, r.Clarify...) {
			if e.Method == resolve.MethodModelSuggestion {
				t.Errorf("%q surfaced a model suggestion from the compiler: %+v", q, e)
			}
		}
	}
	if calls == 0 {
		t.Fatal("test is vacuous: the suggester was never consulted")
	}
}
