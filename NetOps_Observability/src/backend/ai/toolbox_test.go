// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// toolbox_test.go — tracker 337 N-A5, one brain / one registry, proven at the
// package level: BuildToolRegistry is the union both paths draw from, every
// tool it can register is reachable by the model (or is on an explicit,
// justified engine-only list), and a policy denial is the same denial on the
// engine path and on the model path.

// allSeamDeps wires EVERY troubleshooting seam, so BuildToolRegistry registers
// everything it ever can. The functions are registration-shaped only.
func allSeamDeps() TroubleshootDeps {
	d := caseDeps()
	d.RCAResult = func(context.Context, Principal, string) (RCAResult, error) {
		return RCAResult{}, ErrNotFound
	}
	d.CompileQuery = func(context.Context, Principal, string) (QueryInterpretation, error) {
		return QueryInterpretation{}, nil
	}
	return d
}

func regNames(r *ToolRegistry) []string {
	n := r.Names()
	sort.Strings(n)
	return n
}

// engineOnlyTools are registered but deliberately carry no model-facing schema,
// so the manifest never offers them: the wireless inventory reads (#128 Phase
// 6) predate the agent loop and stay engine-only until they get an authored
// argument schema. Adding a name here is a deliberate, reviewed decision — a
// tool that silently lacks a schema fails TestEveryRegisteredToolIsModelReachable.
var engineOnlyTools = map[string]bool{
	"get_wireless_ap_inventory": true,
	"get_wireless_controllers":  true,
}

// TestBuildToolRegistryIsTheUnion: the one constructor holds the correlation and
// module reads, every wired Phase-A tool AND search_docs — the set that was
// split across two constructors before N-A5.
func TestBuildToolRegistryIsTheUnion(t *testing.T) {
	ds := newMockDS()
	reg := BuildToolRegistry(ds, allSeamDeps(), LoadDocsIndex())
	got := map[string]bool{}
	for _, n := range reg.Names() {
		got[n] = true
	}
	want := append([]string{"search_docs"}, TroubleshootToolNames()...)
	want = append(want, regNames(Tools(ds))...)
	want = append(want, "get_causal_chain", "get_blast_radius", "get_owner", "get_affected_entities",
		"get_confidence_breakdown", "compile_query", "get_recent_changes", "get_config_diff")
	for _, n := range want {
		if !got[n] {
			t.Errorf("BuildToolRegistry is missing %q — a tool absent from the one registry is absent from BOTH paths", n)
		}
	}

	// Seams still decide: a nil seam registers nothing, and a nil docs index
	// registers no search_docs (unchanged AddTroubleshootTools / AddDocsSearch).
	bare := BuildToolRegistry(ds, TroubleshootDeps{}, nil)
	for _, n := range []string{"search_docs", "get_topology_context", "get_device_state", "run_protocol_diagnostic"} {
		if _, ok := bare.Get(n); ok {
			t.Errorf("%q registered with its seam unwired", n)
		}
	}
}

// TestEveryRegisteredToolIsModelReachable is the drift guard for the agent
// loop's half of "one registry": a tool the engine can run but the model can
// never be offered would quietly re-create two tool surfaces.
func TestEveryRegisteredToolIsModelReachable(t *testing.T) {
	reg := BuildToolRegistry(newMockDS(), allSeamDeps(), LoadDocsIndex())
	for _, n := range regNames(reg) {
		_, declared := toolMetas[n]
		switch {
		case engineOnlyTools[n] && declared:
			t.Errorf("%q now has a schema — drop it from engineOnlyTools", n)
		case !engineOnlyTools[n] && !declared:
			t.Errorf("%q is registered but has no toolMetas entry: the engine can run it, the model can never be offered it", n)
		}
	}
	// And every schema names a tool the registry can actually hold.
	held := map[string]bool{}
	for _, n := range reg.Names() {
		held[n] = true
	}
	for n := range toolMetas {
		if !held[n] {
			t.Errorf("toolMetas declares %q but no seam registers it", n)
		}
	}
}

func TestToolboxAuthorizeFailsClosed(t *testing.T) {
	p := opsA()
	if _, d, ok := (Toolbox{}).Authorize("get_problem", p); ok || d.Allow {
		t.Fatalf("an empty toolbox must refuse, got registered=%v %+v", ok, d)
	}
	reg := Tools(newMockDS())
	if _, d, ok := (Toolbox{Registry: reg}).Authorize("get_problem", p); !ok || d.Allow {
		t.Fatalf("no policy engine must deny a registered tool, got registered=%v %+v", ok, d)
	}
	tb := Toolbox{Registry: reg, Policy: NewPolicyEngine(PolicyConfig{}, nil)}
	if _, d, ok := tb.Authorize("rm_rf", p); ok || d.Allow {
		t.Fatalf("an unknown tool must be unregistered and denied, got %v %+v", ok, d)
	}
	tool, d, ok := tb.Authorize("get_problem", p)
	if !ok || !d.Allow || tool == nil || tool.Name() != "get_problem" {
		t.Fatalf("a permitted tool must authorize, got %v %+v", ok, d)
	}
	if _, d, _ := tb.Authorize("get_problem", Principal{Tenant: "t-a"}); d.Allow {
		t.Fatal("a caller without the permission must be denied")
	}
}

// TestPolicyDenialIsTheSameOnBothPaths: one PolicyConfig denial removes the tool
// from what the model may see (gate 1), refuses it at execution (gate 2) and
// stops the grounded engine running it — with the identical reason. The
// baseline run proves the denial is what changed, not the fixture.
func TestPolicyDenialIsTheSameOnBothPaths(t *testing.T) {
	const denied = "get_top_talkers"
	build := func(pol *PolicyEngine) *Orchestrator {
		ds := newMockDS()
		o := newOrch(ds)
		o.Tools = BuildToolRegistry(ds, allSeamDeps(), LoadDocsIndex())
		o.Policy = pol
		return o
	}
	hasCite := func(a Answer, id string) bool {
		for _, c := range a.Citations {
			if c.ID == id {
				return true
			}
		}
		return false
	}
	inManifest := func(o *Orchestrator) bool {
		for _, s := range o.Toolbox().Manifest(opsA()) {
			if s.Name == denied {
				return true
			}
		}
		return false
	}

	// Baseline: allowed on both paths.
	open := build(NewPolicyEngine(PolicyConfig{}, nil))
	if !inManifest(open) {
		t.Fatal("baseline: the model must be offered get_top_talkers")
	}
	ans, err := open.Ask(context.Background(), opsA(), "show me the top talkers", nil)
	if err != nil || !hasCite(ans, "flow:talker:0") {
		t.Fatalf("baseline: the engine must run get_top_talkers (err %v, cites %+v)", err, ans.Citations)
	}

	// Denied: absent from the manifest, refused at execution, not run by the engine.
	shut := build(NewPolicyEngine(PolicyConfig{DenyTools: []string{denied}}, nil))
	if inManifest(shut) {
		t.Fatal("gate 1: a denied tool must not be offered to the model")
	}
	_, d, ok := shut.Toolbox().Authorize(denied, opsA())
	if !ok || d.Allow {
		t.Fatalf("gate 2: a denied tool must be refused at execution, got registered=%v %+v", ok, d)
	}
	ans, err = shut.Ask(context.Background(), opsA(), "show me the top talkers", nil)
	if err != nil {
		t.Fatal(err)
	}
	if hasCite(ans, "flow:talker:0") {
		t.Fatal("engine path: a denied tool ran anyway")
	}
	var disclosed bool
	for _, line := range ans.Disclaimers {
		if strings.Contains(strings.ToLower(line), strings.ToLower(d.Reason)) {
			disclosed = true
		}
	}
	if !disclosed {
		t.Fatalf("engine path must disclose the SAME denial reason %q, got %v", d.Reason, ans.Disclaimers)
	}
}

// TestToolboxIsTheOrchestratorsOwn: the agent loop's surface IS the engine's —
// the same registry pointer and the same policy decisions — never a copy.
func TestToolboxIsTheOrchestratorsOwn(t *testing.T) {
	o := newOrch(newMockDS())
	if o.Toolbox().Registry != o.Tools {
		t.Fatal("Toolbox must hand out the orchestrator's own registry")
	}
	o.Policy = NewPolicyEngine(PolicyConfig{DenyTools: []string{"get_problem"}}, nil)
	if o.Toolbox().Policy != o.Policy {
		t.Fatal("Toolbox must hand out the orchestrator's own policy engine")
	}
	o.Policy = nil
	if o.Toolbox().Policy == nil {
		t.Fatal("an unset policy must fall back to the safe default, never nil")
	}
}
