// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"
)

// toolcontract_test.go — tracker 337 N-A8, tool contract v2.

// Every tool the ONE registry can ever register has a valid contract, nothing
// is rejected, and no contract names a tool that does not exist.
func TestEveryRegisteredToolHasAValidContract(t *testing.T) {
	if err := CheckToolContracts(); err != nil {
		t.Fatalf("contract table: %v", err)
	}
	reg := BuildToolRegistry(newMockDS(), allSeamDeps(), LoadDocsIndex())
	if rej := reg.Rejected(); len(rej) != 0 {
		t.Fatalf("tools rejected at registration: %v", rej)
	}
	got := map[string]bool{}
	for _, n := range reg.Names() {
		got[n] = true
	}
	// Tools that exist only behind seams the mock DS does not implement are
	// still declared; the orphan check below compares against every
	// constructor's names.
	var orphans []string
	for n := range toolContracts {
		if !got[n] && !knownToolName(n) {
			orphans = append(orphans, n)
		}
	}
	sort.Strings(orphans)
	if len(orphans) != 0 {
		t.Fatalf("contracts for tools that do not exist: %v", orphans)
	}
	for n := range got {
		if _, ok := toolContracts[n]; !ok {
			t.Errorf("%s registered without a contract", n)
		}
	}
}

// knownToolName covers registry entries that need a DataSource the mock does
// not implement (wireless, module reads): they are declared by name in code.
func knownToolName(n string) bool {
	if n == "get_wireless_ap_inventory" || n == "get_wireless_controllers" {
		return true
	}
	for _, mt := range moduleTools {
		if mt.name == n {
			return true
		}
	}
	return false
}

// The probe tier is exactly the tools that open a device session.
func TestProbeTierIsExactlyTheDeviceTouchingTools(t *testing.T) {
	var probes []string
	for n, c := range toolContracts {
		if c.Risk == CapProbe {
			probes = append(probes, n)
		}
	}
	sort.Strings(probes)
	if strings.Join(probes, ",") != "get_device_state,run_protocol_diagnostic" {
		t.Fatalf("probe tier = %v", probes)
	}
}

type contractFake struct {
	name string
	cap  Capability
}

func (f contractFake) Name() string            { return f.name }
func (f contractFake) Module() string          { return "correlations_rca" }
func (f contractFake) Capability() Capability  { return f.cap }
func (f contractFake) RequiredPerms() []string { return []string{"incident:read"} }
func (f contractFake) Freshness() Freshness    { return FreshnessLive }
func (f contractFake) Run(context.Context, Principal, ToolArgs) (ToolResult, error) {
	return ToolResult{}, nil
}

// Registration refuses a tool without a contract, a contract that is
// incomplete, a capability that differs from the contract, a duplicate, and
// — structurally, whatever the policy config — any write or execute tool.
func TestRegisterRefusesWhatHasNoValidContract(t *testing.T) {
	valid := ToolContract{1, CapRead, time.Second, 10, out(5, 100)}
	defer func(saved map[string]ToolContract) { toolContracts = saved }(toolContracts)
	toolContracts = map[string]ToolContract{"ok_tool": valid}
	cases := map[string]ToolContract{
		"no_version": {0, CapRead, time.Second, 10, out(5, 100)},
		"no_timeout": {1, CapRead, 0, 10, out(5, 100)},
		"long":       {1, CapRead, 91 * time.Second, 10, out(5, 100)},
		"no_rate":    {1, CapRead, time.Second, 0, out(5, 100)},
		"no_items":   {1, CapRead, time.Second, 10, OutputSchema{MaxTextChars: 1, MaxNotes: 1, MaxSignals: 1}},
		"no_risk":    {1, "", time.Second, 10, out(5, 100)},
		"write":      {1, CapWrite, time.Second, 10, out(5, 100)},
		"execute":    {1, CapExecute, time.Second, 10, out(5, 100)},
	}
	for name, c := range cases {
		toolContracts[name] = c
	}
	reg := &ToolRegistry{byName: map[string]AITool{}}
	if err := reg.register(contractFake{"ok_tool", CapRead}); err != nil {
		t.Fatalf("valid tool refused: %v", err)
	}
	if err := reg.register(contractFake{"ok_tool", CapRead}); err == nil {
		t.Error("duplicate accepted")
	}
	if err := reg.register(contractFake{"undeclared", CapRead}); err == nil {
		t.Error("tool without a contract accepted")
	}
	for name, c := range cases {
		if err := reg.register(contractFake{name, c.Risk}); err == nil {
			t.Errorf("%s: invalid contract accepted", name)
		}
	}
	toolContracts["mismatch"] = valid
	if err := reg.register(contractFake{"mismatch", CapProbe}); err == nil {
		t.Error("a tool whose capability differs from its contract was accepted")
	}
	// The real write fake from policy_test can never be registered.
	reg.add(fakeWriteTool{})
	if _, ok := reg.Get(fakeWriteTool{}.Name()); ok || len(reg.Rejected()) != 1 {
		t.Fatalf("a write tool entered the registry: rejected=%v", reg.Rejected())
	}
}

func TestOutputSchemaValidate(t *testing.T) {
	s := out(2, 20)
	ok := EvidenceItem{CitationID: "problem:abc", Kind: "finding", Text: "BGP down", Href: "#/monitoring/correlations?id=abc"}
	if err := s.Validate(ToolResult{Items: []EvidenceItem{ok, {CitationID: "doc:x", Kind: "doc", Text: "t", Href: "/docs/a#b"}}}); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}
	bad := map[string]ToolResult{
		"too many items":      {Items: []EvidenceItem{ok, ok, ok}},
		"javascript href":     {Items: []EvidenceItem{{CitationID: "a", Kind: "log", Text: "t", Href: "javascript:alert(1)"}}},
		"external href":       {Items: []EvidenceItem{{CitationID: "a", Kind: "log", Text: "t", Href: "#/x?u=https://evil"}}},
		"bad kind":            {Items: []EvidenceItem{{CitationID: "a", Kind: "Log Item", Text: "t"}}},
		"empty citation":      {Items: []EvidenceItem{{Kind: "log", Text: "t"}}},
		"bracket citation":    {Items: []EvidenceItem{{CitationID: "a]b", Kind: "log", Text: "t"}}},
		"control in text":     {Items: []EvidenceItem{{CitationID: "a", Kind: "log", Text: "t\x1b[31m"}}},
		"invalid utf8":        {Items: []EvidenceItem{{CitationID: "a", Kind: "log", Text: "\xff\xfe"}}},
		"text too long":       {Items: []EvidenceItem{{CitationID: "a", Kind: "log", Text: strings.Repeat("x", 21)}}},
		"empty text":          {Items: []EvidenceItem{{CitationID: "a", Kind: "log", Text: "  "}}},
		"unknown cause role":  {Items: []EvidenceItem{{CitationID: "a", Kind: "log", Text: "t", CauseRole: "root"}}},
		"too many notes":      {Notes: make([]string, defaultMaxNotes+1)},
		"control in a signal": {Signals: []string{"verdict:tier=\x00confirmed"}},
	}
	for name, r := range bad {
		if err := s.Validate(r); !errors.Is(err, ErrSchemaRejected) {
			t.Errorf("%s: want ErrSchemaRejected, got %v", name, err)
		}
	}
	// Newlines and tabs are text, not control characters.
	if err := s.Validate(ToolResult{Items: []EvidenceItem{{CitationID: "a", Kind: "log", Text: "a\nb\tc"}}}); err != nil {
		t.Errorf("newline/tab rejected: %v", err)
	}
}

// The policy engine admits a probe like a read (permissions still apply) and
// still refuses write/execute.
func TestPolicyAdmitsProbeNotWrite(t *testing.T) {
	pe := NewPolicyEngine(PolicyConfig{}, func(string) bool { return true })
	p := Principal{Tenant: "acme", Perms: map[string]bool{"incident:read": true, "correlations:read": true}}
	if d := pe.EvaluateTool(contractFake{"probe_tool", CapProbe}, p); !d.Allow {
		t.Fatalf("probe denied: %s", d.Reason)
	}
	if d := pe.EvaluateTool(contractFake{"w", CapWrite}, p); d.Allow {
		t.Fatal("write allowed")
	}
}
