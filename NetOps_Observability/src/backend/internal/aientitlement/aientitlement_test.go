// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aientitlement_test

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/aientitlement"
	"netops/backend/internal/entitlement"
)

// every is the full vocabulary, the shipped grant for every tier until the
// owner places the AI capabilities (plan owner decision 1).
var every = aientitlement.All()

// TestTierMappingTable is THE tier → entitlement table. It reads the shipped
// data (tiers.json) and pins, per licence tier, exactly which AI entitlements
// the tier grants. A change to tier placement is a change to tiers.json AND to
// this table, reviewed together; the Go gate code never changes for it.
func TestTierMappingTable(t *testing.T) {
	p, err := aientitlement.Default()
	if err != nil {
		t.Fatalf("the shipped mapping must parse: %v", err)
	}
	want := map[entitlement.Tier][]aientitlement.Entitlement{
		entitlement.TierCommunity:  every,
		entitlement.TierTeam:       every,
		entitlement.TierEnterprise: every,
	}
	// Every licence tier the product knows must have a row — a tier with no row
	// would silently grant no AI at all.
	for _, tier := range entitlement.Tiers() {
		if _, ok := want[tier]; !ok {
			t.Fatalf("licence tier %q has no row in this table", tier)
		}
	}
	gotTiers := p.Tiers()
	var wantTiers []string
	for tier := range want {
		wantTiers = append(wantTiers, string(tier))
	}
	sort.Strings(wantTiers)
	if !reflect.DeepEqual(gotTiers, wantTiers) {
		t.Fatalf("mapping tiers = %v, want %v", gotTiers, wantTiers)
	}
	for tier, grants := range want {
		g := map[aientitlement.Entitlement]bool{}
		for _, e := range grants {
			g[e] = true
		}
		for _, e := range aientitlement.All() {
			if got := p.TierGrants(string(tier), e); got != g[e] {
				t.Errorf("tier %s, %s: granted=%v, want %v", tier, e, got, g[e])
			}
		}
	}
	if p.TierGrants("no-such-tier", aientitlement.Chat) {
		t.Fatal("an unknown tier must grant nothing")
	}
}

func TestVocabularyIsClosedAndBackingIsHonest(t *testing.T) {
	want := []aientitlement.Entitlement{"ai.chat", "ai.investigate", "ai.nlquery", "ai.context.author", "ai.runbook.author", "ai.mcp"}
	if !reflect.DeepEqual(aientitlement.All(), want) {
		t.Fatalf("vocabulary = %v, want %v", aientitlement.All(), want)
	}
	for _, e := range []aientitlement.Entitlement{"", "ai", "ai.chat ", "AI.CHAT", "ai.admin"} {
		if aientitlement.Valid(e) {
			t.Errorf("%q must not be valid", e)
		}
	}
	backed := map[aientitlement.Entitlement]bool{aientitlement.Chat: true, aientitlement.Investigate: true, aientitlement.NLQuery: true}
	for _, e := range aientitlement.All() {
		if aientitlement.Backed(e) != backed[e] {
			t.Errorf("Backed(%s) = %v, want %v", e, aientitlement.Backed(e), backed[e])
		}
		if aientitlement.Label(e) == string(e) {
			t.Errorf("%s has no operator label", e)
		}
	}
}

func TestParseIsStrict(t *testing.T) {
	for name, doc := range map[string]string{
		"unknown entitlement": `{"tiers":{"x":["ai.chat","ai.root"]}}`,
		"unknown field":       `{"tiers":{"x":["ai.chat"]},"grant_all":true}`,
		"empty tier key":      `{"tiers":{"":["ai.chat"]}}`,
		"padded tier key":     `{"tiers":{" x":["ai.chat"]}}`,
		"no tiers":            `{"tiers":{}}`,
		"trailing data":       `{"tiers":{"x":[]}} {}`,
		"not json":            `tiers: x`,
	} {
		if _, err := aientitlement.Parse([]byte(doc)); err == nil {
			t.Errorf("%s: must not parse", name)
		}
	}
	p, err := aientitlement.Parse([]byte(`{"note":"n","tiers":{"x":["ai.nlquery"],"y":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !p.TierGrants("x", aientitlement.NLQuery) || p.TierGrants("x", aientitlement.Chat) || p.TierGrants("y", aientitlement.NLQuery) {
		t.Fatal("grants must be exactly what the document lists")
	}
	var nilP *aientitlement.Policy
	if nilP.TierGrants("x", aientitlement.Chat) || nilP.Tiers() != nil {
		t.Fatal("a nil policy grants nothing")
	}
}

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestDeploymentFlagsKeepTheirMeaning(t *testing.T) {
	cases := []struct {
		name          string
		env           map[string]string
		iris, investi bool
	}{
		{"defaults: Iris on, investigations off", nil, true, false},
		{"FEATURE_AI=false", map[string]string{"FEATURE_AI": "false", "FEATURE_AI_TOOLS": "true"}, false, false},
		{"legacy FEATURE_COPILOT=false", map[string]string{"FEATURE_COPILOT": "false"}, false, false},
		{"FEATURE_AI wins over FEATURE_COPILOT", map[string]string{"FEATURE_AI": "true", "FEATURE_COPILOT": "false"}, true, false},
		{"tools on", map[string]string{"FEATURE_AI_TOOLS": "true"}, true, true},
	}
	for _, c := range cases {
		e := env(c.env)
		for _, ent := range []aientitlement.Entitlement{aientitlement.Chat, aientitlement.NLQuery, aientitlement.ContextAuthor, aientitlement.RunbookAuthor, aientitlement.MCP} {
			if got := aientitlement.DeploymentAllows(ent, e); got != c.iris {
				t.Errorf("%s: %s = %v, want %v", c.name, ent, got, c.iris)
			}
		}
		if got := aientitlement.DeploymentAllows(aientitlement.Investigate, e); got != c.investi {
			t.Errorf("%s: investigate = %v, want %v", c.name, got, c.investi)
		}
	}
	if aientitlement.IrisOn(nil) {
		t.Fatal("no environment source is not an 'on'")
	}
}

type switches struct{ assistant, tools map[string]bool }

func (s switches) AssistantEnabled(t string) bool  { return s.assistant[t] }
func (s switches) AgentToolsEnabled(t string) bool { return s.tools[t] }

func TestDecideOrderAndTenantScope(t *testing.T) {
	p, err := aientitlement.Parse([]byte(`{"tiers":{"paid":["ai.chat","ai.investigate","ai.nlquery"],"free":["ai.chat"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	sw := switches{assistant: map[string]bool{"t-a": true}, tools: map[string]bool{"t-a": true}}
	on := env(map[string]string{"FEATURE_AI_TOOLS": "true"})
	in := aientitlement.Inputs{Tier: "paid", Env: on, Tenant: "t-a", Switches: sw}

	if d := aientitlement.Decide(p, aientitlement.NLQuery, in); !d.Granted {
		t.Fatalf("all three switches on must grant: %+v", d)
	}
	off := in
	off.Env = env(map[string]string{"FEATURE_AI": "false"})
	off.Tier = "free" // also not in tier — the deployment switch is named first
	if d := aientitlement.Decide(p, aientitlement.NLQuery, off); d.Granted || d.Reason != aientitlement.ReasonDisabled {
		t.Fatalf("Iris off must refuse as disabled: %+v", d)
	}
	free := in
	free.Tier = "free"
	if d := aientitlement.Decide(p, aientitlement.NLQuery, free); d.Granted || d.Reason != aientitlement.ReasonNotInTier {
		t.Fatalf("a tier without the grant must refuse as not_in_tier: %+v", d)
	}
	other := in
	other.Tenant = "t-b"
	if d := aientitlement.Decide(p, aientitlement.Chat, other); d.Granted || d.Reason != aientitlement.ReasonTenantOff {
		t.Fatalf("tenant B is not switched on — tenant A's switch must not leak: %+v", d)
	}
	cross := other
	cross.Cross = true
	if d := aientitlement.Decide(p, aientitlement.Investigate, cross); !d.Granted {
		t.Fatalf("a cross-tenant principal is not tenant-gated: %+v", d)
	}
	allTn := other
	allTn.Env = env(map[string]string{"FEATURE_AI_TOOLS": "true", "AI_TOOLS_ALL_TENANTS": "true"})
	if !aientitlement.Decide(p, aientitlement.Investigate, allTn).Granted {
		t.Fatal("AI_TOOLS_ALL_TENANTS widens investigations to every tenant")
	}
	if aientitlement.Decide(p, aientitlement.Chat, allTn).Granted {
		t.Fatal("AI_TOOLS_ALL_TENANTS must not switch on the assistant for a tenant")
	}
	noSw := in
	noSw.Switches = nil
	if aientitlement.Decide(p, aientitlement.Chat, noSw).Granted {
		t.Fatal("no tenant switch source grants a tenant caller nothing")
	}
	if d := aientitlement.Decide(p, "ai.root", in); d.Granted || d.Reason != aientitlement.ReasonUnknown {
		t.Fatalf("unknown entitlement: %+v", d)
	}
	if aientitlement.Decide(nil, aientitlement.Chat, in).Granted {
		t.Fatal("a nil policy grants nothing")
	}

	got := aientitlement.Resolve(p, in)
	want := []aientitlement.Entitlement{aientitlement.Chat, aientitlement.Investigate, aientitlement.NLQuery}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve = %v, want %v", got, want)
	}
	if r := aientitlement.Resolve(p, off); r == nil || len(r) != 0 {
		t.Fatalf("Resolve must be an empty, non-nil list when nothing is granted: %#v", r)
	}
}

// TestNoTierNamesInGoSource: tier placement is data. The package's Go source
// must not spell a licence tier — if it does, someone has started deciding
// placement in code.
func TestNoTierNamesInGoSource(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this file")
	}
	dir := filepath.Dir(self)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tier := range entitlement.Tiers() {
		names = append(names, regexp.QuoteMeta(string(tier)))
	}
	re := regexp.MustCompile(`(?i)\b(` + strings.Join(names, "|") + `)\b`)
	scanned := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		if m := re.FindString(string(b)); m != "" {
			t.Errorf("%s spells the tier name %q — tier placement belongs in tiers.json", e.Name(), m)
		}
	}
	if scanned == 0 {
		t.Fatal("scanned no source — the guard proved nothing")
	}
}
