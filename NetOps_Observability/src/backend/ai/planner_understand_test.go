// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

func TestParsePlannerTermsLine(t *testing.T) {
	o := plannerOrch(&plannerLLM{route: func(string) string { return "" }})
	for _, tc := range []struct {
		reply string
		ok    bool
		terms string
	}{
		{"ROUTE: product\nTERMS: seam ownership handoff", true, "seam ownership handoff"},
		{"ROUTE: data\nTERMS: interface utilization  cEdge-80", true, "interface utilization cEdge-80"},
		{"ROUTE: module\nMODULE: telemetry\nTERMS: metric anomalies", true, "metric anomalies"},
		{"ROUTE: product", true, ""},
		{"ROUTE: product\nTERMS: ping 10.1.1.1", false, ""},                  // an address is refused
		{"ROUTE: product\nTERMS: <script>alert(1)</script>", false, ""},      // markup is refused
		{"ROUTE: product\nTERMS: " + strings.Repeat("word ", 30), false, ""}, // too long
		{"ROUTE: product\nTERMS: a\nTERMS: b", false, ""},                    // one TERMS line only
		{"ROUTE: product\nSKILL: bgp\nTERMS: x", false, ""},                  // SKILL only with troubleshoot
		{"TERMS: seams\nROUTE: product", false, ""},                          // TERMS is the last line
		{"ROUTE: module\nMODULE: telemetry\nTERMS: ok\nextra", false, ""},    // nothing after
	} {
		ch, ok := o.parsePlannerReply(tc.reply, false)
		if ok != tc.ok || (ok && ch.Terms != tc.terms) {
			t.Errorf("%q: ok=%v terms=%q, want ok=%v terms=%q", tc.reply, ok, ch.Terms, tc.ok, tc.terms)
		}
	}
}

// The restatement rescues a docs lookup the operator's own words missed, and
// the answer discloses that it searched with it.
func TestRestatementRescuesTheDocsLookup(t *testing.T) {
	llm := &plannerLLM{route: func(string) string { return "ROUTE: product\nTERMS: what is a seam" }}
	o := plannerOrch(llm)
	o.Docs = LoadDocsIndex()
	ans, err := o.Ask(context.Background(), tenantA(), "zxqv blorp handoff thingy meaning", nil)
	if err != nil {
		t.Fatal(err)
	}
	if IsDeadEnd(ans) || ans.Mode != ModeProductAnswer {
		t.Fatalf("mode=%s text=%q disc=%v", ans.Mode, ans.Text, ans.Disclaimers)
	}
	if !strings.Contains(strings.Join(ans.Disclaimers, " "), "what is a seam") {
		t.Fatalf("the restatement must be disclosed: %v", ans.Disclaimers)
	}
}

// The restatement rescues the data grammar: the words fail, the terms parse.
func TestRestatementRescuesTheDataGrammar(t *testing.T) {
	llm := &plannerLLM{route: func(string) string { return "ROUTE: data\nTERMS: list devices" }}
	o := plannerOrch(llm)
	var asked []string
	o.NLQuery = func(_ context.Context, _ Principal, q string, _ DataOpts) (DataAnswer, error) {
		asked = append(asked, q)
		if q == "list devices" {
			return DataAnswer{Status: DataAnswered, Intent: "data_query", Text: "8 devices"}, nil
		}
		return DataAnswer{Status: DataNotData}, nil
	}
	ans, err := o.Ask(context.Background(), tenantA(), "gimme the boxes we got", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeDataQuery || ans.Text != "8 devices" {
		t.Fatalf("mode=%s text=%q asked=%v", ans.Mode, ans.Text, asked)
	}
}

// A planned module whose tools are missing goes to the model; a permission
// denial NEVER does — the denial is the answer (§3a).
func TestModuleFallbackNeverBypassesADenial(t *testing.T) {
	llm := &plannerLLM{route: func(string) string { return "ROUTE: module\nMODULE: telemetry" }}
	o := plannerOrch(llm)
	o.Tools = Tools(o.DS)
	agent := 0
	o.AgentAnswer = func(context.Context, Principal, string, []string) (Answer, error) {
		agent++
		return Answer{Mode: ModeModelAnswer, Text: "from the tools"}, nil
	}
	ans, err := o.Ask(context.Background(), tenantA(), "any metric anomalies", nil) // tenantA lacks the module's permission
	if err != nil {
		t.Fatal(err)
	}
	if agent != 0 || ans.Mode != ModeUnavailable || !strings.Contains(strings.Join(ans.Disclaimers, " "), "permission") {
		t.Fatalf("a permission denial was handed to the model: agent=%d mode=%s disc=%v", agent, ans.Mode, ans.Disclaimers)
	}
}

// The caller's vocabulary reaches the planner prompt and the grounded model
// answer as fenced data; with no glossary wired, neither prompt changes.
func TestGlossaryReachesTheModelPathsAsData(t *testing.T) {
	const vocab = "VOCABULARY — test\nSites:\n- Dallas HQ — operator aliases: the Dallas office\n"
	var prompts []string
	llm := &plannerLLM{route: func(string) string { return "ROUTE: network" }}
	o := plannerOrch(llm)
	o.Glossary = func(context.Context, Principal) string { return vocab }
	o.LLM = recordingLLM{inner: llm, seen: &prompts}
	if _, err := o.Ask(context.Background(), tenantA(), "how is the dallas office doing", nil); err != nil {
		t.Fatal(err)
	}
	if len(prompts) < 2 {
		t.Fatalf("want the planner and the model answer, got %d calls", len(prompts))
	}
	for i, p := range prompts {
		if !strings.Contains(p, "the Dallas office") {
			t.Errorf("call %d lacks the vocabulary:\n%s", i, p)
		}
	}
	if !strings.Contains(prompts[len(prompts)-1], "not evidence") {
		t.Error("the model answer must be told the vocabulary is not evidence")
	}
	// No glossary wired: the planner prompt carries no vocabulary block.
	o2 := plannerOrch(llm)
	if strings.Contains(o2.plannerPrompt(context.Background(), tenantA(), "q", false), "VOCABULARY") {
		t.Error("no glossary wired must add no vocabulary block")
	}
}

// recordingLLM records every user prompt and answers like the stub.
type recordingLLM struct {
	inner *plannerLLM
	seen  *[]string
}

func (r recordingLLM) Complete(ctx context.Context, system string, msgs []LLMMessage) (string, string, error) {
	return r.CompleteTier(ctx, "", system, msgs)
}

func (r recordingLLM) CompleteTier(ctx context.Context, tier ModelTier, system string, msgs []LLMMessage) (string, string, error) {
	if len(msgs) > 0 {
		*r.seen = append(*r.seen, msgs[len(msgs)-1].Content)
	}
	return r.inner.CompleteTier(ctx, tier, system, msgs)
}

func TestIsDeadEnd(t *testing.T) {
	for _, tc := range []struct {
		a    Answer
		dead bool
	}{
		{Answer{Mode: ModeUnavailable}, true},
		{Answer{Mode: ModeProductNavigationHelp, Text: NoFeatureMatchText}, true},
		{Answer{Mode: ModeProductAnswer, Disclaimers: []string{NoDocsNote}}, true},
		{Answer{Mode: ModeInvestigationPlan, Disclaimers: []string{NoPlaybookNote}}, true},
		{Answer{Mode: ModeModelAnswer, Text: "The data does not cover that; flows would."}, false},
		{Answer{Mode: ModeProductAnswer, Text: "A seam is…"}, false},
	} {
		if got := IsDeadEnd(tc.a); got != tc.dead {
			t.Errorf("IsDeadEnd(%+v)=%v want %v", tc.a, got, tc.dead)
		}
	}
}
