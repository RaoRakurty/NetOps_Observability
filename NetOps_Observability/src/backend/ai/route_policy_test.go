// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestScopeAnswerSaysWhichViewTheCallerIsIn(t *testing.T) {
	for _, c := range []struct {
		sf   ScopeFacts
		want string
	}{
		{ScopeFacts{AllTenants: true}, "All tenants view"},
		{ScopeFacts{Provider: true, TenantID: "global"}, "Provider view"},
		{ScopeFacts{TenantID: "t-acme", TenantName: "Acme Retail"}, "You are in tenant Acme Retail (t-acme)."},
		{ScopeFacts{TenantID: "t-acme"}, "You are in tenant t-acme."},
		{ScopeFacts{}, "does not name a tenant"},
	} {
		if got := scopeAnswer(c.sf); !strings.Contains(got, c.want) {
			t.Errorf("scopeAnswer(%+v) = %q, want it to contain %q", c.sf, got, c.want)
		}
	}
}

func TestDiscoveryAnswerBreaksTheInventoryDownBySource(t *testing.T) {
	got := discoveryAnswer(InventoryFacts{Total: 5, BySource: []SourceCount{
		{Source: "manual", Label: "manual entry", Count: 1},
		{Source: "snmp", Label: "SNMP discovery", Count: 3},
		{Source: "api:vmanage", Label: "the Cisco vManage integration", Count: 1},
	}})
	if !strings.HasPrefix(got, "Of the 5 devices in your inventory: 3 by SNMP discovery") ||
		!strings.Contains(got, "1 by the Cisco vManage integration") || !strings.Contains(got, "1 by manual entry") {
		t.Fatalf("discoveryAnswer = %q", got)
	}
	if got := discoveryAnswer(InventoryFacts{}); !strings.Contains(got, "no devices") {
		t.Fatalf("an empty inventory says so: %q", got)
	}
}

func TestModelUnavailableNoteNamesTheReason(t *testing.T) {
	for err, want := range map[error]string{
		ErrNoProvider:                      "No AI model is connected",
		context.DeadlineExceeded:           "timed out",
		ErrProviderBreakerOpen:             "paused",
		ErrBudgetExhausted:                 "budget",
		errors.New("something else broke"): "did not answer",
	} {
		if got := ModelUnavailableNote(err); !strings.Contains(got, want) {
			t.Errorf("ModelUnavailableNote(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestProblemInView(t *testing.T) {
	ctx := map[string]string{"correlation_id": "abc"}
	for q, want := range map[string]string{
		"Explain this problem":                     "abc",
		"why only suspected":                       "abc",
		"what am I looking at":                     "abc",
		"what does this page show":                 "",
		"how do I export this as a PDF":            "",
		"what does the evidence column mean":       "",
		"what should I check":                      "abc",
		"who is affected":                          "abc",
		"what changed before this":                 "abc",
		"why is this only suspected and what next": "abc",
	} {
		if got := ProblemInView(q, ctx); got != want {
			t.Errorf("ProblemInView(%q) = %q, want %q", q, got, want)
		}
	}
	if got := ProblemInView("explain this", map[string]string{"problem_id": "p1"}); got != "p1" {
		t.Fatalf("problem_id is a subject too: %q", got)
	}
	if got := ProblemInView("explain this", nil); got != "" {
		t.Fatalf("no context, no subject: %q", got)
	}
}

// A model answer cites only what it was given: an invented id is stripped and
// only the cited evidence becomes a citation; the prompt is fenced and redacted.
func TestAnswerByModelIsGroundedInTheEvidence(t *testing.T) {
	ds := newMockDS()
	llm := &captureLLM{reply: "Two problems are active [problem:pa]; one is invented [problem:zzz]."}
	o := &Orchestrator{DS: ds, LLM: llm, Flags: func(string) bool { return true },
		Scope: &ScopeFacts{TenantID: "t-a"}}
	ans, ok, err := o.answerByModel(context.Background(), tenantA(), "which one should I care about", "capability", RouteReasonMiss)
	if !ok || err != nil {
		t.Fatalf("answerByModel: ok=%v err=%v", ok, err)
	}
	if strings.Contains(ans.Text, "zzz") {
		t.Fatalf("an invented citation must be stripped: %q", ans.Text)
	}
	for _, c := range ans.Citations {
		if !strings.Contains(ans.Text, c.ID) {
			t.Fatalf("citation %s is not cited by the text", c.ID)
		}
	}
	if ans.Mode != ModeModelAnswer || ans.Routing == nil || ans.Routing.Path != RoutePathModel {
		t.Fatalf("answer = %+v", ans)
	}
	if !strings.Contains(llm.user, "EVIDENCE (cite ids)") || !strings.Contains(llm.user, "[scope:caller]") {
		t.Fatalf("the prompt must carry the evidence block: %q", llm.user)
	}
	if llm.system != o.systemPrompt() {
		t.Fatal("the system prompt is the server's own (LLM01)")
	}
}

func TestAnswerByModelWithoutAModel(t *testing.T) {
	o := &Orchestrator{DS: newMockDS(), Flags: func(string) bool { return true }}
	if _, ok, err := o.answerByModel(context.Background(), tenantA(), "q", "capability", RouteReasonMiss); ok || !errors.Is(err, ErrNoProvider) {
		t.Fatalf("no LLM: ok=%v err=%v", ok, err)
	}
}

// An agent path that is not available to the caller falls back to the single
// grounded answer; one that fails is a model failure.
func TestAnswerByModelPrefersTheAgentPath(t *testing.T) {
	o := &Orchestrator{DS: newMockDS(), LLM: &captureLLM{reply: "fallback [scope:caller]"}, Flags: func(string) bool { return true },
		Scope: &ScopeFacts{TenantID: "t-a"}}
	o.AgentAnswer = func(context.Context, Principal, string, []string) (Answer, error) {
		return Answer{Mode: ModeModelAnswer, Text: "from the tools"}, nil
	}
	if ans, ok, _ := o.answerByModel(context.Background(), tenantA(), "q", "capability", RouteReasonMiss); !ok || ans.Text != "from the tools" || ans.Routing.Reason != RouteReasonMiss {
		t.Fatalf("the agent path answers when wired: %+v", ans)
	}
	o.AgentAnswer = func(context.Context, Principal, string, []string) (Answer, error) {
		return Answer{}, ErrAgentUnavailable
	}
	if ans, ok, _ := o.answerByModel(context.Background(), tenantA(), "q", "capability", RouteReasonMiss); !ok || !strings.Contains(ans.Text, "fallback") {
		t.Fatalf("an unavailable agent path falls back to the grounded answer: %+v", ans)
	}
	o.AgentAnswer = func(context.Context, Principal, string, []string) (Answer, error) {
		return Answer{}, context.DeadlineExceeded
	}
	if _, ok, err := o.answerByModel(context.Background(), tenantA(), "q", "capability", RouteReasonMiss); ok || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a failed agent path is a model failure: ok=%v err=%v", ok, err)
	}
}

type captureLLM struct {
	reply, system, user string
}

func (c *captureLLM) Complete(_ context.Context, system string, msgs []LLMMessage) (string, string, error) {
	c.system = system
	if len(msgs) > 0 {
		c.user = msgs[len(msgs)-1].Content
	}
	return c.reply, "mock", nil
}
