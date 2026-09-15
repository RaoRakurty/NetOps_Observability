// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
)

// fakeTAC answers only for questions naming BGP, the way the real catalogue
// returns nothing for an off-topic question.
type fakeTAC struct{ calls []string }

func (f *fakeTAC) Lookup(q string, limit int) []TACKnowledgeHit {
	f.calls = append(f.calls, q)
	if !strings.Contains(strings.ToLower(q), "bgp") {
		return nil
	}
	return []TACKnowledgeHit{{
		ClassID: "bgp.session-down", Title: "BGP session down", Protocol: "bgp",
		FirstLook: "The neighbour state and the last error.", Dialect: "Nokia SR Linux",
		Intents: []TACKnowledgeIntent{
			{Title: "BGP neighbour summary", Command: "show network-instance default protocols bgp neighbor", Verified: true},
			{Title: "BGP neighbour detail"},
		},
	}}
}

func hasTACCitation(cs []Citation) bool {
	for _, c := range cs {
		if strings.HasPrefix(c.ID, "tac:") {
			return true
		}
	}
	return false
}

func TestIrisReadsTACKnowledgeWhenNoPlaybookIsWired(t *testing.T) {
	ds := newMockDS()
	tacSrc := &fakeTAC{}
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}, TAC: tacSrc}
	ans, err := o.Ask(context.Background(), Principal{Cross: true}, "how do I troubleshoot a BGP session that will not establish on Nokia SR Linux?", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if len(tacSrc.calls) == 0 {
		t.Fatal("Iris answered a BGP troubleshooting question without reading its TAC knowledge")
	}
	if ans.Mode != ModeInvestigationPlan || !hasTACCitation(ans.Citations) {
		t.Fatalf("mode=%q citations=%v — want an investigation plan citing TAC knowledge", ans.Mode, ans.Citations)
	}
	joined := strings.Join(ans.NextActions, " | ")
	if !strings.Contains(joined, "show network-instance default protocols bgp neighbor") || !strings.Contains(joined, "verified on a capture") {
		t.Errorf("next actions must carry the bound command and its honesty label: %s", joined)
	}
}

func TestPlaybookAnswerCarriesTACKnowledgeToo(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}, KB: LoadKB(), TAC: &fakeTAC{}}
	ans, err := o.Ask(context.Background(), Principal{Cross: true}, "how do I troubleshoot a BGP adjacency flap?", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if len(ans.Citations) == 0 || !strings.HasPrefix(ans.Citations[0].ID, "playbook:") {
		t.Fatalf("the playbook must still lead: %v", ans.Citations)
	}
	if !hasTACCitation(ans.Citations) {
		t.Errorf("TAC knowledge must ride along with the playbook: %v", ans.Citations)
	}
}

func TestProblemPromptShowsTACKnowledgeAsGuidanceNotEvidence(t *testing.T) {
	o := &Orchestrator{TAC: &fakeTAC{}}
	prompt := o.problemPrompt("why is spine1 down?", &Problem{ID: "p1", Title: "BGP neighbor down", Devices: []string{"spine1"}}, nil)
	if !strings.Contains(prompt, "SUPPORTING VENDOR TAC KNOWLEDGE") || !strings.Contains(prompt, "NOT Correlix evidence") {
		t.Fatalf("problem prompt must fence TAC knowledge as guidance:\n%s", prompt)
	}
	if strings.Contains(prompt, "\nWhat TAC looks at first") {
		t.Error("each hit must stay on one line inside the prompt block")
	}
}

func TestOffTopicQuestionIsUntouchedByTACKnowledge(t *testing.T) {
	ds := newMockDS()
	with := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}, TAC: &fakeTAC{}}
	without := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}}
	q := "what colour should the dashboard be?"
	a1, err1 := with.Ask(context.Background(), Principal{Cross: true}, q, nil)
	a2, err2 := without.Ask(context.Background(), Principal{Cross: true}, q, nil)
	if err1 != nil || err2 != nil {
		t.Fatalf("Ask: %v / %v", err1, err2)
	}
	if a1.Mode != a2.Mode || hasTACCitation(a1.Citations) {
		t.Errorf("an off-topic question changed shape with TAC wired: %q vs %q, %v", a1.Mode, a2.Mode, a1.Citations)
	}
}
