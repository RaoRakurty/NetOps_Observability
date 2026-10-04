// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// score_test.go — the production-scorecard seam (tracker 337 N-A3, design 19).
//
// Pinned: one AnswerObserved per finished answer; one ProviderObserved per
// completion attempt, failures included, with usage passed through only when
// the client reports the provider's own numbers; each deterministic guard
// reports where it acts; a skill-chain turn reports its hops and per-call tool
// outcomes; and a nil sink changes nothing.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type recordingSink struct {
	mu        sync.Mutex
	answers   []AnswerScore
	invs      []InvestigationScore
	guards    map[string]int
	providers []ProviderScore
}

func newRecordingSink() *recordingSink { return &recordingSink{guards: map[string]int{}} }

func (r *recordingSink) AnswerObserved(a AnswerScore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers = append(r.answers, a)
}
func (r *recordingSink) InvestigationObserved(i InvestigationScore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.invs = append(r.invs, i)
}
func (r *recordingSink) GuardObserved(g string, removed int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.guards[g] += removed
}
func (r *recordingSink) ProviderObserved(p ProviderScore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = append(r.providers, p)
}

func TestAskObservesExactlyOneAnswer(t *testing.T) {
	sink := newRecordingSink()
	o := newOrch(newMockDS())
	o.Score = sink
	ans, err := o.Ask(context.Background(), tenantA(), "what is broken right now?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(sink.answers) != 1 {
		t.Fatalf("want exactly one answer observation, got %d", len(sink.answers))
	}
	if sink.answers[0].Citations != len(ans.Citations) {
		t.Fatalf("observed %d citations, answer shipped %d", sink.answers[0].Citations, len(ans.Citations))
	}
}

// usageLLM reports the provider's own token accounting.
type usageLLM struct{ MockLLM }

func (u usageLLM) CompleteTier(ctx context.Context, _ ModelTier, system string, msgs []LLMMessage) (string, string, error) {
	return u.Complete(ctx, system, msgs)
}
func (u usageLLM) CompleteTierWithUsage(ctx context.Context, tier ModelTier, system string, msgs []LLMMessage) (string, string, TokenUsage, error) {
	text, provider, err := u.CompleteTier(ctx, tier, system, msgs)
	return text, provider, TokenUsage{InputTokens: 120, OutputTokens: 30, Reported: true}, err
}

func TestProviderObservedOncePerAttemptIncludingFailures(t *testing.T) {
	sink := newRecordingSink()
	o := &Orchestrator{LLM: MockLLM{Err: errors.New("provider down")}, Score: sink}
	if _, _, err := o.completeTier(context.Background(), TierFast, "s", nil, false); err == nil {
		t.Fatal("the provider error must propagate")
	}
	if len(sink.providers) != 1 || sink.providers[0].Usage.Reported {
		t.Fatalf("a failed call is still one observation, with no invented usage: %+v", sink.providers)
	}

	o.LLM = usageLLM{MockLLM{Reply: "ok"}}
	if _, _, err := o.completeTier(context.Background(), TierStrong, "s", nil, true); err != nil {
		t.Fatal(err)
	}
	got := sink.providers[1]
	if !got.Usage.Reported || got.Usage.InputTokens != 120 || !got.Investigation {
		t.Fatalf("usage + investigation flag must pass through: %+v", got)
	}

	// No LLM at all: an honest error and NO observation — nothing was called.
	o = &Orchestrator{Score: sink}
	if _, _, err := o.completeTier(context.Background(), TierFast, "s", nil, false); !errors.Is(err, ErrNoProvider) {
		t.Fatalf("want ErrNoProvider, got %v", err)
	}
	if len(sink.providers) != 2 {
		t.Fatalf("an unwired provider must not be observed as a call: %d", len(sink.providers))
	}
}

func TestGuardsReportWhereTheyAct(t *testing.T) {
	sink := newRecordingSink()
	o := &Orchestrator{Score: sink}
	o.verifyNarrative("Loss on edge-1 [log:real:1] and [log:made:2] and [log:made:3].", []string{"log:real:1"}, nil, nil)
	if sink.guards[GuardFabricatedCitation] != 2 {
		t.Fatalf("fabricated-citation guard removed %d, want 2", sink.guards[GuardFabricatedCitation])
	}
	text := "edge-1 logged repeated BGP adjacency changes over 20 minutes and two probe paths degraded [log:os:1]. " +
		"The root cause is a BGP session reset on core-1. Next: verify the peering link."
	o.enforceVerdictHonesty(text, "undetermined", "fallback summary", nil, nil)
	if sink.guards[GuardUncertainClaim] != 1 {
		t.Fatalf("uncertain-claim guard = %d, want 1", sink.guards[GuardUncertainClaim])
	}
	// A confirmed verdict passes untouched and fires nothing.
	o.enforceVerdictHonesty(text, "confirmed", "fallback", nil, nil)
	if sink.guards[GuardUncertainClaim] != 1 {
		t.Fatal("a confirmed verdict must not fire the honesty guard")
	}
}

func TestSkillTurnObservesHopsAndToolOutcomes(t *testing.T) {
	set := loadTestSkills(t)
	sk, ok := set.Get("bgp-session-down")
	if !ok || len(sk.Cases) == 0 {
		t.Fatal("fixture skill missing")
	}
	c := sk.Cases[0]
	o, _, _ := caseOrchestrator(t, set, c)
	sink := newRecordingSink()
	o.Score = sink
	if _, handled := o.answerSkill(context.Background(), runPrincipal(), c.Question,
		Plan{Intent: firstNonEmpty(c.Intent, "troubleshoot")},
		SkillMatch{Skill: sk, Reason: "score fixture"}, c.UI, nil); !handled {
		t.Fatal("turn not handled")
	}
	if len(sink.invs) != 1 {
		t.Fatalf("want one investigation observation, got %d", len(sink.invs))
	}
	inv := sink.invs[0]
	if inv.Outcome != InvestigationAnswered || len(inv.Hops) == 0 || len(inv.ToolOutcomes) == 0 {
		t.Fatalf("investigation score = %+v", inv)
	}
	if inv.Hops[0] != ChainSelectedEntry {
		t.Fatalf("the first hop is the entry, got %q", inv.Hops[0])
	}
	for _, p := range sink.providers {
		if !p.Investigation {
			t.Fatal("every provider call inside a skill turn is an investigation call")
		}
	}
}

func TestNilSinkIsFree(t *testing.T) {
	o := newOrch(newMockDS())
	if _, err := o.Ask(context.Background(), tenantA(), "what is broken right now?", nil); err != nil {
		t.Fatal(err)
	}
	o.observeGuard(GuardFabricatedCitation, 1) // must not panic
	o.observeInvestigation(nil, time.Now(), InvestigationAnswered, true)
}
