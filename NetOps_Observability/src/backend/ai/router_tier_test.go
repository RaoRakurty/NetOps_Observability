// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"sync"
	"testing"
)

// router_tier_test.go — the MECHANISM half of the §10 model router (review item
// 9). The policy (RouteFor) was already tested; what was untested — because it
// did not exist — is that the tier a route names actually reaches the provider
// chain, that a deterministic mode still calls nothing, and that a client which
// knows nothing about tiers keeps behaving exactly as before.

// tierSpy is a TieredLLMClient that records every tier it was asked for. It also
// counts plain Complete calls separately, so a regression that drops the tier on
// the floor (falling back to the untiered path) is visible rather than silent.
type tierSpy struct {
	mu       sync.Mutex
	tiers    []ModelTier
	untiered int
	reply    string
}

func (s *tierSpy) Complete(_ context.Context, _ string, _ []LLMMessage) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.untiered++
	return s.reply, "spy", nil
}

func (s *tierSpy) CompleteTier(_ context.Context, tier ModelTier, _ string, _ []LLMMessage) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tiers = append(s.tiers, tier)
	return s.reply, "spy", nil
}

func (s *tierSpy) calls() ([]ModelTier, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ModelTier(nil), s.tiers...), s.untiered
}

// plainSpy implements ONLY LLMClient — the pre-router contract. Every existing
// stub in this repo has this shape, and the back-compat claim is that such a
// client is still called through Complete with no behaviour change at all.
type plainSpy struct {
	mu    sync.Mutex
	calls int
	reply string
}

func (s *plainSpy) Complete(_ context.Context, _ string, _ []LLMMessage) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	return s.reply, "plain", nil
}

func (s *plainSpy) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// TestTierModelsBackCompat: a configuration that names ONE model resolves every
// tier to that model. This is the whole promise made to an existing deployment —
// nothing changes until an operator deliberately splits the tiers.
func TestTierModelsBackCompat(t *testing.T) {
	single := TierModels{Default: "claude-sonnet-4-6"}
	for _, tier := range []ModelTier{TierDeterministic, TierFast, TierStrong, ""} {
		if got := single.For(tier); got != "claude-sonnet-4-6" {
			t.Errorf("single-model config: For(%q) = %q, want the one configured model", tier, got)
		}
	}
	// A configuration with NOTHING set resolves to "" for every tier, which is
	// the caller's signal to keep the provider's own default model.
	var empty TierModels
	for _, tier := range []ModelTier{TierDeterministic, TierFast, TierStrong, ""} {
		if got := empty.For(tier); got != "" {
			t.Errorf("empty config: For(%q) = %q, want \"\"", tier, got)
		}
	}
}

// TestTierModelsOverrides: each override applies to its own tier and NOTHING
// else — including a half-configured setup, where the unset tier must still
// fall back to the default rather than borrow the other tier's model.
func TestTierModelsOverrides(t *testing.T) {
	full := TierModels{Default: "sonnet", Fast: "haiku", Strong: "opus"}
	cases := []struct {
		tier ModelTier
		want string
	}{
		{TierFast, "haiku"},
		{TierStrong, "opus"},
		{TierDeterministic, "sonnet"},
		{"", "sonnet"},
	}
	for _, c := range cases {
		if got := full.For(c.tier); got != c.want {
			t.Errorf("For(%q) = %q, want %q", c.tier, got, c.want)
		}
	}
	// Half-configured: only the fast tier is split out.
	half := TierModels{Default: "sonnet", Fast: "haiku"}
	if got := half.For(TierStrong); got != "sonnet" {
		t.Errorf("unset strong tier must fall back to the default, got %q", got)
	}
	// Whitespace is not a configuration: "   " must not become the model name.
	blank := TierModels{Default: "sonnet", Fast: "   ", Strong: "\t"}
	if got := blank.For(TierFast); got != "sonnet" {
		t.Errorf("whitespace-only override must fall back, got %q", got)
	}
	if got := blank.For(TierStrong); got != "sonnet" {
		t.Errorf("whitespace-only override must fall back, got %q", got)
	}
}

// TestRouteForCoversEveryMode: the tier partition over the WHOLE AnswerMode
// vocabulary, asserted exhaustively rather than by sample. The review's claim
// was "nine of thirteen modes never call a provider"; the vocabulary has grown
// since, so the invariant is pinned instead of the count: exactly four modes are
// model modes, every other mode — present and future, since the switch's default
// arm decides them — is deterministic and verifies nothing.
func TestRouteForCoversEveryMode(t *testing.T) {
	all := []AnswerMode{
		ModeProblemExplanation, ModeCurrentStateSummary, ModeTimeRangeOutageSummary,
		ModeModuleHealthSummary, ModeTopologyPathExplanation, ModeEvidenceExplanation,
		ModeMissingEvidenceExplained, ModeItsmUpdate, ModeShiftHandoff, ModeExecutiveSummary,
		ModeProductNavigationHelp, ModeProductAnswer, ModeInvestigationPlan,
		ModeTroubleshootFinding, ModeNocFocusRecommendation, ModeIncidentStatusBreakdown,
		ModeTopIncidentExplanation, ModeUnavailable,
	}
	modelModes := map[AnswerMode]ModelTier{
		ModeProblemExplanation:  TierStrong,
		ModeTroubleshootFinding: TierStrong,
		ModeCurrentStateSummary: TierFast,
		ModeModuleHealthSummary: TierFast,
	}
	deterministic := 0
	for _, m := range all {
		r := RouteFor(m)
		want, isModel := modelModes[m]
		switch {
		case isModel:
			if !r.UseLLM || r.Tier != want || !r.Verify {
				t.Errorf("%s: want a verified %s model route, got %+v", m, want, r)
			}
		default:
			deterministic++
			if r.UseLLM || r.Verify || r.Tier != TierDeterministic {
				t.Errorf("%s: want a deterministic route (no provider call), got %+v", m, r)
			}
		}
	}
	if deterministic != len(all)-len(modelModes) {
		t.Fatalf("deterministic modes = %d, want %d", deterministic, len(all)-len(modelModes))
	}
	// An unknown / future mode falls to the switch default: deterministic, which
	// is the fail-closed direction (a new mode cannot silently start spending).
	if r := RouteFor(AnswerMode("a_mode_nobody_has_written_yet")); r.UseLLM {
		t.Errorf("an unknown mode must be deterministic, got %+v", r)
	}
}

// TestOrchestratorRoutesByTier: the end-to-end mechanism. For a spread of real
// questions, whatever mode the orchestrator LANDS in, the provider call it made
// (or did not make) matches RouteFor for exactly that mode.
//
// This is the cost-regression assertion item 9 owes: a deterministic answer makes
// ZERO provider calls, tiered or otherwise.
func TestOrchestratorRoutesByTier(t *testing.T) {
	questions := []struct {
		q   string
		ctx map[string]string
	}{
		{"explain this", map[string]string{"correlation_id": "pa"}}, // problem_explanation → strong
		{"what is going on right now?", nil},                        // current_state_summary → fast
		{"show me the top talkers", nil},                            // module_health_summary → fast
		{"what happened overnight", nil},                            // time_range → deterministic
		{"give me the shift handoff", nil},                          // shift_handoff → deterministic
		{"where do I configure servicenow", nil},                    // navigation → deterministic
		{"how do I troubleshoot a bgp flap", nil},                   // KB plan → deterministic
		{"show me the critical incidents", nil},                     // incident list → deterministic
		{"what should the NOC focus on first?", nil},                // noc focus → deterministic
	}
	for _, c := range questions {
		ds := newMockDS()
		spy := &tierSpy{reply: "Likely BGP session loss on edge-1 [log:os:1]. Next: check the peering link."}
		o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: spy, Flags: func(string) bool { return false }}
		ans, err := o.Ask(context.Background(), opsA(), c.q, c.ctx)
		if err != nil {
			t.Fatalf("%q: %v", c.q, err)
		}
		tiers, untiered := spy.calls()
		if untiered != 0 {
			t.Errorf("%q (mode %s): %d completions bypassed the tier seam", c.q, ans.Mode, untiered)
		}
		route := RouteFor(ans.Mode)
		if !route.UseLLM {
			if len(tiers) != 0 {
				t.Errorf("%q: mode %s is deterministic but made %d provider call(s) at tiers %v",
					c.q, ans.Mode, len(tiers), tiers)
			}
			continue
		}
		if len(tiers) != 1 {
			t.Errorf("%q: mode %s wanted exactly one provider call, got %d (%v)", c.q, ans.Mode, len(tiers), tiers)
			continue
		}
		if tiers[0] != route.Tier {
			t.Errorf("%q: mode %s called tier %q, want %q", c.q, ans.Mode, tiers[0], route.Tier)
		}
	}
}

// TestOrchestratorUntieredClientUnchanged: an LLMClient that does NOT implement
// TieredLLMClient is still called through Complete. This is the back-compat
// contract for every existing adapter and test stub in the tree.
func TestOrchestratorUntieredClientUnchanged(t *testing.T) {
	ds := newMockDS()
	plain := &plainSpy{reply: "Likely BGP session loss on edge-1 [log:os:1]."}
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: plain, Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), opsA(), "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeProblemExplanation {
		t.Fatalf("mode = %s, want problem_explanation", ans.Mode)
	}
	if plain.count() != 1 {
		t.Fatalf("an untiered client must still be called exactly once, got %d", plain.count())
	}
	if ans.EvidenceOnly {
		t.Error("an untiered client must still produce a model narrative, not the evidence-only fallback")
	}
}

// TestCompleteTierWithoutProviderIsHonest: an orchestrator built with no LLM
// seam returns ErrNoProvider instead of panicking — the three orchestrator call
// sites dereferenced o.LLM unguarded before, and every one of them treats an
// error as "fall back to the deterministic, evidence-only answer".
func TestCompleteTierWithoutProviderIsHonest(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), Flags: func(string) bool { return false }}
	if _, _, err := o.completeTier(context.Background(), TierStrong, "sys", nil); err == nil {
		t.Fatal("a missing provider must be an error, not an empty success")
	}
	ans, err := o.Ask(context.Background(), opsA(), "explain this", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatalf("a key-free deployment must still answer: %v", err)
	}
	if !ans.EvidenceOnly {
		t.Error("with no provider the answer must be marked evidence-only")
	}
}
