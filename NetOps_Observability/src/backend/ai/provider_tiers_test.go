// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"sync"
	"testing"
)

// Owner decision 2026-11-12: a blank tier is the provider's recommended model
// for that tier, never the single default again.
func TestForProviderUsesTheRecommendedTierModel(t *testing.T) {
	rec := RecommendedModels()["gemini"]
	lab := TierModels{Default: "gemini-flash-latest"} // the lab's config that day
	for tier, want := range map[ModelTier]string{
		TierFast: rec.Fast, TierStrong: rec.Strong, TierDeterministic: "gemini-flash-latest", "": "gemini-flash-latest",
	} {
		if got := lab.ForProvider(tier, "gemini"); got != want {
			t.Errorf("ForProvider(%q) = %q, want %q", tier, got, want)
		}
	}
	set := TierModels{Default: "d", Fast: "f", Strong: "s"}
	for tier, want := range map[ModelTier]string{TierFast: "f", TierStrong: "s", "": "d"} {
		if got := set.ForProvider(tier, "gemini"); got != want {
			t.Errorf("an explicit tier model wins: ForProvider(%q) = %q, want %q", tier, got, want)
		}
	}
	if got := (TierModels{}).ForProvider("", "gemini"); got != rec.Default {
		t.Errorf("nothing configured: the recommended default, got %q", got)
	}
	if got := (TierModels{Default: "x"}).ForProvider(TierFast, "unknown-provider"); got != "x" {
		t.Errorf("an unknown provider has no recommendation: the default, got %q", got)
	}
}

// The Gemini recommendation is the probe-verified set of 2026-11-12, not the
// moving alias that timed out.
func TestGeminiRecommendationIsTheVerifiedSet(t *testing.T) {
	rec := RecommendedModels()["gemini"]
	if rec.Default != "gemini-2.5-flash" || rec.Strong != "gemini-2.5-flash" || rec.Fast != "gemini-flash-lite-latest" {
		t.Fatalf("gemini recommendation = %+v", rec)
	}
	if ModelSuggestions()["gemini"][0] != rec.Default {
		t.Fatal("the recommended default leads the suggestions")
	}
}

// Each distinct tier model is tested once, and every tier reports its own
// verdict and latency.
func TestProbeTiersTestsEachModelOnce(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	probe := func(model string) ProbeResult {
		mu.Lock()
		calls[model]++
		mu.Unlock()
		if model == "gemini-flash-latest" {
			return ProbeResult{OK: false, Model: model, LatencyMS: 10000, ErrorClass: ProvTimeout}
		}
		return ProbeResult{OK: true, Model: model, LatencyMS: 600}
	}
	got := ProbeTiers("gemini", TierModels{Default: "gemini-flash-latest"}, probe)
	if len(got) != 3 || got[0].Tier != "default" || got[1].Tier != "fast" || got[2].Tier != "strong" {
		t.Fatalf("tiers = %+v", got)
	}
	if got[0].OK || got[0].ErrorClass != ProvTimeout || got[0].LatencyMS != 10000 {
		t.Errorf("the default tier's own verdict: %+v", got[0])
	}
	if !got[1].OK || got[1].Model != "gemini-flash-lite-latest" || !got[2].OK || got[2].Model != "gemini-2.5-flash" {
		t.Errorf("the recommended tier models answer: %+v", got[1:])
	}
	for m, n := range calls {
		if n != 1 {
			t.Errorf("%s probed %d times, want once", m, n)
		}
	}
	// One model for every tier: one call.
	calls = map[string]int{}
	ProbeTiers("gemini", TierModels{Default: "m", Fast: "m", Strong: "m"}, probe)
	if len(calls) != 1 || calls["m"] != 1 {
		t.Fatalf("one model, one call: %v", calls)
	}
}

// The model fallback (2026-11-12): one other model of the SAME provider, never
// dearer than the recommended default — the default, or the fast pick when the
// failed model already is the default; nothing for an unknown provider.
func TestFallbackModel(t *testing.T) {
	rec := RecommendedModels()
	for _, p := range []string{"gemini", "openai", "anthropic"} {
		r := rec[p]
		if got := FallbackModel(p, "some-alias-latest"); got != r.Default {
			t.Errorf("%s: a non-default model falls back to the default %q, got %q", p, r.Default, got)
		}
		if got := FallbackModel(p, " "+r.Default+" "); r.Fast != r.Default && got != r.Fast {
			t.Errorf("%s: the default falls back to the fast pick %q, got %q", p, r.Fast, got)
		}
		if FallbackModel(p, r.Default) == r.Default {
			t.Errorf("%s: a model never falls back to itself", p)
		}
		if got := FallbackModel(p, r.Strong); r.Strong != r.Default && got != r.Default {
			t.Errorf("%s: the strong pick falls back to the default (never dearer), got %q", p, got)
		}
	}
	if got := FallbackModel("gemini", "gemini-flash-latest"); got != "gemini-2.5-flash" {
		t.Fatalf("the lab case: gemini-flash-latest → %q, want gemini-2.5-flash", got)
	}
	if FallbackModel("google", "x") != rec["gemini"].Default {
		t.Fatal("provider aliases normalise")
	}
	if FallbackModel("mistral", "x") != "" {
		t.Fatal("an unknown provider has no fallback")
	}
	// openai's default and fast are the same model: the default has no fallback.
	if r := rec["openai"]; r.Default == r.Fast && FallbackModel("openai", r.Default) != "" {
		t.Fatal("no fallback when the default is also the fast pick")
	}
}
