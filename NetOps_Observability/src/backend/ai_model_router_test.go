// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/ai"
)

// ai_model_router_test.go — the SERVER half of the §10 model router (review
// item 9): a tier resolves to a model name inside the per-principal provider
// chain, and doing so changes NOTHING about which provider or which key is used.
//
// The invariants, in the order they matter:
//
//  1. back-compat — one configured Model serves every tier, so an existing
//     deployment's cost and behaviour are untouched;
//  2. the split — once ModelFast/ModelStrong are set, the tier picks the model;
//  3. BYO is preserved exactly — a tenant's own key still wins outright, a
//     tenant's own tier overrides ride that key, and a strict tenant still gets
//     NOTHING rather than riding the platform key at any tier.

// aiRouterEnv clears every out-of-band provider key so the chain under test is
// only what the case configures.
func aiRouterEnv(t *testing.T) {
	t.Helper()
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")
	t.Setenv("COPILOT_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "sk-platform-anthropic")
	t.Setenv("COPILOT_PROVIDER", "anthropic")
	t.Setenv("COPILOT_MODEL", "claude-sonnet-4-6")
}

// TestProviderTierBackCompatSingleModel: with ONE model configured, every tier —
// including the tier-less copilot path — resolves to that model, from the same
// provider, with the same key. This is the promise made to every deployment that
// upgrades into the router without touching its settings.
func TestProviderTierBackCompatSingleModel(t *testing.T) {
	aiRouterEnv(t)
	s := aiCfgTestServer(t)
	s.copilotCfg.Set(ai.CopilotConfig{Provider: "anthropic", Model: "claude-sonnet-4-6"})

	claims := jwtClaims{Role: "viewer", Tenant: "t-a"}
	for _, tier := range []ai.ModelTier{"", ai.TierDeterministic, ai.TierFast, ai.TierStrong} {
		cands := s.providerCandidatesForTier(claims, tier)
		if len(cands) != 1 {
			t.Fatalf("tier %q: want one candidate, got %+v", tier, cands)
		}
		if cands[0].model != "claude-sonnet-4-6" || cands[0].name != "anthropic" ||
			cands[0].key != "sk-platform-anthropic" || cands[0].source != "platform" {
			t.Errorf("tier %q: single-model config must resolve unchanged, got %+v", tier, cands[0])
		}
	}
	// The tier-less helper the copilot proxy uses must agree with tier "".
	if a, b := s.providerCandidates(claims), s.providerCandidatesForTier(claims, ""); len(a) != len(b) || a[0] != b[0] {
		t.Errorf("providerCandidates must equal the untiered chain: %+v vs %+v", a, b)
	}
}

// TestProviderTierPlatformSplit: once the operator names a fast and a strong
// model, each tier calls its own model — and the provider and key are the same
// for both, because a tier is a model choice inside ONE provider account.
func TestProviderTierPlatformSplit(t *testing.T) {
	aiRouterEnv(t)
	s := aiCfgTestServer(t)
	s.copilotCfg.Set(ai.CopilotConfig{
		Provider: "anthropic", Model: "claude-sonnet-4-6",
		ModelFast: "claude-haiku-4-5-20251001", ModelStrong: "claude-opus-4-8",
	})
	claims := jwtClaims{Role: "viewer", Tenant: "t-a"}
	want := map[ai.ModelTier]string{
		ai.TierFast:          "claude-haiku-4-5-20251001",
		ai.TierStrong:        "claude-opus-4-8",
		ai.TierDeterministic: "claude-sonnet-4-6",
		"":                   "claude-sonnet-4-6",
	}
	for tier, model := range want {
		cands := s.providerCandidatesForTier(claims, tier)
		if len(cands) != 1 {
			t.Fatalf("tier %q: want one candidate, got %+v", tier, cands)
		}
		if cands[0].model != model {
			t.Errorf("tier %q: model = %q, want %q", tier, cands[0].model, model)
		}
		if cands[0].name != "anthropic" || cands[0].key != "sk-platform-anthropic" {
			t.Errorf("tier %q: the tier must not change provider or key, got %+v", tier, cands[0])
		}
	}
	// A half-configured split still resolves the unset tier to the default model.
	s.copilotCfg.Set(ai.CopilotConfig{Provider: "anthropic", Model: "claude-sonnet-4-6", ModelFast: "claude-haiku-4-5-20251001"})
	if c := s.providerCandidatesForTier(claims, ai.TierStrong); len(c) != 1 || c[0].model != "claude-sonnet-4-6" {
		t.Errorf("an unset strong tier must fall back to the default model, got %+v", c)
	}
}

// TestProviderTierTenantOverridesWin: a tenant that brought its own key also
// brings its own per-tier models, and those win over the platform's — for the
// tenant, and only for the tenant. The platform owner and every other tenant are
// untouched, which is the §3a half of this feature.
func TestProviderTierTenantOverridesWin(t *testing.T) {
	aiRouterEnv(t)
	s := aiCfgTestServer(t)
	s.copilotCfg.Set(ai.CopilotConfig{
		Provider: "anthropic", Model: "claude-sonnet-4-6",
		ModelFast: "platform-fast", ModelStrong: "platform-strong",
	})
	if _, err := s.aiTenantCfg.SetTenantSettings("t-a", ai.TenantSettings{
		Provider: "openai", Model: "gpt-4o", ModelFast: "gpt-4o-mini", ModelStrong: "gpt-4.1",
		Key: "sk-tenant-a",
	}); err != nil {
		t.Fatal(err)
	}
	a := jwtClaims{Role: "viewer", Tenant: "t-a"}
	want := map[ai.ModelTier]string{
		ai.TierFast:          "gpt-4o-mini",
		ai.TierStrong:        "gpt-4.1",
		ai.TierDeterministic: "gpt-4o",
		"":                   "gpt-4o",
	}
	for tier, model := range want {
		cands := s.providerCandidatesForTier(a, tier)
		if len(cands) != 1 || cands[0].source != "tenant" {
			t.Fatalf("tier %q: a BYO tenant must resolve to exactly its own candidate, got %+v", tier, cands)
		}
		if cands[0].model != model {
			t.Errorf("tier %q: tenant model = %q, want %q", tier, cands[0].model, model)
		}
		if cands[0].key != "sk-tenant-a" || cands[0].name != "openai" {
			t.Errorf("tier %q: the BYO provider/key must be unchanged by the tier, got %+v", tier, cands[0])
		}
	}

	// A tenant that set only a default model still gets that model at every tier
	// (it never inherits the PLATFORM's fast/strong choice — different account).
	if _, err := s.aiTenantCfg.SetTenantSettings("t-c", ai.TenantSettings{
		Provider: "anthropic", Model: "tenant-c-only", Key: "sk-tenant-c",
	}); err != nil {
		t.Fatal(err)
	}
	for _, tier := range []ai.ModelTier{ai.TierFast, ai.TierStrong} {
		c := s.providerCandidatesForTier(jwtClaims{Role: "viewer", Tenant: "t-c"}, tier)
		if len(c) != 1 || c[0].model != "tenant-c-only" {
			t.Errorf("tier %q: a single-model tenant must not inherit the platform's tier models, got %+v", tier, c)
		}
	}

	// No leak in either direction: another tenant and the platform owner keep the
	// PLATFORM's tier models and never see tenant A's key.
	for _, c := range []jwtClaims{{Role: "viewer", Tenant: "t-b"}, aiPlatformOwn} {
		got := s.providerCandidatesForTier(c, ai.TierStrong)
		if len(got) != 1 || got[0].source != "platform" || got[0].model != "platform-strong" {
			t.Errorf("%s must keep the platform strong model, got %+v", c.Tenant, got)
		}
		if got[0].key == "sk-tenant-a" {
			t.Fatalf("CROSS-TENANT LEAK: tenant A's key resolved for %s", c.Tenant)
		}
	}
}

// TestProviderTierStrictTenantStillGetsNothing: `no_platform_key` is a hard
// refusal, and the tier cannot be used to get around it. A strict tenant with no
// key of its own resolves to NOTHING at every tier — including the cheap one,
// which is exactly the direction a cost feature would be tempted to leak.
func TestProviderTierStrictTenantStillGetsNothing(t *testing.T) {
	aiRouterEnv(t)
	s := aiCfgTestServer(t)
	s.copilotCfg.Set(ai.CopilotConfig{
		Provider: "anthropic", Model: "claude-sonnet-4-6",
		ModelFast: "platform-fast", ModelStrong: "platform-strong",
	})
	if _, err := s.aiTenantCfg.SetTenantSettings("t-strict", ai.TenantSettings{NoPlatformKey: true}); err != nil {
		t.Fatal(err)
	}
	// Even with per-tier models configured on their record but NO key: a model
	// name is not a credential, and it must not conjure a candidate.
	if _, err := s.aiTenantCfg.SetTenantSettings("t-strict2", ai.TenantSettings{
		Model: "wishful", ModelFast: "wishful-fast", ModelStrong: "wishful-strong", NoPlatformKey: true,
	}); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"t-strict", "t-strict2"} {
		for _, tier := range []ai.ModelTier{"", ai.TierDeterministic, ai.TierFast, ai.TierStrong} {
			if c := s.providerCandidatesForTier(jwtClaims{Role: "viewer", Tenant: tenant}, tier); c != nil {
				t.Errorf("%s tier %q: a strict tenant must get no provider, got %+v", tenant, tier, c)
			}
		}
	}
}

// TestAILLMImplementsTieredClient: the server's adapter must satisfy the tiered
// seam, or every answer silently falls back to the single-model path and this
// whole item is inert. Compile-time assertion plus the interface check.
func TestAILLMImplementsTieredClient(t *testing.T) {
	var c ai.LLMClient = aiLLM{}
	if _, ok := c.(ai.TieredLLMClient); !ok {
		t.Fatal("aiLLM must implement ai.TieredLLMClient — otherwise the router's tiers never reach a provider")
	}
}
