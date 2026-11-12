// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_provider_probe_test.go — "Connect a model" handlers (tracker 337 plan
// C3/C5, D4): Test connection is platform-admin only and never keeps, logs or
// echoes the key; the tenant test uses ONLY the caller's own key (§3a); the
// banner's config views are admin-only and carry the budget status.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/ai"
)

func doJSON(t *testing.T, h http.HandlerFunc, method, path, body string, c jwtClaims) (int, map[string]any, string) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	h(w, claimsCtx(r, c))
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return w.Code, m, w.Body.String()
}

func TestCopilotConfigTestIsPlatformAdminOnlyAndNeverKeepsTheKey(t *testing.T) {
	clearAIEnv(t)
	s := aiCfgTestServer(t)
	g := startFakeGemini(t, 200, geminiOK)
	logs := captureProviderLogs(t)
	body := fmt.Sprintf(`{"provider":"gemini","key":%q}`, draftKey)
	for _, c := range []jwtClaims{aiTenantAdminA, aiTenantUserA} {
		if code, _, _ := doJSON(t, s.handleCopilotConfigTest, http.MethodPost, "/api/copilot/config/test", body, c); code != http.StatusForbidden {
			t.Fatalf("%s/%s must get 403, got %d", c.Tenant, c.Role, code)
		}
	}
	if g.hits() != 0 {
		t.Fatal("a refused caller must not reach the provider")
	}
	code, m, raw := doJSON(t, s.handleCopilotConfigTest, http.MethodPost, "/api/copilot/config/test", body, aiPlatformOwn)
	if code != http.StatusOK || m["ok"] != true || m["provider"] != "gemini" || m["model"] != ai.RecommendedModels()["gemini"].Fast {
		t.Fatalf("test: %d %s", code, raw)
	}
	if _, ok := m["latency_ms"]; !ok {
		t.Fatalf("latency_ms missing: %s", raw)
	}
	if g.keys[0] != draftKey {
		t.Fatalf("the pasted key must be the one tested: %v", g.keys)
	}
	if strings.Contains(raw, draftKey) || strings.Contains(raw, "OK\"") && strings.Contains(raw, "text") {
		t.Fatalf("the response must carry neither the key nor the provider's text: %s", raw)
	}
	if s.copilotCfg.APIKey() != "" {
		t.Fatal("a test must NEVER persist the key")
	}
	logs.mustNotContain(t, draftKey)
	// The verdict shows up as last_test on the config view.
	_, view, _ := doJSON(t, s.handleCopilotConfig, http.MethodGet, "/api/copilot/config", "", aiPlatformOwn)
	if lt, _ := view["last_test"].(map[string]any); lt == nil || lt["ok"] != true {
		t.Fatalf("last_test = %v", view["last_test"])
	}
	// A failing key: closed error class, no provider message.
	g.set(400, geminiBadKey)
	_, m, raw = doJSON(t, s.handleCopilotConfigTest, http.MethodPost, "/api/copilot/config/test", body, aiPlatformOwn)
	if m["ok"] != false || m["error_class"] != ai.ProvAuth || strings.Contains(raw, "API key not valid") {
		t.Fatalf("failed test: %s", raw)
	}
	// No key anywhere → 400, no call.
	before := g.hits()
	if code, _, _ := doJSON(t, s.handleCopilotConfigTest, http.MethodPost, "/api/copilot/config/test", `{"provider":"gemini"}`, aiPlatformOwn); code != http.StatusBadRequest || g.hits() != before {
		t.Fatalf("blank key with nothing stored: %d", code)
	}
	// Junk is refused before any call.
	for _, b := range []string{`{"provider":"grok","key":"x"}`, `{"provider":"gemini","key":"x","model":"../../x"}`, `not json`} {
		if code, _, _ := doJSON(t, s.handleCopilotConfigTest, http.MethodPost, "/api/copilot/config/test", b, aiPlatformOwn); code != http.StatusBadRequest {
			t.Fatalf("%s → %d, want 400", b, code)
		}
	}
	if g.hits() != before {
		t.Fatal("invalid requests must not reach the provider")
	}
}

// §3a: a tenant admin's test uses THEIR OWN key — never the platform key and
// never another tenant's; as_tenant in the URL is ignored.
func TestTenantConfigTestUsesOnlyTheCallersOwnKey(t *testing.T) {
	s := platformGeminiServer(t) // platform key present
	if _, err := s.aiTenantCfg.SetTenantSettings("t-a", ai.TenantSettings{Provider: "gemini", Key: tenantAKey}); err != nil {
		t.Fatal(err)
	}
	g := startFakeGemini(t, 200, geminiOK)
	logs := captureProviderLogs(t)
	h := s.handleAITenantConfigTest
	code, m, raw := doJSON(t, h, http.MethodPost, "/api/ai/tenant-config/test?as_tenant=t-b", `{}`, aiTenantAdminA)
	if code != http.StatusOK || m["ok"] != true || g.hits() == 0 {
		t.Fatalf("tenant A: %d %s keys=%v", code, raw, g.keys)
	}
	// Every tier model was tested (2026-11-12), each with tenant A's own key.
	for _, k := range g.keys {
		if k != tenantAKey {
			t.Fatalf("tenant A's test must use only its own key: %v", g.keys)
		}
	}
	afterA := g.hits()
	// Tenant B has no key of its own: refused, and the platform key is NOT tested.
	code, _, _ = doJSON(t, h, http.MethodPost, "/api/ai/tenant-config/test?as_tenant=t-a", `{}`, aiTenantAdminB)
	if code != http.StatusBadRequest || g.hits() != afterA {
		t.Fatalf("tenant B without a key: %d hits=%d keys=%v", code, g.hits(), g.keys)
	}
	// B pastes a draft key: that key, and only for this call.
	code, _, _ = doJSON(t, h, http.MethodPost, "/api/ai/tenant-config/test", fmt.Sprintf(`{"provider":"gemini","key":%q}`, draftKey), aiTenantAdminB)
	if code != http.StatusOK || g.hits() <= afterA || g.keys[afterA] != draftKey {
		t.Fatalf("tenant B draft: %d keys=%v", code, g.keys)
	}
	if _, _, _, has := s.aiTenantCfg.BYOProvider("t-b", "", providerModel); has {
		t.Fatal("a test must never store the key")
	}
	for _, k := range g.keys {
		if k == platformKey {
			t.Fatal("ISOLATION: a tenant test reached the PLATFORM key")
		}
	}
	// A viewer and the platform owner are refused here.
	if code, _, _ := doJSON(t, h, http.MethodPost, "/api/ai/tenant-config/test", `{}`, aiTenantUserA); code != http.StatusForbidden {
		t.Fatalf("viewer: %d", code)
	}
	if code, _, _ := doJSON(t, h, http.MethodPost, "/api/ai/tenant-config/test", `{}`, aiPlatformOwn); code != http.StatusBadRequest {
		t.Fatalf("platform owner: %d", code)
	}
	logs.mustNotContain(t, tenantAKey, draftKey, platformKey)
}

// C5/D4: the banner's sources are admin-only; the platform view carries the
// recommended models and the budget status; the default is 1 M tokens/day.
func TestConfigViewIsAdminOnlyAndCarriesBudget(t *testing.T) {
	clearAIEnv(t)
	s := aiCfgTestServer(t)
	for _, c := range []jwtClaims{aiTenantUserA, aiTenantAdminA} {
		if code, _, _ := doJSON(t, s.handleCopilotConfig, http.MethodGet, "/api/copilot/config", "", c); code != http.StatusForbidden {
			t.Fatalf("%s/%s: platform config must be 403, got %d", c.Tenant, c.Role, code)
		}
	}
	if code, _, _ := doJSON(t, s.handleAITenantConfig, http.MethodGet, "/api/ai/tenant-config", "", aiTenantUserA); code != http.StatusForbidden {
		t.Fatalf("viewer: tenant config must be 403, got %d", code)
	}
	if aiToolsDailyTokens() != 1_000_000 {
		t.Fatalf("D4 default = %d, want 1000000", aiToolsDailyTokens())
	}
	s.aiToolBudget.Charge("t-a", 1_000_000)
	code, m, raw := doJSON(t, s.handleCopilotConfig, http.MethodGet, "/api/copilot/config", "", aiPlatformOwn)
	if code != http.StatusOK || m["provider"] != "gemini" || m["key_source"] != "none" {
		t.Fatalf("platform view: %d %s", code, raw)
	}
	rec, _ := m["recommended"].(map[string]any)
	gm, _ := rec["gemini"].(map[string]any)
	want := ai.RecommendedModels()["gemini"]
	if gm["default"] != want.Default || gm["fast"] != want.Fast || gm["strong"] != want.Strong {
		t.Fatalf("recommended = %v", m["recommended"])
	}
	bud, _ := m["budget"].(map[string]any)
	if bud["daily_tokens_default"] != float64(1_000_000) || bud["workspaces_exhausted"] != float64(1) {
		t.Fatalf("platform budget = %v", bud)
	}
	if strings.Contains(raw, "t-a") {
		t.Fatalf("the platform banner counts spent workspaces; it never names them: %s", raw)
	}
	_, ta, _ := doJSON(t, s.handleAITenantConfig, http.MethodGet, "/api/ai/tenant-config", "", aiTenantAdminA)
	if b, _ := ta["budget"].(map[string]any); b["exhausted"] != true {
		t.Fatalf("tenant A budget = %v", ta["budget"])
	}
	_, tb, _ := doJSON(t, s.handleAITenantConfig, http.MethodGet, "/api/ai/tenant-config", "", aiTenantAdminB)
	if b, _ := tb["budget"].(map[string]any); b["exhausted"] != false || b["used_today"] != float64(0) {
		t.Fatalf("ISOLATION: tenant B sees A's spend: %v", tb["budget"])
	}
}
