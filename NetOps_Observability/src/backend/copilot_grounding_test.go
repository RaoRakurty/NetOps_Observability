// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/ratelimit"
)

// copilot_grounding_test.go — tracker 330.
//
// /api/copilot/chat is NOT the grounded engine, and the SPA now labels whatever
// comes back from it. That label has to come from the server, because only the
// server knows whether the answer had any evidence behind it: a plain provider
// completion, an agent-loop turn that actually investigated, and the
// grounded-engine fallback all return through this one handler.
//
// These tests pin the one claim the UI reads: `is_grounded`.

// groundingTestServer is the minimum server the chat handler needs: a rate
// limiter, the role grid (the engine fallback derives its principal from it),
// the tenant entitlement store and a platform config store.
func groundingTestServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	rs, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	return &server{
		roles:          rs,
		copilotLimiter: ratelimit.New(),
		aiToolBudget:   ai.NewDailyBudget(),
		copilotCfg:     newCopilotConfigStore(dir+"/copilot_config.json", nil),
		aiTenantCfg:    newAITenantConfigStore(dir+"/ai_tenant_config.json", nil),
	}
}

// cannedProvider answers every provider call with one OpenAI-shaped completion.
type cannedProvider struct {
	status int
	body   string
}

func (c cannedProvider) RoundTrip(r *http.Request) (*http.Response, error) {
	st := c.status
	if st == 0 {
		st = http.StatusOK
	}
	body := c.body
	if body == "" {
		body = `{"choices":[{"message":{"content":"BGP flaps usually mean a link problem."}}]}`
	}
	return &http.Response{
		StatusCode: st,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    r,
	}, nil
}

// chatOnce drives the real handler and returns the decoded response body.
func chatOnce(t *testing.T, s *server, claims jwtClaims, question string) map[string]any {
	t.Helper()
	body, err := json.Marshal(copilotRequest{Messages: []copilotMessage{{Role: "user", Content: question}}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/copilot/chat", strings.NewReader(string(body)))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, claims))
	w := httptest.NewRecorder()
	s.handleCopilot(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("handleCopilot = %d, body %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v (%s)", err, w.Body.String())
	}
	return out
}

// TestPlainChatAnswerIsReportedUngrounded is the defect's server half: a plain
// provider completion reads no tenant evidence and verifies no citation, so it
// must say so. Before tracker 330 the field did not exist and the UI rendered
// this answer beneath "Answers are grounded, tenant-scoped and cited".
func TestPlainChatAnswerIsReportedUngrounded(t *testing.T) {
	t.Setenv("FEATURE_COPILOT", "true")
	t.Setenv("FEATURE_AI_TOOLS", "")
	restore := ai.SwapProviderHTTPForTest(&http.Client{Transport: cannedProvider{}})
	defer restore()

	s := groundingTestServer(t)
	// A tenant with its own key: the production state that used to un-ground the
	// assistant silently.
	if _, err := s.aiTenantCfg.SetTenantSettings("t-a", ai.TenantSettings{Provider: "openai", Model: "gpt-4o-mini", Key: "sk-test"}); err != nil {
		t.Fatal(err)
	}

	out := chatOnce(t, s, jwtClaims{Tenant: "t-a", Sub: "u", Role: "viewer"}, "why do BGP sessions flap?")

	got, ok := out["is_grounded"]
	if !ok {
		t.Fatal("the chat response must STATE its grounding — is_grounded is missing, so the UI would have to guess")
	}
	if got != false {
		t.Fatalf("a plain provider completion claimed is_grounded=%v", got)
	}
	if txt, _ := out["text"].(string); !strings.Contains(txt, "BGP flaps") {
		t.Fatalf("the answer itself must still come through, got %q", txt)
	}
	if _, isGroundedAnswer := out["grounded"]; isGroundedAnswer {
		t.Fatal("no grounded answer object should be present on a plain completion")
	}
}

// TestGroundingFlagIsAbsentOnNoAnswer — a turn that produces no answer at all
// must not leave a stale, reassuring flag behind. The handler refuses (503/502)
// rather than returning a body the UI could label.
func TestUnconfiguredProviderNeverClaimsGrounding(t *testing.T) {
	t.Setenv("FEATURE_COPILOT", "true")
	t.Setenv("FEATURE_AI_TOOLS", "")
	// No key anywhere: providerCandidates is empty → 503, no body to mislabel.
	for _, k := range []string{"OPENAI_API_KEY", "GEMINI_API_KEY", "GOOGLE_API_KEY", "ANTHROPIC_API_KEY", "COPILOT_API_KEY"} {
		t.Setenv(k, "")
	}
	s := groundingTestServer(t)
	body, _ := json.Marshal(copilotRequest{Messages: []copilotMessage{{Role: "user", Content: "hello"}}})
	r := httptest.NewRequest(http.MethodPost, "/api/copilot/chat", strings.NewReader(string(body)))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, jwtClaims{Tenant: "t-a", Sub: "u"}))
	w := httptest.NewRecorder()
	s.handleCopilot(w, r)
	if w.Code == http.StatusOK {
		t.Fatalf("an unconfigured provider must not answer 200: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "is_grounded") {
		t.Fatal("an error body must not carry a grounding claim")
	}
}

// TestProviderDownFallbackIsReportedGrounded — when no provider can be reached
// the GROUNDED orchestrator answers instead (owner decision 2026-07-02). That
// answer is tenant-scoped, redacted and cited, so the same field that condemns a
// plain completion must vouch for this one. A flag that is always false would
// pass the test above and still be useless.
func TestProviderDownFallbackIsReportedGrounded(t *testing.T) {
	t.Setenv("FEATURE_COPILOT", "true")
	t.Setenv("FEATURE_AI", "true")
	t.Setenv("FEATURE_AI_TOOLS", "")
	// Every provider attempt fails → the chain exhausts → engine fallback.
	restore := ai.SwapProviderHTTPForTest(&http.Client{Transport: cannedProvider{status: http.StatusInternalServerError, body: `{"error":"boom"}`}})
	defer restore()

	s := groundingTestServer(t)
	if _, err := s.aiTenantCfg.SetTenantSettings("t-a", ai.TenantSettings{Provider: "openai", Model: "gpt-4o-mini", Key: "sk-test"}); err != nil {
		t.Fatal(err)
	}

	// A question the engine answers WITHOUT reading tenant data (the capability
	// clarification), so the fallback is exercised without a storage backend.
	out := chatOnce(t, s, jwtClaims{Tenant: "t-a", Sub: "u", Role: "viewer"}, "qqq zzz")

	if out["is_grounded"] != true {
		t.Fatalf("the grounded-engine fallback must report is_grounded=true, got %v", out["is_grounded"])
	}
	if out["provider"] != "engine" {
		t.Fatalf("expected the engine fallback, got provider %v", out["provider"])
	}
	if _, ok := out["grounded"]; !ok {
		t.Fatal("the engine fallback must carry its structured answer for the rich card")
	}
	if out["fallback"] != "provider_unavailable" {
		t.Fatalf("the provider-down disclosure must survive, got %v", out["fallback"])
	}
}
