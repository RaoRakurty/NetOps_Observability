// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/ai"
)

// Owner 2026-11-12: the Test shows each tier model's own verdict and latency,
// so a slow or failing tier model (the lab's default alias) is visible before
// it is saved. Each distinct model is called once; blanks are the provider's
// recommended tier models. No real provider is called.
func TestConnectionTestReportsEveryTierModel(t *testing.T) {
	clearAIEnv(t)
	s := aiCfgTestServer(t)
	var mu sync.Mutex
	var hits []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits = append(hits, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/gemini-flash-latest:") {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(geminiNotFound))
			return
		}
		_, _ = w.Write([]byte(geminiOK))
	}))
	defer srv.Close()
	t.Cleanup(ai.SwapGeminiBaseForTest(srv.URL + "/v1beta/models/"))
	body := fmt.Sprintf(`{"provider":"gemini","key":%q,"model":"gemini-flash-latest","model_fast":"","model_strong":""}`, draftKey)
	code, m, raw := doJSON(t, s.handleCopilotConfigTest, http.MethodPost, "/api/copilot/config/test", body, aiPlatformOwn)
	if code != http.StatusOK {
		t.Fatalf("test: %d %s", code, raw)
	}
	tiers, _ := m["tiers"].([]any)
	if len(tiers) != 3 {
		t.Fatalf("one verdict per tier: %s", raw)
	}
	want := map[string]struct {
		model string
		ok    bool
	}{"default": {"gemini-flash-latest", false}, "fast": {"gemini-flash-lite-latest", true}, "strong": {"gemini-2.5-flash", true}}
	for _, x := range tiers {
		tp, _ := x.(map[string]any)
		tier, _ := tp["tier"].(string)
		w, known := want[tier]
		if !known || tp["model"] != w.model || tp["ok"] != w.ok {
			t.Errorf("tier verdict %v, want %+v", tp, w)
		}
		if _, has := tp["latency_ms"]; !has {
			t.Errorf("tier %v carries no latency", tp)
		}
		if !w.ok && tp["error_class"] != ai.ProvModelNotFound {
			t.Errorf("a failing tier names its error class: %v", tp)
		}
	}
	mu.Lock()
	n := len(hits)
	mu.Unlock()
	if n != 3 {
		t.Fatalf("each distinct model once (the fast verdict is reused for the top-level fields): %v", hits)
	}
	if strings.Contains(raw, draftKey) {
		t.Fatal("the key must never be echoed")
	}
	if code, _, _ := doJSON(t, s.handleCopilotConfigTest, http.MethodPost, "/api/copilot/config/test",
		fmt.Sprintf(`{"provider":"gemini","key":%q,"model_fast":"../x"}`, draftKey), aiPlatformOwn); code != http.StatusBadRequest {
		t.Fatalf("an invalid tier model name is refused: %d", code)
	}
}
