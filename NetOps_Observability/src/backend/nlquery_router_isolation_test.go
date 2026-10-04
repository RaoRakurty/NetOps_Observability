// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_router_isolation_test.go — the question router's data arm through
// the real /api/ai/ask handler (tracker 337 N-G4).
//
// Pinned: a data question is answered from the NL query engine, in the
// caller's scope only (the read carries only the caller's scope filter); the
// same words from another tenant never reach tenant A's device and fall back
// to the classic path; a principal without infrastructure:read gets no data
// arm at all; a product question is never captured.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/internal/irisconvo"
)

func askIris(t *testing.T, s *server, c jwtClaims, question string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"question": question})
	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", strings.NewReader(string(body)))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIAsk(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("ask %q: %d %s", question, w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestTheIrisBoxAnswersDataQuestionsInScope(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	var mu sync.Mutex
	var filters [][]string
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		filters = append(filters, r.URL.Query()["extra_filters[]"])
		mu.Unlock()
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"values":[[1,"12"],[2,"48"]]}]}}`))
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, b := nlqAPIFixture(t)

	out := askIris(t, s, a, "show cpu on edge-a for the last hour")
	if out["mode"] != "data_query" {
		t.Fatalf("a data question must take the data arm: %v", out)
	}
	if txt, _ := out["text"].(string); !strings.Contains(txt, "peak 48%") {
		t.Fatalf("the answer must summarise the result: %q", txt)
	}
	if !strings.Contains(nlqJSON(out["data"]), "device:dev-a") {
		t.Fatalf("the payload carries the validated query: %v", out["data"])
	}
	mu.Lock()
	got := append([][]string(nil), filters...)
	mu.Unlock()
	if len(got) == 0 || strings.Contains(strings.Join(got[0], " "), "dev-b") {
		t.Fatalf("the read must carry only tenant A's scope: %v", got)
	}

	// Tenant B, same words: A's device is invisible, so the question is not
	// a data question for B (cross-tenant ≡ missing) and nothing is read.
	mu.Lock()
	filters = nil
	mu.Unlock()
	if out := askIris(t, s, b, "show cpu on edge-a for the last hour"); out["mode"] == "data_query" {
		t.Fatalf("tenant B must not get a data answer about tenant A's device: %v", out)
	}
	walker := b
	walker.ActingTenant = a.Tenant // as_tenant smuggled into a non-owner's claims
	if out := askIris(t, s, walker, "show cpu on edge-a for the last hour"); out["mode"] == "data_query" {
		t.Fatalf("an as_tenant walk must not reach tenant A's device: %v", out)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, f := range filters {
		if strings.Contains(strings.Join(f, " "), "dev-a") {
			t.Fatalf("tenant B's asks read tenant A's scope: %v", filters)
		}
	}
}

func TestTheDataArmNeedsInfrastructureRead(t *testing.T) {
	s, a, _ := nlqAPIFixture(t)
	if s.aiNLQuery(httptest.NewRequest(http.MethodPost, "/api/ai/ask", nil), a) == nil {
		t.Fatal("an admin must get the data arm")
	}
	noInfra := a
	noInfra.Role = "ingest"
	if s.aiNLQuery(httptest.NewRequest(http.MethodPost, "/api/ai/ask", nil), noInfra) != nil {
		t.Fatal("a principal without infrastructure:read must not get the data arm")
	}
	s.nlqCatalog = nil
	if s.aiNLQuery(httptest.NewRequest(http.MethodPost, "/api/ai/ask", nil), a) != nil {
		t.Fatal("no catalog, no data arm")
	}
}

func TestProductAndDiagnosticQuestionsKeepTheirPath(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, _ := nlqAPIFixture(t)
	s.copilotCfg = newCopilotConfigStore(t.TempDir()+"/copilot_config.json", nil) // no key: the classic path answers without a model
	for _, q := range []string{"how do I add a device", "what is a seam", "why is cpu high on edge-a"} {
		if out := askIris(t, s, a, q); out["mode"] == "data_query" {
			t.Errorf("%q must not be captured by the data arm: %v", q, out)
		}
	}
}

func askIrisIn(t *testing.T, s *server, c jwtClaims, convID, question string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"question": question, "conversation_id": convID})
	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", strings.NewReader(string(body)))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIAsk(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // best-effort: error bodies are asserted by status
	return w.Code, out
}

func irisBoxFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	t.Setenv("FEATURE_AI", "true")
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"values":[[1,"12"],[2,"48"]]}]}}`))
	}))
	t.Cleanup(vm.Close)
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, b := nlqAPIFixture(t)
	s.nlqConvos = irisconvo.NewMemStore()
	s.copilotCfg = newCopilotConfigStore(t.TempDir()+"/copilot_config.json", nil)
	return s, a, b
}

func TestTheIrisBoxFollowsUpInsideAConversation(t *testing.T) {
	s, a, _ := irisBoxFixture(t)
	id := startConvo(t, s, a)

	code, out := askIrisIn(t, s, a, id, "show cpu on edge-a for the last hour")
	if code != 200 || out["mode"] != "data_query" || out["conversation_id"] != id {
		t.Fatalf("first question: %d %v", code, out)
	}
	code, out = askIrisIn(t, s, a, id, "memory on that device for the last hour")
	if code != 200 || out["mode"] != "data_query" || !strings.Contains(nlqJSON(out["data"]), "device:dev-a") {
		t.Fatalf("'that device' must bind the previous answer's device: %d %v", code, out)
	}
	// The same follow-up with no conversation has nothing to point at: it is
	// NOT answered as data (never widened to every device).
	if out := askIris(t, s, a, "memory on that device for the last hour"); out["mode"] == "data_query" {
		t.Fatalf("an unbound reference must not become a data answer: %v", out)
	}
	// Both asks are turns of the conversation.
	_, got := convoCall(t, s, a, http.MethodGet, "/api/ai/conversations/"+id, "")
	if n := len(got["turns"].([]any)); n != 2 {
		t.Fatalf("want 2 turns, got %d", n)
	}
}

func TestTheIrisBoxRefusesSomeoneElsesConversation(t *testing.T) {
	s, a, b := irisBoxFixture(t)
	id := startConvo(t, s, a)
	colleague := a
	colleague.Sub = "ua-colleague"
	for name, c := range map[string]jwtClaims{"other tenant": b, "same-tenant colleague": colleague} {
		if code, _ := askIrisIn(t, s, c, id, "show cpu on edge-a for the last hour"); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", name, code)
		}
	}
	if code, _ := askIrisIn(t, s, a, "not-a-uuid", "open incidents"); code != http.StatusNotFound {
		t.Errorf("malformed conversation id: %d, want 404", code)
	}
}

func TestAFullConversationStillAnswers(t *testing.T) {
	s, a, _ := irisBoxFixture(t)
	id := startConvo(t, s, a)
	tenant, _ := principalTenant(a)
	for i := 0; i < irisconvo.MaxTurns; i++ {
		if _, err := s.nlqConvos.Append(context.Background(), tenant, a.Sub, id, irisconvo.Turn{Question: "q", Outcome: irisconvo.OutcomeUnparsed}, irisconvo.State{}); err != nil {
			t.Fatal(err)
		}
	}
	code, out := askIrisIn(t, s, a, id, "show cpu on edge-a for the last hour")
	if code != 200 || out["mode"] != "data_query" || out["conversation_id"] != nil {
		t.Fatalf("a full conversation must still answer, without claiming to have recorded it: %d %v", code, out)
	}
	if !strings.Contains(nlqJSON(out["disclaimers"]), "conversation is full") {
		t.Fatalf("the full conversation must be disclosed: %v", out["disclaimers"])
	}
}
