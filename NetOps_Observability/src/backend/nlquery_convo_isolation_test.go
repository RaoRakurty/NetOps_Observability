// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_convo_isolation_test.go — /api/ai/conversations (tracker 337 N-C7).
//
// Pinned: a conversation is its owner's alone — another tenant, a colleague in
// the same tenant, and an as_tenant walk all get the same 404 as an id that
// never existed; a follow-up binds "that device" from the SERVER-held state of
// the previous answer; the client can supply no state; a reference with
// nothing to point at is not understood; the state never leaves the server;
// and the turn cap holds.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/irisconvo"
)

func convoCall(t *testing.T, s *server, c jwtClaims, method, path, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	if path == "/api/ai/conversations" {
		s.handleAIConversations(w, r)
	} else {
		s.handleAIConversation(w, r)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // best-effort: error bodies are asserted by status
	return w.Code, out
}

func convoFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	t.Setenv("FEATURE_AI", "true")
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"values":[[1,"12"]]}]}}`))
	}))
	t.Cleanup(vm.Close)
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, b := nlqAPIFixture(t)
	s.nlqConvos = irisconvo.NewMemStore()
	return s, a, b
}

func startConvo(t *testing.T, s *server, c jwtClaims) string {
	t.Helper()
	code, out := convoCall(t, s, c, http.MethodPost, "/api/ai/conversations", "")
	id, _ := out["id"].(string)
	if code != http.StatusCreated || !irisconvo.ValidID(id) {
		t.Fatalf("create: %d %v", code, out)
	}
	return id
}

func ask(t *testing.T, s *server, c jwtClaims, id, question string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"question": question})
	return convoCall(t, s, c, http.MethodPost, "/api/ai/conversations/"+id+"/messages", string(body))
}

func TestConversationIsItsOwnersAlone(t *testing.T) {
	s, a, b := convoFixture(t)
	id := startConvo(t, s, a)
	colleague := a
	colleague.Sub = "ua-colleague"
	walker := b
	walker.ActingTenant = a.Tenant
	for name, c := range map[string]jwtClaims{"other tenant": b, "same-tenant colleague": colleague, "as_tenant walk": walker} {
		if code, _ := convoCall(t, s, c, http.MethodGet, "/api/ai/conversations/"+id+"?as_tenant="+a.Tenant, ""); code != http.StatusNotFound {
			t.Errorf("%s GET: %d, want 404", name, code)
		}
		if code, _ := ask(t, s, c, id, "show cpu on edge-a for the last hour"); code != http.StatusNotFound {
			t.Errorf("%s message: %d, want 404", name, code)
		}
	}
	// Indistinguishable from an id that never existed.
	if code, _ := convoCall(t, s, b, http.MethodGet, "/api/ai/conversations/11111111-2222-4333-8444-555555555555", ""); code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", code)
	}
	for _, bad := range []string{"/api/ai/conversations/not-a-uuid", "/api/ai/conversations/" + id + "/other", "/api/ai/conversations/../x"} {
		if code, _ := convoCall(t, s, a, http.MethodGet, bad, ""); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", bad, code)
		}
	}
	// The owner still sees it, untouched by the attempts.
	code, out := convoCall(t, s, a, http.MethodGet, "/api/ai/conversations/"+id, "")
	if code != 200 || len(out["turns"].([]any)) != 0 {
		t.Fatalf("owner GET: %d %v", code, out)
	}
}

func TestAFollowUpBindsFromTheServerHeldState(t *testing.T) {
	s, a, _ := convoFixture(t)
	id := startConvo(t, s, a)

	// Nothing to point at yet: not understood, and nothing ran.
	code, out := ask(t, s, a, id, "show cpu on that device")
	if code != 200 || out["unparsed"] != true || out["result"] != nil || !strings.Contains(nlqJSON(out), "that device") {
		t.Fatalf("an unbound reference must be not-understood: %d %v", code, out)
	}

	code, out = ask(t, s, a, id, "show cpu on edge-a for the last hour")
	if code != 200 || out["result"] == nil {
		t.Fatalf("first answer: %d %v", code, out)
	}
	code, out = ask(t, s, a, id, "memory on that device for the last hour")
	if code != 200 || out["result"] == nil {
		t.Fatalf("the follow-up must answer: %d %v", code, out)
	}
	if ast := nlqJSON(out["ast"]); !strings.Contains(ast, "device:dev-a") {
		t.Fatalf("'that device' must bind the previous answer's device: %s", ast)
	}
	if !strings.Contains(nlqJSON(out["entities"]), `"resolution_method":"conversation"`) {
		t.Fatalf("the binding must say where it came from: %v", out["entities"])
	}

	// Three turns recorded, with their outcomes; the state is never rendered.
	_, got := convoCall(t, s, a, http.MethodGet, "/api/ai/conversations/"+id, "")
	raw := nlqJSON(got)
	if n := len(got["turns"].([]any)); n != 3 {
		t.Fatalf("want 3 turns, got %d", n)
	}
	for _, leak := range []string{"last_ast", "change_ids", `"state"`, "dev-a"} {
		if strings.Contains(raw, leak) {
			t.Errorf("the server-held state leaked into the conversation read: %q in %s", leak, raw)
		}
	}
}

func TestTheClientCannotSupplyState(t *testing.T) {
	s, a, _ := convoFixture(t)
	id := startConvo(t, s, a)
	for name, body := range map[string]string{
		"prior query": `{"question":"only dallas","prior_ast":{"v":1}}`,
		"state":       `{"question":"cpu on it","state":{"entities":[{"type":"device","id":"device:dev-b"}]}}`,
		"tenant":      `{"question":"cpu","tenant":"t-b"}`,
		"bad tz":      `{"question":"cpu","tz":"Mars/Olympus"}`,
		"empty":       `{"question":" "}`,
	} {
		code, _ := convoCall(t, s, a, http.MethodPost, "/api/ai/conversations/"+id+"/messages", body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
}

func TestAConversationIsBounded(t *testing.T) {
	s, a, _ := convoFixture(t)
	id := startConvo(t, s, a)
	tenant, _ := principalTenant(a)
	for i := 0; i < irisconvo.MaxTurns; i++ {
		if _, err := s.nlqConvos.Append(context.Background(), tenant, a.Sub, id, irisconvo.Turn{Question: "q", Outcome: irisconvo.OutcomeUnparsed}, irisconvo.State{}); err != nil {
			t.Fatal(err)
		}
	}
	if code, _ := ask(t, s, a, id, "open incidents"); code != http.StatusConflict {
		t.Fatalf("past the turn cap: %d, want 409", code)
	}
}

func TestConversationRoutesAreGated(t *testing.T) {
	s, a, _ := convoFixture(t)
	if code, _ := convoCall(t, s, a, http.MethodGet, "/api/ai/conversations", ""); code != http.StatusMethodNotAllowed {
		t.Errorf("GET on the collection: %d, want 405", code)
	}
	t.Setenv("FEATURE_AI", "false")
	if code, _ := convoCall(t, s, a, http.MethodPost, "/api/ai/conversations", ""); code != http.StatusServiceUnavailable {
		t.Errorf("AI disabled: %d, want 503", code)
	}
}
