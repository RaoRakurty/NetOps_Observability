// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_hypotheses_isolation_test.go — /api/ai/hypotheses/{id} and the hold
// behind /api/ai/ask (tracker 337 N-B3, CLAUDE.md §3a).
//
// Pinned: an investigation's hypotheses are held under its decision id in the
// ASKER's tenant (from the token); the owner reads them back; another tenant,
// an as_tenant walk and a malformed id all get the same 404; the platform
// owner reads any tenant's; the ledger records them (HYPOTHESIS_CREATED per
// hypothesis, HYPOTHESIS_REJECTED for each rejected one, never
// ROOT_CAUSE_SELECTED); and a store that cannot hold them never costs the
// operator the answer.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/irishypo"
)

func hypFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	t.Setenv("FEATURE_AI_TOOLS", "true")     // ai.investigate: the investigation loop is on
	t.Setenv("AI_TOOLS_ALL_TENANTS", "true") // … for every tenant
	s, a, b := ledgerFixture(t)
	s.aiHypotheses = irishypo.NewMemStore()
	s.copilotCfg = newCopilotConfigStore(t.TempDir()+"/copilot_config.json", nil) // no key: no provider is ever called
	return s, a, b
}

// hypAnswer is a skill-chain answer carrying a resolved hypothesis set, built
// by the real tracker (one supported, one rejected).
func hypAnswer() ai.Answer {
	tr := irishypo.NewTracker(irishypo.Wording{})
	tr.Enter(1, "interface-down", "physical", []string{"get_device_state"})
	tr.Observe(1, "interface-down", map[string]string{"get_device_state": "ok"},
		map[string][]string{"get_device_state": {"state:interfaces:dev-a:1"}})
	f := irishypo.Facts{States: map[string]bool{"if_oper=down": true, "if_errors=none": true}}
	return ai.Answer{Mode: ai.ModeTroubleshootFinding, Text: "The uplink is down.",
		Hypotheses: tr.Finish(f, irishypo.NewEngine("", "", ""))}
}

// holdAs runs the ask handler's hold step for claims, as a ledgered decision.
func holdAs(t *testing.T, s *server, c jwtClaims) (ai.Answer, *aidecision.Recorder) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/ai/ask", strings.NewReader(`{"question":"q"}`))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	r, rec := s.aiDecisionStart(r, c, aiAskRequest{Question: "q"})
	ans := hypAnswer()
	// A client-looking id on the set must never survive: the server names it.
	ans.Hypotheses.ID = "99999999-9999-4999-8999-999999999999"
	s.aiHypothesesHold(r, c, rec, &ans)
	return ans, rec
}

func hypCall(t *testing.T, s *server, c jwtClaims, path string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIHypotheses(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // error bodies are asserted by status
	return w.Code, out
}

func TestHypothesesAreHeldUnderTheDecisionInTheAskersTenant(t *testing.T) {
	s, a, _ := hypFixture(t)
	ans, rec := holdAs(t, s, a)
	id := ans.Hypotheses.ID
	if id == "" || id != rec.DecisionID() {
		t.Fatalf("the set must be named by its decision: set %q, decision %q", id, rec.DecisionID())
	}
	// Stored in the token's tenant — and nowhere else.
	if _, err := s.aiHypotheses.Get(context.Background(), a.Tenant, false, id); err != nil {
		t.Fatalf("not held in the asker's tenant: %v", err)
	}
	if _, err := s.aiHypotheses.Get(context.Background(), "t-b", false, id); !errors.Is(err, irishypo.ErrNotFound) {
		t.Fatalf("held outside the asker's tenant: %v", err)
	}
	// The ledger records every hypothesis, the rejected one twice over, and
	// never a root cause.
	aiLedgerAnswerEntries(rec, &ans)
	created, rejected := map[string]string{}, 0
	for _, e := range rec.Entries() {
		switch e.EventType {
		case aidecision.HypothesisCreated:
			created[e.Outcome] = e.ResultSHA256
			if e.Skill != "interface-down" || e.Tool != "get_device_state" || !aidecision.ValidSHA256(e.ResultSHA256) {
				t.Errorf("HYPOTHESIS_CREATED = %+v", e)
			}
		case aidecision.HypothesisRejected:
			rejected++
			if e.Outcome != "interface-errors" {
				t.Errorf("HYPOTHESIS_REJECTED = %+v", e)
			}
		case aidecision.RootCauseSelected:
			t.Fatalf("Iris recorded a root cause — the engine owns it: %+v", e)
		}
	}
	if _, ok := created["link-down:supported"]; !ok || rejected != 1 {
		t.Fatalf("ledger hypotheses: created %v, rejected %d", created, rejected)
	}
	if _, ok := created["interface-errors:rejected"]; !ok {
		t.Fatalf("ledger hypotheses: created %v", created)
	}
}

// TestAskHoldsItsInvestigationsHypotheses drives the real /api/ai/ask: a
// troubleshooting question runs the skill chain, the answer carries its
// hypotheses named by the decision id, the owner reads them back, another
// tenant cannot, and the ledger recorded them.
func TestAskHoldsItsInvestigationsHypotheses(t *testing.T) {
	s, a, b := hypFixture(t)
	out := askIris(t, s, a, "why is the bgp session down on edge-a")
	if out["mode"] != string(ai.ModeTroubleshootFinding) {
		t.Fatalf("expected the skill chain to answer: %v", out["mode"])
	}
	decision, _ := out["decision_id"].(string)
	hyp, _ := out["hypotheses"].(map[string]any)
	if hyp == nil || hyp["id"] != decision || !aidecision.ValidID(decision) {
		t.Fatalf("hypotheses must ride the answer, named by the decision %q: %v", decision, hyp)
	}
	if hs, _ := hyp["hypotheses"].([]any); len(hs) == 0 {
		t.Fatalf("the chain opened no hypotheses: %v", hyp)
	}
	if code, back := hypCall(t, s, a, "/api/ai/hypotheses/"+decision); code != http.StatusOK || back["id"] != decision {
		t.Fatalf("owner read-back: %d %v", code, back)
	}
	if code, _ := hypCall(t, s, b, "/api/ai/hypotheses/"+decision); code != http.StatusNotFound {
		t.Fatalf("CROSS-TENANT LEAK: t-b read t-a's investigation: %d", code)
	}
	created := 0
	for _, e := range ledgerEntries(t, s, a, "?decision_id="+decision) {
		switch e["event_type"] {
		case aidecision.HypothesisCreated:
			created++
		case aidecision.RootCauseSelected:
			t.Fatalf("Iris recorded a root cause: %v", e)
		}
	}
	if created == 0 {
		t.Fatal("the ledger must record the investigation's hypotheses")
	}
}

func TestHypothesesIsolation(t *testing.T) {
	s, a, b := hypFixture(t)
	ansA, _ := holdAs(t, s, a)
	ansB, _ := holdAs(t, s, b)
	idA, idB := ansA.Hypotheses.ID, ansB.Hypotheses.ID
	if idA == "" || idB == "" || idA == idB {
		t.Fatalf("ids: %q %q", idA, idB)
	}

	// The owner reads their own investigation back, exactly as shown.
	code, out := hypCall(t, s, a, "/api/ai/hypotheses/"+idA)
	if code != http.StatusOK || out["id"] != idA {
		t.Fatalf("own read: %d %v", code, out)
	}
	hs, _ := out["hypotheses"].([]any)
	if len(hs) != 2 || hs[0].(map[string]any)["state"] != "SUPPORTED" {
		t.Fatalf("own read body: %v", out)
	}
	// Another tenant's id: 404, the same as an id that never existed.
	if code, out := hypCall(t, s, b, "/api/ai/hypotheses/"+idA); code != http.StatusNotFound {
		t.Fatalf("CROSS-TENANT LEAK: t-b read t-a's hypotheses: %d %v", code, out)
	}
	if code, _ := hypCall(t, s, a, "/api/ai/hypotheses/"+idB); code != http.StatusNotFound {
		t.Fatalf("CROSS-TENANT LEAK: t-a read t-b's hypotheses: %d", code)
	}
	unknown := "0b0a0c0d-1e1f-4a2b-8c3d-4e5f6a7b8c9d"
	if code, _ := hypCall(t, s, a, "/api/ai/hypotheses/"+unknown); code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", code)
	}
	// as_tenant into another org is ignored for a non-owner.
	walker := b
	walker.ActingTenant = a.Tenant
	if code, _ := hypCall(t, s, walker, "/api/ai/hypotheses/"+idA+"?as_tenant="+a.Tenant); code != http.StatusNotFound {
		t.Fatalf("as_tenant walk read t-a's hypotheses: %d", code)
	}
	// Malformed ids are a plain 404 — never a store lookup on attacker text.
	for _, bad := range []string{"", "x", "..%2F..%2Fetc", strings.ToUpper(idA), idA + "/x"} {
		if code, _ := hypCall(t, s, a, "/api/ai/hypotheses/"+bad); code != http.StatusNotFound {
			t.Errorf("malformed id %q: %d", bad, code)
		}
	}
	// The platform owner reads any tenant's.
	owner := jwtClaims{Sub: "root", Role: "admin", Tenant: TenantGlobal}
	if code, out := hypCall(t, s, owner, "/api/ai/hypotheses/"+idB); code != http.StatusOK || out["id"] != idB {
		t.Fatalf("owner read: %d %v", code, out)
	}
	// Read-only route.
	r := httptest.NewRequest(http.MethodPost, "/api/ai/hypotheses/"+idA, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, a))
	w := httptest.NewRecorder()
	s.handleAIHypotheses(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
}

// failingHypotheses refuses every Put.
type failingHypotheses struct{ irishypo.Store }

func (failingHypotheses) Put(context.Context, string, irishypo.Set) error {
	return errors.New("store unavailable")
}

func TestHypothesesDegradeWithoutAStore(t *testing.T) {
	s, a, _ := hypFixture(t)

	s.aiHypotheses = failingHypotheses{}
	ans, _ := holdAs(t, s, a)
	if ans.Hypotheses == nil || ans.Hypotheses.ID != "" || len(ans.Hypotheses.Hypotheses) != 2 {
		t.Fatalf("a failed hold keeps the set inline and names no id: %+v", ans.Hypotheses)
	}

	s.aiHypotheses = nil
	ans, _ = holdAs(t, s, a)
	if ans.Hypotheses == nil || ans.Hypotheses.ID != "" {
		t.Fatalf("no store: the set stays inline, unnamed: %+v", ans.Hypotheses)
	}
	if code, _ := hypCall(t, s, a, "/api/ai/hypotheses/0b0a0c0d-1e1f-4a2b-8c3d-4e5f6a7b8c9d"); code != http.StatusServiceUnavailable {
		t.Fatalf("no store: %d, want 503", code)
	}
}
