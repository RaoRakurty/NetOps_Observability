// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_investigation_isolation_test.go — the read-only Investigator end to end
// (tracker 337 N-I1, CLAUDE.md §3a).
//
// Pinned: "Investigate this" on /api/ai/ask runs an investigation whose trace
// rides the answer, named by the decision id and held in the ASKER's tenant;
// the owner reads it back on /api/ai/investigations/{id} and in their recent
// list; another tenant, an as_tenant walk and a malformed id all get 404; the
// platform owner reads any tenant's; a device the caller cannot see is never
// bound; and without AI investigations the action is refused with a clear
// message while the ask itself still succeeds.

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
	"netops/backend/internal/aientitlement"
	"netops/backend/internal/irisinvest"
)

func invFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := hypFixture(t) // ai.investigate on for every tenant, no provider key
	s.aiInvestigations = irisinvest.NewMemStore()
	return s, a, b
}

func invCall(t *testing.T, s *server, c jwtClaims, path string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIInvestigations(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // error bodies are asserted by status
	return w.Code, out
}

func investigateAs(t *testing.T, s *server, c jwtClaims, ui map[string]string) map[string]any {
	t.Helper()
	ctx := map[string]string{ai.UIActionKey: ai.UIActionInvestigate}
	for k, v := range ui {
		ctx[k] = v
	}
	return askIrisCtx(t, s, c, "investigate", ctx)
}

func TestInvestigateActionHoldsItsTraceInTheAskersTenant(t *testing.T) {
	s, a, b := invFixture(t)
	out := investigateAs(t, s, a, map[string]string{"device": "edge-a"})
	inv, _ := out["investigation"].(map[string]any)
	if inv == nil {
		t.Fatalf("the investigation trace must ride the answer: %v", out)
	}
	decision, _ := out["decision_id"].(string)
	if inv["id"] != decision || !aidecision.ValidID(decision) {
		t.Fatalf("the trace must be named by the decision %q: %v", decision, inv["id"])
	}
	steps, _ := inv["steps"].([]any)
	if len(steps) == 0 {
		t.Fatalf("an investigation without steps: %v", inv)
	}
	if first, _ := steps[0].(map[string]any); first["kind"] != ai.InvStepBind {
		t.Fatalf("the trace must start by binding the scope: %v", first)
	}
	// Owner read-back; another tenant gets the same 404 as an unknown id.
	if code, back := invCall(t, s, a, "/api/ai/investigations/"+decision); code != http.StatusOK || back["id"] != decision {
		t.Fatalf("owner read-back: %d %v", code, back)
	}
	if code, _ := invCall(t, s, b, "/api/ai/investigations/"+decision); code != http.StatusNotFound {
		t.Fatalf("CROSS-TENANT LEAK: t-b read t-a's investigation: %d", code)
	}
	// The recent list is the asker's own.
	if code, l := invCall(t, s, a, "/api/ai/investigations"); code != http.StatusOK || len(l["investigations"].([]any)) != 1 {
		t.Fatalf("owner list: %d %v", code, l)
	}
	if code, l := invCall(t, s, b, "/api/ai/investigations"); code != http.StatusOK || len(l["investigations"].([]any)) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: t-b lists t-a's investigations: %d %v", code, l)
	}
}

func TestInvestigationIsolation(t *testing.T) {
	s, a, b := invFixture(t)
	idA := investigateAs(t, s, a, nil)["decision_id"].(string)
	idB := investigateAs(t, s, b, nil)["decision_id"].(string)
	if idA == "" || idB == "" || idA == idB {
		t.Fatalf("ids: %q %q", idA, idB)
	}
	if code, _ := invCall(t, s, a, "/api/ai/investigations/"+idB); code != http.StatusNotFound {
		t.Fatalf("CROSS-TENANT LEAK: t-a read t-b's investigation: %d", code)
	}
	unknown := "0b0a0c0d-1e1f-4a2b-8c3d-4e5f6a7b8c9d"
	if code, _ := invCall(t, s, a, "/api/ai/investigations/"+unknown); code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", code)
	}
	// as_tenant into another org is ignored for a non-owner.
	walker := b
	walker.ActingTenant = a.Tenant
	if code, _ := invCall(t, s, walker, "/api/ai/investigations/"+idA+"?as_tenant="+a.Tenant); code != http.StatusNotFound {
		t.Fatalf("as_tenant walk read t-a's investigation: %d", code)
	}
	if code, l := invCall(t, s, walker, "/api/ai/investigations?as_tenant="+a.Tenant); code != http.StatusOK || len(l["investigations"].([]any)) != 1 {
		t.Fatalf("as_tenant walk widened the list: %d %v", code, l)
	}
	for _, bad := range []string{"x", "..%2F..%2Fetc", strings.ToUpper(idA), idA + "/x"} {
		if code, _ := invCall(t, s, a, "/api/ai/investigations/"+bad); code != http.StatusNotFound {
			t.Errorf("malformed id %q: %d", bad, code)
		}
	}
	// The platform owner reads any tenant's.
	owner := jwtClaims{Sub: "root", Role: "admin", Tenant: TenantGlobal}
	if code, out := invCall(t, s, owner, "/api/ai/investigations/"+idB); code != http.StatusOK || out["id"] != idB {
		t.Fatalf("owner read: %d %v", code, out)
	}
	// Read-only route.
	r := httptest.NewRequest(http.MethodPost, "/api/ai/investigations/"+idA, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, a))
	w := httptest.NewRecorder()
	s.handleAIInvestigations(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", w.Code)
	}
}

// A device in the page context that the caller cannot see is never bound: the
// trace shows no target and the answer says why.
func TestInvestigationNeverBindsAnotherTenantsDevice(t *testing.T) {
	s, a, b := invFixture(t)
	// edge-a is t-a's device in the fixture; t-b asks to investigate it.
	out := investigateAs(t, s, b, map[string]string{"device": "edge-a"})
	inv, _ := out["investigation"].(map[string]any)
	if inv == nil {
		t.Fatalf("no trace: %v", out)
	}
	target, _ := inv["target"].(map[string]any)
	if target["device_id"] != nil && target["device_id"] != "" {
		t.Fatalf("CROSS-TENANT LEAK: t-b bound t-a's device: %v", target)
	}
	_ = a
	disc, _ := out["disclaimers"].([]any)
	said := false
	for _, d := range disc {
		if s, _ := d.(string); strings.Contains(s, "not in this workspace's inventory") {
			said = true
		}
	}
	if !said {
		t.Errorf("the dropped device must be disclosed: %v", disc)
	}
}

func TestInvestigateActionRefusedWithoutAIInvestigations(t *testing.T) {
	s, a, _ := invFixture(t)
	s.aiEntitlementPolicy = policyWithout(t, s, aientitlement.Investigate)
	out := investigateAs(t, s, a, map[string]string{"device": "edge-a"})
	if out["mode"] != string(ai.ModeUnavailable) || out["text"] != ai.InvestigationsOffText {
		t.Fatalf("refusal = mode %v text %v", out["mode"], out["text"])
	}
	inv, _ := out["investigation"].(map[string]any)
	if inv == nil || inv["status"] != ai.InvestigationStatusRefused {
		t.Fatalf("trace = %v, want status refused", inv)
	}
	// And the trace endpoint itself is gated by ai.investigate.
	if code, _ := invCall(t, s, a, "/api/ai/investigations"); code != http.StatusForbidden {
		t.Fatalf("trace list without ai.investigate: %d", code)
	}
}

// failingInvestigations refuses every Put.
type failingInvestigations struct{ irisinvest.Store }

func (failingInvestigations) Put(context.Context, string, ai.InvestigationTrace) error {
	return errors.New("store unavailable")
}

func TestInvestigationTraceDegradesWithoutAStore(t *testing.T) {
	s, a, _ := invFixture(t)
	s.aiInvestigations = failingInvestigations{}
	out := investigateAs(t, s, a, nil)
	inv, _ := out["investigation"].(map[string]any)
	if inv == nil || inv["id"] != nil {
		t.Fatalf("a failed hold keeps the trace inline and names no id: %v", inv)
	}
	s.aiInvestigations = nil
	out = investigateAs(t, s, a, nil)
	if inv, _ := out["investigation"].(map[string]any); inv == nil || inv["id"] != nil {
		t.Fatalf("no store: the trace stays inline with no id: %v", inv)
	}
}
