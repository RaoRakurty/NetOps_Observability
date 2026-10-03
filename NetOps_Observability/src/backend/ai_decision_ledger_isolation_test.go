// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// ai_decision_ledger_isolation_test.go — /api/ai/decisions and the decision
// ledger behind /api/ai/ask (tracker 337 N-A6).
//
// Pinned: an accepted ask is ONE decision — QUESTION_RECEIVED first,
// ANSWER_RETURNED last, the data arm's PLAN_CREATED / TOOL_EXECUTED between,
// in seq order — carrying hashes and never the question, the data or the
// answer text; the answer names its decision id; the ask enters the platform
// audit trail with that id; the read API is a workspace admin's own tenant
// only (another tenant's decision id lists nothing, an as_tenant walk is
// ignored, a non-admin is refused) and the platform owner's every tenant; and
// a ledger that cannot be written never costs the operator the answer — it is
// counted, and the answer then names no decision.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/irisquerylog"
)

func ledgerFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := convoFixture(t) // FEATURE_AI on, a fake VictoriaMetrics; a/b are admins of t-a / t-b
	s.nlqQueryLog = irisquerylog.NewMemStore()
	s.nlqQueryLogMetrics = irisquerylog.NewMetrics()
	s.aiDecisions = aidecision.NewMemStore()
	s.aiDecisionMetrics = aidecision.NewMetrics()
	au, err := newAuditStore(t.TempDir() + "/audit.json")
	if err != nil {
		t.Fatal(err)
	}
	s.audit = au
	return s, a, b
}

func ledgerCall(t *testing.T, s *server, c jwtClaims, query string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/ai/decisions"+query, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIDecisions(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // best-effort: error bodies are asserted by status
	return w.Code, out
}

func ledgerEntries(t *testing.T, s *server, c jwtClaims, query string) []map[string]any {
	t.Helper()
	code, out := ledgerCall(t, s, c, query)
	if code != http.StatusOK {
		t.Fatalf("list %s as %s/%s: %d %v", query, c.Tenant, c.Sub, code, out)
	}
	raw, _ := out["decisions"].([]any)
	var es []map[string]any
	for _, x := range raw {
		es = append(es, x.(map[string]any))
	}
	return es
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestAskIsOneLedgeredDecision(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	const question = "show cpu on edge-a for the last hour"
	out := askIris(t, s, a, question)
	id, _ := out["decision_id"].(string)
	if !aidecision.ValidID(id) {
		t.Fatalf("the answer must name its decision: %v", out)
	}
	es := ledgerEntries(t, s, a, "?decision_id="+id)
	if len(es) < 4 {
		t.Fatalf("decision too short: %v", es)
	}
	var types []string
	for i, e := range es {
		types = append(types, e["event_type"].(string))
		if int(e["seq"].(float64)) != i || e["decision_id"] != id || e["principal"] != a.Sub || e["surface"] != "ask" {
			t.Errorf("entry %d not stamped with its decision: %v", i, e)
		}
		if _, leak := e["tenant"]; leak {
			t.Errorf("a tenant read must not echo the tenant: %v", e)
		}
	}
	want := []string{aidecision.QuestionReceived, aidecision.PlanCreated, aidecision.ToolExecuted}
	for i, w := range want {
		if types[i] != w {
			t.Fatalf("event order %v, want %v first", types, want)
		}
	}
	if types[len(types)-1] != aidecision.AnswerReturned {
		t.Fatalf("ANSWER_RETURNED must close the decision: %v", types)
	}
	if es[0]["args_sha256"] != sha256hex([]byte(question)) {
		t.Errorf("QUESTION_RECEIVED must carry the question's hash: %v", es[0])
	}
	plan, run, final := es[1], es[2], es[len(es)-1]
	if plan["tool"] != "nl_query" || plan["outcome"] != "compiled" || !aidecision.ValidSHA256(plan["result_sha256"].(string)) {
		t.Errorf("PLAN_CREATED: %v", plan)
	}
	if run["tool"] != "nl_query" || run["outcome"] != "ok" || run["args_sha256"] != plan["result_sha256"] ||
		!aidecision.ValidSHA256(run["result_sha256"].(string)) || run["item_count"].(float64) != 1 {
		t.Errorf("TOOL_EXECUTED must run exactly the planned query: %v (plan %v)", run, plan)
	}
	data, _ := out["data"].(map[string]any)
	if final["mode"] != "data_query" || final["outcome"] != "answered" || final["query_log_id"] != data["query_log_id"] ||
		final["model_tier"] == nil {
		t.Errorf("ANSWER_RETURNED: %v", final)
	}
	// The answer hash is of the answer exactly as returned, minus its own id.
	var ans ai.Answer
	raw, _ := json.Marshal(out)
	if err := json.Unmarshal(raw, &ans); err != nil {
		t.Fatal(err)
	}
	ans.DecisionID = ""
	body, _ := json.Marshal(ans)
	if final["result_sha256"] != sha256hex(body) {
		t.Errorf("ANSWER_RETURNED hash does not match the answer returned")
	}
	// Hashes only: not the question, not a device, not the answer text.
	dump := nlqJSON(es)
	for _, leak := range []string{"edge-a", "dev-a", "cpu", "peak", "last hour"} {
		if strings.Contains(dump, leak) {
			t.Errorf("the ledger stored %q: %s", leak, dump)
		}
	}
	if dec, ent, failed, _ := s.aiDecisionMetrics.Snapshot(); dec != 1 || ent != uint64(len(es)) || failed != 0 {
		t.Errorf("metrics: decisions=%d entries=%d failed=%d", dec, ent, failed)
	}

	// The platform audit trail carries the ask with its decision id.
	evs, err := s.audit.List(a.Tenant, false, auditQuery{Path: "/api/ai/ask", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Detail["action"] == "ai.ask" && e.Detail["decision_id"] == id && e.Actor == a.Sub {
			found = true
			if strings.Contains(nlqJSON(e), "edge-a") {
				t.Errorf("the audit row carries the question: %v", e)
			}
		}
	}
	if !found {
		t.Fatalf("/api/ai/ask did not enter the audit trail with its decision: %v", evs)
	}
}

func TestDecisionLedgerIsolation(t *testing.T) {
	s, a, b := ledgerFixture(t)
	idA, _ := askIris(t, s, a, "show cpu on edge-a for the last hour")["decision_id"].(string)
	idB, _ := askIris(t, s, b, "show cpu on edge-b for the last hour")["decision_id"].(string)
	if !aidecision.ValidID(idA) || !aidecision.ValidID(idB) || idA == idB {
		t.Fatalf("decision ids: %q %q", idA, idB)
	}

	// Own-only list.
	for _, e := range ledgerEntries(t, s, a, "") {
		if e["decision_id"] != idA {
			t.Fatalf("CROSS-TENANT LEAK: t-a's ledger lists %v", e)
		}
	}
	// Another tenant's decision id, by id: nothing (existence not revealed).
	if es := ledgerEntries(t, s, b, "?decision_id="+idA); len(es) != 0 {
		t.Fatalf("CROSS-TENANT LEAK: t-b read t-a's decision: %v", es)
	}
	// as_tenant into another org is ignored for a non-owner.
	walker := b
	walker.ActingTenant = a.Tenant
	if es := ledgerEntries(t, s, walker, "?as_tenant="+a.Tenant+"&decision_id="+idA); len(es) != 0 {
		t.Fatalf("as_tenant walk read t-a's decision: %v", es)
	}
	for _, e := range ledgerEntries(t, s, walker, "?as_tenant="+a.Tenant) {
		if e["decision_id"] == idA {
			t.Fatalf("as_tenant walk listed t-a's decision: %v", e)
		}
	}
	// A non-admin is refused outright.
	op := a
	op.Role = "operator"
	if code, _ := ledgerCall(t, s, op, ""); code != http.StatusForbidden {
		t.Fatalf("a non-admin read the ledger: %d", code)
	}
	// The platform owner sees every tenant, each entry naming its tenant.
	owner := jwtClaims{Sub: "root", Role: "admin", Tenant: TenantGlobal}
	code, out := ledgerCall(t, s, owner, "?limit=200")
	if code != http.StatusOK || out["scope"] != "platform" {
		t.Fatalf("owner: %d %v", code, out)
	}
	seen := map[string]string{}
	for _, x := range out["decisions"].([]any) {
		e := x.(map[string]any)
		seen[e["decision_id"].(string)], _ = e["tenant"].(string)
	}
	if seen[idA] != a.Tenant || seen[idB] != b.Tenant {
		t.Fatalf("owner view: %v", seen)
	}
}

func TestDecisionLedgerRequestBounds(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	for name, q := range map[string]string{
		"bad id":     "?decision_id=x' OR 1=1",
		"limit 0":    "?limit=0",
		"limit huge": "?limit=100000",
		"bad before": "?before=yesterday",
	} {
		if code, _ := ledgerCall(t, s, a, q); code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, code)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/api/ai/decisions", strings.NewReader("{}"))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, a))
	w := httptest.NewRecorder()
	s.handleAIDecisions(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("the ledger is read-only over HTTP: POST got %d", w.Code)
	}
	s.aiDecisions = nil
	if code, _ := ledgerCall(t, s, a, ""); code != http.StatusServiceUnavailable {
		t.Errorf("no store: %d, want 503", code)
	}
}

// failingLedger refuses every append.
type failingLedger struct{ aidecision.Store }

func (failingLedger) Append(context.Context, string, []aidecision.Entry) error {
	return errors.New("database unavailable")
}

func TestALedgerFailureNeverCostsTheAnswer(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	s.aiDecisions = failingLedger{aidecision.NewMemStore()}
	out := askIris(t, s, a, "show cpu on edge-a for the last hour")
	if out["mode"] != "data_query" {
		t.Fatalf("the operator must still get the answer: %v", out)
	}
	if _, named := out["decision_id"]; named {
		t.Fatalf("an answer must not name a decision that was never stored: %v", out)
	}
	if _, _, failed, _ := s.aiDecisionMetrics.Snapshot(); failed != 1 {
		t.Fatalf("a failed append must be counted, got %d", failed)
	}
	// The audit trail still records the ask (with no decision id).
	evs, err := s.audit.List(a.Tenant, false, auditQuery{Path: "/api/ai/ask", Limit: 10})
	if err != nil || len(evs) == 0 || evs[0].Detail["decision_id"] != "" {
		t.Fatalf("audit row on a ledger failure: %v %v", err, evs)
	}
}

func TestNoLedgerStoreMeansNoDecisionID(t *testing.T) {
	s, a, _ := ledgerFixture(t)
	s.aiDecisions = nil
	out := askIris(t, s, a, "show cpu on edge-a for the last hour")
	if _, named := out["decision_id"]; named {
		t.Fatalf("no ledger, no decision id: %v", out)
	}
}

// The skill-chain path: tool steps reach the ledger through the ToolAudit hook
// with their argument/result hashes, a denial as POLICY_EVALUATED deny, and
// the first method as INVESTIGATION_STARTED.
func TestToolAuditEntriesMapToLedgerEvents(t *testing.T) {
	rec, err := aidecision.NewRecorder("ua", aidecision.SurfaceAsk)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256hex([]byte("x"))
	aiLedgerToolEntry(rec, ai.ToolAuditEntry{Skill: "bgp-peer-down", Tool: "bgp_peers", Allowed: true, Reason: "ok",
		Items: 3, Selected: "entry", ArgsSHA256: h, ResultSHA256: h})
	aiLedgerToolEntry(rec, ai.ToolAuditEntry{Skill: "bgp-peer-down", Tool: "device_ssh", Reason: "policy_denied", ArgsSHA256: h})
	aiLedgerToolEntry(rec, ai.ToolAuditEntry{Skill: "bgp-peer-down", Tool: "missing_tool", Reason: "not_registered"})
	aiLedgerToolEntry(rec, ai.ToolAuditEntry{Skill: "bgp-peer-down", Tool: "next_skill", Reason: "rule_selected"})
	aiLedgerToolEntry(rec, ai.ToolAuditEntry{Tool: "get_problem", Reason: "not_found", ArgsSHA256: h})
	aiLedgerToolEntry(nil, ai.ToolAuditEntry{Tool: "anything"}) // no ledger: a no-op, never a panic

	got := rec.Entries()
	want := []struct{ typ, tool, outcome string }{
		{aidecision.InvestigationStarted, "", "entry"},
		{aidecision.PolicyEvaluated, "bgp_peers", "allow"},
		{aidecision.ToolExecuted, "bgp_peers", "ok"},
		{aidecision.PolicyEvaluated, "device_ssh", "deny"},
		{aidecision.ToolSelected, "missing_tool", "not_registered"},
		{aidecision.PlanCreated, "", "rule_selected"},
		{aidecision.PolicyEvaluated, "get_problem", "allow"},
		{aidecision.ToolExecuted, "get_problem", "not_found"},
	}
	if len(got) != len(want) {
		t.Fatalf("entries: %+v", got)
	}
	for i, w := range want {
		if got[i].EventType != w.typ || got[i].Tool != w.tool || got[i].Outcome != w.outcome || got[i].Seq != i {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], w)
		}
	}
	if got[2].ArgsSHA256 != h || got[2].ResultSHA256 != h || got[2].ItemCount != 3 || got[2].ToolVersion == "" {
		t.Errorf("TOOL_EXECUTED must carry hashes, count and the tool version: %+v", got[2])
	}
	if got[0].Skill != "bgp-peer-down" {
		t.Errorf("INVESTIGATION_STARTED must name the method: %+v", got[0])
	}
}
