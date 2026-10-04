// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_explain_isolation_test.go — GET /api/ai/query/{id} and
// GET /api/ai/query/{id}/explain (tracker 337 N-C5).
//
// Pinned (§3a): a record is read inside the caller's tenant only — another
// tenant, an as_tenant walk into another org (the ?as_tenant= parameter and an
// ActingTenant claim alike) and an id that never existed get the SAME 404,
// byte for byte; a same-tenant colleague gets 404 unless they are a workspace
// admin, who reads it the way the workspace list shows it — without the
// colleague's own words. And (§15): a model-written query is disclosed on
// both reads (compiled_by=model, source=model, the disclosure text), for as
// long as the record lives. The explanation re-validates the stored query
// against the caller's CURRENT scope and names devices only from what the
// caller can see: a stored foreign id is reported invalid, never named.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/irisquerylog"
	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/modelc"
)

// queryRead GETs path (/api/ai/query/{id}[/explain]) as c.
func queryRead(t *testing.T, s *server, c jwtClaims, method, path string) (int, map[string]any, string) {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	s.handleAIQueryRecord(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // best-effort: error bodies are asserted by status and raw text
	return w.Code, out, w.Body.String()
}

func compiledID(t *testing.T, s *server, c jwtClaims, question string) string {
	t.Helper()
	out := compileQ(t, s, c, question)
	id, _ := out["query_log_id"].(string)
	if !irisquerylog.ValidID(id) {
		t.Fatalf("compile %q left no record: %v", question, out)
	}
	return id
}

func part(t *testing.T, out map[string]any, facet string) string {
	t.Helper()
	ex, _ := out["explanation"].(map[string]any)
	parts, _ := ex["parts"].([]any)
	for _, p := range parts {
		m, _ := p.(map[string]any)
		if m["facet"] == facet {
			s, _ := m["text"].(string)
			return s
		}
	}
	return ""
}

func TestQueryRecordAndExplainAreTheCallersOwn(t *testing.T) {
	s, a, b := qlogFixture(t)
	id := compiledID(t, s, a, "show cpu on edge-a for the last hour")
	colleague := a
	colleague.Sub, colleague.Role = "ua-colleague", "operator"
	walker := b
	walker.ActingTenant = a.Tenant
	unknown := "11111111-2222-4333-8444-555555555555"

	for _, suffix := range []string{"", "/explain"} {
		// The owner reads it.
		if code, out, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id+suffix); code != http.StatusOK || out["id"] != id {
			t.Fatalf("owner GET %s: %d %v", suffix, code, out)
		}
		// Everyone else: the SAME 404 as an id that never existed.
		_, _, unknownBody := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+unknown+suffix)
		for name, c := range map[string]jwtClaims{"other tenant (its own admin)": b, "same-tenant colleague": colleague, "as_tenant walk": walker} {
			code, _, body := queryRead(t, s, c, http.MethodGet, "/api/ai/query/"+id+suffix+"?as_tenant="+a.Tenant)
			if code != http.StatusNotFound {
				t.Errorf("CROSS-TENANT/PRINCIPAL LEAK: %s read A's record%s: %d %s", name, suffix, code, body)
			}
			if body != unknownBody {
				t.Errorf("%s: a foreign record must be indistinguishable from a missing one:\n%s\n%s", name, body, unknownBody)
			}
		}
		if code, _, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+unknown+suffix); code != http.StatusNotFound {
			t.Errorf("unknown id%s: %d", suffix, code)
		}
	}

	// Tenant B's own record is B's alone: A (an admin of A's workspace) and
	// an A→B as_tenant walk cannot read it either.
	bID := compiledID(t, s, b, "open incidents")
	walkerA := a
	walkerA.ActingTenant = b.Tenant
	for name, c := range map[string]jwtClaims{"tenant A admin": a, "A as_tenant walk into B": walkerA} {
		if code, _, _ := queryRead(t, s, c, http.MethodGet, "/api/ai/query/"+bID+"/explain?as_tenant="+b.Tenant); code != http.StatusNotFound {
			t.Errorf("CROSS-TENANT LEAK: %s explained B's query: %d", name, code)
		}
	}

	// A workspace admin reads a colleague's record as the workspace list
	// shows it: what was asked about and how it went, never their words.
	cID := compiledID(t, s, colleague, "show cpu on edge-a for the last hour")
	if code, _, _ := queryRead(t, s, colleague, http.MethodGet, "/api/ai/query/"+id); code != http.StatusNotFound {
		t.Errorf("a non-admin colleague read the admin's record: %d", code)
	}
	for _, suffix := range []string{"", "/explain"} {
		code, out, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+cID+suffix)
		if code != http.StatusOK {
			t.Fatalf("workspace admin reading a colleague's record%s: %d %v", suffix, code, out)
		}
		if q, _ := out["question"].(string); q != "" {
			t.Errorf("the colleague's question text was exposed%s: %q", suffix, q)
		}
		if out["outcome"] != "compiled" {
			t.Errorf("how it went must still show%s: %v", suffix, out)
		}
	}
	if _, out, _ := queryRead(t, s, colleague, http.MethodGet, "/api/ai/query/"+cID); out["question"] != "show cpu on edge-a for the last hour" {
		t.Errorf("the colleague's own read keeps their words: %v", out)
	}
}

func TestQueryRecordKeepsTheValidatedQuery(t *testing.T) {
	s, a, _ := qlogFixture(t)
	comp := compileQ(t, s, a, "show cpu on edge-a for the last hour")
	id := comp["query_log_id"].(string)
	code, out, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id)
	if code != http.StatusOK || out["compiled_by"] != irisquerylog.CompiledByGrammar || out["disclosure"] != nil {
		t.Fatalf("a grammar query: %d %v", code, out)
	}
	if nlqJSON(out["query"]) != nlqJSON(comp["ast"]) {
		t.Fatalf("the record keeps the validated query the compile returned:\n%v\n%v", out["query"], comp["ast"])
	}
	if h, _ := out["ast_hash"].(string); h == "" {
		t.Fatalf("ast hash: %v", out)
	}

	// The list stays a summary: no query, but who wrote it.
	for _, r := range qlogList(t, s, a, "") {
		if r["id"] == id {
			if _, has := r["query"]; has {
				t.Errorf("the list must not carry the query: %v", r)
			}
			if r["compiled_by"] != irisquerylog.CompiledByGrammar {
				t.Errorf("the list must say who wrote the query: %v", r)
			}
		}
	}

	// A client-supplied query is kept as validated and marked supplied.
	astJSON, _ := json.Marshal(comp["ast"])
	_, exe := nlqAPI(t, s, a, "/api/ai/query/execute", `{"ast":`+string(astJSON)+`}`)
	eid, _ := exe["query_log_id"].(string)
	_, out, _ = queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+eid+"/explain")
	if out["compiled_by"] != irisquerylog.CompiledBySupplied || out["source"] != nil || out["explanation"] == nil {
		t.Fatalf("a supplied query: %v", out)
	}

	// No query compiled → no explanation, and a plain reason.
	uid := compiledID(t, s, a, "show cpu on that thing over there")
	_, out, _ = queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+uid+"/explain")
	if out["explanation"] != nil || out["outcome"] != "unparsed" || !strings.Contains(out["reason"].(string), "did not understand") {
		t.Fatalf("an unparsed question: %v", out)
	}
	if _, has := out["query"]; has {
		t.Fatalf("no query to show: %v", out)
	}
}

func TestExplainSaysWhatTheQueryDoes(t *testing.T) {
	s, a, _ := qlogFixture(t)
	id := compiledID(t, s, a, "show cpu on edge-a for the last hour")
	code, out, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id+"/explain")
	if code != http.StatusOK || out["still_valid"] != true || out["catalog_current"] != true {
		t.Fatalf("explain: %d %v", code, out)
	}
	if out["source"] != nil || out["disclosure"] != nil || out["compiled_by"] != irisquerylog.CompiledByGrammar {
		t.Fatalf("a grammar query is not disclosed as a model one: %v", out)
	}
	for facet, want := range map[string]string{
		"what":     "Shows cpu over time",
		"metric":   "cpu_util_pct",
		"entities": "device edge-a (dev-a)", // named from the caller's own inventory
		"window":   "the last hour",
	} {
		if got := part(t, out, facet); !strings.Contains(got, want) {
			t.Errorf("%s: %q does not say %q", facet, got, want)
		}
	}
	ex, _ := out["explanation"].(map[string]any)
	if sum, _ := ex["summary"].(string); !strings.Contains(sum, "edge-a") {
		t.Errorf("summary: %q", sum)
	}
}

func TestExplainDisclosesAModelWrittenQuery(t *testing.T) {
	s, a, b, _ := modelFallbackFixture(t, modelEnvelope(cpuOnDevA), "t-a")
	s.nlqQueryLog = irisquerylog.NewMemStore()
	s.nlqQueryLogMetrics = irisquerylog.NewMetrics()
	comp := compileQ(t, s, a, hotCPUQuestion)
	if comp["source"] != modelc.SourceModel {
		t.Fatalf("fixture: the model must have compiled it: %v", comp)
	}
	id := comp["query_log_id"].(string)
	code, rec, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id)
	if code != http.StatusOK || rec["compiled_by"] != irisquerylog.CompiledByModel || rec["disclosure"] != nlqModelDisclosure {
		t.Fatalf("GET must disclose a model-written query: %d %v", code, rec)
	}
	code, out, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id+"/explain")
	if code != http.StatusOK || out["source"] != modelc.SourceModel || out["compiled_by"] != irisquerylog.CompiledByModel ||
		out["disclosure"] != nlqModelDisclosure || out["explanation"] == nil {
		t.Fatalf("explain must disclose source=model: %d %v", code, out)
	}
	// Disclosed in the list too.
	for _, r := range qlogList(t, s, a, "") {
		if r["id"] == id && r["compiled_by"] != irisquerylog.CompiledByModel {
			t.Errorf("list: %v", r)
		}
	}
	// And still the caller's alone.
	if code, _, _ := queryRead(t, s, b, http.MethodGet, "/api/ai/query/"+id+"/explain"); code != http.StatusNotFound {
		t.Errorf("CROSS-TENANT LEAK: tenant B explained A's model query: %d", code)
	}
}

func TestExplainRevalidatesAndNeverNamesWhatTheCallerCannotSee(t *testing.T) {
	s, a, _ := qlogFixture(t)
	// A record naming tenant B's device — as if visibility changed after the
	// question was asked. Planted straight into A's tenant of the store.
	q := &nlqast.AST{V: 1, Type: nlqast.MetricSeries, Target: "device", Metric: "cpu_util_pct",
		Refs: []nlqast.EntityRef{{Type: "device", ID: "device:dev-b"}},
		Time: nlqast.TimeRange{Kind: nlqast.TimeRelative, Last: "1h"}}
	rec, err := s.nlqQueryLog.Record(context.Background(), a.Tenant, irisquerylog.Record{Principal: a.Sub,
		Source: irisquerylog.SourceQueryCompile, Outcome: irisquerylog.OutcomeCompiled, Question: "cpu",
		Query: q, CompiledBy: irisquerylog.CompiledByGrammar})
	if err != nil {
		t.Fatal(err)
	}
	code, out, raw := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+rec.ID+"/explain")
	if code != http.StatusOK || out["still_valid"] != false || !strings.Contains(nlqJSON(out["validation"]), "unknown_entity") {
		t.Fatalf("a query naming an entity the caller cannot see now must be reported invalid: %d %v", code, out)
	}
	if strings.Contains(raw, "edge-b") {
		t.Fatalf("CROSS-TENANT LEAK: the explanation named tenant B's device: %s", raw)
	}
	if got := part(t, out, "entities"); got != "About device dev-b." {
		t.Fatalf("an invisible device is shown by the id the record already holds: %q", got)
	}
}

func TestQueryRecordRoutesAreGated(t *testing.T) {
	s, a, _ := qlogFixture(t)
	id := compiledID(t, s, a, "open incidents")
	for _, bad := range []string{"/api/ai/query/", "/api/ai/query/not-a-uuid", "/api/ai/query/" + strings.ToUpper(id),
		"/api/ai/query/" + id + "/other", "/api/ai/query/" + id + "/explain/x", "/api/ai/query/compile/x", "/api/ai/query/../queries"} {
		if code, _, _ := queryRead(t, s, a, http.MethodGet, bad); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", bad, code)
		}
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		if code, _, _ := queryRead(t, s, a, m, "/api/ai/query/"+id); code != http.StatusMethodNotAllowed {
			t.Errorf("%s: %d, want 405", m, code)
		}
	}
	noInfra := a
	noInfra.Role = "api_client_none"
	if code, _, _ := queryRead(t, s, noInfra, http.MethodGet, "/api/ai/query/"+id); code != http.StatusForbidden {
		t.Errorf("a role without infrastructure:read: %d, want 403", code)
	}
	cat := s.nlqCatalog
	s.nlqCatalog = nil
	if code, _, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id+"/explain"); code != http.StatusServiceUnavailable {
		t.Errorf("explain without a catalog: %d, want 503", code)
	}
	s.nlqCatalog = cat
	log := s.nlqQueryLog
	s.nlqQueryLog = nil
	if code, _, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id); code != http.StatusServiceUnavailable {
		t.Errorf("capture off: %d, want 503", code)
	}
	s.nlqQueryLog = log
	t.Setenv("FEATURE_AI", "false")
	if code, _, _ := queryRead(t, s, a, http.MethodGet, "/api/ai/query/"+id); code != http.StatusServiceUnavailable {
		t.Errorf("AI disabled: %d, want 503", code)
	}
}
