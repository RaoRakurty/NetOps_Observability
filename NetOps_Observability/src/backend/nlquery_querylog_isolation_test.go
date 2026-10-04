// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_querylog_isolation_test.go — /api/ai/queries (tracker 337 N-C8).
//
// Pinned: every compiled question — the query API (compile + execute), a
// conversation turn and the /api/ai/ask data arm — leaves one record with
// counts, never rows; the list is the caller's own (a workspace admin sees the
// workspace's, nobody sees another tenant's); a correction lands only on the
// caller's own record — another tenant, a same-tenant colleague and an
// as_tenant walk get the same 404 as an id that never existed; a corrected
// query is decoded strictly and validated in the caller's scope (a foreign
// device is refused like a missing one, a smuggled tenant field is a 400); a
// capture failure never fails the question; and a correction changes nothing
// about how the next question compiles.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/irisquerylog"
)

func qlogCall(t *testing.T, s *server, c jwtClaims, method, path, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
	w := httptest.NewRecorder()
	if strings.HasPrefix(r.URL.Path, "/api/ai/queries/") {
		s.handleAIQueryCorrection(w, r)
	} else {
		s.handleAIQueries(w, r)
	}
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out) // best-effort: error bodies are asserted by status
	return w.Code, out
}

func qlogFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := convoFixture(t) // FEATURE_AI on, a fake VictoriaMetrics, conversations in memory
	s.nlqQueryLog = irisquerylog.NewMemStore()
	s.nlqQueryLogMetrics = irisquerylog.NewMetrics()
	return s, a, b
}

func qlogList(t *testing.T, s *server, c jwtClaims, query string) []map[string]any {
	t.Helper()
	code, out := qlogCall(t, s, c, http.MethodGet, "/api/ai/queries"+query, "")
	if code != http.StatusOK {
		t.Fatalf("list %s as %s/%s: %d %v", query, c.Tenant, c.Sub, code, out)
	}
	raw, _ := out["queries"].([]any)
	var recs []map[string]any
	for _, x := range raw {
		recs = append(recs, x.(map[string]any))
	}
	return recs
}

func correct(t *testing.T, s *server, c jwtClaims, id, body string) (int, map[string]any) {
	t.Helper()
	return qlogCall(t, s, c, http.MethodPost, "/api/ai/queries/"+id+"/corrections", body)
}

func TestEveryCompiledQuestionIsCaptured(t *testing.T) {
	s, a, _ := qlogFixture(t)

	code, comp := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"show cpu on edge-a for the last hour"}`)
	if code != 200 || comp["query_log_id"] == nil {
		t.Fatalf("compile must return its record id: %d %v", code, comp)
	}
	astJSON, _ := json.Marshal(comp["ast"])
	code, exe := nlqAPI(t, s, a, "/api/ai/query/execute", `{"ast":`+string(astJSON)+`}`)
	if code != 200 || exe["query_log_id"] == nil {
		t.Fatalf("execute must return its record id: %d %v", code, exe)
	}
	id := startConvo(t, s, a)
	code, turn := ask(t, s, a, id, "show cpu on edge-a for the last hour")
	if code != 200 || turn["query_log_id"] == nil {
		t.Fatalf("a conversation turn must return its record id: %d %v", code, turn)
	}
	box := askIris(t, s, a, "show cpu on edge-a for the last hour")
	data, _ := box["data"].(map[string]any)
	if box["mode"] != "data_query" || data["query_log_id"] == nil {
		t.Fatalf("the Iris box's data answer must carry its record id: %v", box)
	}

	recs := qlogList(t, s, a, "")
	bySource := map[string]map[string]any{}
	for _, r := range recs {
		bySource[r["source"].(string)] = r
	}
	for _, src := range []string{"query_compile", "query_execute", "conversation", "router"} {
		if bySource[src] == nil {
			t.Fatalf("no %s record in %v", src, recs)
		}
	}
	if r := bySource["query_compile"]; r["outcome"] != "compiled" || r["question"] != "show cpu on edge-a for the last hour" ||
		r["catalog_version"] == "" || r["ast_hash"] == "" {
		t.Errorf("compile record: %v", r)
	}
	if r := bySource["query_execute"]; r["outcome"] != "answered" || r["question"] != "" || r["series"].(float64) != 1 {
		t.Errorf("execute record: %v", r)
	}
	if r := bySource["conversation"]; r["conversation_id"] != id || r["outcome"] != "answered" {
		t.Errorf("conversation record: %v", r)
	}
	if r := bySource["router"]; r["outcome"] != "answered" || r["id"] != data["query_log_id"] {
		t.Errorf("router record: %v", r)
	}
	ents := nlqJSON(bySource["router"]["entities"])
	if !strings.Contains(ents, `"id":"device:dev-a"`) || !strings.Contains(ents, `"resolution_method":"inventory_name"`) {
		t.Errorf("entities must carry how they resolved: %s", ents)
	}
	// Counts, never the answer: no result rows, points or summary text.
	raw := nlqJSON(recs)
	for _, leak := range []string{`"result"`, `"points"`, `"values"`, "peak", `"text"`} {
		if strings.Contains(raw, leak) {
			t.Errorf("the query log stored part of the answer: %q in %s", leak, raw)
		}
	}
	// An unparsed question is recorded too (its words are the evaluation).
	nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"show cpu on that thing over there"}`)
	if recs := qlogList(t, s, a, "?limit=1"); len(recs) != 1 || recs[0]["outcome"] != "unparsed" {
		t.Errorf("unparsed question: %v", recs)
	}
}

func TestQueryLogIsTheCallersOwn(t *testing.T) {
	s, a, b := qlogFixture(t)
	_, comp := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"show cpu on edge-a for the last hour"}`)
	id, _ := comp["query_log_id"].(string)
	if !irisquerylog.ValidID(id) {
		t.Fatalf("no record id: %v", comp)
	}
	colleague := a
	colleague.Sub, colleague.Role = "ua-colleague", "operator"
	walker := b
	walker.ActingTenant = a.Tenant

	// Lists: another tenant, a colleague and an as_tenant walk see none of it.
	for name, c := range map[string]jwtClaims{"other tenant": b, "same-tenant colleague": colleague, "as_tenant walk": walker} {
		for _, r := range qlogList(t, s, c, "?as_tenant="+a.Tenant) {
			if r["id"] == id {
				t.Errorf("%s listed tenant A's question", name)
			}
		}
		if code, _ := correct(t, s, c, id, `{"kind":"wrong_entity","note":"x"}`); code != http.StatusNotFound {
			t.Errorf("%s correcting A's record: %d, want 404", name, code)
		}
	}
	// B's tenant-wide view (B is its own workspace's admin) is B's workspace only.
	for _, r := range qlogList(t, s, b, "?scope=tenant&as_tenant="+a.Tenant) {
		if r["id"] == id {
			t.Fatal("CROSS-TENANT LEAK: another workspace's admin listed tenant A's question")
		}
	}
	// Indistinguishable from an id that never existed.
	if code, _ := correct(t, s, a, "11111111-2222-4333-8444-555555555555", `{"kind":"other","note":"x"}`); code != http.StatusNotFound {
		t.Errorf("unknown id: %d", code)
	}
	for _, bad := range []string{"/api/ai/queries/not-a-uuid/corrections", "/api/ai/queries/" + id, "/api/ai/queries/" + id + "/other", "/api/ai/queries/../x"} {
		if code, _ := qlogCall(t, s, a, http.MethodPost, bad, `{"kind":"other","note":"x"}`); code != http.StatusNotFound {
			t.Errorf("%s: %d, want 404", bad, code)
		}
	}

	// The colleague's own question; a workspace admin sees both, the
	// colleague sees only their own and may not ask for the workspace view.
	nlqAPI(t, s, colleague, "/api/ai/query/compile", `{"question":"open incidents"}`)
	if got := qlogList(t, s, colleague, ""); len(got) != 1 || got[0]["principal"] != "ua-colleague" {
		t.Fatalf("colleague's own list: %v", got)
	}
	if code, _ := qlogCall(t, s, colleague, http.MethodGet, "/api/ai/queries?scope=tenant", ""); code != http.StatusForbidden {
		t.Errorf("a non-admin asking for the workspace view: %d, want 403", code)
	}
	got := qlogList(t, s, a, "?scope=tenant")
	if len(got) != 2 {
		t.Fatalf("the workspace admin's view: %v", got)
	}
	// ...but never the colleague's own words.
	for _, r := range got {
		switch r["principal"] {
		case "ua-colleague":
			if q, _ := r["question"].(string); q != "" {
				t.Errorf("the workspace view exposed a colleague's question text: %q", q)
			}
			if r["outcome"] == nil || r["outcome"] == "" {
				t.Error("the workspace view must still say how the colleague's question went")
			}
		case a.Sub:
			if q, _ := r["question"].(string); q == "" {
				t.Error("an admin's own question text is theirs to see")
			}
		}
	}
	if got := qlogList(t, s, a, ""); len(got) != 1 || got[0]["id"] != id {
		t.Fatalf("the admin's own view is still their own: %v", got)
	}
	// Even an admin corrects only their OWN question.
	colleagueID := qlogList(t, s, colleague, "")[0]["id"].(string)
	if code, _ := correct(t, s, a, colleagueID, `{"kind":"wrong_entity","note":"x"}`); code != http.StatusNotFound {
		t.Errorf("an admin correcting a colleague's question: %d, want 404", code)
	}
	// And the untouched record is still A's, correctable by A.
	if code, out := correct(t, s, a, id, `{"kind":"wrong_window","note":"I meant yesterday"}`); code != http.StatusCreated ||
		len(out["corrections"].([]any)) != 1 {
		t.Fatalf("owner correction: %d %v", code, out)
	}
}

func TestACorrectedQueryIsValidatedInTheCallersScope(t *testing.T) {
	s, a, _ := qlogFixture(t)
	_, comp := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"show cpu on edge-a for the last hour"}`)
	id := comp["query_log_id"].(string)
	astJSON, _ := json.Marshal(comp["ast"])
	good := string(astJSON)
	if !strings.Contains(good, "device:dev-a") {
		t.Fatalf("fixture: %s", good)
	}
	foreign := strings.Replace(good, "device:dev-a", "device:dev-b", 1) // tenant B's device
	missing := strings.Replace(good, "device:dev-a", "device:no-such", 1)
	var bodies [2]string
	for i, q := range []string{foreign, missing} {
		code, out := correct(t, s, a, id, `{"kind":"wrong_entity","ast":`+q+`}`)
		if code != http.StatusUnprocessableEntity {
			t.Fatalf("a corrected query naming an entity the caller cannot see: %d %v", code, out)
		}
		bodies[i] = nlqJSON(out)
	}
	if bodies[0] != strings.ReplaceAll(bodies[1], "device:no-such", "device:dev-b") || !strings.Contains(bodies[0], "unknown_entity") {
		t.Errorf("a foreign device must be refused exactly like a missing one:\n%s\n%s", bodies[0], bodies[1])
	}
	for name, body := range map[string]string{
		"tenant in the query":   `{"kind":"wrong_entity","ast":` + strings.Replace(good, `"v":1`, `"v":1,"tenant":"t-b"`, 1) + `}`,
		"tenant in the body":    `{"kind":"wrong_entity","note":"x","tenant":"t-b"}`,
		"principal in the body": `{"kind":"wrong_entity","note":"x","by":"ub"}`,
		"unknown kind":          `{"kind":"retrain","note":"x"}`,
		"note too long":         `{"kind":"other","note":"` + strings.Repeat("n", irisquerylog.MaxNoteLen+1) + `"}`,
		"nothing said":          `{"kind":"other"}`,
		"not json":              `kind=other`,
	} {
		if code, out := correct(t, s, a, id, body); code != http.StatusBadRequest {
			t.Errorf("%s: %d %v, want 400", name, code, out)
		}
	}
	if code, _ := qlogCall(t, s, a, http.MethodGet, "/api/ai/queries?scope=everyone", ""); code != http.StatusBadRequest {
		t.Errorf("unknown scope: %d", code)
	}
	if code, _ := qlogCall(t, s, a, http.MethodGet, "/api/ai/queries?limit=100000", ""); code != http.StatusBadRequest {
		t.Errorf("limit past the cap: %d", code)
	}

	code, out := correct(t, s, a, id, `{"kind":"wrong_metric","note":"I meant memory","ast":`+strings.Replace(good, "cpu_util_pct", "mem_util_pct", 1)+`}`)
	if code != http.StatusCreated {
		t.Fatalf("a valid correction: %d %v", code, out)
	}
	cs := out["corrections"].([]any)
	c := cs[len(cs)-1].(map[string]any)
	if c["kind"] != "wrong_metric" || c["by"] != a.Sub || c["corrected_ast_hash"] == "" || !strings.Contains(nlqJSON(c["corrected_ast"]), "mem_util_pct") {
		t.Fatalf("stored correction: %v", c)
	}

	// Offline only: the same question compiles to the same query afterwards.
	_, again := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"show cpu on edge-a for the last hour"}`)
	if nlqJSON(again["ast"]) != nlqJSON(comp["ast"]) {
		t.Fatalf("a correction must not change how Iris compiles:\n%v\n%v", comp["ast"], again["ast"])
	}
}

// failingLog is a query log whose every write fails.
type failingLog struct{ irisquerylog.Store }

func (failingLog) Record(context.Context, string, irisquerylog.Record) (irisquerylog.Record, error) {
	return irisquerylog.Record{}, errors.New("disk on fire")
}

func TestACaptureFailureNeverFailsTheQuestion(t *testing.T) {
	s, a, _ := qlogFixture(t)
	s.nlqQueryLog = failingLog{irisquerylog.NewMemStore()}
	code, out := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"show cpu on edge-a for the last hour"}`)
	if code != 200 || out["ast"] == nil || out["query_log_id"] != nil {
		t.Fatalf("the question must still be answered, without a record id: %d %v", code, out)
	}
	box := askIris(t, s, a, "show cpu on edge-a for the last hour")
	if box["mode"] != "data_query" || strings.Contains(nlqJSON(box["data"]), "query_log_id") {
		t.Fatalf("the Iris box must still answer: %v", box)
	}
	if got := s.nlqQueryLogMetrics.Failed(); got != 2 {
		t.Fatalf("every failed capture is counted: %d", got)
	}
	// Capture off entirely: no ids, no errors, no list.
	s.nlqQueryLog = nil
	if code, out := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"open incidents"}`); code != 200 || out["query_log_id"] != nil {
		t.Fatalf("capture off: %d %v", code, out)
	}
	if code, _ := qlogCall(t, s, a, http.MethodGet, "/api/ai/queries", ""); code != http.StatusServiceUnavailable {
		t.Errorf("list with capture off: %d, want 503", code)
	}
}

func TestQueryLogRoutesAreGated(t *testing.T) {
	s, a, _ := qlogFixture(t)
	if code, _ := qlogCall(t, s, a, http.MethodPost, "/api/ai/queries", ""); code != http.StatusMethodNotAllowed {
		t.Errorf("POST on the list: %d, want 405", code)
	}
	_, comp := nlqAPI(t, s, a, "/api/ai/query/compile", `{"question":"open incidents"}`)
	id := comp["query_log_id"].(string)
	if code, _ := qlogCall(t, s, a, http.MethodGet, "/api/ai/queries/"+id+"/corrections", ""); code != http.StatusMethodNotAllowed {
		t.Errorf("GET on corrections: %d, want 405", code)
	}
	noInfra := a
	noInfra.Role = "api_client_none"
	if code, _ := qlogCall(t, s, noInfra, http.MethodGet, "/api/ai/queries", ""); code != http.StatusForbidden {
		t.Errorf("a role without infrastructure:read: %d, want 403", code)
	}
	t.Setenv("FEATURE_AI", "false")
	if code, _ := qlogCall(t, s, a, http.MethodGet, "/api/ai/queries", ""); code != http.StatusServiceUnavailable {
		t.Errorf("AI disabled: %d, want 503", code)
	}
}
