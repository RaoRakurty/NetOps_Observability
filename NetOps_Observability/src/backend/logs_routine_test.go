// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// Routine management sessions on the Logs page (owner decision 2026-11-11,
// internal/logroutine). The search, the severity tiles and "Export all" leave
// the class out by default and show it with include_routine_mgmt=true. These
// tests pin the wiring: the class is only ever ANDed OUT (post_filter or
// must_not), never put in the scope's filter list, so it cannot widen what a
// caller reads; the tenant filter is the same with the flag on or off; and the
// controller addresses that classify a tenant's records are that tenant's own
// (§3a). The rule itself is proven by evaluation in internal/logroutine.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/logroutine"
	"netops/backend/internal/ratelimit"
	"netops/backend/nms"
)

const (
	acmeCtl   = "10.255.255.1" // acme's vManage system IP
	globexCtl = "172.16.255.1" // globex's: must never classify acme's records
)

const osRoutineReply = `{"took":2,"hits":{"total":{"value":7,"relation":"eq"},"hits":[` +
	`{"_index":"netops-syslog-acme-2026.11.11","_id":"x1","_source":{"event_category":"security_audit","event_type":"snmp_auth_failed_community"}}]},` +
	`"aggregations":{"cx_routine_mgmt":{"doc_count":1234}}}`

// routineServer is logsTestServer with two tenants' controller integrations.
func routineServer(t *testing.T) *server {
	t.Helper()
	s := logsTestServer(t)
	st := nms.NewMemStore()
	ctx := context.Background()
	for _, x := range []struct{ tenant, id, ip string }{{"acme", "vm-acme", acmeCtl}, {"globex", "vm-globex", globexCtl}} {
		if err := st.Upsert(ctx, nms.Integration{Tenant: x.tenant, ID: x.id, Vendor: "cisco", Enabled: true, BaseURL: "https://vmanage.example"}); err != nil {
			t.Fatal(err)
		}
		devs := []nms.ControllerDevice{
			{SourceSystem: "vmanage", KeyKind: nms.KeySystemIP, Key: x.ip, MgmtAddr: x.ip, Role: "controller", Managed: false},
		}
		if err := st.ReplaceDevices(ctx, x.tenant, x.id, devs, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	s.routineCtl = logroutine.NewControllerAddrs(st, time.Minute, nil)
	t.Setenv("CX_PLATFORM_ADDRESSES", "10.70.245.122")
	t.Setenv("PATH_GRAPH_VANTAGE_ADDRESSES", "")
	return s
}

func decodeStoreBody(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("store request is not JSON: %v\n%s", err, raw)
	}
	return m
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// queryBool returns body.query.bool.
func queryBool(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	q, _ := body["query"].(map[string]any)
	b, _ := q["bool"].(map[string]any)
	if b == nil {
		t.Fatalf("no query.bool in %s", jsonOf(body))
	}
	return b
}

func TestLogsSearchHidesRoutineMgmtByDefault(t *testing.T) {
	_, bodies := fakeOS(t, osRoutineReply)
	s := routineServer(t)

	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search", `{"query":"*","signal":"syslog"}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", w.Code, w.Body.String())
	}
	body := decodeStoreBody(t, (*bodies)[0])
	pf := jsonOf(body["post_filter"])
	for _, want := range []string{`"must_not"`, logroutine.RulePoll, logroutine.RuleSessionDetail, logroutine.RuleControllerSource, logroutine.RuleMonitoringSource, acmeCtl, "10.70.245.122"} {
		if !strings.Contains(pf, want) {
			t.Errorf("post_filter missing %q:\n%s", want, pf)
		}
	}
	if !strings.Contains(jsonOf(body["aggs"]), logroutine.AggName) {
		t.Errorf("no routine count aggregation: %s", jsonOf(body["aggs"]))
	}
	// The class never enters the query's own filter list: it can only remove.
	b := queryBool(t, body)
	if strings.Contains(jsonOf(b["filter"]), "routine_mgmt") {
		t.Errorf("the routine class reached the scope filter: %s", jsonOf(b["filter"]))
	}
	if _, has := b["should"]; has {
		t.Errorf("hidden class must not be a should clause: %s", jsonOf(b))
	}

	var resp struct {
		Routine logroutine.Summary `json:"routine_mgmt"`
		Hits    struct {
			Total struct{ Value int } `json:"total"`
			Hits  []map[string]any    `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("answer is not JSON: %v\n%s", err, w.Body.String())
	}
	if resp.Routine != (logroutine.Summary{Included: false, Count: 1234}) {
		t.Errorf("routine summary = %+v", resp.Routine)
	}
	if resp.Hits.Total.Value != 7 || len(resp.Hits.Hits) != 1 {
		t.Errorf("the store's answer changed: %s", w.Body.String())
	}
}

func TestLogsSearchShowsRoutineMgmtWhenAsked(t *testing.T) {
	_, bodies := fakeOS(t, osRoutineReply)
	s := routineServer(t)

	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search", `{"query":"*","signal":"syslog","include_routine_mgmt":true}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", w.Code, w.Body.String())
	}
	body := decodeStoreBody(t, (*bodies)[0])
	if _, has := body["post_filter"]; has {
		t.Errorf("shown class must not be filtered: %s", jsonOf(body["post_filter"]))
	}
	b := queryBool(t, body)
	// Optional and named: it decides nothing about which rows match (must and
	// filter are present, so minimum_should_match is 0) and names the rule.
	if _, has := b["must"]; !has {
		t.Fatal("the query lost its must clause; a should would then become required")
	}
	if !strings.Contains(jsonOf(b["should"]), logroutine.RulePoll) {
		t.Errorf("shown class is not a named should clause: %s", jsonOf(b["should"]))
	}
	if !strings.Contains(w.Body.String(), `"routine_mgmt":{"included":true,"count":1234}`) {
		t.Errorf("answer lacks the routine summary: %s", w.Body.String())
	}

	// The GET form reads the same parameter, and refuses a word that is not a boolean.
	w = httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?query=*&signal=syslog&include_routine_mgmt=true", "", acme()))
	if w.Code != http.StatusOK || strings.Contains((*bodies)[1], "post_filter") {
		t.Errorf("GET include_routine_mgmt=true: status %d, body %s", w.Code, (*bodies)[1])
	}
	w = httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodGet, "/api/logs/search?query=*&include_routine_mgmt=maybe", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Errorf("a non-boolean flag: status %d, want 400", w.Code)
	}
}

// The flows store holds no management sessions: nothing is sent and the answer
// carries no summary (flows has its own toggle).
func TestLogsSearchFlowsCarryNoRoutineClass(t *testing.T) {
	_, bodies := fakeOS(t, `{"hits":{"total":{"value":0},"hits":[]}}`)
	s := routineServer(t)
	w := httptest.NewRecorder()
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search", `{"query":"*","signal":"flows"}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if strings.Contains((*bodies)[0], "routine_mgmt") || strings.Contains((*bodies)[0], "post_filter") {
		t.Errorf("flows search carries the routine class: %s", (*bodies)[0])
	}
	if strings.Contains(w.Body.String(), `"routine_mgmt"`) {
		t.Errorf("flows answer carries a routine summary: %s", w.Body.String())
	}
}

// §3a: the new clause leaves the tenant scope exactly as it was, with the flag
// on or off, and only the caller's OWN controller addresses classify records.
func TestRoutineMgmtKeepsTheTenantScope(t *testing.T) {
	_, bodies := fakeOS(t, osRoutineReply)
	s := routineServer(t)

	for i, payload := range []string{
		`{"query":"*","signal":"syslog"}`,
		`{"query":"*","signal":"syslog","include_routine_mgmt":true}`,
		`{"query":"*","signal":""}`,
	} {
		w := httptest.NewRecorder()
		s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search", payload, acme()))
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", payload, w.Code)
		}
		raw := (*bodies)[i]
		body := decodeStoreBody(t, raw)
		filter := jsonOf(queryBool(t, body)["filter"])
		if !strings.Contains(filter, `"tenant_id":"acme"`) {
			t.Errorf("%s: TENANT FILTER DROPPED from the query filter:\n%s", payload, filter)
		}
		if strings.Contains(raw, globexCtl) || strings.Contains(raw, "globex") {
			t.Errorf("%s: TENANT LEAK: another tenant's controller or name reached acme's query:\n%s", payload, raw)
		}
		if !strings.Contains(raw, acmeCtl) {
			t.Errorf("%s: acme's own controller address is not used", payload)
		}
	}

	// A globex principal gets globex's controller, never acme's.
	w := httptest.NewRecorder()
	globex := jwtClaims{Sub: "g@globex", Role: RoleOperator, Tenant: "globex"}
	s.handleLogsSearch(w, req(http.MethodPost, "/api/logs/search", `{"query":"*","signal":"syslog"}`, globex))
	raw := (*bodies)[len(*bodies)-1]
	if strings.Contains(raw, acmeCtl) || !strings.Contains(raw, globexCtl) {
		t.Errorf("globex's query used the wrong controller addresses:\n%s", raw)
	}
	if !strings.Contains(jsonOf(queryBool(t, decodeStoreBody(t, raw))["filter"]), `"tenant_id":"globex"`) {
		t.Errorf("globex's tenant filter missing:\n%s", raw)
	}
}

// The tiles count what the rows show.
func TestSeverityCountsFollowTheRoutineToggle(t *testing.T) {
	_, bodies := fakeOS(t, osSeverityReply)
	s := routineServer(t)

	w := httptest.NewRecorder()
	s.handleLogsSeverityCounts(w, req(http.MethodGet, "/api/logs/severity-counts?signal=syslog", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", w.Code, w.Body.String())
	}
	b := queryBool(t, decodeStoreBody(t, (*bodies)[0]))
	if !strings.Contains(jsonOf(b["must_not"]), logroutine.RulePoll) {
		t.Errorf("default count must leave the class out (must_not): %s", jsonOf(b))
	}
	if strings.Contains(jsonOf(b["filter"]), "routine_mgmt") || !strings.Contains(jsonOf(b["filter"]), `"tenant_id":"acme"`) {
		t.Errorf("scope filter changed: %s", jsonOf(b["filter"]))
	}
	// The scope's own must_not members (the synthetic-debug exclusion) are kept.
	if !strings.Contains(jsonOf(b["must_not"]), "match_phrase") {
		t.Errorf("the scope's must_not members were lost: %s", jsonOf(b["must_not"]))
	}
	if out := decodeSeverity(t, w); out.RoutineMgmtIncluded == nil || *out.RoutineMgmtIncluded {
		t.Errorf("routine_mgmt_included = %v, want false", out.RoutineMgmtIncluded)
	}

	w = httptest.NewRecorder()
	s.handleLogsSeverityCounts(w, req(http.MethodGet, "/api/logs/severity-counts?signal=syslog&include_routine_mgmt=true", "", acme()))
	if strings.Contains((*bodies)[1], "routine_mgmt") {
		t.Errorf("shown class still counted out: %s", (*bodies)[1])
	}
	if out := decodeSeverity(t, w); out.RoutineMgmtIncluded == nil || !*out.RoutineMgmtIncluded {
		t.Errorf("routine_mgmt_included = %v, want true", out.RoutineMgmtIncluded)
	}

	w = httptest.NewRecorder()
	s.handleLogsSeverityCounts(w, req(http.MethodGet, "/api/logs/severity-counts?signal=syslog&include_routine_mgmt=sometimes", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Errorf("non-boolean flag: status %d, want 400", w.Code)
	}
}

// "Export all" leaves out what the page leaves out, and its count agrees.
func TestLogsExportFollowsTheRoutineToggle(t *testing.T) {
	_, bodies := fakeOS(t, `{"count":0,"hits":{"total":{"value":0},"hits":[]}}`)
	s := routineServer(t)
	s.exportLimiter = ratelimit.New()

	w := httptest.NewRecorder()
	s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?format=csv&signal=syslog&query=*", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", w.Code, w.Body.String())
	}
	if len(*bodies) == 0 {
		t.Fatal("the export never reached the store")
	}
	for _, raw := range *bodies {
		b := queryBool(t, decodeStoreBody(t, raw))
		if !strings.Contains(jsonOf(b["must_not"]), logroutine.RulePoll) {
			t.Errorf("default export must leave the class out: %s", raw)
		}
		if !strings.Contains(jsonOf(b["filter"]), `"tenant_id":"acme"`) || strings.Contains(raw, globexCtl) {
			t.Errorf("export scope changed or leaked: %s", raw)
		}
	}

	n := len(*bodies)
	w = httptest.NewRecorder()
	s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?format=csv&signal=syslog&query=*&include_routine_mgmt=true", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", w.Code, w.Body.String())
	}
	for _, raw := range (*bodies)[n:] {
		if strings.Contains(raw, "routine_mgmt") {
			t.Errorf("shown class still left out of the export: %s", raw)
		}
	}

	w = httptest.NewRecorder()
	s.handleLogsExport(w, req(http.MethodGet, "/api/logs/export?format=csv&signal=syslog&include_routine_mgmt=x", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Errorf("non-boolean flag: status %d, want 400", w.Code)
	}
}
