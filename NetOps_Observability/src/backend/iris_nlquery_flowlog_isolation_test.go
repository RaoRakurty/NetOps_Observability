// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// The NL query's flow_top and log_search reads (tracker 337 N-C4, §3a.5).
//
// nlqScope.FlowTop / LogSearch receive only what a validated AST carries —
// device ids the planner already resolved as visible, a window, a closed
// grouping, closed severity and topic values — and run the same reads as the
// Iris tools. Pinned here: the ids are RE-CHECKED against the caller's own
// devices (a foreign id that slipped through reads nothing, and with no own
// device left nothing is queried at all); only inventory addresses reach SQL;
// the flow scope is the Flows page's stricter link rule; the syslog read keeps
// the per-tenant index, the doc-level tenant filter and the routine-session
// exclusion; severity and topic become the server's own terms and patterns,
// never text; and a tenant with no devices never queries.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/plan"
)

var nlqWin = struct{ from, to time.Time }{time.Now().Add(-time.Hour), time.Now()}

func TestNLQFlowTopReadsOnlyTheCallersOwnExporters(t *testing.T) {
	t.Setenv("CX_PLATFORM_ADDRESSES", "10.70.0.5")
	calls := fakeCHScoped(t, `{"meta":[],"data":[{"a":"192.0.2.10","b":"198.51.100.1","bytes_total":"24000","flows":"60","rate_reported":"0"}],"rows":1}`)
	s := flowsTestServer(t)
	h := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", acme()), acme())
	ans, err := h.FlowTop(context.Background(), plan.FlowQuery{
		From: nlqWin.from, To: nlqWin.to, Devices: []string{"acme-core", "globex-core"}, By: nlqast.FlowGroupTalker, Limit: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 1 {
		t.Fatalf("want one statement, got %d", len(*calls))
	}
	c := (*calls)[0]
	if c.scope != "acme" {
		t.Errorf("tenant_scope %q, want acme", c.scope)
	}
	for _, want := range []string{acmeLinkClause, "sampler_address IN ('10.1.0.1')", "NOT (src_addr IN ('10.70.0.5')", "GROUP BY a, b"} {
		if !strings.Contains(c.sql, want) {
			t.Errorf("statement lacks %q:\n%s", want, c.sql)
		}
	}
	if strings.Contains(c.sql, "10.2.0.1") || strings.Contains(c.sql, "globex") {
		t.Errorf("TENANT LEAK: a foreign device id reached SQL:\n%s", c.sql)
	}
	if len(ans.Rows) != 1 || ans.Rows[0].Bytes != 24000 || ans.Sampling != "not_reported" {
		t.Fatalf("answer = %+v", ans)
	}
	notes := strings.Join(ans.Notes, " | ")
	if !strings.Contains(notes, "monitoring traffic is left out") || !strings.Contains(notes, "did not report a sampling rate") {
		t.Errorf("notes must carry the exclusion and the sampling basis: %q", notes)
	}
}

func TestNLQFlowTopForeignOnlyDevicesAndNoDeviceTenantNeverQuery(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[],"rows":0}`)
	s := flowsTestServer(t)
	h := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", acme()), acme())
	if ans, err := h.FlowTop(context.Background(), plan.FlowQuery{From: nlqWin.from, To: nlqWin.to, Devices: []string{"globex-core"}, Limit: 10}); err != nil || len(ans.Rows) != 0 {
		t.Fatalf("foreign-only devices: %+v %v", ans, err)
	}
	nobody := jwtClaims{Sub: "n@nobody", Role: RoleOperator, Tenant: "nobody"}
	hn := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", nobody), nobody)
	if ans, err := hn.FlowTop(context.Background(), plan.FlowQuery{From: nlqWin.from, To: nlqWin.to, Limit: 10}); err != nil || len(ans.Rows) != 0 {
		t.Fatalf("no-device tenant: %+v %v", ans, err)
	}
	if len(*calls) != 0 {
		t.Fatalf("default-closed: %d statements ran", len(*calls))
	}
}

func TestNLQFlowTopServicesUsesTheServicesStatement(t *testing.T) {
	calls := fakeCHScoped(t, `{"meta":[],"data":[{"port":"443","bytes_total":"9","flows":"1","rate_reported":"1"}],"rows":1}`)
	s := flowsTestServer(t)
	h := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", acme()), acme())
	ans, err := h.FlowTop(context.Background(), plan.FlowQuery{From: nlqWin.from, To: nlqWin.to, By: nlqast.FlowGroupService, Limit: 5})
	if err != nil || len(*calls) != 1 {
		t.Fatalf("%v, %d statements", err, len(*calls))
	}
	if !strings.Contains((*calls)[0].sql, "dst_port > 0") || !strings.Contains((*calls)[0].sql, "LIMIT 5") {
		t.Errorf("services statement:\n%s", (*calls)[0].sql)
	}
	if len(ans.Rows) != 1 || ans.Rows[0].Service != "HTTPS" || ans.Rows[0].Port != 443 || ans.Sampling != "reported" {
		t.Fatalf("answer = %+v", ans)
	}
}

const nlqLogReply = `{"hits":{"total":{"value":3},"hits":[{"_source":{"summary":"BGP neighbor 10.0.0.2 Down (hold timer expired) password=hunter2","timestamp":"2026-11-13T10:00:00Z","host":"acme-core","normalized_severity":"error","event_type":"bgp_neighbor_down"}}]},` +
	`"aggregations":{"cx_routine_mgmt":{"doc_count":777}}}`

func TestNLQLogSearchClosedFiltersAndOwnDevicesOnly(t *testing.T) {
	paths, bodies := fakeOS(t, nlqLogReply)
	s := routineServer(t)
	h := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", acme()), acme())
	ans, err := h.LogSearch(context.Background(), plan.LogQuery{
		From: nlqWin.from, To: nlqWin.to, Devices: []string{"acme-core", "globex-core"},
		MinSeverity: "error", Topics: []string{"bgp"}, Limit: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(*bodies) != 1 {
		t.Fatalf("want one search, got %d", len(*bodies))
	}
	if p := (*paths)[0]; !strings.Contains(p, "acme") || strings.Contains(p, "globex") {
		t.Errorf("index pattern %q must be acme's own", p)
	}
	body := decodeStoreBody(t, (*bodies)[0])
	filter := jsonOf(queryBool(t, body)["filter"])
	for _, want := range []string{`"device_id":["acme-core"]`, `"host":["acme-core"]`, `"normalized_severity":["critical","error"]`, `"*bgp*"`} {
		if !strings.Contains(filter, want) {
			t.Errorf("filter lacks %s:\n%s", want, filter)
		}
	}
	if strings.Contains(filter, "globex") {
		t.Errorf("TENANT LEAK: a foreign device reached the syslog filter:\n%s", filter)
	}
	if _, ok := body["post_filter"]; !ok {
		t.Error("routine management sessions must be left out by default")
	}
	if len(ans.Rows) != 1 || ans.Total != 3 || ans.Rows[0].Device != "acme-core" || ans.Rows[0].Severity != "error" {
		t.Fatalf("answer = %+v", ans)
	}
	if strings.Contains(ans.Rows[0].Text, "hunter2") {
		t.Errorf("a secret in a log line reached the answer unredacted: %q", ans.Rows[0].Text)
	}
	if !strings.Contains(strings.Join(ans.Notes, " | "), "left out 777 routine management-session lines") {
		t.Errorf("the routine exclusion must be said: %q", ans.Notes)
	}
}

func TestNLQLogSearchForeignOnlyDevicesNeverSearch(t *testing.T) {
	_, bodies := fakeOS(t, nlqLogReply)
	s := routineServer(t)
	h := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", acme()), acme())
	ans, err := h.LogSearch(context.Background(), plan.LogQuery{From: nlqWin.from, To: nlqWin.to, Devices: []string{"globex-core"}, Limit: 20})
	if err != nil || len(ans.Rows) != 0 {
		t.Fatalf("%+v %v", ans, err)
	}
	if len(*bodies) != 0 {
		t.Fatalf("a foreign-only device list ran %d searches", len(*bodies))
	}
}

func TestNLQLogSearchUnknownTopicMatchesNothing(t *testing.T) {
	_, bodies := fakeOS(t, nlqLogReply)
	s := routineServer(t)
	h := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", acme()), acme())
	if _, err := h.LogSearch(context.Background(), plan.LogQuery{From: nlqWin.from, To: nlqWin.to, Topics: []string{"*"}, Limit: 5}); err != nil {
		t.Fatal(err)
	}
	filter := jsonOf(queryBool(t, decodeStoreBody(t, (*bodies)[0]))["filter"])
	if !strings.Contains(filter, "match_none") || strings.Contains(filter, `"value":"*"`) {
		t.Fatalf("an unknown topic must match nothing, never become a pattern:\n%s", filter)
	}
}

// Every closed topic the AST admits has server-owned patterns, and no pattern
// exists for a topic the AST does not know.
func TestEveryLogTopicHasPatterns(t *testing.T) {
	for _, tp := range nlqast.LogTopics {
		if len(logTopicEventTypes[tp]) == 0 {
			t.Errorf("topic %q has no event-type patterns", tp)
		}
	}
	if len(logTopicEventTypes) != len(nlqast.LogTopics) {
		t.Errorf("logTopicEventTypes has %d topics, the AST %d", len(logTopicEventTypes), len(nlqast.LogTopics))
	}
}
