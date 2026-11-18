// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServiceNowFetchChangeIsOneBoundedRead(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true") // the fake listens on loopback
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)
		if q := r.URL.Query().Get("sysparm_query"); q != "number=CHG0012345" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{}}) // best-effort fake reply
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{ // best-effort fake reply
			"number": "CHG0012345", "sys_id": "abc", "short_description": "Upgrade core-1",
			"implementation_plan": strings.Repeat("x", MaxChangeFieldBytes+50), "backout_plan": "install rollback",
			"test_plan": "compare with baseline", "risk": "Moderate", "state": "Scheduled",
			"start_date": "2026-11-20 02:00:00", "end_date": "2026-11-20 04:00:00",
		}}})
	}))
	defer srv.Close()
	a := NewServiceNowAdapterWithClient(srv.Client())
	cfg := SystemConfig{System: "servicenow", InstanceURL: srv.URL, AuthType: "basic", User: "u", Password: "p"}

	ch, found, err := a.FetchChange(context.Background(), cfg, "CHG0012345")
	if err != nil || !found {
		t.Fatalf("fetch: %v %v", found, err)
	}
	if ch.Title != "Upgrade core-1" || ch.BackoutPlan != "install rollback" || ch.StartAt.IsZero() || ch.EndAt.Hour() != 4 {
		t.Fatalf("fields: %+v", ch)
	}
	if len(ch.ImplementationPlan) != MaxChangeFieldBytes {
		t.Fatalf("a field is bounded to %d bytes, got %d", MaxChangeFieldBytes, len(ch.ImplementationPlan))
	}
	if _, found, err := a.FetchChange(context.Background(), cfg, "CHG0099999"); err != nil || found {
		t.Fatalf("an unknown change is not found: %v %v", found, err)
	}
	for _, m := range methods {
		if !strings.HasPrefix(m, "GET /api/now/table/change_request") {
			t.Fatalf("a change read sent %s — only a GET of change_request is allowed", m)
		}
	}
	// A reference that is not a change number never reaches the wire.
	before := len(methods)
	for _, bad := range []string{"INC0012345", "CHG12345&sysparm_query=x", "../incident", ""} {
		if _, _, err := a.FetchChange(context.Background(), cfg, bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	if len(methods) != before {
		t.Fatalf("an invalid reference made a request")
	}
}

func TestJiraFetchChangeReadsAnIssue(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true") // the fake listens on loopback
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/rest/api/2/issue/NET-42" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"10001","key":"NET-42","fields":{"summary":"Upgrade edge-1","description":"rollback: reload previous image","status":{"name":"To Do"}}}`)) // best-effort fake reply
	}))
	defer srv.Close()
	a := NewJiraAdapterWithClient(srv.Client())
	cfg := SystemConfig{System: "jira", InstanceURL: srv.URL, User: "u", APIToken: "t"}
	ch, found, err := a.FetchChange(context.Background(), cfg, "NET-42")
	if err != nil || !found || ch.Title != "Upgrade edge-1" || !strings.Contains(ch.Description, "rollback") || ch.State != "To Do" {
		t.Fatalf("jira issue: %+v %v %v", ch, found, err)
	}
	if _, found, err := a.FetchChange(context.Background(), cfg, "NET-43"); err != nil || found {
		t.Fatalf("a missing issue is not found: %v %v", found, err)
	}
	if _, _, err := a.FetchChange(context.Background(), cfg, "net-42/../x"); err == nil {
		t.Fatal("an invalid key was accepted")
	}
}

func TestValidChangeNumber(t *testing.T) {
	for _, c := range []struct {
		system, n string
		ok        bool
	}{
		{"servicenow", "CHG0012345", true}, {"servicenow", "NET-42", false},
		{"jira", "NET-42", true}, {"jira", "CHG0012345", false}, {"pagerduty", "CHG0012345", false},
	} {
		if got := ValidChangeNumber(c.system, c.n); got != c.ok {
			t.Errorf("ValidChangeNumber(%s, %s) = %v", c.system, c.n, got)
		}
	}
}
