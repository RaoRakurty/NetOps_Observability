// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"netops/backend/ai"
	"netops/backend/internal/ticketing"
)

// §3a for Iris's change-plan review: a change ticket is read through the
// CALLER's own workspace connection only. Tenant B, with no connection, never
// reaches tenant A's ServiceNow; the Global view reads none; the read is one GET.
func TestIrisChangeTicketReadIsOwnTenantOnly(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true") // the fake ServiceNow listens on loopback
	s, _, alice, bob, _ := ctxFixture(t)
	tenantA, _ := principalTenant(alice)

	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.Path+"?"+r.URL.Query().Get("sysparm_query"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("sysparm_query") != "number=CHG0012345" {
			_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{}}) // best-effort fake reply
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"result": []any{map[string]any{ // best-effort fake reply
			"number": "CHG0012345", "short_description": "Upgrade core-sw-1", "backout_plan": "boot the previous release",
		}}})
	}))
	defer srv.Close()

	cred := strings.Join([]string{"not", "a", "credential"}, "-")
	s.itsmCfg = ticketing.NewITSMConfigStoreForTest(map[string]itsmConfig{
		itsmKey(tenantA): {ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: srv.URL, User: "svc", Password: cred}},
	})
	reader := &irisChangeReader{srv: s, readers: map[string]ticketing.ChangeReader{
		"servicenow": ticketing.NewServiceNowAdapterWithClient(srv.Client()),
		"jira":       ticketing.NewJiraAdapterWithClient(srv.Client()),
	}}
	ctx := context.Background()

	ch, err := reader.read(ctx, tenantA, "CHG0012345")
	if err != nil || ch.Title != "Upgrade core-sw-1" || ch.BackoutPlan != "boot the previous release" || ch.System != "servicenow" {
		t.Fatalf("tenant A reads its own change: %+v %v", ch, err)
	}
	if _, err := reader.read(ctx, tenantA, "CHG0099999"); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("an unknown change is not found: %v", err)
	}
	before := len(seen)

	tenantB, _ := principalTenant(bob)
	if _, err := reader.read(ctx, tenantB, "CHG0012345"); !errors.Is(err, ai.ErrChangeTicketUnavailable) {
		t.Fatalf("tenant B (no connection) must not read tenant A's change: %v", err)
	}
	if _, err := reader.read(ctx, tenantA, "NET-42"); !errors.Is(err, ai.ErrChangeTicketUnavailable) {
		t.Fatalf("tenant A has no Jira connection: %v", err)
	}
	for _, bad := range []string{"CHG12&sysparm_query=x", "INC0012345", "../x"} {
		if _, err := reader.read(ctx, tenantA, bad); !errors.Is(err, ai.ErrNotFound) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	if len(seen) != before {
		t.Fatalf("a refused read reached the ITSM system: %v", seen[before:])
	}
	for _, r := range seen {
		if !strings.HasPrefix(r, "GET /api/now/table/change_request?") {
			t.Fatalf("the change read sent %s", r)
		}
	}

	// The seam takes its tenant from the token, never the ai.Principal.
	fn := s.aiChangeTicket(bob)
	if _, err := fn(ctx, ai.Principal{Tenant: tenantA}, "CHG0012345"); !errors.Is(err, ai.ErrChangeTicketUnavailable) {
		t.Fatalf("a forged principal tenant widened the read: %v", err)
	}
	global := jwtClaims{Sub: "root", Role: "super-admin", Tenant: ""}
	if _, cross := principalTenant(global); !cross {
		t.Fatal("fixture: the platform owner with no acting tenant is the Global view")
	}
	if _, err := s.aiChangeTicket(global)(ctx, ai.Principal{Tenant: tenantA}, "CHG0012345"); !errors.Is(err, ai.ErrChangeTicketUnavailable) {
		t.Fatalf("the Global view read a workspace's change: %v", err)
	}
}
