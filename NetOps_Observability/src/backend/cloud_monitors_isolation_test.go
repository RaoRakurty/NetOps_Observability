// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_monitors_isolation_test.go — CROSS-ORG isolation for
// /api/cloud/monitors[/{id}] (CLAUDE.md §3a rule 5), through the real router +
// auth middleware: own-only list, cross-tenant get/put/delete → 404, as_tenant
// into another org ignored, tenant stamped from the token.

import (
	"encoding/json"
	"testing"
)

func TestCloudMonitorsIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.cloudMonitors = newCloudMonitorStore("") // in-memory
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	onboardOrg := func(org, tenant, slug string) onboardResponse {
		st, b := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
			"org_name": org, "tenant_name": tenant, "tenant_slug": slug,
		})
		if st != 201 {
			t.Fatalf("onboard %s: %d %s", org, st, b)
		}
		var r onboardResponse
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	acme := onboardOrg("Acme Corp", "Acme Prod", "acme-mon")
	globex := onboardOrg("Globex Inc", "Globex Prod", "globex-mon")

	mkUser := func(name, tenantID string) string {
		if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": name, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		return login(t, srv, name, "Passw0rd!2345").Token
	}
	alice := mkUser("alice-mon", acme.Tenant.ID)
	bob := mkUser("bob-mon", globex.Tenant.ID)

	create := func(token, name string) cloudMonitor {
		st, b := do(t, srv, "POST", "/api/cloud/monitors", token, map[string]any{
			"name": name, "metric": "cloud_cpu_util", "mode": "threshold",
			"condition": "above", "threshold": 90, "enabled": true,
		})
		if st != 201 {
			t.Fatalf("create %s: %d %s", name, st, b)
		}
		var m cloudMonitor
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	listNames := func(token, extraQS string) []string {
		st, b := do(t, srv, "GET", "/api/cloud/monitors"+extraQS, token, nil)
		if st != 200 {
			t.Fatalf("list: %d %s", st, b)
		}
		var r struct {
			Monitors []cloudMonitor `json:"monitors"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			t.Fatal(err)
		}
		out := make([]string, 0, len(r.Monitors))
		for _, m := range r.Monitors {
			out = append(out, m.Name)
		}
		return out
	}

	aMon := create(alice, "acme-cpu")
	bMon := create(bob, "globex-cpu")

	// 1) Own-only list.
	if got := listNames(alice, ""); len(got) != 1 || got[0] != "acme-cpu" {
		t.Fatalf("alice leak: %v", got)
	}
	if got := listNames(bob, ""); len(got) != 1 || got[0] != "globex-cpu" {
		t.Fatalf("bob leak: %v", got)
	}

	// 2) Cross-tenant by id → 404 for GET/PUT/DELETE (never reveal existence).
	if st, _ := do(t, srv, "GET", "/api/cloud/monitors/"+bMon.ID, alice, nil); st != 404 {
		t.Fatalf("cross GET: want 404, got %d", st)
	}
	if st, _ := do(t, srv, "PUT", "/api/cloud/monitors/"+bMon.ID, alice, map[string]any{
		"name": "hijack", "metric": "cloud_cpu_util", "mode": "threshold", "condition": "above", "threshold": 1, "enabled": true,
	}); st != 404 {
		t.Fatalf("cross PUT: want 404, got %d", st)
	}
	if st, _ := do(t, srv, "DELETE", "/api/cloud/monitors/"+bMon.ID, alice, nil); st != 404 {
		t.Fatalf("cross DELETE: want 404, got %d", st)
	}
	if got := listNames(bob, ""); len(got) != 1 || got[0] != "globex-cpu" {
		t.Fatalf("bob's monitor was touched: %v", got)
	}

	// 3) as_tenant into another org ignored — alice still sees/writes her own.
	if got := listNames(alice, "?as_tenant="+globex.Tenant.ID); len(got) != 1 || got[0] != "acme-cpu" {
		t.Fatalf("as_tenant read leaked: %v", got)
	}
	if st, _ := do(t, srv, "GET", "/api/cloud/monitors/"+bMon.ID+"?as_tenant="+globex.Tenant.ID, alice, nil); st != 404 {
		t.Fatal("as_tenant get must still be 404")
	}

	// 4) Tenant stamped from the token: alice's own monitor carries her tenant.
	if aMon.TenantID != acme.Tenant.ID {
		t.Fatalf("monitor tenant %q, want %q", aMon.TenantID, acme.Tenant.ID)
	}

	// 5) Unauthenticated → 401.
	if st, _ := do(t, srv, "GET", "/api/cloud/monitors", "", nil); st != 401 {
		t.Fatal("unauthenticated must be refused")
	}
}
