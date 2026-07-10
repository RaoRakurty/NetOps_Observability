package main

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// ticketing_http_test.go — cross-tenant isolation through the REAL router + auth
// middleware for the #78 P3 ticketing API (CLAUDE.md §3a). Two tenants, each a
// tenant-scoped admin; assert incident-policy create stamps the tenant from the
// TOKEN (not the body), lists are own-only, a cross-tenant policy id is 404 on
// get/put/delete, and the outbox view never leaks across tenants.

type tktFixture struct {
	tenantID, token string
}

func setupTicketingTenants(t *testing.T) (*httptest.Server, *server, map[string]*tktFixture) {
	t.Helper()
	srv, s := newTestServerState(t)
	s.ticketing = newMemTicketingStore() // harness doesn't wire it; handlers read it live
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*tktFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "tadmin-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &tktFixture{tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	return srv, s, fix
}

func TestIncidentPolicyAPI_TenantIsolation(t *testing.T) {
	srv, _, fix := setupTicketingTenants(t)
	a, b := fix["A"], fix["B"]

	// A creates a policy AND tries to forge tenant_id=B in the body → the server
	// must stamp A's tenant, ignoring the payload (§3a #2).
	st, body := do(t, srv, "POST", "/api/incident-policies", a.token, map[string]any{
		"name": "A policy", "tenant_id": b.tenantID, "enabled": true, "min_verdict": "confirmed",
	})
	if st != 200 {
		t.Fatalf("A create policy: %d %s", st, body)
	}
	var aPol incidentPolicy
	if err := json.Unmarshal(body, &aPol); err != nil {
		t.Fatal(err)
	}
	if aPol.TenantID != a.tenantID {
		t.Fatalf("policy tenant stamped from body, not token: got %q want %q", aPol.TenantID, a.tenantID)
	}

	// B creates its own policy.
	st, body = do(t, srv, "POST", "/api/incident-policies", b.token, map[string]any{
		"name": "B policy", "enabled": true,
	})
	if st != 200 {
		t.Fatalf("B create policy: %d %s", st, body)
	}
	bPol := incidentPolicy{}
	_ = json.Unmarshal(body, &bPol)

	// A lists → sees ONLY its own policy.
	st, body = do(t, srv, "GET", "/api/incident-policies", a.token, nil)
	if st != 200 {
		t.Fatalf("A list: %d %s", st, body)
	}
	var listed struct {
		Policies []incidentPolicy `json:"policies"`
	}
	_ = json.Unmarshal(body, &listed)
	if len(listed.Policies) != 1 || listed.Policies[0].TenantID != a.tenantID {
		t.Fatalf("A list leaked across tenants: %+v", listed.Policies)
	}

	// A cannot GET / PUT / DELETE B's policy — each is 404 (never reveal the id).
	if st, _ := do(t, srv, "GET", "/api/incident-policies/"+bPol.ID, a.token, nil); st != 404 {
		t.Fatalf("A GET B's policy: status %d, want 404", st)
	}
	if st, _ := do(t, srv, "PUT", "/api/incident-policies/"+bPol.ID, a.token, map[string]any{"name": "hijack", "enabled": false}); st != 404 {
		t.Fatalf("A PUT B's policy: status %d, want 404", st)
	}
	if st, _ := do(t, srv, "DELETE", "/api/incident-policies/"+bPol.ID, a.token, nil); st != 404 {
		t.Fatalf("A DELETE B's policy: status %d, want 404", st)
	}
	// B's policy still resolves for B — A's failed delete did not touch it.
	if st, _ := do(t, srv, "GET", "/api/incident-policies/"+bPol.ID, b.token, nil); st != 200 {
		t.Fatalf("B's own policy vanished after A's cross-tenant delete attempt: status %d", st)
	}
}

func TestIncidentPolicyAPI_Simulator(t *testing.T) {
	srv, _, fix := setupTicketingTenants(t)
	a := fix["A"]
	st, body := do(t, srv, "POST", "/api/incident-policies", a.token, map[string]any{
		"name": "A policy", "enabled": true, "min_verdict": "suspected", "require_customer_facing": true,
		"suspected_requires_critical": true,
	})
	if st != 200 {
		t.Fatalf("create: %d %s", st, body)
	}
	pol := incidentPolicy{}
	_ = json.Unmarshal(body, &pol)

	// A confirmed, customer-facing fault should be ticket-worthy.
	st, body = do(t, srv, "POST", "/api/incident-policies/"+pol.ID+"/test", a.token, map[string]any{
		"verdict": "confirmed", "peak_severity": "crit", "has_affected_entity": true,
	})
	if st != 200 {
		t.Fatalf("simulate: %d %s", st, body)
	}
	var dec ticketDecision
	_ = json.Unmarshal(body, &dec)
	if !dec.Create {
		t.Fatalf("confirmed customer fault should create, got hold: %q", dec.Reason)
	}

	// An undetermined object must hold.
	_, body = do(t, srv, "POST", "/api/incident-policies/"+pol.ID+"/test", a.token, map[string]any{
		"verdict": "undetermined", "has_affected_entity": true,
	})
	_ = json.Unmarshal(body, &dec)
	if dec.Create {
		t.Fatalf("undetermined must hold, got create")
	}
}

func TestTicketsOutboxAPI_TenantIsolation(t *testing.T) {
	srv, s, fix := setupTicketingTenants(t)
	a, b := fix["A"], fix["B"]
	ctx := context.Background()

	// Seed an outbox item for each tenant directly in the store.
	_ = s.ticketing.EnqueueOutbox(ctx, ticketOutboxItem{
		TenantID: a.tenantID, ID: "oa", CorrObjectID: "obj-a", Action: "create",
		IdempotencyKey: "servicenow:create:" + a.tenantID + ":obj-a", Status: "pending"})
	_ = s.ticketing.EnqueueOutbox(ctx, ticketOutboxItem{
		TenantID: b.tenantID, ID: "ob", CorrObjectID: "obj-b", Action: "create",
		IdempotencyKey: "servicenow:create:" + b.tenantID + ":obj-b", Status: "pending"})

	st, body := do(t, srv, "GET", "/api/tickets/outbox", a.token, nil)
	if st != 200 {
		t.Fatalf("A outbox: %d %s", st, body)
	}
	var out struct {
		Outbox []ticketOutboxItem `json:"outbox"`
	}
	_ = json.Unmarshal(body, &out)
	if len(out.Outbox) != 1 || out.Outbox[0].TenantID != a.tenantID {
		t.Fatalf("A outbox leaked across tenants: %+v", out.Outbox)
	}
}

// TestTicketStatusView_URLNotDoubled guards the incident deep-link against the
// live-PDI bug (2026-07-10): links written before the InstanceURL fix stored the
// FULL nav_to.do incident URL, and the view appended the nav path a second time.
// Both row shapes must yield ONE clean deep-link.
func TestTicketStatusView_URLNotDoubled(t *testing.T) {
	const inst = "https://dev000000.service-now.com"
	const sys = "abc123"
	want := inst + "/nav_to.do?uri=incident.do?sys_id=" + sys

	for name, stored := range map[string]string{
		"bare-instance": inst,
		"legacy-full-deep-link": inst + "/nav_to.do?uri=incident.do?sys_id=" + sys,
	} {
		v := ticketStatusView(ticketLink{
			ExternalSystem: "servicenow", TicketNumber: "INC0010001",
			SysID: sys, InstanceURL: stored, Status: "open",
		}, true)
		if got := v["url"]; got != want {
			t.Fatalf("%s: url = %v, want %s", name, got, want)
		}
		if got := v["instance_url"]; got != inst {
			t.Fatalf("%s: instance_url = %v, want %s", name, got, inst)
		}
	}
}
