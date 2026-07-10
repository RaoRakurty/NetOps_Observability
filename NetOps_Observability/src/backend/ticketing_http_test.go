package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// corrCHStub emulates ClickHouse with the STRICT tenant_iso row policy on the
// corr tables (visible iff tenant_id = tenant_scope OR scope = '__all__'). It
// serves one platform-owned object (tenant_id "") under strictID. Under laxID it
// deliberately mis-emulates a LAX policy that leaks the platform row to ANY named
// scope — exercising the handler's default-closed owner guard (defense in depth
// if the DB policy ever drifts).
const (
	tktStrictCorrID = "11111111-2222-4333-8444-555555555555"
	tktLaxCorrID    = "99999999-8888-4777-8666-555555555555"
)

func corrCHStub(t *testing.T) *httptest.Server {
	t.Helper()
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sqlB, _ := io.ReadAll(r.Body)
		sql := string(sqlB)
		scope := r.URL.Query().Get("tenant_scope")
		data := []map[string]any{}
		switch {
		case strings.Contains(sql, "FROM netops.corr_objects"):
			visible := scope == "__all__" || strings.Contains(sql, tktLaxCorrID)
			if visible {
				data = append(data, map[string]any{
					"version": 3, "tenant_id": "",
					"window_start": "2026-07-10 20:00:00", "window_end": "2026-07-10 20:10:00",
					"trigger_signal": "sig-1", "verdict_tier": "suspected",
					"top_hypothesis": "test hypothesis", "top_confidence": 0.9,
					"evidence_missing": "", "hypotheses": "[]", "affected": "[]",
					"layer_coverage": "{}", "app_impact": "{}",
				})
			}
		case strings.Contains(sql, "max(archived_version)"):
			data = append(data, map[string]any{"av": 0})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(ch.Close)
	return ch
}

// TestManualTicketCreate_CrossTenantAdminReachesPlatformObject is the regression
// for the 2026-07-10 live bug: the platform owner's manual "Create ticket"
// (POST /api/correlations/{id}/ticket) scoped the CH read to the literal tenant
// "global", but platform objects are stored tenant_id="" and the strict row
// policy has no untagged allowance — so every platform object 404'd even though
// the sweeper (which reads at "__all__") ticketed them fine.
func TestManualTicketCreate_CrossTenantAdminReachesPlatformObject(t *testing.T) {
	ch := corrCHStub(t)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	srv, s, fix := setupTicketingTenants(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, body := do(t, srv, "POST", "/api/correlations/"+tktStrictCorrID+"/ticket", admin, map[string]any{})
	if st != 202 {
		t.Fatalf("platform owner manual create = %d %s, want 202 (the live bug 404'd here)", st, body)
	}
	// The enqueued action is stamped with the object's OWNING tenant (""→global),
	// mirroring the sweeper — never the raw read scope.
	items, err := s.ticketing.ListOutbox(context.Background(), "", true)
	if err != nil || len(items) != 1 {
		t.Fatalf("outbox after manual create: items=%d err=%v, want exactly 1", len(items), err)
	}
	if items[0].TenantID != TenantGlobal || items[0].CorrObjectID != tktStrictCorrID {
		t.Fatalf("outbox item stamped tenant=%q corr=%q, want %q/%q",
			items[0].TenantID, items[0].CorrObjectID, TenantGlobal, tktStrictCorrID)
	}

	// A tenant-scoped admin must NOT reach the platform object: the strict scope
	// hides the row → 404, never a ticket on someone else's incident (§3a).
	st, body = do(t, srv, "POST", "/api/correlations/"+tktStrictCorrID+"/ticket", fix["A"].token, map[string]any{})
	if st != 404 {
		t.Fatalf("tenant-scoped manual create on platform object = %d %s, want 404", st, body)
	}
}

// TestManualTicketCreate_OwnerGuardDefaultClosed proves the handler refuses to
// ticket a foreign object even if the DB row policy leaks it (lax stub): the
// object's row tenant ("" → global) ≠ the caller's tenant → 404, no enqueue.
func TestManualTicketCreate_OwnerGuardDefaultClosed(t *testing.T) {
	ch := corrCHStub(t)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	srv, s, fix := setupTicketingTenants(t)

	st, body := do(t, srv, "POST", "/api/correlations/"+tktLaxCorrID+"/ticket", fix["A"].token, map[string]any{})
	if st != 404 {
		t.Fatalf("owner guard: tenant A ticketing a leaked platform object = %d %s, want 404", st, body)
	}
	if items, _ := s.ticketing.ListOutbox(context.Background(), "", true); len(items) != 0 {
		t.Fatalf("owner guard must not enqueue; outbox has %d items", len(items))
	}
}

// TestIncidentPolicyAPI_SingleEnabledPerSystem guards the 2026-07-10 PDI-flood
// footgun: two enabled policies for one tenant+system silently shadow each other
// (resolvePolicy takes the first enabled), so enabling a second must 409 and the
// conflict must clear once the first is disabled. Per-tenant: B is unaffected.
func TestIncidentPolicyAPI_SingleEnabledPerSystem(t *testing.T) {
	srv, _, fix := setupTicketingTenants(t)
	a, b := fix["A"], fix["B"]

	st, body := do(t, srv, "POST", "/api/incident-policies", a.token, map[string]any{
		"id": "pol-1", "name": "first", "enabled": true, "min_verdict": "confirmed",
	})
	if st != 200 {
		t.Fatalf("A first enabled policy: %d %s", st, body)
	}
	st, body = do(t, srv, "POST", "/api/incident-policies", a.token, map[string]any{
		"id": "pol-2", "name": "second", "enabled": true, "min_verdict": "suspected",
	})
	if st != 409 || !strings.Contains(string(body), "first") {
		t.Fatalf("A second enabled policy = %d %s, want 409 naming the conflicting policy", st, body)
	}
	// A disabled second policy coexists fine.
	if st, body = do(t, srv, "POST", "/api/incident-policies", a.token, map[string]any{
		"id": "pol-2", "name": "second", "enabled": false, "min_verdict": "suspected",
	}); st != 200 {
		t.Fatalf("A second DISABLED policy: %d %s", st, body)
	}
	// Disabling the first clears the conflict for the second.
	if st, body = do(t, srv, "PUT", "/api/incident-policies/pol-1", a.token, map[string]any{
		"name": "first", "enabled": false, "min_verdict": "confirmed",
	}); st != 200 {
		t.Fatalf("A disable first: %d %s", st, body)
	}
	if st, body = do(t, srv, "PUT", "/api/incident-policies/pol-2", a.token, map[string]any{
		"name": "second", "enabled": true, "min_verdict": "suspected",
	}); st != 200 {
		t.Fatalf("A enable second after disabling first: %d %s", st, body)
	}
	// The rule is per-tenant: B enabling its own policy never conflicts with A's.
	if st, body = do(t, srv, "POST", "/api/incident-policies", b.token, map[string]any{
		"name": "B policy", "enabled": true, "min_verdict": "confirmed",
	}); st != 200 {
		t.Fatalf("B enabled policy: %d %s", st, body)
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
