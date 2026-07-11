package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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
// corr tables (a row is visible iff tenant_id = tenant_scope OR scope =
// '__all__'). rows maps correlation_id → its stored row shape; rows marked lax
// deliberately mis-emulate a LAX policy that leaks the row to ANY named scope,
// exercising the handler's default-closed owner guard (defense in depth if the
// DB policy ever drifts). The map may be filled in AFTER the stub starts (the
// fixture mints tenant ids) as long as it is not mutated concurrently with
// requests.
const (
	tktStrictCorrID = "11111111-2222-4333-8444-555555555555"
	tktLaxCorrID    = "99999999-8888-4777-8666-555555555555"
	tktTenantCorrID = "22222222-3333-4444-8555-666666666666"
	tktMergedCorrID = "33333333-4444-4555-8666-777777777777"
	tktCanonCorrID  = "44444444-5555-4666-8777-888888888888"
)

type stubCorrRow struct {
	tenant string // stored tenant_id ("" = platform-owned)
	merged string // non-empty → state=merged, merged_into=this id
	lax    bool   // mis-emulated policy: visible to every scope
}

func corrCHStub(t *testing.T, rows map[string]stubCorrRow) *httptest.Server {
	t.Helper()
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sqlB, _ := io.ReadAll(r.Body)
		sql := string(sqlB)
		scope := r.URL.Query().Get("tenant_scope")
		data := []map[string]any{}
		switch {
		case strings.Contains(sql, "FROM netops.corr_objects"):
			for id, row := range rows {
				if !strings.Contains(sql, id) {
					continue
				}
				if row.lax || scope == "__all__" || scope == row.tenant {
					state, mergedInto := "open", ""
					if row.merged != "" {
						state, mergedInto = "merged", row.merged
					}
					data = append(data, map[string]any{
						"version": 3, "tenant_id": row.tenant, "state": state, "merged_into": mergedInto,
						"window_start": "2026-07-10 20:00:00", "window_end": "2026-07-10 20:10:00",
						"trigger_signal": "sig-1", "verdict_tier": "suspected",
						"top_hypothesis": "test hypothesis", "top_confidence": 0.9,
						"evidence_missing": "", "hypotheses": "[]", "affected": "[]",
						"layer_coverage": "{}", "app_impact": "{}",
					})
				}
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
	ch := corrCHStub(t, map[string]stubCorrRow{tktStrictCorrID: {tenant: ""}})
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
	ch := corrCHStub(t, map[string]stubCorrRow{tktLaxCorrID: {tenant: "", lax: true}})
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

// TestManualTicketCreate_TenantObjectOwnerStamped covers the tenant-owned leg of
// the manual path: the platform owner may ticket a TENANT's object, and the
// action must be stamped with the OBJECT's tenant (its policy, its connection,
// its outbox) — never the caller's "global". A manual create by the owning
// tenant races into the SAME idempotency key, so two clicks file one action; a
// third tenant still 404s.
func TestManualTicketCreate_TenantObjectOwnerStamped(t *testing.T) {
	rows := map[string]stubCorrRow{}
	ch := corrCHStub(t, rows)
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	srv, s, fix := setupTicketingTenants(t)
	a, b := fix["A"], fix["B"]
	rows[tktTenantCorrID] = stubCorrRow{tenant: a.tenantID}
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, body := do(t, srv, "POST", "/api/correlations/"+tktTenantCorrID+"/ticket", admin, map[string]any{})
	if st != 202 {
		t.Fatalf("platform owner create on tenant object = %d %s, want 202", st, body)
	}
	if st, body = do(t, srv, "POST", "/api/correlations/"+tktTenantCorrID+"/ticket", a.token, map[string]any{}); st != 202 {
		t.Fatalf("owning tenant create on own object = %d %s, want 202", st, body)
	}
	items, err := s.ticketing.ListOutbox(context.Background(), "", true)
	if err != nil || len(items) != 1 {
		t.Fatalf("outbox = %d items err=%v, want exactly 1 (same idempotency key)", len(items), err)
	}
	if items[0].TenantID != a.tenantID {
		t.Fatalf("outbox stamped tenant %q, want the OBJECT's tenant %q", items[0].TenantID, a.tenantID)
	}
	if st, body = do(t, srv, "POST", "/api/correlations/"+tktTenantCorrID+"/ticket", b.token, map[string]any{}); st != 404 {
		t.Fatalf("foreign tenant create = %d %s, want 404", st, body)
	}
}

// TestManualTicketSync_OwnerKeyedUpdate covers the sync (update) leg through the
// owner-keyed path: an open link stored under the object's owning tenant is
// found, the update enqueues under that tenant, and an object with no open
// ticket refuses with 409.
func TestManualTicketSync_OwnerKeyedUpdate(t *testing.T) {
	ch := corrCHStub(t, map[string]stubCorrRow{
		tktStrictCorrID: {tenant: ""},
		tktTenantCorrID: {tenant: ""},
	})
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	srv, s, _ := setupTicketingTenants(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	if err := s.ticketing.PutLink(context.Background(), ticketLink{
		TenantID: TenantGlobal, CorrObjectID: tktStrictCorrID, ExternalSystem: "servicenow",
		Status: "open", TicketNumber: "INC0000042", SysID: "sysabc",
	}); err != nil {
		t.Fatal(err)
	}
	st, body := do(t, srv, "POST", "/api/correlations/"+tktStrictCorrID+"/ticket/sync", admin, map[string]any{})
	if st != 202 {
		t.Fatalf("manual sync with open link = %d %s, want 202", st, body)
	}
	items, _ := s.ticketing.ListOutbox(context.Background(), "", true)
	if len(items) != 1 || items[0].Action != "update" || items[0].TenantID != TenantGlobal {
		t.Fatalf("outbox after sync = %+v, want one update stamped %q", items, TenantGlobal)
	}
	// No open ticket → 409, nothing enqueued.
	if st, body = do(t, srv, "POST", "/api/correlations/"+tktTenantCorrID+"/ticket/sync", admin, map[string]any{}); st != 409 {
		t.Fatalf("manual sync without a link = %d %s, want 409", st, body)
	}
}

// TestManualTicketCreate_MergedObject409 pins the merged-object contract: acting
// on a superseded object refuses with 409 carrying the canonical id (never a
// misleading 404, never a duplicate ticket on a dead object).
func TestManualTicketCreate_MergedObject409(t *testing.T) {
	ch := corrCHStub(t, map[string]stubCorrRow{
		tktMergedCorrID: {tenant: "", merged: tktCanonCorrID},
	})
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	srv, s, _ := setupTicketingTenants(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, body := do(t, srv, "POST", "/api/correlations/"+tktMergedCorrID+"/ticket", admin, map[string]any{})
	if st != 409 || !strings.Contains(string(body), tktCanonCorrID) {
		t.Fatalf("create on merged object = %d %s, want 409 carrying canonical id %s", st, body, tktCanonCorrID)
	}
	if items, _ := s.ticketing.ListOutbox(context.Background(), "", true); len(items) != 0 {
		t.Fatalf("merged object must not enqueue; outbox has %d items", len(items))
	}
}

// TestResolvePolicy_FailsClosedOnMultipleEnabled pins the runtime invariant:
// one enabled policy → it governs; a violated invariant (two enabled, seeded
// past the store guard as legacy data would be) NEVER picks a winner by row
// order — ticketing holds (fail closed).
func TestResolvePolicy_FailsClosedOnMultipleEnabled(t *testing.T) {
	store := newMemTicketingStore()
	sw := &ticketSweeper{store: store}
	ctx := context.Background()

	if err := store.PutPolicy(ctx, incidentPolicy{ID: "p1", TenantID: "t-x", Name: "strict",
		ExternalSystem: "servicenow", Enabled: true, MinVerdict: "confirmed"}); err != nil {
		t.Fatal(err)
	}
	if got := sw.resolvePolicy(ctx, "t-x"); got.ID != "p1" {
		t.Fatalf("one enabled policy: resolved %q, want p1", got.ID)
	}
	// Seed a second ENABLED policy directly (legacy/drifted data — PutPolicy and
	// the pg unique index both refuse this shape now).
	store.mu.Lock()
	store.policies[memKey("t-x", "p2")] = incidentPolicy{ID: "p2", TenantID: "t-x", Name: "permissive",
		ExternalSystem: "servicenow", Enabled: true, MinVerdict: "suspected"}
	store.mu.Unlock()
	got := sw.resolvePolicy(ctx, "t-x")
	if got.Enabled {
		t.Fatalf("two enabled policies must fail CLOSED (Enabled=false hold), resolved %+v", got)
	}
}

// TestPutPolicy_ConcurrentEnableSingleWinner proves the store-level invariant
// closes the check-then-write race the HTTP pre-check cannot: of two concurrent
// enables for one tenant+system, exactly one wins and the loser gets
// errPolicyConflict.
func TestPutPolicy_ConcurrentEnableSingleWinner(t *testing.T) {
	store := newMemTicketingStore()
	ctx := context.Background()
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for _, id := range []string{"c1", "c2"} {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			errs <- store.PutPolicy(ctx, incidentPolicy{ID: id, TenantID: "t-race",
				ExternalSystem: "servicenow", Enabled: true, MinVerdict: "confirmed"})
		}(id)
	}
	wg.Wait()
	close(errs)
	conflicts, oks := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			oks++
		case errors.Is(err, errPolicyConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if oks != 1 || conflicts != 1 {
		t.Fatalf("concurrent enables: %d ok / %d conflict, want exactly 1/1", oks, conflicts)
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

// TestManualTicketCreate_MergedChainResolvesToTerminal extends the merged-object
// contract to CHAINS: when A→B→C, the 409 must carry the TERMINAL survivor C
// (not the intermediate B) so the operator's retry lands on a live object in
// one hop, with merge_depth reporting the hops.
func TestManualTicketCreate_MergedChainResolvesToTerminal(t *testing.T) {
	const tktChainEndID = "55555555-6666-4777-8888-999999999999"
	ch := corrCHStub(t, map[string]stubCorrRow{
		tktMergedCorrID: {tenant: "", merged: tktCanonCorrID},
		tktCanonCorrID:  {tenant: "", merged: tktChainEndID},
		tktChainEndID:   {tenant: ""},
	})
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	srv, _, _ := setupTicketingTenants(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, body := do(t, srv, "POST", "/api/correlations/"+tktMergedCorrID+"/ticket", admin, map[string]any{})
	if st != 409 {
		t.Fatalf("create on chain head = %d %s, want 409", st, body)
	}
	var out struct {
		Canonical string `json:"canonical_correlation_id"`
		Depth     int    `json:"merge_depth"`
	}
	_ = json.Unmarshal(body, &out)
	if out.Canonical != tktChainEndID || out.Depth != 2 {
		t.Fatalf("chain resolution = %q depth %d, want terminal %s depth 2", out.Canonical, out.Depth, tktChainEndID)
	}
}

// TestManualTicketCreate_MergedChainCycleBounded proves a cyclic merge chain
// (A→B→A — an engine invariant violation) terminates: bounded walk, 409 with
// the last sane id, never a hang or a canonical id equal to the requested one.
func TestManualTicketCreate_MergedChainCycleBounded(t *testing.T) {
	ch := corrCHStub(t, map[string]stubCorrRow{
		tktMergedCorrID: {tenant: "", merged: tktCanonCorrID},
		tktCanonCorrID:  {tenant: "", merged: tktMergedCorrID},
	})
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	srv, _, _ := setupTicketingTenants(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, body := do(t, srv, "POST", "/api/correlations/"+tktMergedCorrID+"/ticket", admin, map[string]any{})
	if st != 409 {
		t.Fatalf("create on cyclic chain = %d %s, want 409", st, body)
	}
	var out struct {
		Canonical string `json:"canonical_correlation_id"`
	}
	_ = json.Unmarshal(body, &out)
	if out.Canonical != tktCanonCorrID {
		t.Fatalf("cycle must stop at the last non-repeating id %s, got %q", tktCanonCorrID, out.Canonical)
	}
}

// TestSimulator_ReportsRuntimeState is the differential guard between the
// simulator and the runtime: the dry-run names whether the evaluated policy is
// the one the sweeper would ACTUALLY apply (active), shadowed by another,
// held by a conflict, or moot because the tenant opted out.
func TestSimulator_ReportsRuntimeState(t *testing.T) {
	srv, s, fix := setupTicketingTenants(t)
	a, b := fix["A"], fix["B"]

	type simOut struct {
		RuntimeState      string `json:"runtime_state"`
		RuntimePolicyID   string `json:"runtime_policy_id"`
		RuntimePolicyName string `json:"runtime_policy_name"`
	}
	simulate := func(token, id string) simOut {
		t.Helper()
		st, body := do(t, srv, "POST", "/api/incident-policies/"+id+"/test", token,
			map[string]any{"verdict": "confirmed", "peak_severity": "crit", "has_affected_entity": true})
		if st != 200 {
			t.Fatalf("simulate %s: %d %s", id, st, body)
		}
		var out simOut
		_ = json.Unmarshal(body, &out)
		return out
	}

	// One enabled policy → it is the runtime-active policy.
	if st, body := do(t, srv, "POST", "/api/incident-policies", a.token, map[string]any{
		"id": "act-1", "name": "governing", "enabled": true, "min_verdict": "confirmed"}); st != 200 {
		t.Fatalf("create act-1: %d %s", st, body)
	}
	if out := simulate(a.token, "act-1"); out.RuntimeState != "active" {
		t.Fatalf("enabled policy runtime_state = %q, want active", out.RuntimeState)
	}

	// A disabled second policy simulates fine but is SHADOWED by the active one.
	if st, body := do(t, srv, "POST", "/api/incident-policies", a.token, map[string]any{
		"id": "shd-1", "name": "candidate", "enabled": false, "min_verdict": "suspected"}); st != 200 {
		t.Fatalf("create shd-1: %d %s", st, body)
	}
	if out := simulate(a.token, "shd-1"); out.RuntimeState != "shadowed" || out.RuntimePolicyID != "act-1" {
		t.Fatalf("shadowed sim = %+v, want shadowed by act-1", out)
	}

	// Legacy multi-enabled drift (seeded past the store guard) → held.
	mem := s.ticketing.(*memTicketingStore)
	mem.mu.Lock()
	mem.policies[memKey(a.tenantID, "drift")] = incidentPolicy{ID: "drift", TenantID: a.tenantID,
		Name: "drifted", ExternalSystem: "servicenow", Enabled: true, MinVerdict: "suspected"}
	mem.mu.Unlock()
	if out := simulate(a.token, "act-1"); out.RuntimeState != "held" {
		t.Fatalf("multi-enabled sim runtime_state = %q, want held", out.RuntimeState)
	}

	// A tenant whose only policy is disabled has opted out.
	if st, body := do(t, srv, "POST", "/api/incident-policies", b.token, map[string]any{
		"id": "off-1", "name": "opt-out", "enabled": false, "min_verdict": "confirmed"}); st != 200 {
		t.Fatalf("create off-1: %d %s", st, body)
	}
	if out := simulate(b.token, "off-1"); out.RuntimeState != "opted_out" {
		t.Fatalf("opted-out sim runtime_state = %q, want opted_out", out.RuntimeState)
	}
}

// TestTicketStatusRead_AgreesAcrossPaths is the list/detail vs manual-path
// agreement check (hypothesis-C differential): the ticket link of a PLATFORM
// (global) object — stored under the canonical "global" key by sweeper and
// manual path alike — is visible to the platform owner through the read
// endpoint, and invisible to a tenant-scoped caller (no cross-tenant leak).
func TestTicketStatusRead_AgreesAcrossPaths(t *testing.T) {
	srv, s, fix := setupTicketingTenants(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	if err := s.ticketing.PutLink(context.Background(), ticketLink{
		TenantID: TenantGlobal, CorrObjectID: tktStrictCorrID, ExternalSystem: "servicenow",
		Status: "open", TicketNumber: "INC0000077", SysID: "sys77",
	}); err != nil {
		t.Fatal(err)
	}
	var out struct {
		Status map[string]any `json:"status"`
	}
	st, body := do(t, srv, "GET", "/api/correlations/"+tktStrictCorrID+"/tickets", admin, nil)
	if st != 200 {
		t.Fatalf("owner reads global ticket status: %d %s", st, body)
	}
	_ = json.Unmarshal(body, &out)
	if out.Status["state"] != "open" || out.Status["ticket_number"] != "INC0000077" {
		t.Fatalf("owner sees %v, want the open global ticket (the manual path filed it under 'global')", out.Status)
	}
	// Tenant-scoped caller: the same read must NOT reveal the platform ticket.
	st, body = do(t, srv, "GET", "/api/correlations/"+tktStrictCorrID+"/tickets", fix["A"].token, nil)
	if st != 200 {
		t.Fatalf("tenant read: %d %s", st, body)
	}
	out.Status = nil
	_ = json.Unmarshal(body, &out)
	if out.Status["state"] != "not_created" {
		t.Fatalf("tenant sees %v, want not_created (no cross-tenant ticket leak)", out.Status)
	}
}
