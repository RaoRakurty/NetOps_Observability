package backend

// timeintel_metrics_isolation_test.go — §3a cross-org isolation guard for the
// persisted phase-metrics surface, exercised through the REAL router + auth
// middleware (org_isolation_test.go template): own-only list, acting-tenant
// override into another org ignored, platform owner sees all, and the
// backfill trigger (a cross-tenant worker operation) is platform-admin only.
//
// Store-level tenant filtering is additionally unit-proven in
// timeintel/metrics_store_test.go; this test pins the HTTP route itself.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"netops/backend/timeintel"
)

func TestReliabilityTimeMetricsCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	store := timeintel.NewMemMetricsStore()
	s.incidentTimeMetrics = store

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// ── orgs A and B, each: org → tenant → tenant-scoped operator ──────────────
	fix := map[string]*orgFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "tm-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// One snapshot per tenant, stamped from the DATA (the corr object's tenant),
	// never from any request.
	now := time.Now().UTC()
	mustUpsert := func(tenant, corr string) {
		t.Helper()
		if err := store.Upsert(context.Background(), timeintel.MetricRow{
			TenantID: tenant, CorrelationID: corr, CalcVersion: "ti-1", OccurredAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	mustUpsert(a.tenantID, "corr-a")
	mustUpsert(b.tenantID, "corr-b")

	type listResp struct {
		Snapshots []incidentTimeMetricRow `json:"snapshots"`
	}
	list := func(token string) listResp {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/reliability/time-metrics", token, nil)
		if st != 200 {
			t.Fatalf("list snapshots: %d %s", st, body)
		}
		var lr listResp
		if err := json.Unmarshal(body, &lr); err != nil {
			t.Fatal(err)
		}
		return lr
	}

	// ── own-only list: A sees exactly its own snapshot, never org B's ──────────
	lrA := list(a.token)
	if len(lrA.Snapshots) != 1 || lrA.Snapshots[0].CorrelationID != "corr-a" {
		t.Fatalf("TENANT LEAK: org-A user must see only its own snapshot: %+v", lrA.Snapshots)
	}
	lrB := list(b.token)
	if len(lrB.Snapshots) != 1 || lrB.Snapshots[0].CorrelationID != "corr-b" {
		t.Fatalf("TENANT LEAK: org-B user must see only its own snapshot: %+v", lrB.Snapshots)
	}
	// Platform owner (cross) sees both.
	if all := list(admin); len(all.Snapshots) != 2 {
		t.Fatalf("platform owner must see all snapshots: %+v", all.Snapshots)
	}

	// ── acting-tenant override into another org is ignored for a non-owner ─────
	{
		httpReq, err := http.NewRequest("GET", srv.URL+"/api/reliability/time-metrics", bytes.NewReader(nil))
		if err != nil {
			t.Fatal(err)
		}
		httpReq.Header.Set("Authorization", "Bearer "+a.token)
		httpReq.Header.Set("X-Acting-Tenant", b.tenantID)
		resp, err := http.DefaultClient.Do(httpReq)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var lr listResp
		if err := json.NewDecoder(resp.Body).Decode(&lr); err != nil {
			t.Fatal(err)
		}
		for _, row := range lr.Snapshots {
			if row.CorrelationID == "corr-b" {
				t.Fatalf("acting-tenant override must not widen a scoped caller: %+v", lr.Snapshots)
			}
		}
	}

	// ── the backfill trigger recomputes ACROSS tenants → platform-admin only ───
	if st, body := do(t, srv, "POST", "/api/reliability/time-metrics", a.token, map[string]any{}); st == http.StatusOK {
		t.Fatalf("cross-tenant backfill must be refused for a tenant operator: %d %s", st, body)
	}
}
