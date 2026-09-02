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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// ── §3a: engine-inferred recovery must not cross a tenant boundary ───────────
//
// The v2 lifecycle mapping lets a CLOSED correlation object stand in for an ITSM
// recovery signal (timeintel/derive.go). That adds a new way for one tenant's
// object to influence another's numbers, so it needs its own isolation proof:
// tenant B's closed object must never contribute a recovery stamp to tenant A's
// /api/reliability/rollups, and asking for B's id on /time-metrics must 404 —
// indistinguishable from an id that does not exist (no existence oracle).

// recoveryFakeCH answers the per-object time-metrics read the way ClickHouse
// does WITH the tenant row policy applied: a corr_objects row comes back only for
// its own tenant scope (or the cross-tenant scope). Every other read (the signal
// archive) answers empty, which is the honest "no archived signals" shape.
type recoveryFakeCH struct {
	mu     sync.Mutex
	scopes []string
	// objects: correlation id → (tenant, window_start, window_end, state)
	objects map[string]recoveryFakeObj
}

type recoveryFakeObj struct {
	tenant                 string
	windowStart, windowEnd time.Time
	state                  string
}

func newRecoveryFakeCH(t *testing.T, objects map[string]recoveryFakeObj) *recoveryFakeCH {
	t.Helper()
	f := &recoveryFakeCH{objects: objects}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("tenant_scope")
		body, _ := io.ReadAll(r.Body)
		sql := string(body)
		f.mu.Lock()
		f.scopes = append(f.scopes, scope)
		f.mu.Unlock()

		out := []map[string]any{}
		if strings.Contains(sql, "netops.corr_objects") {
			for id, o := range f.objects {
				if !strings.Contains(sql, id) {
					continue
				}
				if scope != "__all__" && scope != o.tenant {
					continue // the row policy hides it
				}
				iso := func(tm time.Time) string {
					if tm.IsZero() {
						return ""
					}
					return tm.UTC().Format("2006-01-02T15:04:05.000") + "Z"
				}
				out = append(out, map[string]any{
					"window_start": iso(o.windowStart), "window_end": iso(o.windowEnd),
					"created_at":   iso(o.windowStart.Add(30 * time.Second)),
					"verdict_tier": "confirmed", "top_confidence": 0.9, "state": o.state,
					"hypotheses":       `{"ranking":{"hypotheses":[{"verdict":{"owner":"isp"}}]}}`,
					"evidence_missing": "[]", "affected": `{"devices":["wan-r2"]}`,
				})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	return f
}

func TestInferredRecoveryCrossOrgIsolation(t *testing.T) {
	const (
		idA = "a1a1a1a1-1111-4111-8111-a1a1a1a1a1a1"
		idB = "b1b1b1b1-2222-4222-8222-b1b1b1b1b1b1"
		idX = "c1c1c1c1-3333-4333-8333-c1c1c1c1c1c1" // never exists
	)
	srv, s := newTestServerState(t)
	store := timeintel.NewMemMetricsStore()
	s.incidentTimeMetrics = store
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

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
		user := "rec-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	base := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Millisecond)
	newRecoveryFakeCH(t, map[string]recoveryFakeObj{
		// A's object is still OPEN: it has no recovery of its own.
		idA: {tenant: a.tenantID, windowStart: base, state: "open"},
		// B's object CLOSED — the only recovery evidence in the whole fixture.
		idB: {tenant: b.tenantID, windowStart: base, windowEnd: base.Add(8 * time.Minute), state: "closed"},
	})

	// ── per-object /time-metrics: B sees its own inferred recovery ─────────────
	recoveryOf := func(token, id string) (int, timeIntelResponse) {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/correlations/"+id+"/time-metrics", token, nil)
		var out timeIntelResponse
		if st == http.StatusOK {
			if err := json.Unmarshal(body, &out); err != nil {
				t.Fatalf("decode time-metrics: %v (%s)", err, body)
			}
		}
		return st, out
	}
	st, own := recoveryOf(b.token, idB)
	if st != http.StatusOK {
		t.Fatalf("own-tenant time-metrics must succeed, got %d", st)
	}
	var rec *timeIntelLifecycleRow
	for i := range own.Lifecycle {
		if own.Lifecycle[i].EventType == timeintel.EvRecovered {
			rec = &own.Lifecycle[i]
		}
	}
	if rec == nil {
		t.Fatal("tenant B's CLOSED object must expose an engine-inferred recovery")
	}
	if rec.Source != timeintel.SrcInferred || !rec.At.Equal(base.Add(8*time.Minute)) {
		t.Fatalf("recovery stamp wrong: %+v", *rec)
	}
	if own.CurrentBottleneck == timeintel.DriverWorkflow {
		t.Errorf("a recovered object must not report workflow_not_connected: %q", own.BottleneckMessage)
	}

	// A's OWN object is open → no recovery. The proxy is per-object, not global.
	if st, mine := recoveryOf(a.token, idA); st != http.StatusOK {
		t.Fatalf("own-tenant open object must still serve, got %d", st)
	} else {
		for _, row := range mine.Lifecycle {
			if row.EventType == timeintel.EvRecovered {
				t.Fatalf("an OPEN object must expose no recovery: %+v", row)
			}
		}
	}

	// ── cross-tenant id → 404, byte-identical to an id that does not exist ─────
	stCross, bodyCross := do(t, srv, "GET", "/api/correlations/"+idB+"/time-metrics", a.token, nil)
	if stCross != http.StatusNotFound {
		t.Fatalf("TENANT LEAK: org-A reading org-B's time-metrics returned %d %s", stCross, bodyCross)
	}
	stUnknown, bodyUnknown := do(t, srv, "GET", "/api/correlations/"+idX+"/time-metrics", a.token, nil)
	if stUnknown != stCross || string(bodyUnknown) != string(bodyCross) {
		t.Fatalf("cross-tenant 404 (%s) differs from unknown-id 404 (%s) — an existence oracle", bodyCross, bodyUnknown)
	}

	// ── rollups: B's recovery must never appear in A's window ─────────────────
	now := time.Now().UTC()
	closedSnap := func(tenant, corr string, recoveryMs int64) timeintel.MetricRow {
		return timeintel.MetricRow{
			TenantID: tenant, CorrelationID: corr, CalcVersion: timeIntelCalcVersion,
			OccurredAt: now.Add(-time.Hour), CalculatedAt: now, State: "closed", Owner: "isp",
			Group: map[string]string{"device": "wan-r2"},
			Metrics: []timeintel.TimeMetric{{
				Name: timeintel.MetricTTRRecovery, Complete: true,
				DurationMs: recoveryMs, IsInferred: true,
			}},
		}
	}
	// Only tenant B has a recovered incident.
	if err := store.Upsert(context.Background(), closedSnap(b.tenantID, "corr-b-closed", 480_000)); err != nil {
		t.Fatal(err)
	}
	if err := store.Upsert(context.Background(), timeintel.MetricRow{
		TenantID: a.tenantID, CorrelationID: "corr-a-open", CalcVersion: timeIntelCalcVersion,
		OccurredAt: now.Add(-time.Hour), CalculatedAt: now, State: "open", Owner: "isp",
		Group: map[string]string{"device": "lan-sw1"},
	}); err != nil {
		t.Fatal(err)
	}

	rollupMetrics := func(token string) map[string]map[string]any {
		t.Helper()
		st, body := do(t, srv, "GET", "/api/reliability/rollups?since=2592000", token, nil)
		if st != http.StatusOK {
			t.Fatalf("rollups: %d %s", st, body)
		}
		var out struct {
			Rollup struct {
				Metrics map[string]map[string]any `json:"metrics"`
			} `json:"rollup"`
		}
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode rollups: %v (%s)", err, body)
		}
		return out.Rollup.Metrics
	}
	if _, leaked := rollupMetrics(a.token)["ttr_recovery"]; leaked {
		t.Fatal("TENANT LEAK: org-A's rollup carries a recovery it has no recovered incident for")
	}
	if _, ok := rollupMetrics(b.token)["ttr_recovery"]; !ok {
		t.Fatal("org-B owns the only recovered incident and must see its ttr_recovery stats")
	}
}
