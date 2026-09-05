package backend

// applications_pg_durability_test.go — tracker 245, the Postgres half.
//
// The bug this closes was invisible precisely because nothing tested the thing
// operators care about: does an application STILL EXIST after the api restarts,
// and does a Postgres outage keep the records where they belong instead of
// quietly writing them somewhere else. So the tests here restart the store for
// real (close the pool, open a new one against the same database) rather than
// asserting which constructor was called.
//
// Gated on DATABASE_URL_TEST (a superuser DSN; provisionAppRole mints the
// non-superuser role FORCE ROW LEVEL SECURITY actually applies to).

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"netops/backend/appid"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/registrystatus"
)

// openAppStore opens a fresh Postgres app-state store and selects it as the
// process backend — i.e. exactly what a fresh api process does at boot.
func openAppStore(ctx context.Context, t *testing.T, dsn string) *platformdb.PGStore {
	t.Helper()
	if err := platformdb.UsePostgres(ctx, dsn); err != nil {
		t.Fatalf("UsePostgres: %v", err)
	}
	ps, ok := platformdb.ActivePG()
	if !ok {
		t.Fatal("UsePostgres succeeded but the active backend is not the pg store")
	}
	return ps
}

// TestApplicationsSurviveAnAPIRestartPG is THE tracker-245 regression: create an
// application for two different tenants, restart the store, and find both still
// there and still isolated. On the pre-fix build (file backend → in-memory
// store) the second half of this test found nothing.
func TestApplicationsSurviveAnAPIRestartPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the applications durability test")
	}
	ctx := context.Background()
	dsn := provisionAppRole(ctx, t, adminDSN)
	t.Cleanup(func() { platformdb.UseFile() })

	// ── boot 1 ───────────────────────────────────────────────────────────────
	ps := openAppStore(ctx, t, dsn)
	if platformdb.Kind() != platformdb.KindPostgres {
		t.Fatalf("kind = %q, want postgres", platformdb.Kind())
	}
	st := newApplicationStore() // T4: explicit postgres selects the durable store
	if st == nil {
		t.Fatal("postgres backend must provide the applications store")
	}
	a, err := st.Create(ctx, "org-a", false, appid.Application{TenantID: "org-a", Name: "Billing"})
	if err != nil {
		t.Fatalf("org-a create: %v", err)
	}
	b, err := st.Create(ctx, "org-b", false, appid.Application{TenantID: "org-b", Name: "Payroll"})
	if err != nil {
		t.Fatalf("org-b create: %v", err)
	}
	ps.DB().Close() // the api process ends here

	// ── boot 2: a NEW process against the SAME database ─────────────────────
	ps2 := openAppStore(ctx, t, dsn)
	defer ps2.DB().Close()
	st2 := newApplicationStore()
	if st2 == nil {
		t.Fatal("postgres backend must provide the applications store after a restart")
	}

	la, err := st2.List(ctx, "org-a", false, false)
	if err != nil {
		t.Fatalf("org-a list after restart: %v", err)
	}
	if len(la) != 1 || la[0].ApplicationID != a.ApplicationID || la[0].Name != "Billing" {
		t.Fatalf("org-a lost its application across the restart: %+v", la)
	}
	lb, err := st2.List(ctx, "org-b", false, false)
	if err != nil {
		t.Fatalf("org-b list after restart: %v", err)
	}
	if len(lb) != 1 || lb[0].ApplicationID != b.ApplicationID {
		t.Fatalf("org-b lost its application across the restart: %+v", lb)
	}

	// ── isolation still holds on the restored rows (RLS, §3a) ───────────────
	if _, found, err := st2.Get(ctx, "org-b", false, a.ApplicationID); err != nil || found {
		t.Fatalf("cross-tenant get must be a miss (found=%v err=%v) — never reveal another tenant's id", found, err)
	}
	if ok, err := st2.Archive(ctx, "org-b", false, a.ApplicationID); err != nil || ok {
		t.Fatalf("cross-tenant archive must refuse (ok=%v err=%v)", ok, err)
	}
	if la, _ := st2.List(ctx, "org-a", false, false); len(la) != 1 {
		t.Fatal("org-a's application must survive org-b's archive attempt")
	}
	// The platform owner (cross) still sees both.
	if all, err := st2.List(ctx, "", true, false); err != nil || len(all) != 2 {
		t.Fatalf("platform-owner list: %d apps, err %v", len(all), err)
	}
	// Own-tenant archive works and is an archive, not a delete.
	if ok, err := st2.Archive(ctx, "org-a", false, a.ApplicationID); err != nil || !ok {
		t.Fatalf("own archive: ok=%v err=%v", ok, err)
	}
	if arch, _ := st2.List(ctx, "org-a", false, true); len(arch) != 1 {
		t.Fatal("archived application must remain readable with archived=true")
	}
	if live, _ := st2.List(ctx, "org-a", false, false); len(live) != 0 {
		t.Fatal("archived application must leave the active list")
	}
}

// TestApplicationsPostgresOutageDoesNotFailOverPG: with the database down the
// registry reports unavailable — it does NOT answer an empty 200, does NOT
// accept a write, and does NOT switch to another backend. When the database
// comes back, the original records are still the authoritative ones.
func TestApplicationsPostgresOutageDoesNotFailOverPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the applications outage test")
	}
	ctx := context.Background()
	dsn := provisionAppRole(ctx, t, adminDSN)
	t.Cleanup(func() { platformdb.UseFile() })

	ps := openAppStore(ctx, t, dsn)
	srv, s := newTestServerState(t)
	s.applications = newApplicationStore()
	tok := adminToken(t, srv)

	st, body := do(t, srv, "POST", "/api/applications", tok, map[string]any{"name": "Billing"})
	if st != http.StatusCreated {
		t.Fatalf("create while healthy: %d %s", st, body)
	}
	var created appid.Application
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}

	// ── the outage ──────────────────────────────────────────────────────────
	ps.DB().Close()

	st, body = do(t, srv, "GET", "/api/applications", tok, nil)
	if st != http.StatusServiceUnavailable {
		t.Fatalf("read during an outage: %d %s — unavailable storage must never render as an empty registry", st, body)
	}
	var env struct{ Error, Code string }
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatal(err)
	}
	if env.Code != "APPLICATIONS_STORAGE_UNAVAILABLE" {
		t.Fatalf("read during an outage: code %q", env.Code)
	}
	st, body = do(t, srv, "POST", "/api/applications", tok, map[string]any{"name": "Ghost"})
	if st != http.StatusServiceUnavailable {
		t.Fatalf("write during an outage: %d %s — a write must never be acknowledged without its store", st, body)
	}

	// No failover: the configured AND active backend are still postgres, and the
	// status surface says unavailable rather than naming file or memory.
	if platformdb.Kind() != platformdb.KindPostgres {
		t.Fatalf("backend switched to %q during an outage — failover is forbidden", platformdb.Kind())
	}
	st, body = do(t, srv, "GET", "/api/registries/status", tok, nil)
	if st != http.StatusOK {
		t.Fatalf("status during an outage: %d %s", st, body)
	}
	var rep registrystatus.Report
	if err := json.Unmarshal(body, &rep); err != nil {
		t.Fatal(err)
	}
	var app registrystatus.Status
	for _, r := range rep.Registries {
		if r.Registry == applicationRegistry {
			app = r
		}
	}
	if app.ConfiguredBackend != platformdb.KindPostgres || app.ActiveBackend != platformdb.KindPostgres {
		t.Fatalf("an outage must not change which backend owns the registry: %+v", app)
	}
	if app.Available || app.Healthy || app.Reason == "" {
		t.Fatalf("an outage must be reported as unavailable with a reason: %+v", app)
	}
	if app.Persistence != registrystatus.Persistent {
		t.Fatalf("the registry is still persistently backed during an outage: %+v", app)
	}

	// ── recovery: the original record is intact and nothing else was written ─
	ps2 := openAppStore(ctx, t, dsn)
	defer ps2.DB().Close()
	s.applications = newApplicationStore()
	st, body = do(t, srv, "GET", "/api/applications", tok, nil)
	if st != http.StatusOK {
		t.Fatalf("read after recovery: %d %s", st, body)
	}
	var apps []appid.Application
	if err := json.Unmarshal(body, &apps); err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || apps[0].ApplicationID != created.ApplicationID {
		t.Fatalf("after recovery the authoritative store must hold exactly the pre-outage record, got %+v", apps)
	}
	for _, a := range apps {
		if a.Name == "Ghost" {
			t.Fatal("a write refused during the outage was persisted anyway")
		}
	}
}
