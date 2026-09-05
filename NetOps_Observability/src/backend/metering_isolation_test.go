package backend

// metering_isolation_test.go — CROSS-ORG isolation for the usage-metering
// surface (CLAUDE.md §3a rule 5), exercised through the REAL router and auth
// middleware, the way the running system behaves.
//
// The routes under test, spelled out literally so the coverage guard in
// route_isolation_coverage_test.go can see them:
//
//	/api/system/licence/usage
//	/api/system/licence/usage/report
//
// What is proved here:
//
//   - own-only list: a tenant admin's usage read returns rows for THEIR tenant
//     and no other, and never the installation row (whose key is the empty
//     string, which is also what an unresolved scope looks like);
//   - cross-tenant selection is 404, not 403: `?tenant=` naming another org's
//     tenant must not confirm that tenant exists;
//   - as_tenant into another org is ignored — the auth middleware refuses to
//     apply it for a non-owner, so the answer stays the caller's own;
//   - the platform owner sees every tenant plus the installation row, and may
//     narrow with `?tenant=`;
//   - the SIGNED report obeys exactly the same scoping, and a tenant's document
//     carries no customer name and no licence id.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"netops/backend/internal/metering"
)

// meteringFixtureRows records one snapshot per named tenant plus the
// installation row, straight into the store — the recorder's own loop is not
// running in the harness, and this test is about who may READ the rows.
func meteringFixtureRows(t *testing.T, s *server, tenants map[string][]string) {
	t.Helper()
	readings := map[string][]metering.Reading{
		metering.ScopeInstallation: {
			metering.Measured(metering.MeterTenants, metering.ScopeInstallation, float64(len(tenants))),
			metering.Measured(metering.MeterOrgs, metering.ScopeInstallation, float64(len(tenants))),
		},
	}
	for tenant, devices := range tenants {
		readings[tenant] = []metering.Reading{
			metering.Unique(metering.MeterMonitoredDevicesUnique, tenant, devices),
			metering.Measured(metering.MeterMonitoredDevicesPeak, tenant, float64(len(devices))),
		}
	}
	if err := s.meteringStore.Record(context.Background(), time.Now().UTC(), readings); err != nil {
		t.Fatalf("record metering fixture: %v", err)
	}
}

type meteringUsageBody struct {
	Scope  string `json:"scope"`
	Tenant string `json:"tenant"`
	Days   []struct {
		Day      string `json:"day"`
		TenantID string `json:"tenant_id"`
	} `json:"days"`
	Tenants []struct {
		TenantID string `json:"tenant_id"`
	} `json:"tenants"`
	Licence struct {
		Customer  string `json:"customer"`
		LicenceID string `json:"licence_id"`
	} `json:"licence"`
}

func decodeUsage(t *testing.T, body []byte) meteringUsageBody {
	t.Helper()
	var v meteringUsageBody
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("decode usage: %v (body %s)", err, body)
	}
	return v
}

func TestMeteringUsageCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	type org struct{ orgID, tenantID, token string }
	fix := map[string]*org{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Meter Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Meter Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "meter-admin-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &org{orgID: orgID, tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
	}

	meteringFixtureRows(t, s, map[string][]string{
		fix["A"].tenantID: {"a-dev-1", "a-dev-2"},
		fix["B"].tenantID: {"b-dev-1"},
	})

	// ── own-only list ───────────────────────────────────────────────────────
	st, b := do(t, srv, "GET", "/api/system/licence/usage", fix["A"].token, nil)
	if st != 200 {
		t.Fatalf("A reads its own usage: %d %s", st, b)
	}
	v := decodeUsage(t, b)
	if v.Scope != "tenant" || v.Tenant != fix["A"].tenantID {
		t.Fatalf("A got scope=%q tenant=%q, want its own tenant projection", v.Scope, v.Tenant)
	}
	if len(v.Days) == 0 {
		t.Fatalf("A sees no rows at all — the fixture did not land and the guard would pass vacuously")
	}
	for _, d := range v.Days {
		switch d.TenantID {
		case fix["A"].tenantID:
		case "":
			t.Fatalf("a tenant admin was handed the INSTALLATION row")
		default:
			t.Fatalf("CROSS-TENANT LEAK: A was handed a %q row", d.TenantID)
		}
	}
	if len(v.Tenants) != 0 {
		t.Errorf("the per-tenant breakdown is platform-only; a tenant got %d rows of it", len(v.Tenants))
	}
	if v.Licence.Customer != "" || v.Licence.LicenceID != "" {
		t.Errorf("a tenant's usage carries the provider's commercial identity: %+v", v.Licence)
	}

	// ── cross-tenant selection is 404, never 403 ────────────────────────────
	for _, path := range []string{
		"/api/system/licence/usage?tenant=" + fix["B"].tenantID,
		"/api/system/licence/usage/report?tenant=" + fix["B"].tenantID,
	} {
		st, b := do(t, srv, "GET", path, fix["A"].token, nil)
		if st != 404 {
			t.Errorf("%s as org A: %d %s — a cross-tenant selector must 404, never 403 (a 403 confirms the tenant exists)", path, st, b)
		}
	}

	// ── as_tenant into another org is ignored ───────────────────────────────
	st, b = do(t, srv, "GET", "/api/system/licence/usage?as_tenant="+fix["B"].tenantID, fix["A"].token, nil)
	if st != 200 {
		t.Fatalf("A with as_tenant into org B: %d %s", st, b)
	}
	v = decodeUsage(t, b)
	if v.Tenant != fix["A"].tenantID {
		t.Fatalf("as_tenant into another org was HONOURED: answer is scoped to %q", v.Tenant)
	}
	for _, d := range v.Days {
		if d.TenantID != fix["A"].tenantID {
			t.Fatalf("CROSS-TENANT LEAK via as_tenant: %q row", d.TenantID)
		}
	}

	// ── the platform owner sees everything, and may narrow ──────────────────
	st, b = do(t, srv, "GET", "/api/system/licence/usage", admin, nil)
	if st != 200 {
		t.Fatalf("owner reads usage: %d %s", st, b)
	}
	v = decodeUsage(t, b)
	if v.Scope != "platform" {
		t.Fatalf("the owner got scope %q, want the platform view", v.Scope)
	}
	seen := map[string]bool{}
	for _, row := range v.Tenants {
		seen[row.TenantID] = true
	}
	for _, want := range []string{fix["A"].tenantID, fix["B"].tenantID, ""} {
		if !seen[want] {
			t.Errorf("the platform breakdown is missing %q", want)
		}
	}
	st, b = do(t, srv, "GET", "/api/system/licence/usage?tenant="+fix["B"].tenantID, admin, nil)
	if st != 200 {
		t.Fatalf("owner narrows to B: %d %s", st, b)
	}
	v = decodeUsage(t, b)
	if v.Scope != "tenant" || v.Tenant != fix["B"].tenantID {
		t.Fatalf("the owner's narrowing did not take: scope=%q tenant=%q", v.Scope, v.Tenant)
	}
}

func TestMeteringUsageReportIsScopedAndSigned(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Report Org"})
	if st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Report Tenant", "org_id": idOf(t, b)})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "report-admin", "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
	})
	if st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	token := login(t, srv, "report-admin", "Passw0rd!2345").Token
	meteringFixtureRows(t, s, map[string][]string{tenantID: {"dev-1", "dev-2", "dev-3"}, "other-tenant": {"x-1"}})

	st, b = do(t, srv, "GET", "/api/system/licence/usage/report", token, nil)
	if st != 200 {
		t.Fatalf("tenant downloads its report: %d %s", st, b)
	}
	rep, err := metering.VerifyReport(b, nil)
	if err != nil {
		t.Fatalf("the served report does not verify against its own embedded key: %v", err)
	}
	if rep.Scope != metering.ReportScopeTenant || rep.Tenant != tenantID {
		t.Fatalf("report scope=%q tenant=%q", rep.Scope, rep.Tenant)
	}
	for _, d := range rep.Days {
		if d.TenantID != tenantID {
			t.Fatalf("CROSS-TENANT LEAK in a signed report: %q row", d.TenantID)
		}
	}
	if rep.Licence.Customer != "" || rep.Licence.LicenceID != "" {
		t.Fatalf("a tenant's signed report carries the provider's commercial identity: %+v", rep.Licence)
	}
	if _, disagree := metering.RecomputeTotals(rep); len(disagree) != 0 {
		t.Fatalf("the report's totals do not follow from its own daily rows: %v", disagree)
	}

	// The OWNER's report carries the installation row and the commercial context.
	st, b = do(t, srv, "GET", "/api/system/licence/usage/report", admin, nil)
	if st != 200 {
		t.Fatalf("owner downloads the report: %d %s", st, b)
	}
	rep, err = metering.VerifyReport(b, nil)
	if err != nil {
		t.Fatalf("the owner's report does not verify: %v", err)
	}
	if rep.Scope != metering.ReportScopePlatform {
		t.Fatalf("owner report scope = %q", rep.Scope)
	}
	installation := false
	for _, d := range rep.Days {
		if d.TenantID == metering.ScopeInstallation {
			installation = true
		}
	}
	if !installation {
		t.Errorf("the platform report has no installation row")
	}
}

func TestMeteringUsageRequiresAnAdmin(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Viewer Tenant"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "meter-viewer", "password": "Passw0rd!2345", "role": "viewer", "tenant_id": tenantID,
	})
	if st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	viewer := login(t, srv, "meter-viewer", "Passw0rd!2345").Token
	for _, path := range []string{"/api/system/licence/usage", "/api/system/licence/usage/report"} {
		if st, _ := do(t, srv, "GET", path, viewer, nil); st != 403 {
			t.Errorf("%s as a viewer: %d, want 403", path, st)
		}
		if st, _ := do(t, srv, "GET", path, "", nil); st != 401 {
			t.Errorf("%s unauthenticated: %d, want 401", path, st)
		}
	}
}
