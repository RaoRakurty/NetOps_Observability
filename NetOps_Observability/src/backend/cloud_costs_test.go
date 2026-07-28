package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/chschema"
	"strings"
	"testing"
	"time"
)

// ── Tenant isolation (CLAUDE.md §3a) ─────────────────────────────────────────
// The cost read surface is scoped by the CALLER's principal: the scope literal
// is what the STRICT tenant_iso_cloud_costs row policy enforces on, a request
// without claims fails closed, and no query reaches ClickHouse unscoped or
// unbounded. Mirrors the cloud_service_map_test.go isolation contract.
func TestCloudCostsQueryIsTenantScoped(t *testing.T) {
	scopeFor := func(c *jwtClaims) string {
		r := httptest.NewRequest(http.MethodGet, "/api/cloud/costs", nil)
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), userCtxKey, *c))
		}
		return safeScopeLiteral(chTenantScope(r))
	}
	cases := []struct {
		name  string
		claim *jwtClaims
		want  string
	}{
		{"platform owner", &jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, "__all__"},
		{"tenant admin", &jwtClaims{Role: "admin", Tenant: "acme"}, "acme"},
		{"tenant super-admin is NOT cross-tenant", &jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}, "acme"},
		{"no claims fails closed", nil, "__none__"},
		{"tenantless viewer fails closed", &jwtClaims{Role: "viewer", Tenant: ""}, "__none__"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := scopeFor(tc.claim)
			if scope != tc.want {
				t.Fatalf("scope = %q, want %q", scope, tc.want)
			}
			q := cloudCostsSQL("2026-06-18", "2026-07-17", "", 500, scope)
			if !strings.Contains(q, "SETTINGS tenant_scope = '"+tc.want+"'") {
				t.Fatalf("query is not scoped to %q:\n%s", tc.want, q)
			}
			if tc.want == "acme" && strings.Contains(q, "globex") {
				t.Fatalf("query leaked another tenant:\n%s", q)
			}
			// bounded by construction (§9 / #100 read budgets)
			if !strings.Contains(q, "LIMIT") || !strings.Contains(q, "toDate('2026-06-18')") {
				t.Fatalf("query is unbounded:\n%s", q)
			}
			if strings.Contains(q, "SELECT *") {
				t.Fatalf("query must name its columns (#100 contract):\n%s", q)
			}
		})
	}
}

// The store DDL the boot path converges: the table exists and its row policy
// is the STRICT form (billing data — no untagged-shared escape) applied
// atomically (OR REPLACE, never DROP+CREATE).
func TestCloudCostsSchemaIsStrictTenantIsolated(t *testing.T) {
	stmts := chschema.ConvergeStmts(cloudCostsSchemaDDL(), pathBaselineSchemaDDL())
	var tableSeen, policySeen bool
	for _, s := range stmts {
		if strings.Contains(s, "CREATE TABLE IF NOT EXISTS netops.cloud_costs") {
			tableSeen = true
			if !strings.Contains(s, "tenant_id") {
				t.Errorf("cloud_costs table has no tenant_id column:\n%s", s)
			}
			if !strings.Contains(s, "PARTITION BY (tenant_id") {
				t.Errorf("cloud_costs must lead its partition key with tenant_id (at-rest separation):\n%s", s)
			}
		}
		if strings.Contains(s, "ROW POLICY") && strings.Contains(s, "ON netops.cloud_costs") {
			policySeen = true
			if strings.Contains(s, "tenant_id = ''") {
				t.Errorf("cloud_costs row policy carries the lenient untagged-shared escape (cross-tenant billing leak):\n%s", s)
			}
			if !strings.HasPrefix(s, "CREATE ROW POLICY OR REPLACE tenant_iso_cloud_costs") {
				t.Errorf("cloud_costs policy must be the atomic strict form:\n%s", s)
			}
		}
	}
	if !tableSeen {
		t.Error("boot convergence missing the netops.cloud_costs table DDL")
	}
	if !policySeen {
		t.Error("boot convergence missing the netops.cloud_costs row policy")
	}
}

// ── input validation (zero-trust §3: everything caller-supplied is checked) ──

func TestCostDayValidation(t *testing.T) {
	for _, ok := range []string{"2026-07-17", "2025-01-01"} {
		if !costDayOK(ok) {
			t.Errorf("costDayOK(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "07/17/2026", "2026-13-40", "2026-07-17T00:00:00Z",
		"2026-7-1", "junk", "2026-07-17' OR 1=1 --"} {
		if costDayOK(bad) {
			t.Errorf("costDayOK(%q) = true, want false", bad)
		}
	}
}

func TestCostProviderAndAccountValidation(t *testing.T) {
	for _, p := range []string{"aws", "azure", "gcp"} {
		if !costProviderOK(p) {
			t.Errorf("provider %q rejected", p)
		}
	}
	for _, p := range []string{"", "AWS", "oracle", "aws' --"} {
		if costProviderOK(p) {
			t.Errorf("provider %q accepted", p)
		}
	}
	for _, a := range []string{"111111111111", "1b2c3d4e-aaaa-bbbb-cccc-000000000000", "my-project_1.x"} {
		if !costAccountOK(a) {
			t.Errorf("account %q rejected", a)
		}
	}
	for _, a := range []string{"", "acct' OR 1=1", strings.Repeat("a", 65), "a b"} {
		if costAccountOK(a) {
			t.Errorf("account %q accepted", a)
		}
	}
}

func TestCostWindowDefaultsClampsAndRejects(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)

	// defaults: last 30 complete days ending YESTERDAY (in-flight day never implied)
	from, to, err := costWindow("", "", now)
	if err != nil || to != "2026-07-17" || from != "2026-06-18" {
		t.Fatalf("default window = [%s, %s] err=%v", from, to, err)
	}

	// explicit valid range honored
	from, to, err = costWindow("2026-07-01", "2026-07-10", now)
	if err != nil || from != "2026-07-01" || to != "2026-07-10" {
		t.Fatalf("explicit window = [%s, %s] err=%v", from, to, err)
	}

	// too-wide range clamps to the ceiling (echoed, never silent)
	from, to, err = costWindow("2025-01-01", "2026-07-10", now)
	if err != nil || to != "2026-07-10" {
		t.Fatalf("clamped window err=%v to=%s", err, to)
	}
	fromT, _ := time.Parse("2006-01-02", from)
	toT, _ := time.Parse("2006-01-02", to)
	if days := int(toT.Sub(fromT).Hours()/24) + 1; days != cloudCostMaxWindowDays {
		t.Fatalf("clamped span = %d days, want %d", days, cloudCostMaxWindowDays)
	}

	// malformed / inverted input is a refusal, never a guess
	for _, bad := range [][2]string{
		{"junk", ""}, {"", "junk"}, {"2026-07-10", "2026-07-01"},
	} {
		if _, _, err := costWindow(bad[0], bad[1], now); err == nil {
			t.Errorf("costWindow(%q, %q) accepted, want error", bad[0], bad[1])
		}
	}
}

func TestClampCostLimit(t *testing.T) {
	if got := clampCostLimit(""); got != cloudCostDefaultLimit {
		t.Errorf("default limit = %d", got)
	}
	if got := clampCostLimit("999999"); got != cloudCostMaxLimit {
		t.Errorf("max clamp = %d", got)
	}
	if got := clampCostLimit("-3"); got != cloudCostDefaultLimit {
		t.Errorf("junk clamp = %d", got)
	}
	if got := clampCostLimit("25"); got != 25 {
		t.Errorf("honored limit = %d", got)
	}
}

func TestCostFilterSQLEscapesService(t *testing.T) {
	pred := costFilterSQL("aws", "111111111111",
		clampCostService("Amazon EC2 ' OR 1=1 --"))
	if !strings.Contains(pred, "provider = 'aws'") ||
		!strings.Contains(pred, "account = '111111111111'") {
		t.Fatalf("filters missing: %s", pred)
	}
	if !strings.Contains(pred, `\' OR 1=1`) {
		t.Fatalf("quote in the service literal must be escaped: %s", pred)
	}
	if strings.Contains(pred, "service = 'Amazon EC2 ' OR") {
		t.Fatalf("unescaped quote broke out of the literal: %s", pred)
	}
	if costFilterSQL("", "", "") != "" {
		t.Fatal("empty filters must render no predicate")
	}
}

// The read must survive a ReplacingMergeTree restatement correctly: FINAL is
// part of the contract (a restated day reads as ONE replaced row, not two).
func TestCloudCostsQueryReadsFinal(t *testing.T) {
	q := cloudCostsSQL("2026-06-18", "2026-07-17", "", 500, "acme")
	if !strings.Contains(q, "FROM netops.cloud_costs FINAL") {
		t.Fatalf("query must read FINAL:\n%s", q)
	}
}
