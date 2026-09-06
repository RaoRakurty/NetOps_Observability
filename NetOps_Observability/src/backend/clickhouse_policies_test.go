// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/chschema"
	"strings"
	"testing"

	"netops/backend/cloud"
)

func reqWithClaims(c jwtClaims) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/flows/top", nil)
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
}

// TestChTenantScope locks down the security-critical mapping from a caller to the
// ClickHouse tenant_scope the row policies enforce. Getting this wrong is a
// cross-tenant data leak, so the cases are exhaustive.
func TestChTenantScope(t *testing.T) {
	cases := []struct {
		name  string
		claim *jwtClaims // nil = no claims on the request
		want  string
	}{
		{"platform owner (super-admin, global)", &jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, "__all__"},
		{"platform owner (super-admin, 'global')", &jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal}, "__all__"},
		{"scoped tenant admin", &jwtClaims{Role: "admin", Tenant: "acme"}, "acme"},
		// The key one: a tenant's OWN super-admin is NOT cross-tenant — must be
		// confined to its tenant, never '__all__'.
		{"tenant super-admin (scoped)", &jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}, "acme"},
		{"viewer in tenant", &jwtClaims{Role: "viewer", Tenant: "globex"}, "globex"},
		// Fail-closed cases — see only untagged rows, never another tenant's.
		{"empty tenant, not cross", &jwtClaims{Role: "viewer", Tenant: ""}, "__none__"},
	}
	for _, c := range cases {
		var r *http.Request
		if c.claim != nil {
			r = reqWithClaims(*c.claim)
		} else {
			r = httptest.NewRequest(http.MethodGet, "/api/flows/top", nil)
		}
		if got := chTenantScope(r); got != c.want {
			t.Errorf("%s: chTenantScope = %q, want %q", c.name, got, c.want)
		}
	}

	// No claims at all (should never reach an authed handler) → fail closed.
	if got := chTenantScope(httptest.NewRequest(http.MethodGet, "/api/flows/top", nil)); got != "__none__" {
		t.Errorf("no-claims request scope = %q, want __none__ (fail closed)", got)
	}
}

// TestCorrRowPoliciesStrict is the regression lock for the 2026-07-17 security
// fix: the boot-convergence path must NEVER emit the lenient untagged-shared
// escape (`tenant_id = ”`) for any correlation-family (corr_*) or path graph
// (path_*) row policy — untagged correlation intel is platform-only, and the
// lenient clause would leak platform-global rows into every tenant's view.
// It asserts over the ACTUAL DDL strings the boot path executes.
func TestCorrRowPoliciesStrict(t *testing.T) {
	stmts := chschema.ConvergeStmts(cloud.CostsSchemaDDL(), pathBaselineSchemaDDL())

	// Every ROW POLICY statement on a corr_* / path_* table: strict filter,
	// no untagged escape.
	strictSeen := map[string]bool{}
	for _, s := range stmts {
		if !strings.Contains(s, "ROW POLICY") {
			continue
		}
		strict := strings.Contains(s, "ON netops.corr_") || strings.Contains(s, "ON netops.path_")
		if !strict {
			continue
		}
		if strings.Contains(s, "tenant_id = ''") {
			t.Errorf("correlation-family row policy carries the lenient untagged-shared escape (cross-tenant leak):\n%s", s)
		}
		if !strings.Contains(s, "getSetting('tenant_scope')") || !strings.Contains(s, "'__all__'") {
			t.Errorf("correlation-family row policy missing the strict tenant_scope filter:\n%s", s)
		}
		if !strings.Contains(s, "TO ALL") {
			t.Errorf("correlation-family row policy must apply TO ALL:\n%s", s)
		}
		strictSeen[s] = true
	}

	// The five owner-approved corr tables must use CREATE OR REPLACE — upgrade
	// semantics: an existing pre-2026-07-02 LENIENT policy is atomically
	// replaced on boot, not skipped by IF NOT EXISTS. (Never DROP+CREATE: that
	// would open a policyless exposure window.)
	for _, table := range []string{
		"corr_signals", "corr_signals_archive", "corr_objects", "corr_edges", "corr_evidence",
		// Same-pattern extension (separate commit): the already-strict family
		// also self-heals via atomic OR REPLACE.
		"corr_current", "corr_tenant_write_amp", "corr_path_edges",
		"path_observations", "path_hops",
	} {
		want := "CREATE ROW POLICY OR REPLACE tenant_iso_" + table + " ON netops." + table
		found := false
		for s := range strictSeen {
			if strings.Contains(s, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("boot convergence missing atomic strict upgrade for %s: want a statement starting %q", table, want)
		}
	}

	// No statement anywhere in the boot list may DROP a row policy — a
	// DROP+CREATE sequence would expose unfiltered rows in between.
	for _, s := range stmts {
		if strings.Contains(s, "DROP ROW POLICY") {
			t.Errorf("boot convergence must never DROP a row policy (policyless window):\n%s", s)
		}
	}

	// Helper-level lock: the strict generator output is exactly the approved
	// form (atomic OR REPLACE + strict filter, no escape).
	got := chschema.StrictRowPolicyDDL("corr_signals")
	want := "CREATE ROW POLICY OR REPLACE tenant_iso_corr_signals ON netops.corr_signals" +
		" USING tenant_id = getSetting('tenant_scope') OR getSetting('tenant_scope') = '__all__' TO ALL"
	if got != want {
		t.Errorf("chschema.StrictRowPolicyDDL(corr_signals):\n got %q\nwant %q", got, want)
	}

	// Guard the scope boundary too: the lenient telemetry policies (flows,
	// findings, tunnels) are OUT of scope of the strict model by design —
	// their data model depends on untagged shared rows. If one goes missing
	// or silently changes family, that is a deliberate decision, not drift.
	for _, table := range []string{"flows", "findings", "tunnels"} {
		found := false
		for _, s := range stmts {
			if strings.Contains(s, "ROW POLICY") && strings.Contains(s, "ON netops."+table+" ") {
				found = true
				if !strings.Contains(s, "tenant_id = ''") {
					t.Errorf("lenient telemetry policy for %s lost its untagged-shared clause — that is a data-model change, not this fix:\n%s", table, s)
				}
			}
		}
		if !found {
			t.Errorf("boot convergence missing telemetry row policy for %s", table)
		}
	}
}

// TestRowPolicyGrammarShape guards the CLASS of bug that shipped on
// 2026-07-21, not the one instance of it. The strict builder emitted
// `CREATE OR REPLACE ROW POLICY …`, which ClickHouse parses as
// CREATE OR REPLACE {TABLE|VIEW|DICTIONARY|FUNCTION} and rejects at 'ROW'.
// It failed 1,560 times and never once succeeded — yet four test files passed,
// because every one of them asserted the exact broken STRING. A test that
// pins a literal cannot fail when the literal is wrong; it only proves the
// code still says what it said yesterday.
//
// So assert the GRAMMAR instead: every policy statement this package emits
// must begin with the one prefix ClickHouse accepts. Any future rewording of
// the modifier fails here rather than in production.
func TestRowPolicyGrammarShape(t *testing.T) {
	stmts := []string{
		chschema.RowPolicyDDL("flows"),
		chschema.StrictRowPolicyDDL("corr_signals"),
	}
	for _, s := range chschema.ConvergeStmts(cloud.CostsSchemaDDL(), pathBaselineSchemaDDL()) {
		if strings.Contains(s, "ROW POLICY") {
			stmts = append(stmts, s)
		}
	}
	if len(stmts) < 3 {
		t.Fatalf("expected the converge list to emit row policies; got %d statements", len(stmts))
	}
	for _, s := range stmts {
		if !strings.HasPrefix(s, "CREATE ROW POLICY ") {
			t.Errorf("row-policy DDL must start with %q (ClickHouse puts the modifier AFTER\n"+
				"ROW POLICY: `CREATE ROW POLICY OR REPLACE|IF NOT EXISTS name ON …`).\ngot: %s",
				"CREATE ROW POLICY ", s)
		}
		// Catch the exact inversion that shipped.
		if strings.HasPrefix(s, "CREATE OR REPLACE") {
			t.Errorf("invalid ClickHouse grammar (parses as CREATE OR REPLACE TABLE/VIEW/...): %s", s)
		}
	}
}
