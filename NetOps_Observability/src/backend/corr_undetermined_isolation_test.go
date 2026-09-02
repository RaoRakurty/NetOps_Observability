package backend

// corr_undetermined_isolation_test.go — CLAUDE.md §3a rule 5 for
// /api/correlations/undetermined-frequency (tracker 201).
//
// The feed ranks a tenant's own UNDETERMINED correlation objects by the shape of
// their evidence gap. That is per-tenant operational data, so the contract is:
// tenant A's ranking must be computed from tenant A's rows and NOTHING else,
// however the caller asks.
//
// Isolation here is ClickHouse-side: the read carries the caller's tenant_scope
// (chRows → chTenantScope) and netops.corr_current's tenant_iso FORCE row policy
// filters on it server-side — visible in the query plan as a "Row-level security
// filter" step above ReadFromMergeTree. A handler that forgot its own filter
// still cannot see another tenant. So the isolation contract this test pins is
// the SCOPE LITERAL on the wire plus the resulting rows: the fake ClickHouse
// below BEHAVES like the row policy (it answers only the scope it was asked for),
// which turns "the endpoint sent the wrong scope" into a visible cross-tenant
// leak in the response body rather than a silent one.
//
// Covered: own-only ranking, cross-tenant rows never surface, `as_tenant` into
// another org ignored, tenantless/absent claims fail closed to '__none__', and
// the platform owner's cross-tenant view.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// undetScopedCH is a ClickHouse stand-in that enforces the row policy the real
// server enforces: it returns ONLY the rows tagged with the scope on the request.
type undetScopedCH struct {
	mu     sync.Mutex
	scopes []string
	rows   map[string][]map[string]any
}

func (f *undetScopedCH) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("tenant_scope")
		f.mu.Lock()
		f.scopes = append(f.scopes, scope)
		f.mu.Unlock()
		out := []map[string]any{}
		if scope == "__all__" {
			for _, rows := range f.rows {
				out = append(out, rows...)
			}
		} else {
			out = append(out, f.rows[scope]...)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	}
}

func (f *undetScopedCH) lastScope(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scopes) == 0 {
		t.Fatal("the endpoint issued no ClickHouse read — the isolation contract is untested")
	}
	return f.scopes[len(f.scopes)-1]
}

// undetRow builds one undetermined object whose nearest-signature token names
// the tenant, so a leaked row is identifiable in the response by its cluster.
func undetRow(id, sig string) map[string]any {
	return map[string]any{
		"correlation_id_s": id,
		"window_start_iso": "2026-08-31T19:08:28.982Z",
		"evidence_missing": `["` + sig + `: needs second-modality observer"]`,
		"affected":         `{"devices":["dev-` + sig + `"]}`,
		"signal_count":     2,
	}
}

// undetSignatures pulls every nearest-signature the response ranked.
func undetSignatures(t *testing.T, body []byte) []string {
	t.Helper()
	var resp struct {
		Total    int `json:"total_undetermined"`
		Clusters []struct {
			NearestSignatures []string `json:"nearest_signatures"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	var out []string
	for _, c := range resp.Clusters {
		out = append(out, c.NearestSignatures...)
	}
	return out
}

func TestUndeterminedFrequencyCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two orgs, one tenant and one tenant-scoped operator each (the
	// org_isolation_test.go template).
	type org struct{ orgID, tenantID, user, token string }
	orgs := map[string]*org{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "UndetOrg " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "UndetTenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "undet-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		orgs[name] = &org{orgID: orgID, tenantID: tenantID, user: user,
			token: login(t, srv, user, "Passw0rd!2345").Token}
	}

	fake := &undetScopedCH{rows: map[string][]map[string]any{
		orgs["A"].tenantID: {undetRow("11111111-1111-4111-8111-111111111111", "sig.tenant.a")},
		orgs["B"].tenantID: {undetRow("22222222-2222-4222-8222-222222222222", "sig.tenant.b")},
	}}
	ch := httptest.NewServer(fake.handler())
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	_ = s // the handler reads CLICKHOUSE_URL at request time

	const path = "/api/correlations/undetermined-frequency?since=604800s&top=20"

	// 1) Own-only: A ranks A's gap and never B's.
	st, body := do(t, srv, "GET", path, orgs["A"].token, nil)
	if st != http.StatusOK {
		t.Fatalf("tenant A: status %d: %s", st, body)
	}
	if got := fake.lastScope(t); got != orgs["A"].tenantID {
		t.Fatalf("tenant A's read carried tenant_scope %q, want %q — the feed is not scoped to the caller", got, orgs["A"].tenantID)
	}
	sigs := undetSignatures(t, body)
	if len(sigs) != 1 || sigs[0] != "sig.tenant.a" {
		t.Fatalf("tenant A ranked %v, want exactly [sig.tenant.a]", sigs)
	}
	for _, sg := range sigs {
		if strings.Contains(sg, "tenant.b") {
			t.Fatalf("CROSS-TENANT LEAK: tenant A's ranking contains tenant B's gap shape: %v", sigs)
		}
	}

	// 2) The mirror: B ranks B's, never A's.
	st, body = do(t, srv, "GET", path, orgs["B"].token, nil)
	if st != http.StatusOK {
		t.Fatalf("tenant B: status %d: %s", st, body)
	}
	if got := fake.lastScope(t); got != orgs["B"].tenantID {
		t.Fatalf("tenant B's read carried tenant_scope %q, want %q", got, orgs["B"].tenantID)
	}
	if sigs = undetSignatures(t, body); len(sigs) != 1 || sigs[0] != "sig.tenant.b" {
		t.Fatalf("tenant B ranked %v, want exactly [sig.tenant.b]", sigs)
	}

	// 3) as_tenant into ANOTHER ORG is ignored — A asking to view as B still gets
	//    A's scope and A's ranking (the override may only ever narrow within
	//    reach, and A reaches only its own tenant).
	st, body = do(t, srv, "GET", path+"&as_tenant="+orgs["B"].tenantID, orgs["A"].token, nil)
	if st != http.StatusOK {
		t.Fatalf("tenant A with as_tenant=B: status %d: %s", st, body)
	}
	if got := fake.lastScope(t); got != orgs["A"].tenantID {
		t.Fatalf("as_tenant into another org WIDENED the scope to %q — §3a rule 2/3 violation", got)
	}
	if sigs = undetSignatures(t, body); len(sigs) != 1 || sigs[0] != "sig.tenant.a" {
		t.Fatalf("as_tenant into another org changed the ranking to %v — cross-tenant read", sigs)
	}

	// 4) The platform owner's cross-tenant view still works (isolation must not
	//    become "nobody sees anything").
	st, body = do(t, srv, "GET", path, admin, nil)
	if st != http.StatusOK {
		t.Fatalf("platform owner: status %d: %s", st, body)
	}
	if got := fake.lastScope(t); got != "__all__" {
		t.Fatalf("platform owner's read carried tenant_scope %q, want __all__", got)
	}
	if sigs = undetSignatures(t, body); len(sigs) != 2 {
		t.Fatalf("platform owner ranked %v, want both tenants' shapes", sigs)
	}
}

// TestUndeterminedFrequencyScopeFailsClosed pins the OTHER half of §3a rule 1:
// a principal with no tenant resolves to the non-matching sentinel, so the row
// policy returns nothing rather than everything. A request with no claims cannot
// reach the handler (auth rejects it first), which is why this asserts the scope
// derivation the handler depends on directly.
func TestUndeterminedFrequencyScopeFailsClosed(t *testing.T) {
	cases := []struct {
		name  string
		claim *jwtClaims
		want  string
	}{
		{"platform owner", &jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, "__all__"},
		{"tenant operator", &jwtClaims{Role: "operator", Tenant: "acme"}, "acme"},
		{"tenantless viewer fails closed", &jwtClaims{Role: "viewer", Tenant: ""}, "__none__"},
		{"no claims fails closed", nil, "__none__"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/correlations/undetermined-frequency", nil)
			if tc.claim != nil {
				r = r.WithContext(context.WithValue(r.Context(), userCtxKey, *tc.claim))
			}
			if got := chTenantScope(r); got != tc.want {
				t.Fatalf("chTenantScope = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestUndeterminedFrequencySQLStaysBounded pins the tracker-201 cost fix as a
// CONTRACT, not a one-off measurement: the read sources the narrow hot
// projection (cost ∝ live objects), never the history fold (cost ∝ versions,
// which a storm multiplies), never touches a wide blob column, and carries its
// own scan cap so a corpus that outgrows it fails loud instead of eating the
// 20 s API budget.
func TestUndeterminedFrequencySQLStaysBounded(t *testing.T) {
	sql := undeterminedFrequencySQL("604800")

	if !strings.Contains(sql, "FROM netops.corr_current FINAL") {
		t.Errorf("the feed must read the corr_current hot projection (#100 / tracker 197):\n%s", sql)
	}
	if strings.Contains(sql, "corr_objects_latest") || strings.Contains(sql, "corr_objects\n") {
		t.Errorf("the feed must NOT fold the history table — that scan is version-shaped and a storm multiplies it (tracker 201):\n%s", sql)
	}
	for _, wide := range []string{"hypotheses", "layer_coverage", "app_impact"} {
		if strings.Contains(sql, wide) {
			t.Errorf("the feed reads wide blob column %q:\n%s", wide, sql)
		}
	}
	if !strings.Contains(sql, "max_bytes_to_read = 2000000000") {
		t.Errorf("the feed lost its scan cap — a storm corpus would spend the whole API budget (tracker 201):\n%s", sql)
	}
	if strings.Contains(sql, "read_overflow_mode") {
		t.Errorf("the cap must FAIL, not truncate: a ranking computed from an arbitrary partial scan is a silent wrong answer (CLAUDE.md §10):\n%s", sql)
	}
	// SETTINGS must precede FORMAT or ClickHouse rejects the statement.
	if strings.Index(sql, " SETTINGS ") > strings.Index(sql, " FORMAT JSON") {
		t.Errorf("SETTINGS must come before FORMAT:\n%s", sql)
	}
	if !strings.Contains(sql, "LIMIT 5000") {
		t.Errorf("the row cap is gone:\n%s", sql)
	}
}
