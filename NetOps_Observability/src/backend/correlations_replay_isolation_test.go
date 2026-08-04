package backend

// correlations_replay_isolation_test.go — §3a guard for the ONE correlation
// subresource that had none.
//
// THE BUG THIS PINS (found 2026-08-04, fixed in the same change):
// /api/correlations/{id}/replay proxied a caller-supplied UUID to the
// correlation service without ever authorizing it. The handler's requirePerm
// gate is a PERMISSION check, not an OWNERSHIP one; the correlation service is
// unauthenticated and reads at tenant_scope=__all__ with no tenant predicate in
// its SQL. So a tenant-A operator holding infrastructure:read who submitted
// tenant B's correlation id received tenant B's RCA drift report — while the
// SIBLING route /api/correlations/{id} correctly returned 404 for the same id.
// That asymmetry was also a cross-tenant existence oracle (CLAUDE.md §3a rule 1
// requires 404, never a hint that the id exists).
//
// WHY THE EXISTING GUARDS MISSED IT: route_isolation_test.go classifies the
// /api/correlations/ PREFIX as scoped — true for the siblings, false for this
// subresource — and the coverage ratchet checks prefixes, so sibling tests
// satisfied it.
//
// The fake ClickHouse below enforces the real row-policy semantics
// (tenant_id = getSetting('tenant_scope') OR scope = '__all__'), so the test
// proves the FIX rather than the mock: the handler must send the CALLER's scope
// and must 404 when that scope returns no rows.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCH answers chSelect's HTTP POST the way ClickHouse does, applying the
// tenant row policy to a two-row corr_objects table (one per tenant).
type replayFakeCH struct {
	mu     sync.Mutex
	scopes []string // tenant_scope seen, in order — asserted below
	rows   map[string]string
}

func newReplayFakeCH(rows map[string]string) (*httptest.Server, *replayFakeCH) {
	f := &replayFakeCH{rows: rows}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scope := r.URL.Query().Get("tenant_scope")
		f.mu.Lock()
		f.scopes = append(f.scopes, scope)
		f.mu.Unlock()

		buf := make([]byte, 1<<16)
		n, _ := r.Body.Read(buf)
		sql := string(buf[:n])

		// Return the row only if the policy would: exact tenant match or __all__.
		out := []map[string]any{}
		for id, tenant := range f.rows {
			if !strings.Contains(sql, id) {
				continue
			}
			if scope == "__all__" || scope == tenant {
				out = append(out, map[string]any{"correlation_id": id})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"data": out})
	}))
	return srv, f
}

func (f *replayFakeCH) seenScopes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.scopes...)
}

func TestCorrelationReplayCrossOrgIsolation(t *testing.T) {
	const (
		idA = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
		idB = "bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb"
	)

	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two orgs, each with a tenant and a tenant-scoped operator.
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
		user := "corr-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &orgFixture{orgID: orgID, tenantID: tenantID, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := fix["A"], fix["B"]

	// corr_objects: one correlation per tenant.
	ch, fake := newReplayFakeCH(map[string]string{idA: a.tenantID, idB: b.tenantID})
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)

	// The correlation service must NEVER be reached for an unauthorized id. If it
	// is, this handler records the breach and the assertions below fail loudly —
	// this is the actual leak detector, not the status code.
	var proxied []string
	var proxyMu sync.Mutex
	corr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyMu.Lock()
		proxied = append(proxied, r.URL.Path)
		proxyMu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"correlation_id": "leaked", "clean": true})
	}))
	defer corr.Close()
	t.Setenv("CORRELATION_URL", corr.URL)

	// ── the bug: tenant A asking for tenant B's correlation ────────────────────
	st, body := do(t, srv, "GET", "/api/correlations/"+idB+"/replay", a.token, nil)
	if st != http.StatusNotFound {
		t.Fatalf("cross-tenant replay must 404, got %d %s", st, body)
	}
	proxyMu.Lock()
	leaked := append([]string(nil), proxied...)
	proxyMu.Unlock()
	if len(leaked) != 0 {
		t.Fatalf("cross-tenant replay reached the correlation service (%v) — the ownership check must run BEFORE the proxy", leaked)
	}

	// ── the caller's own correlation still works, and IS proxied ───────────────
	st, body = do(t, srv, "GET", "/api/correlations/"+idA+"/replay", a.token, nil)
	if st != http.StatusOK {
		t.Fatalf("own-tenant replay must succeed, got %d %s", st, body)
	}
	proxyMu.Lock()
	got := len(proxied)
	proxyMu.Unlock()
	if got != 1 {
		t.Fatalf("own-tenant replay must reach the correlation service exactly once, got %d", got)
	}

	// ── the ownership read must carry the CALLER's scope, never __all__ ────────
	for _, sc := range fake.seenScopes() {
		if sc == "__all__" {
			t.Fatalf("ownership pre-read ran at __all__ — it must use the caller's tenant scope")
		}
		if sc == "" {
			t.Fatalf("ownership pre-read ran with an empty tenant_scope")
		}
	}

	// ── no existence oracle: unknown id and other-tenant id are indistinguishable
	stUnknown, bodyUnknown := do(t, srv, "GET", "/api/correlations/cccccccc-3333-4333-8333-cccccccccccc/replay", a.token, nil)
	if stUnknown != http.StatusNotFound {
		t.Fatalf("unknown id must 404, got %d", stUnknown)
	}
	stCross, bodyCross := do(t, srv, "GET", "/api/correlations/"+idB+"/replay", a.token, nil)
	if stCross != stUnknown || string(bodyCross) != string(bodyUnknown) {
		t.Fatalf("cross-tenant 404 (%d %s) differs from unknown-id 404 (%d %s) — that difference is an existence oracle",
			stCross, bodyCross, stUnknown, bodyUnknown)
	}

	// ── the platform owner may replay any correlation ──────────────────────────
	if st, body = do(t, srv, "GET", "/api/correlations/"+idB+"/replay", admin, nil); st != http.StatusOK {
		t.Fatalf("platform owner must be able to replay any correlation, got %d %s", st, body)
	}
}
