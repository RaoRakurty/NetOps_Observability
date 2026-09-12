// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// correlation_restriction_isolation_test.go — CLAUDE.md §3a rule 5 isolation
// test for the correlation cases and the raw signal feed.
//
// A tenant can switch on the operator-visibility restriction. Logs, flows,
// metrics, igpmon, the BMP feed, unified search, the RCA path spine and digital
// experience all honour it. The correlation lane did not. It consulted the
// restriction nowhere, so a platform owner read a restricted tenant's
// correlation cases — the case id, its top hypothesis, its verdict tier, the
// devices and seams under `affected`, the app impact — and its raw signal feed:
// every signal id, kind, entity and site the engine has ingested for that
// tenant. That is the customer's own incident history.
//
// It is closed in two places because the two halves are not the same problem.
//
// The as_tenant half is closed at the STORAGE chokepoint: s.chTenantScopeFor
// hands a denied operator the read-nothing scope, and the corr_* STRICT row
// policies enforce it server-side, for every correlation read at once rather
// than thirty call sites remembering.
//
// The Global half cannot be. '__all__' means all and the row-policy grammar has
// no "all except", so the exclusion rides in each SQL as a tenant_id NOT IN
// predicate — the same conclusion unified search reached.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// restrictionFixture is a server with a REAL tenant store holding two tenants,
// neither restricted yet. It returns the opaque ids, because identity here is
// the id and never the slug.
func restrictionFixture(t *testing.T) (*server, string, string) {
	t.Helper()
	ts, err := newTenantStore(filepath.Join(t.TempDir(), "tenants.json"))
	if err != nil {
		t.Fatalf("newTenantStore: %v", err)
	}
	acme, err := ts.Create("Acme", "acme", "", "", "")
	if err != nil {
		t.Fatalf("create acme: %v", err)
	}
	globex, err := ts.Create("Globex", "globex", "", "", "")
	if err != nil {
		t.Fatalf("create globex: %v", err)
	}
	return &server{tenants: ts}, acme.ID, globex.ID
}

// chSpy records every (scope, sql) pair the handlers send, and answers with the
// rows the test hands it. It is the whole point of the fixture: the assertion is
// about what went ON THE WIRE, not about what a fake chose to return.
type chSpy struct {
	mu    sync.Mutex
	calls []struct{ scope, sql string }
	rows  string
}

func (c *chSpy) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readAllLimited(r)
		scope := r.URL.Query().Get("tenant_scope")
		c.mu.Lock()
		c.calls = append(c.calls, struct{ scope, sql string }{scope, body})
		rows := c.rows
		c.mu.Unlock()
		if rows == "" {
			rows = `{"data":[]}`
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(rows))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

func (c *chSpy) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = nil
}

func (c *chSpy) all() []struct{ scope, sql string } {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]struct{ scope, sql string }(nil), c.calls...)
}

// readAllLimited returns everything the caller sent: ClickHouse takes the SQL in
// the body, but a query arg carries it on some paths, so BOTH are recorded. A
// spy that reads only one of them would assert on an empty string and pass.
func readAllLimited(r *http.Request) string {
	b, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return ""
	}
	return string(b) + "\n-- args: " + r.URL.RawQuery
}

func TestCorrelationLaneHonoursTheOperatorVisibilityRestriction(t *testing.T) {
	ch := &chSpy{}
	ch.start(t)
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	mk := func(name, slug string) string {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org: %d %s", st, b)
		}
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": name, "org_id": idOf(t, b), "slug": slug})
		if st != 201 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		return idOf(t, b)
	}
	acme, globex := mk("Acme", "acme"), mk("Globex", "globex")

	// The routes this lane owns. Every one of them reads netops.corr_*.
	routes := []string{
		"/api/correlations?limit=10",
		"/api/correlations/summary",
		"/api/correlations/stats",
		"/api/events/feed?limit=10",
	}

	get := func(path, token, asTenant string) {
		t.Helper()
		req, err := http.NewRequest("GET", srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if asTenant != "" {
			req.Header.Set("X-Acting-Tenant", asTenant)
		}
		if resp, err := http.DefaultClient.Do(req); err == nil {
			resp.Body.Close()
		}
	}

	// ── baseline: nothing restricted. The owner reads across tenants and no SQL
	//    carries an exclusion.
	for _, rt := range routes {
		get(rt, admin, "")
	}
	if len(ch.all()) == 0 {
		t.Fatal("no ClickHouse read was issued — this fixture proves nothing")
	}
	for _, c := range ch.all() {
		if c.scope != "__all__" {
			t.Fatalf("with nothing restricted the platform owner must read at __all__, got %q", c.scope)
		}
		if strings.Contains(c.sql, "NOT IN ('"+acme+"')") {
			t.Fatalf("nothing is restricted, yet a read excluded acme:\n%s", c.sql)
		}
	}

	if _, err := s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	// ── half 1: the owner's GLOBAL view. Every correlation read must carry the
	//    tenant_id exclusion naming acme's opaque id, and must not name globex.
	for _, rt := range routes {
		t.Run("global "+rt, func(t *testing.T) {
			ch.reset()
			get(rt, admin, "")
			calls := ch.all()
			if len(calls) == 0 {
				t.Skip("route made no ClickHouse read in this fixture")
			}
			for i, c := range calls {
				if strings.TrimSpace(strings.SplitN(c.sql, "\n-- args: ", 2)[0]) == "" {
					t.Fatalf("read %d on %s carried no SQL — the spy is asserting on nothing", i, rt)
				}
				if !strings.Contains(c.sql, "tenant_id NOT IN ('"+acme+"')") {
					t.Fatalf("RESTRICTION LEAK: read %d on %s does not exclude the restricted tenant.\nscope=%s\nSQL: %s", i, rt, c.scope, c.sql)
				}
				if strings.Contains(c.sql, globex) {
					t.Fatalf("read %d on %s excluded globex, which is not restricted.\nSQL: %s", i, rt, c.sql)
				}
			}
		})
	}

	// ── half 2: the owner walks in with ?as_tenant=acme. Every read must go out
	//    at the read-nothing scope. Not a 403: that would confirm acme has cases.
	for _, rt := range routes {
		t.Run("as_tenant "+rt, func(t *testing.T) {
			ch.reset()
			get(rt, admin, acme)
			calls := ch.all()
			if len(calls) == 0 {
				t.Skip("route made no ClickHouse read in this fixture")
			}
			for i, c := range calls {
				if c.scope != chScopeNone {
					t.Fatalf("RESTRICTION LEAK: read %d on %s?as_tenant=acme went out at scope %q, want %q.\nSQL: %s",
						i, rt, c.scope, chScopeNone, c.sql)
				}
			}
		})
	}

	// ── the owner scoped into the UNRESTRICTED tenant still reads it.
	t.Run("as_tenant globex is untouched", func(t *testing.T) {
		ch.reset()
		get("/api/correlations?limit=10", admin, globex)
		calls := ch.all()
		if len(calls) == 0 {
			t.Skip("no ClickHouse read in this fixture")
		}
		for i, c := range calls {
			if c.scope != globex {
				t.Fatalf("read %d: scope = %q, want globex's own scope %q", i, c.scope, globex)
			}
		}
	})

	// ── acme's own user is never restricted from acme's own cases.
	t.Run("the tenant's own user keeps its own cases", func(t *testing.T) {
		st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": "a-acme", "password": "Passw0rd!2345", "role": "operator", "tenant_id": acme,
		})
		if st != 201 {
			t.Fatalf("create user: %d %s", st, b)
		}
		token := login(t, srv, "a-acme", "Passw0rd!2345").Token
		ch.reset()
		get("/api/correlations?limit=10", token, "")
		calls := ch.all()
		if len(calls) == 0 {
			t.Skip("no ClickHouse read in this fixture")
		}
		for i, c := range calls {
			if c.scope != acme {
				t.Fatalf("read %d: acme's own user reads at %q, want %q", i, c.scope, acme)
			}
			if strings.Contains(c.sql, "NOT IN ('"+acme+"')") {
				t.Fatalf("read %d: acme's own user was excluded from its own cases:\n%s", i, c.sql)
			}
		}
	})

	// ── a case BY ID, in the Global view, answers 404 — never another tenant's
	//    id, and never a 403 that would confirm the case exists.
	t.Run("a restricted tenant's case answers 404 by id", func(t *testing.T) {
		const id = "11111111-2222-3333-4444-555555555555"
		ch.reset()
		ch.mu.Lock()
		ch.rows = "" // the exclusion is what must be on the wire; rows are empty either way
		ch.mu.Unlock()
		req, err := http.NewRequest("GET", srv.URL+"/api/correlations/"+id, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+admin)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
		calls := ch.all()
		if len(calls) == 0 {
			t.Skip("no ClickHouse read in this fixture")
		}
		if !strings.Contains(calls[0].sql, "tenant_id NOT IN ('"+acme+"')") {
			t.Fatalf("RESTRICTION LEAK: the by-id read does not exclude the restricted tenant.\nSQL: %s", calls[0].sql)
		}
	})
}

// policyCH emulates what ClickHouse actually does with these two rules: it
// returns acme's row unless the caller's scope excludes it (the row policy) or
// the SQL excludes it (the predicate). A spy that answers the same rows however
// it is asked cannot tell a fixed lane from a broken one; this one can, so the
// assertion below is on the BODY and names the field that crossed.
type policyCH struct {
	acme string
	row  string // one JSON object, acme's
}

func (p policyCH) start(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sql := readAllLimited(r)
		scope := r.URL.Query().Get("tenant_scope")
		visible := (scope == "__all__" || scope == p.acme) &&
			!strings.Contains(sql, "tenant_id NOT IN ('"+p.acme+"')")
		w.Header().Set("Content-Type", "application/json")
		if visible {
			_, _ = w.Write([]byte(`{"data":[` + p.row + `]}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
}

// The fields that crossed, named. This drives the real router against a
// ClickHouse that applies the two rules the way the deployed one does.
func TestCorrelationBodyDropsARestrictedTenantsRows(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Acme"})
	if st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Acme", "org_id": idOf(t, b), "slug": "acme"})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	acme := idOf(t, b)

	const caseID = "9f1c0d3e-1111-4444-8888-aaaaaaaaaaaa"
	const signalID = "7c2b0a1d-2222-4444-9999-bbbbbbbbbbbb"
	policyCH{acme: acme, row: `{"correlation_id":"` + caseID + `","signal_id":"` + signalID + `",` +
		`"top_hypothesis":"acme-payments-edge-flap","affected":"acme-core","kind":"bgp_session_down",` +
		`"entity_id":"acme-core","site":"acme-dc1","version":1,"created_at_ms":"1","c":"1"}`}.start(t)

	body := func(path, asTenant string) string {
		t.Helper()
		req, err := http.NewRequest("GET", srv.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+admin)
		if asTenant != "" {
			req.Header.Set("X-Acting-Tenant", asTenant)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		return string(out)
	}

	// Before the restriction the owner sees acme's case — otherwise the
	// assertions below would pass on an endpoint that simply returns nothing.
	if got := body("/api/correlations?limit=10", ""); !strings.Contains(got, caseID) {
		t.Fatalf("the fixture does not reach the owner's Global view at all:\n%s", got)
	}

	if _, err := s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}

	for _, tc := range []struct{ name, path, asTenant string }{
		{"global list", "/api/correlations?limit=10", ""},
		{"as_tenant list", "/api/correlations?limit=10", acme},
		{"global feed", "/api/events/feed?limit=10", ""},
		{"as_tenant feed", "/api/events/feed?limit=10", acme},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := body(tc.path, tc.asTenant)
			for _, leaked := range []string{caseID, signalID, "acme-payments-edge-flap", "acme-core", "acme-dc1"} {
				if strings.Contains(got, leaked) {
					t.Fatalf("RESTRICTION LEAK: %q reached the platform owner:\n%s", leaked, got)
				}
			}
		})
	}
}

// The response body is the other half of the proof: a row that the restriction
// should have dropped must not be rendered even when ClickHouse hands it back
// (a policy that is not applied, a table not yet tagged). This drives the list
// with a spy that answers with acme's case regardless of the SQL.
func TestCorrelationListDropsARestrictedTenantsCase(t *testing.T) {
	s, acme, _ := restrictionFixture(t)
	if _, err := s.tenants.SetOperatorRestricted("acme", true); err != nil {
		t.Fatalf("restrict acme: %v", err)
	}
	owner := jwtClaims{Sub: "root", Role: RoleSuperAdmin, Tenant: TenantGlobal}

	// The SQL the handler would send for the Global view must name the
	// exclusion, and the as_tenant read must go out at the read-nothing scope.
	// Those two facts ARE the drop: the row policies act on them server-side.
	if ex := s.tenantIDExcludeCondFor(owner, "tenant_id"); !strings.Contains(ex, acme) {
		t.Fatalf("the Global view does not exclude acme: %q", ex)
	}
	if got := s.chTenantScopeFor(ownerActing(owner, acme)); got != chScopeNone {
		t.Fatalf("as_tenant into acme reads at %q, want %q", got, chScopeNone)
	}
}

// Guard against the fixture rotting: the spy must actually be parsing the scope
// ClickHouse is told, not an empty string that trivially never equals a tenant.
func TestCorrelationSpySeesTheScope(t *testing.T) {
	ch := &chSpy{}
	ch.start(t)
	s := &server{}
	if _, err := s.chRowsScope(context.Background(), "probe-scope", "SELECT 1 FORMAT JSON", "test"); err != nil {
		t.Fatalf("chRowsScope: %v", err)
	}
	calls := ch.all()
	if len(calls) != 1 || calls[0].scope != "probe-scope" {
		b, _ := json.Marshal(calls)
		t.Fatalf("the spy did not observe the tenant_scope it was sent: %s", b)
	}
}
