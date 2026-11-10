// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// discovery_scope_isolation_test.go — §3a rule 5 for the tenant-owned discovery
// scans (/api/discovery/scopes), through the REAL router + auth middleware, on
// the org_isolation_test.go template: three orgs (A, B, C), each with one
// tenant, one tenant operator and one tenant ADMIN. A customer reads only its
// own scans; another customer's scan is the same 404 as a missing one on GET,
// PUT and DELETE; no customer — not even its own admin — can create or change a
// scan (platform owner only, owner decision D1); "view as" another org is
// ignored; the platform owner sees every scan and the Provider view sees only
// the platform's own; a scan created while viewing as A belongs to A whatever
// the body says.

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discoveryscope"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/snmpcred"
)

type discoveryScopeOrg struct {
	tenantID, opToken, adminToken, profileID, scopeID string
}

func TestDiscoveryScopeCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.discoveryScopes = discoveryscope.NewRegistry(discoveryscope.NewFileStore(filepath.Join(t.TempDir(), "discovery_scopes.json"), platformdb.FileKV{}))
	s.discoveryCfg = newDiscoveryConfigStore(filepath.Join(t.TempDir(), "discovery_config.json"), nil)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	fix := map[string]*discoveryScopeOrg{}
	for _, name := range []string{"A", "B", "C"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		f := &discoveryScopeOrg{tenantID: idOf(t, b)}
		for _, u := range []struct{ user, role string }{{"op-" + name, "operator"}, {"adm-" + name, "super-admin"}} {
			st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
				"username": u.user, "password": "Passw0rd!2345", "role": u.role, "tenant_id": f.tenantID,
			})
			if st != 201 {
				t.Fatalf("create user %s: %d %s", u.user, st, b)
			}
		}
		f.opToken = login(t, srv, "op-"+name, "Passw0rd!2345").Token
		f.adminToken = login(t, srv, "adm-"+name, "Passw0rd!2345").Token
		// The customer's own SNMP profile, created by the customer (the store
		// stamps the owner from the token).
		st, b = do(t, srv, "POST", "/api/snmp/credentials", f.opToken, map[string]any{"name": "edges " + name, "version": "v2c", "community": "c-" + name})
		if st != 201 {
			t.Fatalf("create profile %s: %d %s", name, st, b)
		}
		f.profileID = idOf(t, b)
		fix[name] = f
	}
	a, b, c := fix["A"], fix["B"], fix["C"]

	// A platform-owned profile exists too; a customer scan may never use it.
	plat, err := s.snmpCreds.Upsert(snmpcred.Credential{Name: "platform ro", Version: "v2c", Community: "plat"})
	if err != nil {
		t.Fatal(err)
	}

	// ── the platform owner creates one scan per customer ────────────────────
	for _, name := range []string{"A", "B", "C"} {
		f := fix[name]
		st, body := do(t, srv, "POST", "/api/discovery/scopes", admin, map[string]any{
			"tenant_id": f.tenantID, "name": "edges", "ranges": []string{"10.70." + map[string]string{"A": "1", "B": "2", "C": "3"}[name] + ".0/29"},
			"credential_refs": []string{f.profileID}, "enabled": true,
		})
		if st != 201 {
			t.Fatalf("owner create for %s: %d %s", name, st, body)
		}
		f.scopeID = idOf(t, body)
		if !strings.Contains(string(body), `"tenant_id":"`+f.tenantID+`"`) {
			t.Fatalf("scope for %s not stamped with its tenant: %s", name, body)
		}
	}

	listTenants := func(token, asTenant string) (owners []string, platform bool) {
		t.Helper()
		path := "/api/discovery/scopes"
		if asTenant != "" {
			path += "?as_tenant=" + asTenant
		}
		st, raw := do(t, srv, "GET", path, token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, raw)
		}
		var out struct {
			Scopes []struct {
				TenantID string `json:"tenant_id"`
			} `json:"scopes"`
			Platform json.RawMessage `json:"platform"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, raw)
		}
		for _, sc := range out.Scopes {
			owners = append(owners, sc.TenantID)
		}
		sort.Strings(owners)
		return owners, len(out.Platform) > 0
	}

	// 1) Each customer lists ONLY its own scan, and never the platform scan.
	for _, name := range []string{"A", "B", "C"} {
		f := fix[name]
		for _, tok := range []string{f.opToken, f.adminToken} {
			if got, plat := listTenants(tok, ""); len(got) != 1 || got[0] != f.tenantID || plat {
				t.Fatalf("org %s leak: lists %v (platform %v), want exactly [%s]", name, got, plat, f.tenantID)
			}
		}
	}

	// 2) The platform owner sees all three plus the platform scan; the Provider
	// view sees only the platform scan; viewing as A sees only A's.
	if got, plat := listTenants(admin, ""); len(got) != 3 || !plat {
		t.Fatalf("platform owner sees %v (platform %v), want 3 + platform", got, plat)
	}
	if got, plat := listTenants(admin, "global"); len(got) != 0 || !plat {
		t.Fatalf("Provider view sees %v (platform %v), want only the platform scan", got, plat)
	}
	if got, plat := listTenants(admin, a.tenantID); len(got) != 1 || got[0] != a.tenantID || plat {
		t.Fatalf("owner viewing as A sees %v (platform %v)", got, plat)
	}

	// 3) Another customer's scan by id: 404 on GET, PUT and DELETE — for the
	// operator AND the tenant admin, so no write can probe ids either.
	upd := map[string]any{"name": "pwned", "ranges": []string{"10.70.9.0/29"}, "enabled": true}
	for _, tok := range []string{a.opToken, a.adminToken} {
		for _, m := range []string{"GET", "PUT", "DELETE"} {
			if st, raw := do(t, srv, m, "/api/discovery/scopes/"+b.scopeID, tok, upd); st != 404 {
				t.Fatalf("A %s of B's scan: %d %s, want 404", m, st, raw)
			}
		}
	}

	// 4) "View as" another org is ignored for a customer: still A's view only,
	// and B's scan still 404 — by query and by header alike.
	if got, _ := listTenants(a.opToken, b.tenantID); len(got) != 1 || got[0] != a.tenantID {
		t.Fatalf("as_tenant into org B honoured for A: %v", got)
	}
	if st, _ := do(t, srv, "GET", "/api/discovery/scopes/"+b.scopeID+"?as_tenant="+b.tenantID, a.opToken, nil); st != 404 {
		t.Fatalf("A GET B's scan with as_tenant=B: %d, want 404", st)
	}
	req, err := http.NewRequest("GET", srv.URL+"/api/discovery/scopes/"+b.scopeID, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+a.opToken)
	req.Header.Set("X-Acting-Tenant", b.tenantID)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Fatalf("A GET B's scan with X-Acting-Tenant=B: %d, want 404", resp.StatusCode)
	}

	// 5) No customer creates or changes a scan — not even its own admin, not
	// even its own scan (403: the scan is visible to it, the write is not).
	for _, tok := range []string{a.opToken, a.adminToken} {
		if st, raw := do(t, srv, "POST", "/api/discovery/scopes", tok, map[string]any{
			"tenant_id": a.tenantID, "name": "mine", "ranges": []string{"10.70.8.0/29"}, "enabled": true,
		}); st != 403 {
			t.Fatalf("customer POST: %d %s, want 403", st, raw)
		}
		for _, m := range []string{"PUT", "DELETE"} {
			if st, _ := do(t, srv, m, "/api/discovery/scopes/"+a.scopeID, tok, upd); st != 403 {
				t.Fatalf("customer %s of its own scan: %d, want 403", m, st)
			}
		}
	}

	// 6) A scan created while viewing as A belongs to A, whatever the body says.
	st, raw := do(t, srv, "POST", "/api/discovery/scopes?as_tenant="+a.tenantID, admin, map[string]any{
		"tenant_id": b.tenantID, "name": "second", "ranges": []string{"10.70.4.0/29"}, "enabled": false,
	})
	if st != 201 || !strings.Contains(string(raw), `"tenant_id":"`+a.tenantID+`"`) {
		t.Fatalf("owner-as-A create with body tenant B: %d %s — must be stamped A", st, raw)
	}

	// 7) A customer scan never uses another owner's profile — B's, or the
	// platform's.
	for _, ref := range []string{b.profileID, plat.ID} {
		if st, raw := do(t, srv, "POST", "/api/discovery/scopes", admin, map[string]any{
			"tenant_id": a.tenantID, "name": "x", "ranges": []string{"10.70.5.0/29"}, "credential_refs": []string{ref},
		}); st != 400 {
			t.Fatalf("scan for A with profile %s: %d %s, want 400", ref, st, raw)
		}
	}

	// 8) Every scan survived the refused writes, with its owner.
	if got, _ := listTenants(admin, ""); len(got) != 4 {
		t.Fatalf("after refused writes the owner sees %v, want 4 scans", got)
	}
	if st, raw := do(t, srv, "GET", "/api/discovery/scopes/"+b.scopeID, b.opToken, nil); st != 200 || strings.Contains(string(raw), "pwned") {
		t.Fatalf("B's scan changed by another org: %d %s", st, raw)
	}

	// 9) The audit row is filed under the CUSTOMER, so its own trail shows the
	// platform pointed a scan at its network — and never under another org.
	evs, err := s.audit.List(a.tenantID, false, auditQuery{Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Detail["action"] == "discovery_scope_create" {
			if e.Detail["scope_tenant"] != a.tenantID {
				t.Fatalf("A's trail holds another customer's scan: %+v", e.Detail)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("A's audit trail must record the scan created for it")
	}

	// 10) The platform owner can remove a customer's scan; the scanner's view follows.
	if st, _ := do(t, srv, "DELETE", "/api/discovery/scopes/"+c.scopeID, admin, nil); st != 204 {
		t.Fatalf("owner delete: %d", st)
	}
	for _, sc := range s.discoveryScopes.Snapshot() {
		if sc.ID == c.scopeID {
			t.Fatal("the scanner still holds a deleted scan")
		}
	}
}

// TestPlatformScanPutHonoursTheSharedBudget: the platform scan is charged first
// against the ONE sweep budget, so widening it past the budget while customer
// scans are on would silently turn every customer's scan off at the next sweep.
// The platform PUT refuses that with the customer-scan API's own words.
func TestPlatformScanPutHonoursTheSharedBudget(t *testing.T) {
	srv, s := newTestServerState(t)
	ctx := context.Background()
	store := discoveryscope.NewFileStore(filepath.Join(t.TempDir(), "discovery_scopes.json"), platformdb.FileKV{})
	s.discoveryScopes = discoveryscope.NewRegistry(store)
	s.discoveryCfg = newDiscoveryConfigStore(filepath.Join(t.TempDir(), "discovery_config.json"), nil)
	at := time.Now().UTC()
	sc := discoveryscope.Scope{ID: "ds-00000000000000a1", TenantID: "t_retail", Name: "edges", Ranges: []string{"10.70.0.0/29"}, Enabled: true, CreatedAt: at, UpdatedAt: at}
	if err := store.Put(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if err := s.discoveryScopes.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	put := func(enabled bool, ranges ...string) (int, string) {
		st, b := do(t, srv, "PUT", "/api/discovery/config", admin, map[string]any{"enabled": enabled, "ranges": ranges})
		return st, string(b)
	}
	st, body := put(true, "10.80.0.0/20") // 4096 + the customer's 8
	if st != 400 || !strings.Contains(body, discoveryscope.BudgetError(4104).Error()) {
		t.Fatalf("a platform scan past the shared budget must be refused with the shared words: %d %s", st, body)
	}
	if cur := s.discoveryCfg.effective(); len(cur.Ranges) != 0 {
		t.Fatalf("a refused PUT must not be saved: %+v", cur)
	}
	if st, body := put(true, "10.80.0.0/21"); st != 200 {
		t.Fatalf("2048 + 8 fits: %d %s", st, body)
	}
	if st, body := put(false, "10.80.0.0/20"); st != 200 {
		t.Fatalf("a platform scan that is off charges nothing: %d %s", st, body)
	}
	// With the customer's scan off, the platform may use the whole budget.
	sc.Enabled = false
	if err := store.Put(ctx, sc); err != nil {
		t.Fatal(err)
	}
	if err := s.discoveryScopes.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if st, body := put(true, "10.80.0.0/20"); st != 200 {
		t.Fatalf("the whole budget is the platform's when no customer scan is on: %d %s", st, body)
	}
}
