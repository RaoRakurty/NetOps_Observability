package main

// wireless_isolation_test.go — cross-tenant isolation for the wireless
// canonical inventory (tracker #128 Phase 1), MANDATORY per CLAUDE.md §3a.5,
// modelled on org_isolation_test.go: exercised through the REAL router + auth
// middleware, the way the running system behaves. Two orgs (A, B), each with
// one tenant and one tenant-scoped operator; assertions:
//
//   - own-only list: A's operator lists ONLY A's controllers/APs/WLANs/BSSIDs
//   - cross-tenant get by id → 404 (never 403 — B's ids must not be revealed)
//   - the platform owner (cross-tenant) sees both
//   - unauthenticated → 401
//
// The store-level guarantee is exercised too: the mem store is tenant-keyed
// (no unscoped list exists), mirroring the PG store's FORCE-RLS withTenant.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/wireless"
)

func seedWirelessTenant(t *testing.T, s *server, tenant, tag string) (apID, wlcID string) {
	t.Helper()
	ctx := context.Background()
	wlcID = wireless.ControllerID(tenant, "cisco", "10.0.0.1-"+tag)
	if err := s.wireless.UpsertController(ctx, wireless.Controller{
		TenantID: tenant, ControllerID: wlcID, Name: "wlc-" + tag, Vendor: "cisco",
		ClusterRole: wireless.ClusterHAPair,
		Members: []wireless.Member{{
			MemberID: wireless.MemberID(tenant, wlcID, "SER-"+tag, ""), ControllerID: wlcID,
			Name: "wlc-" + tag + "-1", MemberState: "active", RedundancyRole: "primary",
		}},
	}); err != nil {
		t.Fatalf("seed controller %s: %v", tag, err)
	}
	apID = wireless.APID(tenant, "cisco", "APSER-"+tag, "")
	if err := s.wireless.UpsertAP(ctx, wireless.AccessPoint{
		TenantID: tenant, APID: apID, Name: "ap-" + tag, Serial: "APSER-" + tag,
		Vendor: "cisco", ControllerRef: wlcID,
		UplinkSwitchRef: "sw-" + tag, UplinkPortRef: "Gi1/0/1",
		Radios: []wireless.Radio{{APID: apID, Slot: 0, Band: "5GHz", OperState: "up"}},
	}); err != nil {
		t.Fatalf("seed ap %s: %v", tag, err)
	}
	if err := s.wireless.UpsertWLAN(ctx, wireless.WLAN{
		TenantID: tenant, WLANID: wireless.WLANID(tenant, wlcID, "corp"),
		ProfileName: "corp", SSIDName: "corp-" + tag, ControllerRef: wlcID,
		SecurityMode: "wpa2_enterprise", AuthMethod: "dot1x", Enabled: true,
	}); err != nil {
		t.Fatalf("seed wlan %s: %v", tag, err)
	}
	if err := s.wireless.UpsertBSSID(ctx, wireless.BSSID{
		TenantID: tenant, BSSID: "aa:bb:cc:00:00:0" + tag[len(tag)-1:],
		APRef: apID, RadioRef: wireless.RadioID(apID, 0),
	}); err != nil {
		t.Fatalf("seed bssid %s: %v", tag, err)
	}
	return apID, wlcID
}

func TestWirelessCrossTenantIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two orgs, each: org → tenant → tenant-scoped operator.
	type fixture struct{ tenantID, token, apID, wlcID string }
	fix := map[string]*fixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "WOrg " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "WTenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "wuser-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		f := &fixture{tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
		f.apID, f.wlcID = seedWirelessTenant(t, s, tenantID, "t"+name)
		fix[name] = f
	}
	a, b := fix["A"], fix["B"]

	// Own-only list, on every surface. Paths are LITERALS (not built) so the
	// isolation-coverage scanner (route_isolation_coverage_test.go) can prove
	// each scoped route is exercised.
	surfaces := []string{
		"/api/wireless/controllers",
		"/api/wireless/aps",
		"/api/wireless/wlans",
		"/api/wireless/bssids",
	}
	for _, surface := range surfaces {
		st, body := do(t, srv, "GET", surface, a.token, nil)
		if st != 200 {
			t.Fatalf("list %s as A: %d %s", surface, st, body)
		}
		var rows []map[string]any
		if err := json.Unmarshal(body, &rows); err != nil {
			t.Fatalf("list %s: bad json %s", surface, body)
		}
		if len(rows) != 1 {
			t.Fatalf("list %s as A: want exactly 1 own row, got %d (%s)", surface, len(rows), body)
		}
		// No row may carry B's identifiers.
		blob, _ := json.Marshal(rows)
		for _, leaked := range []string{b.apID, b.wlcID, "tB"} {
			if leaked != "" && strings.Contains(string(blob), leaked) {
				t.Fatalf("list %s as A leaked B's %q: %s", surface, leaked, blob)
			}
		}
	}

	// Cross-tenant get by id → 404 (never 403, never the row).
	if st, body := do(t, srv, "GET", "/api/wireless/aps/"+b.apID, a.token, nil); st != 404 {
		t.Fatalf("A getting B's AP: want 404, got %d %s", st, body)
	}
	if st, body := do(t, srv, "GET", "/api/wireless/controllers/"+b.wlcID, a.token, nil); st != 404 {
		t.Fatalf("A getting B's controller: want 404, got %d %s", st, body)
	}
	// Own get works.
	if st, body := do(t, srv, "GET", "/api/wireless/aps/"+a.apID, a.token, nil); st != 200 {
		t.Fatalf("A getting own AP: want 200, got %d %s", st, body)
	}

	// The platform owner sees both tenants' rows.
	st, body := do(t, srv, "GET", "/api/wireless/aps", admin, nil)
	if st != 200 {
		t.Fatalf("admin list aps: %d %s", st, body)
	}
	var all []map[string]any
	if err := json.Unmarshal(body, &all); err != nil || len(all) != 2 {
		t.Fatalf("admin list aps: want 2 rows, got %d (%s)", len(all), body)
	}

	// Unauthenticated → 401.
	if st, _ := do(t, srv, "GET", "/api/wireless/aps", "", nil); st != 401 {
		t.Fatalf("unauthenticated list: want 401, got %d", st)
	}
}
