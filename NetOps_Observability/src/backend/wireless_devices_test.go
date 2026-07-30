package backend

// wireless_devices_test.go — the wireless→fleet projection (#128 follow-on):
// WLCs and APs appear in GET /api/devices as first-class rows (Type wlc/ap,
// Source wireless), tenant-scoped (§3a.5 — same two-org shape as
// wireless_isolation_test.go), and deduped against SNMP-discovered rows by
// management address so one box never shows twice.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/wireless"
)

func TestDevicesIncludeWirelessInventoryTenantScoped(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	type fixture struct{ tenantID, token, apID, wlcID string }
	fix := map[string]*fixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "WDOrg " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "WDTenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "wduser-" + name
		if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		f := &fixture{tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
		f.apID, f.wlcID = seedWirelessTenant(t, s, tenantID, "t"+name)
		fix[name] = f
	}
	a, b := fix["A"], fix["B"]

	// A's fleet: own WLC + AP present, typed and sourced; B's ids absent.
	st, body := do(t, srv, "GET", "/api/devices", a.token, nil)
	if st != 200 {
		t.Fatalf("GET /api/devices as A: %d %s", st, body)
	}
	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		t.Fatalf("devices: bad json %s", body)
	}
	byID := map[string]map[string]any{}
	for _, r := range rows {
		byID[r["id"].(string)] = r
	}
	wlcRow, ok := byID["wlc:"+a.wlcID]
	if !ok {
		t.Fatalf("A's controller missing from /api/devices (rows: %s)", body)
	}
	if wlcRow["type"] != "wlc" || wlcRow["source"] != "wireless" {
		t.Fatalf("controller row mis-typed: type=%v source=%v", wlcRow["type"], wlcRow["source"])
	}
	apRow, ok := byID["ap:"+a.apID]
	if !ok {
		t.Fatalf("A's AP missing from /api/devices (rows: %s)", body)
	}
	if apRow["type"] != "ap" || apRow["source"] != "wireless" {
		t.Fatalf("AP row mis-typed: type=%v source=%v", apRow["type"], apRow["source"])
	}
	// §3a: no row may carry B's identifiers.
	blob, _ := json.Marshal(rows)
	for _, leaked := range []string{b.apID, b.wlcID} {
		if strings.Contains(string(blob), leaked) {
			t.Fatalf("/api/devices as A leaked B's %q: %s", leaked, blob)
		}
	}

	// The platform owner sees both tenants' wireless rows.
	st, body = do(t, srv, "GET", "/api/devices", admin, nil)
	if st != 200 {
		t.Fatalf("GET /api/devices as admin: %d %s", st, body)
	}
	for _, want := range []string{"wlc:" + a.wlcID, "ap:" + a.apID, "wlc:" + b.wlcID, "ap:" + b.apID} {
		if !strings.Contains(string(body), want) {
			t.Fatalf("admin fleet missing %s", want)
		}
	}
}

// A controller that SNMP discovery already found (same management address)
// must not appear twice — the discovery row wins, the projection dedupes.
func TestWirelessProjectionDedupesByAddress(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	const addr = "10.99.88.77"
	if st, b := do(t, srv, "POST", "/api/devices", admin, map[string]any{
		"id": "wlc-snmp-1", "name": "wlc-snmp-1", "address": addr, "vendor": "cisco", "model": "Catalyst 9800-CL",
	}); st != 201 {
		t.Fatalf("create discovered device: %d %s", st, b)
	}
	ctx := context.Background()
	dupID := wireless.ControllerID(TenantGlobal, "cisco", addr)
	if err := s.wireless.UpsertController(ctx, wireless.Controller{
		TenantID: TenantGlobal, ControllerID: dupID, Name: "wlc-dup", Vendor: "cisco",
		ManagementAddress: addr, ClusterRole: wireless.ClusterStandalone,
	}); err != nil {
		t.Fatalf("seed duplicate controller: %v", err)
	}
	freshID := wireless.ControllerID(TenantGlobal, "cisco", "10.99.88.78")
	if err := s.wireless.UpsertController(ctx, wireless.Controller{
		TenantID: TenantGlobal, ControllerID: freshID, Name: "wlc-fresh", Vendor: "cisco",
		ManagementAddress: "10.99.88.78", ClusterRole: wireless.ClusterStandalone,
	}); err != nil {
		t.Fatalf("seed fresh controller: %v", err)
	}

	st, body := do(t, srv, "GET", "/api/devices", admin, nil)
	if st != 200 {
		t.Fatalf("GET /api/devices: %d %s", st, body)
	}
	if strings.Contains(string(body), "wlc:"+dupID) {
		t.Fatalf("projection duplicated an SNMP-discovered controller: %s", body)
	}
	if n := strings.Count(string(body), addr); n != 1 {
		t.Fatalf("address %s appears %d times, want exactly 1", addr, n)
	}
	if !strings.Contains(string(body), "wlc:"+freshID) {
		t.Fatalf("non-duplicate controller missing from fleet: %s", body)
	}
}
