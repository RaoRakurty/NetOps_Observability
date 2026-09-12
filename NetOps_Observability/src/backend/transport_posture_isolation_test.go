// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// transport_posture_isolation_test.go — §3a.5 isolation + gate coverage for the
// SEC-021.1 transport-posture surface, through the real router + auth
// middleware (org_isolation_test.go is the template; this surface is an
// aggregate view, so the per-id 404 assertions become platform-row gate
// assertions: the platform table and validator report must be invisible to a
// tenant admin, and the export must refuse everything below the platform
// identity).

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/secobs"
)

func repoInventory(t *testing.T) *secobs.Inventory {
	t.Helper()
	inv, err := secobs.LoadInventory(filepath.Join("..", "..", "docs", "security", "transport-inventory.yaml"))
	if err != nil {
		t.Fatalf("load repo inventory: %v", err)
	}
	return inv
}

type postureResp struct {
	Scope       string           `json:"scope"`
	Rows        []map[string]any `json:"rows"`
	Validator   *json.RawMessage `json:"validator"`
	DeviceLanes []map[string]any `json:"device_lanes"`
	DeviceCount *int             `json:"device_count"`
}

func TestTransportPostureIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.transportInv = repoInventory(t)

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two orgs, each: org → tenant → tenant ADMIN (holds administration:admin —
	// the §3a.3 privilege-leak candidate this test exists to pin).
	type fx struct{ tenantID, token string }
	mk := func(name string) fx {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org: %d %s", st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		tenantID := idOf(t, b)
		user := "padm-" + name
		if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
		}); st != 201 {
			t.Fatalf("create user: %d %s", st, b)
		}
		return fx{tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := mk("A"), mk("B")

	// Fleet: A registers two devices, B one — the tenant-scoped signal.
	mkDev := func(token, name, addr string) {
		if st, body := do(t, srv, "POST", "/api/devices", token, map[string]any{
			"id": name, "name": name, "address": addr,
		}); st != 200 && st != 201 {
			t.Fatalf("create device %s: %d %s", name, st, body)
		}
	}
	mkDev(a.token, "dev-a1", "203.0.113.11")
	mkDev(a.token, "dev-a2", "203.0.113.12")
	mkDev(b.token, "dev-b1", "203.0.113.21")

	get := func(token, path string) (int, postureResp, []byte) {
		st, body := do(t, srv, "GET", path, token, nil)
		var pr postureResp
		_ = json.Unmarshal(body, &pr)
		return st, pr, body
	}

	// 1) Tenant admin gets the TENANT scope: device lanes + own count only.
	st, pr, body := get(a.token, "/api/security/transport-posture")
	if st != 200 || pr.Scope != "tenant" {
		t.Fatalf("tenant admin: %d scope=%q (%s)", st, pr.Scope, body)
	}
	if pr.DeviceCount == nil || *pr.DeviceCount != 2 {
		t.Fatalf("tenant A device_count = %v, want 2", pr.DeviceCount)
	}
	if len(pr.DeviceLanes) == 0 {
		t.Fatalf("tenant view must include the device lanes")
	}
	// §3a.3 gate: the platform table and validator must be ABSENT.
	if pr.Rows != nil || pr.Validator != nil {
		t.Fatalf("tenant admin received platform rows/validator — privilege leak: %s", body)
	}
	for _, lane := range pr.DeviceLanes {
		if td, _ := lane["trust_domain"].(string); td != "device" {
			t.Fatalf("tenant view leaked non-device edge: %v", lane)
		}
	}

	// 2) Tenant B sees ITS count (1), not A's.
	if _, prB, _ := get(b.token, "/api/security/transport-posture"); prB.DeviceCount == nil {
		t.Fatalf("tenant B device_count missing")
	} else if *prB.DeviceCount != 1 {
		t.Fatalf("tenant B device_count = %d, want 1", *prB.DeviceCount)
	}

	// 3) as_tenant into the other org is ignored for a tenant admin.
	if _, prX, _ := get(a.token, "/api/security/transport-posture?as_tenant="+b.tenantID); prX.DeviceCount == nil || *prX.DeviceCount != 2 {
		t.Fatalf("as_tenant leak: A saw count %v under B's tenant id, want own 2", prX.DeviceCount)
	}

	// 4) The platform owner gets the full table + validator.
	st, prAdm, _ := get(admin, "/api/security/transport-posture")
	if st != 200 || prAdm.Scope != "platform" {
		t.Fatalf("platform admin: %d scope=%q", st, prAdm.Scope)
	}
	if len(prAdm.Rows) < 30 || prAdm.Validator == nil {
		t.Fatalf("platform view incomplete: %d rows, validator=%v", len(prAdm.Rows), prAdm.Validator != nil)
	}

	// 5) Below administration:admin → refused outright.
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "viewer-x", "password": "Passw0rd!2345", "role": "viewer", "tenant_id": a.tenantID,
	}); st != 201 {
		t.Fatalf("create viewer: %d %s", st, b)
	}
	viewer := login(t, srv, "viewer-x", "Passw0rd!2345").Token
	if st, _, _ := get(viewer, "/api/security/transport-posture"); st != 403 {
		t.Fatalf("viewer GET posture: %d, want 403", st)
	}

	// 6) Export is platform-only: tenant admin refused, owner succeeds, and the
	// artifact carries both required sections.
	if st, _ := do(t, srv, "GET", "/api/security/transport-posture/export", a.token, nil); st != 403 {
		t.Fatalf("tenant admin export: %d, want 403", st)
	}
	st, artifact := do(t, srv, "GET", "/api/security/transport-posture/export", admin, nil)
	if st != 200 {
		t.Fatalf("platform export: %d %s", st, artifact)
	}
	html := string(artifact)
	for _, want := range []string{"Correlix-owned paths", "Device lanes", "declared exception"} {
		if !strings.Contains(html, want) {
			t.Fatalf("export missing %q", want)
		}
	}

	// 7) The export left a tenant-scoped audit trail with the SEC-020.1 event
	// type (and the trail is invisible to the tenant admin's audit view).
	st, auditBody := do(t, srv, "GET", "/api/audit", admin, nil)
	if st != 200 {
		t.Fatalf("audit list: %d", st)
	}
	if !strings.Contains(string(auditBody), secobs.SecEventPostureExport) {
		t.Fatalf("audit trail missing %s event: %s", secobs.SecEventPostureExport, auditBody)
	}
	st, auditTenant := do(t, srv, "GET", "/api/audit", a.token, nil)
	if st == 200 && strings.Contains(string(auditTenant), secobs.SecEventPostureExport) {
		t.Fatalf("tenant admin can see the platform export audit event — cross-tenant audit leak")
	}
}

func TestTransportPostureInventoryUnavailable(t *testing.T) {
	srv, _ := newTestServerState(t) // transportInv deliberately left nil
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	if st, b := do(t, srv, "GET", "/api/security/transport-posture", admin, nil); st != 503 {
		t.Fatalf("posture without inventory: %d %s, want 503 (never an empty table)", st, b)
	}
	if st, _ := do(t, srv, "GET", "/api/security/transport-posture/export", admin, nil); st != 503 {
		t.Fatalf("export without inventory: want 503")
	}
}
