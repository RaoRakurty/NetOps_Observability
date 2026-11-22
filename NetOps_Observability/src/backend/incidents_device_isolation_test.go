// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// incidents_device_isolation_test.go — tracker 438: an incident says WHERE.
//
// An alert-born incident carries the firing alert's device id, stamped
// server-side; the operator's own POST body can never set it; and §3a holds: a
// device-stamped incident of tenant A is invisible to tenant B (own-only list,
// 404 by id, ?as_tenant ignored). The route path is written literally so the
// scoped-route coverage guard sees /api/incidents exercised.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/incident"
	"netops/backend/models"
)

func deviceIncidentFixture(t *testing.T) (*server, manualIncidentFixture, func(method, path, tok string, body any) (int, []byte)) {
	t.Helper()
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	orgA := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Where A"}, 201))
	orgB := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Where B"}, 201))
	f := manualIncidentFixture{
		tenantA: idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Where A", "org_id": orgA}, 201)),
		tenantB: idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Where B", "org_id": orgB}, 201)),
	}
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "where-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": f.tenantA}, 201)
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "where-b", "password": "Passw0rd!2345", "role": "operator", "tenant_id": f.tenantB}, 201)
	f.tokA = login(t, srv, "where-a", "Passw0rd!2345").Token
	f.tokB = login(t, srv, "where-b", "Passw0rd!2345").Token
	f.store = &manualIncidentStore{}
	s.incidents = f.store
	if err := s.discovery.Upsert(models.Device{ID: "edge-a-1f2e", Name: "edge-a", Address: "10.1.0.1", TenantID: f.tenantA}); err != nil {
		t.Fatal(err)
	}
	return s, f, func(method, path, tok string, body any) (int, []byte) { return do(t, srv, method, path, tok, body) }
}

func listIncidentRows(t *testing.T, b []byte) []Incident {
	t.Helper()
	var rows []Incident
	if err := json.Unmarshal(b, &rows); err == nil {
		return rows
	}
	var env struct {
		Incidents []Incident `json:"incidents"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		t.Fatalf("decode incident list: %v (%s)", err, truncBody(b))
	}
	return env.Incidents
}

func TestAlertIncidentCarriesTheFiringDevice(t *testing.T) {
	s, f, _ := deviceIncidentFixture(t)
	s.ingestAlertIncident(models.Alert{ID: "al-1", Rule: "InterfaceDown", Severity: "critical",
		DeviceID: "edge-a-1f2e", Summary: "Gi1 down", FiredAt: time.Now()})
	if len(f.store.rows) != 1 {
		t.Fatalf("want one incident, got %d", len(f.store.rows))
	}
	got := f.store.rows[0]
	if got.DeviceID != "edge-a-1f2e" {
		t.Fatalf("incident device = %q, want the firing alert's device", got.DeviceID)
	}
	if got.TenantID != f.tenantA {
		t.Fatalf("incident tenant = %q, want the device's tenant %q", got.TenantID, f.tenantA)
	}
}

func TestAlertIncidentWithoutADeviceStaysDeviceless(t *testing.T) {
	s, f, _ := deviceIncidentFixture(t)
	s.ingestAlertIncident(models.Alert{ID: "al-2", Rule: "StackDiskFull", Severity: "high", Summary: "disk", FiredAt: time.Now()})
	if len(f.store.rows) != 1 || f.store.rows[0].DeviceID != "" {
		t.Fatalf("a device-less alert must leave device_id empty: %+v", f.store.rows)
	}
}

func TestManualIncidentRefusesADeviceInTheBody(t *testing.T) {
	_, f, call := deviceIncidentFixture(t)
	st, b := call("POST", "/api/incidents", f.tokA, map[string]any{"title": "Branch is slow", "device_id": "edge-a-1f2e"})
	if st != http.StatusBadRequest {
		t.Fatalf("a device_id in the body = %d, want 400: %s", st, truncBody(b))
	}
	if !strings.Contains(string(b), "device_id") {
		t.Errorf("the 400 does not name device_id: %s", truncBody(b))
	}
	if len(f.store.rows) != 0 {
		t.Fatalf("a refused body still wrote %d incident(s)", len(f.store.rows))
	}
}

func TestDeviceIncidentIsInvisibleToAnotherTenant(t *testing.T) {
	s, f, call := deviceIncidentFixture(t)
	s.ingestAlertIncident(models.Alert{ID: "al-3", Rule: "BGPDown", Severity: "critical",
		DeviceID: "edge-a-1f2e", Summary: "peer down", FiredAt: time.Now()})
	inc := f.store.rows[0]

	if st, b := call("GET", "/api/incidents/"+inc.ID, f.tokB, nil); st != http.StatusNotFound {
		t.Fatalf("tenant B GET tenant A's device incident = %d, want 404: %s", st, truncBody(b))
	}
	for _, path := range []string{"/api/incidents?limit=500", "/api/incidents?limit=500&as_tenant=" + f.tenantA} {
		st, b := call("GET", path, f.tokB, nil)
		if st != http.StatusOK && st != http.StatusForbidden && st != http.StatusBadRequest {
			t.Fatalf("tenant B %s = %d: %s", path, st, truncBody(b))
		}
		if st != http.StatusOK {
			continue
		}
		if strings.Contains(string(b), "edge-a-1f2e") {
			t.Fatalf("CROSS-TENANT LEAK: tenant B's %s names tenant A's device: %s", path, truncBody(b))
		}
		for _, r := range listIncidentRows(t, b) {
			if r.TenantID != f.tenantB {
				t.Fatalf("CROSS-TENANT LEAK: tenant B received an incident owned by %q", r.TenantID)
			}
		}
	}
	// The owner sees WHERE on its own list.
	st, b := call("GET", "/api/incidents?limit=500", f.tokA, nil)
	if st != http.StatusOK {
		t.Fatalf("tenant A list = %d: %s", st, truncBody(b))
	}
	rows := listIncidentRows(t, b)
	if len(rows) != 1 || rows[0].DeviceID != "edge-a-1f2e" {
		t.Fatalf("tenant A's list does not carry the device: %+v", rows)
	}
}

func TestCleanDeviceIDDropsAnOversizedID(t *testing.T) {
	if got := incident.CleanDeviceID("  edge-1  "); got != "edge-1" {
		t.Errorf("CleanDeviceID trims: got %q", got)
	}
	if got := incident.CleanDeviceID(strings.Repeat("x", incident.MaxDeviceIDLen+1)); got != "" {
		t.Errorf("an id over the column limit must be dropped, got %d chars", len(got))
	}
}
