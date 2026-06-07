package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/alerts"
	"netops/backend/models"
)

// HTTP-boundary multitenancy tests — exercise the real handlers (not just the
// pure tenancy helpers) with a tenant-scoped principal in the request context,
// asserting that the API never leaks one tenant's resources to another. This is
// the "Tenant A can never see Tenant B's data" guarantee, end to end.

func tenantServer(t *testing.T) *server {
	t.Helper()
	d := NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex"})
	d.Upsert(models.Device{ID: "shared-dns", Name: "shared-dns", Address: "10.9.0.1"}) // global/untagged (platform-owned)
	sv, err := newSavedStore(t.TempDir() + "/saved.json")
	if err != nil {
		t.Fatalf("savedStore: %v", err)
	}
	// Device/rule handlers now enforce RBAC (SR-003) via s.roles — seed the
	// built-in role store so requirePerm resolves.
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	return &server{discovery: d, saved: sv, roles: roles}
}

// req builds a request whose context carries the given principal's claims, as
// the auth middleware would have populated it.
func req(method, path, body string, claims jwtClaims) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, claims))
}

func acme() jwtClaims   { return jwtClaims{Sub: "a@acme", Role: RoleOperator, Tenant: "acme"} }
func globex() jwtClaims { return jwtClaims{Sub: "g@globex", Role: RoleOperator, Tenant: "globex"} }
func superA() jwtClaims { return jwtClaims{Sub: "root", Role: RoleSuperAdmin} }

func TestHTTPDevicesTenantScoped(t *testing.T) {
	s := tenantServer(t)

	// acme sees only its own — never globex, never the global/untagged device.
	w := httptest.NewRecorder()
	s.handleDevices(w, req("GET", "/api/devices", "", acme()))
	var devs []models.Device
	json.NewDecoder(w.Body).Decode(&devs)
	ids := map[string]bool{}
	for _, d := range devs {
		ids[d.ID] = true
	}
	if !ids["acme-core"] {
		t.Error("acme should see its own device")
	}
	if ids["shared-dns"] {
		t.Error("strict isolation: acme must NOT see the global/untagged device")
	}
	if ids["globex-core"] {
		t.Fatal("TENANT LEAK: acme saw globex-core via GET /api/devices")
	}

	// Super-admin sees everything.
	w = httptest.NewRecorder()
	s.handleDevices(w, req("GET", "/api/devices", "", superA()))
	json.NewDecoder(w.Body).Decode(&devs)
	if len(devs) != 3 {
		t.Errorf("super-admin should see all 3 devices, got %d", len(devs))
	}
}

func TestHTTPDeviceByIDCrossTenantIs404(t *testing.T) {
	s := tenantServer(t)
	// acme fetching globex's device by id must 404 (not 403 — don't confirm it
	// exists in another tenant).
	w := httptest.NewRecorder()
	s.handleDeviceByID(w, req("GET", "/api/devices/globex-core", "", acme()))
	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant GET-by-id should be 404, got %d", w.Code)
	}
	// Its own device resolves fine.
	w = httptest.NewRecorder()
	s.handleDeviceByID(w, req("GET", "/api/devices/acme-core", "", acme()))
	if w.Code != http.StatusOK {
		t.Errorf("own device should be 200, got %d", w.Code)
	}
}

func TestHTTPDevicePOSTForcedIntoOwnTenant(t *testing.T) {
	s := tenantServer(t)
	// A scoped principal cannot plant a device into another tenant — the server
	// overrides tenant_id with the caller's.
	w := httptest.NewRecorder()
	s.handleDevices(w, req("POST", "/api/devices", `{"id":"x1","tenant_id":"globex"}`, acme()))
	if w.Code != http.StatusCreated {
		t.Fatalf("create should succeed, got %d", w.Code)
	}
	var d models.Device
	json.NewDecoder(w.Body).Decode(&d)
	if d.TenantID != "acme" {
		t.Errorf("scoped create must be forced into caller's tenant, got %q", d.TenantID)
	}
}

func TestHTTPDeviceDeleteCrossTenantIs404(t *testing.T) {
	s := tenantServer(t)
	w := httptest.NewRecorder()
	s.handleDeviceByID(w, req("DELETE", "/api/devices/globex-core", "", acme()))
	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant delete should be 404, got %d", w.Code)
	}
	// globex-core must still exist.
	if _, ok := s.discovery.Get("globex-core"); !ok {
		t.Fatal("TENANT LEAK: acme deleted globex-core")
	}
}

func readonly() jwtClaims {
	return jwtClaims{Sub: "ro@acme", Role: RoleReadOnly, Tenant: "acme"}
}

// SR-003: device mutations require infrastructure:write — a read-only principal
// (authenticated) must be refused, not silently allowed by the auth-only chain.
func TestHTTPDeviceWriteRequiresPermission(t *testing.T) {
	s := tenantServer(t)

	// read-only POST → 403, and no device is created.
	w := httptest.NewRecorder()
	s.handleDevices(w, req("POST", "/api/devices", `{"id":"ro1"}`, readonly()))
	if w.Code != http.StatusForbidden {
		t.Errorf("read-only create should be 403, got %d", w.Code)
	}
	if _, ok := s.discovery.Get("ro1"); ok {
		t.Fatal("read-only principal created a device despite 403")
	}

	// read-only DELETE of an existing device → 403, device survives.
	w = httptest.NewRecorder()
	s.handleDeviceByID(w, req("DELETE", "/api/devices/acme-core", "", readonly()))
	if w.Code != http.StatusForbidden {
		t.Errorf("read-only delete should be 403, got %d", w.Code)
	}
	if _, ok := s.discovery.Get("acme-core"); !ok {
		t.Fatal("read-only principal deleted a device despite 403")
	}

	// operator (infrastructure:write) DELETE of its own device → 204.
	w = httptest.NewRecorder()
	s.handleDeviceByID(w, req("DELETE", "/api/devices/acme-core", "", acme()))
	if w.Code != http.StatusNoContent {
		t.Errorf("operator delete of own device should be 204, got %d", w.Code)
	}
}

// SR-004: alert rules are platform-global; a scoped tenant must neither read nor
// write them. Only the platform owner (cross-tenant super-admin) may.
func TestHTTPRulesPlatformOwnerOnly(t *testing.T) {
	s := tenantServer(t)
	s.alerts = alerts.NewEngine("", nil)

	// tenant operator GET → 403.
	w := httptest.NewRecorder()
	s.handleRules(w, req("GET", "/api/rules", "", acme()))
	if w.Code != http.StatusForbidden {
		t.Errorf("tenant GET /api/rules should be 403, got %d", w.Code)
	}

	// tenant operator POST → 403, no rule added.
	w = httptest.NewRecorder()
	s.handleRules(w, req("POST", "/api/rules", `{"name":"x","expr":"up==0"}`, acme()))
	if w.Code != http.StatusForbidden {
		t.Errorf("tenant POST /api/rules should be 403, got %d", w.Code)
	}

	// platform owner GET → 200.
	w = httptest.NewRecorder()
	s.handleRules(w, req("GET", "/api/rules", "", superA()))
	if w.Code != http.StatusOK {
		t.Errorf("platform owner GET /api/rules should be 200, got %d", w.Code)
	}
}

// SR-002: a tenant holding reports:write must not be able to run another tenant's
// report (which would deliver to the victim tenant's channels). Cross-tenant
// run-now → 404, before any render/delivery.
func TestHTTPReportRunNowCrossTenantIs404(t *testing.T) {
	s := tenantServer(t)

	// acme owns a report saved object.
	w := httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"report","name":"acme rpt","body":{}}`, acme()))
	if w.Code != http.StatusCreated {
		t.Fatalf("acme create report: %d", w.Code)
	}
	var obj SavedObject
	json.NewDecoder(w.Body).Decode(&obj)

	// A globex TENANT super-admin (reports:write, but scoped to globex — not the
	// cross-tenant platform owner) tries to run acme's report → 404. reportPipeline
	// and reports are nil here; the ownership gate returns 404 BEFORE either is
	// touched, which is exactly the property under test.
	globexAdmin := jwtClaims{Sub: "admin@globex", Role: RoleSuperAdmin, Tenant: "globex"}
	w = httptest.NewRecorder()
	s.handleReportRunNow(w, req("POST", "/api/reports/run", `{"id":"`+obj.ID+`"}`, globexAdmin))
	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant report run-now should be 404, got %d", w.Code)
	}
}

func TestHTTPSavedObjectsTenantScoped(t *testing.T) {
	s := tenantServer(t)
	// acme creates a saved search.
	w := httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"saved_search","name":"acme q","body":{}}`, acme()))
	if w.Code != http.StatusCreated {
		t.Fatalf("acme create saved: %d", w.Code)
	}
	var obj SavedObject
	json.NewDecoder(w.Body).Decode(&obj)
	if obj.TenantID != "acme" {
		t.Errorf("saved object should be stamped acme, got %q", obj.TenantID)
	}

	// globex must NOT see it in the list.
	w = httptest.NewRecorder()
	s.handleSaved(w, req("GET", "/api/saved", "", globex()))
	var list []SavedObject
	json.NewDecoder(w.Body).Decode(&list)
	for _, o := range list {
		if o.ID == obj.ID {
			t.Fatal("TENANT LEAK: globex saw acme's saved object in the list")
		}
	}

	// globex fetching it by id → 404.
	w = httptest.NewRecorder()
	s.handleSavedByID(w, req("GET", "/api/saved/"+obj.ID, "", globex()))
	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant saved GET-by-id should be 404, got %d", w.Code)
	}

	// globex deleting it → 404, and it survives.
	w = httptest.NewRecorder()
	s.handleSavedByID(w, req("DELETE", "/api/saved/"+obj.ID, "", globex()))
	if w.Code != http.StatusNotFound {
		t.Errorf("cross-tenant saved delete should be 404, got %d", w.Code)
	}
	if _, ok := s.saved.Get(obj.ID); !ok {
		t.Fatal("TENANT LEAK: globex deleted acme's saved object")
	}
}
