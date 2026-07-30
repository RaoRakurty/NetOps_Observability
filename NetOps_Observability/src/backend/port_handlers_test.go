package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/portintel"
)

// port_handlers_test.go — Port Intelligence API shape, pagination + tenant
// isolation (#94 P5, §3a.5). Uses the in-memory portStore seeded with two
// tenants' ports; a scoped caller sees only its own, a cross-tenant get of a
// foreign port → 404.

func portTestServer(t *testing.T) *server {
	t.Helper()
	dir := t.TempDir()
	rs, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	ms := portintel.NewMemStore()
	_ = ms.UpsertPort(context.Background(), portintel.PortRow{TenantID: "t-a", DeviceID: "leaf1", PortID: "leaf1:Et1", IfName: "Ethernet1", OperStatus: "up", Seam: "DIA", MediaType: "singlemode_fiber", HealthScore: 100, HealthState: "ok"})
	_ = ms.UpsertPort(context.Background(), portintel.PortRow{TenantID: "t-a", DeviceID: "leaf1", PortID: "leaf1:Et2", IfName: "Ethernet2", OperStatus: "down", HealthScore: 55, HealthState: "degraded", MatchedSig: "sig.ent.spdc.mpo-polarity-mismatch"})
	_ = ms.UpsertPort(context.Background(), portintel.PortRow{TenantID: "t-b", DeviceID: "leafX", PortID: "leafX:Et9", IfName: "Ethernet9", OperStatus: "up", HealthScore: 100, HealthState: "ok"})
	return &server{roles: rs, portStore: ms}
}

func portReq(c jwtClaims, method, path string) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	return r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
}

var (
	viewerA = jwtClaims{Role: "viewer", Tenant: "t-a", Sub: "ua"}
	viewerB = jwtClaims{Role: "viewer", Tenant: "t-b", Sub: "ub"}
	ownerX  = jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal, Sub: "root"}
)

func TestPortInterfacesTenantScoped(t *testing.T) {
	s := portTestServer(t)
	w := httptest.NewRecorder()
	s.handlePortInterfaces(w, portReq(viewerA, "GET", "/api/infrastructure/interfaces"))
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Interfaces []portintel.PortRow `json:"interfaces"`
		Total      int                 `json:"total"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Total != 2 {
		t.Fatalf("tenant A must see its 2 ports, got %d", resp.Total)
	}
	for _, p := range resp.Interfaces {
		if p.DeviceID == "leafX" {
			t.Fatal("LEAK: tenant A saw tenant B's port")
		}
	}
	// Cross-tenant owner sees all three.
	w2 := httptest.NewRecorder()
	s.handlePortInterfaces(w2, portReq(ownerX, "GET", "/api/infrastructure/interfaces"))
	var all struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &all)
	if all.Total != 3 {
		t.Fatalf("platform owner must see all 3, got %d", all.Total)
	}
}

func TestPortInterfacesFilterAndPaginate(t *testing.T) {
	s := portTestServer(t)
	// Filter: rca_attached=true → only the mpo-polarity port.
	w := httptest.NewRecorder()
	s.handlePortInterfaces(w, portReq(viewerA, "GET", "/api/infrastructure/interfaces?rca_attached=true"))
	var r struct {
		Interfaces []portintel.PortRow `json:"interfaces"`
		Total      int                 `json:"total"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &r)
	if r.Total != 1 || r.Interfaces[0].MatchedSig == "" {
		t.Fatalf("rca_attached filter wrong: %+v", r)
	}
	// Pagination: limit=1 returns 1 row but total stays 2.
	w2 := httptest.NewRecorder()
	s.handlePortInterfaces(w2, portReq(viewerA, "GET", "/api/infrastructure/interfaces?limit=1"))
	var p struct {
		Interfaces []portintel.PortRow `json:"interfaces"`
		Total      int                 `json:"total"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &p)
	if len(p.Interfaces) != 1 || p.Total != 2 {
		t.Fatalf("pagination wrong: got %d rows total %d", len(p.Interfaces), p.Total)
	}
}

func TestPortDetailCrossTenant404(t *testing.T) {
	s := portTestServer(t)
	// Own port → 200.
	w := httptest.NewRecorder()
	s.handlePortInterfaceDetail(w, portReq(viewerA, "GET", "/api/infrastructure/interfaces/leaf1:Et1"))
	if w.Code != http.StatusOK {
		t.Fatalf("own port must be 200: %d", w.Code)
	}
	// Tenant B fetching tenant A's port → 404 (never reveal).
	w2 := httptest.NewRecorder()
	s.handlePortInterfaceDetail(w2, portReq(viewerB, "GET", "/api/infrastructure/interfaces/leaf1:Et1"))
	if w2.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant port must 404, got %d", w2.Code)
	}
}

func TestPortSummaryScoped(t *testing.T) {
	s := portTestServer(t)
	w := httptest.NewRecorder()
	s.handlePortSummary(w, portReq(viewerA, "GET", "/api/infrastructure/port-summary"))
	var r struct {
		Total   int            `json:"total_ports"`
		ByState map[string]int `json:"by_state"`
		RCA     int            `json:"rca_attached"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &r)
	if r.Total != 2 || r.ByState["degraded"] != 1 || r.RCA != 1 {
		t.Fatalf("summary wrong: %+v", r)
	}
}

func TestPortPathResolution(t *testing.T) {
	s := portTestServer(t)
	ms := s.portStore.(*portintel.MemStore)
	// A fiber path with leaf1:Et1 as the A endpoint → far side leafZ:Et5, + a neighbor.
	_ = ms.UpsertFiberPath(context.Background(), "t-a", portintel.FiberPath{
		PathID: "fp-1", ADevice: "leaf1", APort: "leaf1:Et1", ZDevice: "leafZ", ZPort: "leafZ:Et5",
		Circuit: "CID-9001", Provider: "Lumen", Polarity: "B", PanelID: "PP-3", Cassette: "C-12",
	})
	_ = ms.UpsertNeighbor(context.Background(), "t-a", "leaf1", "leaf1:Et1", "leafZ.dc", "Ethernet5")

	// Own endpoint → resolved with the far side + circuit + neighbor.
	w := httptest.NewRecorder()
	s.handlePortInterfaceDetail(w, portReq(viewerA, "GET", "/api/infrastructure/interfaces/leaf1:Et1/path"))
	if w.Code != http.StatusOK {
		t.Fatalf("path: %d %s", w.Code, w.Body.String())
	}
	var pc portintel.PathContext
	_ = json.Unmarshal(w.Body.Bytes(), &pc)
	if !pc.Resolved || pc.Circuit != "CID-9001" || pc.FarDevice != "leafZ" || pc.Neighbor != "leafZ.dc" {
		t.Fatalf("path resolution wrong: %+v", pc)
	}
	if pc.Port == nil || pc.Port.PortID != "leaf1:Et1" {
		t.Fatalf("path must include the port row: %+v", pc.Port)
	}

	// Tenant B resolving tenant A's endpoint → nothing (no cabling leak).
	w2 := httptest.NewRecorder()
	s.handlePortInterfaceDetail(w2, portReq(viewerB, "GET", "/api/infrastructure/interfaces/leaf1:Et1/path"))
	var pc2 portintel.PathContext
	_ = json.Unmarshal(w2.Body.Bytes(), &pc2)
	if pc2.Resolved || pc2.Port != nil {
		t.Fatalf("cross-tenant path must resolve to nothing: %+v", pc2)
	}
}

func TestModuleTypesAndSignatures(t *testing.T) {
	s := portTestServer(t)
	w := httptest.NewRecorder()
	s.handleModuleTypes(w, portReq(viewerA, "GET", "/api/infrastructure/module-types"))
	if w.Code != http.StatusOK || w.Body.Len() < 50 {
		t.Fatalf("module-types thin: %d %s", w.Code, w.Body.String())
	}
	w2 := httptest.NewRecorder()
	s.handlePortSignatureCatalog(w2, portReq(viewerA, "GET", "/api/infrastructure/port-signatures"))
	var sc struct {
		Signatures []map[string]any `json:"signatures"`
	}
	_ = json.Unmarshal(w2.Body.Bytes(), &sc)
	if len(sc.Signatures) != 23 {
		t.Fatalf("expected 23 SP/DC signatures, got %d", len(sc.Signatures))
	}
}
