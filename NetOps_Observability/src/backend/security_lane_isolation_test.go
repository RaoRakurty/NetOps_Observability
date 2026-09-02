package backend

// security_lane_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for
// the P3-EMIT producer lane's two operator surfaces, exercised through the REAL
// s.securityAuthz gate mapping (not a fake), because the gate CHOICE is half of
// what §3a rule 3 is about.
//
// Proven here:
//   - GET /api/security/lane/status is own-only for a tenant admin and
//     cross-tenant for the platform admin;
//   - a tenant admin never sees another tenant's row, id or segment;
//   - a read-only principal is refused (the surface is administration:write);
//   - POST /api/security/scan enqueues for the CALLER'S OWN tenant, answers 429
//     on overlap, and refuses a cross-tenant caller (400) rather than scanning
//     on someone else's behalf;
//   - with the flag off NOTHING is registered — the routes 404.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/discovery"
	"netops/backend/internal/seclane"
	"netops/backend/models"
	"netops/backend/secapi"
)

// secLaneServer builds the minimal server the lane's handlers need, with a lane
// whose transports are inert fakes (no bus, no OpenSearch, no ClickHouse).
func secLaneServer(t *testing.T) (*server, *seclane.Lane) {
	t.Helper()
	roles, err := newRoleStore(t.TempDir() + "/roles.json")
	if err != nil {
		t.Fatalf("roleStore: %v", err)
	}
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: "globex"})
	s := &server{roles: roles, discovery: d}
	s.secStore = secapi.NewFileStore("") // in-memory

	deps := s.securityLaneDeps()
	deps.Now = func() time.Time { return time.Date(2026, 9, 2, 4, 0, 0, 0, time.UTC) }
	deps.Tenants = func() []string { return []string{"acme", "globex"} }
	deps.Publish = func(context.Context, string, []seclane.Record) (int, error) { return 0, nil }
	deps.Search = func(string, string, any) (*http.Response, error) {
		return nil, context.Canceled // inert: the lane records it as degraded, never as clean
	}
	deps.CHQuery = func(context.Context, string, string) ([]map[string]any, error) { return nil, nil }
	deps.Seams = func(context.Context, string) ([]seclane.SeamRow, error) { return nil, nil }
	deps.Spool = nil

	lane, err := seclane.New(deps)
	if err != nil {
		t.Fatalf("seclane.New: %v", err)
	}
	s.securityLane = lane
	// One completed pass per tenant, so both status rows exist.
	lane.ScanAll(context.Background())
	return s, lane
}

type laneStatusBody struct {
	Enabled bool                 `json:"enabled"`
	Tenants []seclane.ScanStatus `json:"tenants"`
}

func TestSecurityLaneStatusIsOwnTenantOnly(t *testing.T) {
	s, _ := secLaneServer(t)

	w := httptest.NewRecorder()
	s.securityLane.HandleStatus(w, req(http.MethodGet, "/api/security/lane/status", "", tAdmin("acme")))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("TENANT LEAK: acme's lane status carried globex: %s", w.Body.String())
	}
	var body laneStatusBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Tenants) != 1 || body.Tenants[0].TenantID != "acme" {
		t.Fatalf("acme saw %+v, want exactly its own row", body.Tenants)
	}
}

func TestSecurityLaneStatusIsCrossTenantForThePlatformAdmin(t *testing.T) {
	s, _ := secLaneServer(t)

	w := httptest.NewRecorder()
	s.securityLane.HandleStatus(w, req(http.MethodGet, "/api/security/lane/status", "", platformOwner()))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	var body laneStatusBody
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Tenants) != 2 {
		t.Fatalf("the platform admin saw %d rows, want 2 (%s)", len(body.Tenants), w.Body.String())
	}
}

func TestSecurityLaneStatusAsTenantIsIgnoredForANonOwner(t *testing.T) {
	s, _ := secLaneServer(t)

	w := httptest.NewRecorder()
	s.securityLane.HandleStatus(w,
		req(http.MethodGet, "/api/security/lane/status?as_tenant=globex", "", tAdmin("acme")))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("TENANT LEAK: ?as_tenant let a tenant admin read another org: %s", w.Body.String())
	}
}

func TestSecurityLaneStatusRefusesAReadOnlyPrincipal(t *testing.T) {
	s, _ := secLaneServer(t)

	w := httptest.NewRecorder()
	s.securityLane.HandleStatus(w, req(http.MethodGet, "/api/security/lane/status", "", tViewer("acme")))
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only principal got %d, want 403", w.Code)
	}
}

func TestSecurityScanEnqueuesOwnTenantAnd429sOnOverlap(t *testing.T) {
	s, _ := secLaneServer(t)

	w := httptest.NewRecorder()
	s.securityLane.HandleScan(w, req(http.MethodPost, "/api/security/scan", "", tAdmin("acme")))
	if w.Code != http.StatusAccepted {
		t.Fatalf("first trigger = %d (%s), want 202", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"tenant_seg":"acme"`) {
		t.Fatalf("the accepted scan was not attributed to the caller's tenant: %s", w.Body.String())
	}

	w2 := httptest.NewRecorder()
	s.securityLane.HandleScan(w2, req(http.MethodPost, "/api/security/scan", "", tAdmin("acme")))
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("overlapping trigger = %d, want 429", w2.Code)
	}

	// Another tenant is unaffected — the bound is per tenant, not global.
	w3 := httptest.NewRecorder()
	s.securityLane.HandleScan(w3, req(http.MethodPost, "/api/security/scan", "", tAdmin("globex")))
	if w3.Code != http.StatusAccepted {
		t.Fatalf("globex trigger = %d, want 202 (acme's in-flight scan must not block it)", w3.Code)
	}
}

func TestSecurityScanRefusesACrossTenantCaller(t *testing.T) {
	s, _ := secLaneServer(t)

	w := httptest.NewRecorder()
	s.securityLane.HandleScan(w, req(http.MethodPost, "/api/security/scan", "", platformOwner()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross-tenant trigger = %d, want 400 — a scan writes tenant-attributed "+
			"evidence and must never run unattributed", w.Code)
	}
}

func TestSecurityScanRefusesAReadOnlyPrincipal(t *testing.T) {
	s, _ := secLaneServer(t)

	w := httptest.NewRecorder()
	s.securityLane.HandleScan(w, req(http.MethodPost, "/api/security/scan", "", tViewer("acme")))
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only principal got %d, want 403", w.Code)
	}
}

// ── the flag-off path registers nothing ─────────────────────────────────────

func TestSecurityLaneFlagIsOffByDefault(t *testing.T) {
	t.Setenv(seclane.EnvFeatureFlag, "")
	if envBool(seclane.EnvFeatureFlag) {
		t.Fatal("the security producer lane defaults to ON — it must be opt-in")
	}
	t.Setenv(seclane.EnvFeatureFlag, "false")
	if envBool(seclane.EnvFeatureFlag) {
		t.Fatal("FEATURE_SECURITY_LANE=false still enabled the lane")
	}
	t.Setenv(seclane.EnvFeatureFlag, "true")
	if !envBool(seclane.EnvFeatureFlag) {
		t.Fatal("FEATURE_SECURITY_LANE=true did not enable the lane")
	}
}

func TestSecurityLaneRoutesAreRegisteredOnlyWhenTheLaneIsOn(t *testing.T) {
	paths := []string{"/api/security/lane/status", "/api/security/scan"}

	off := http.NewServeMux()
	(&server{}).registerSecurityLaneRoutes(off) // nil lane == flag off
	for _, p := range paths {
		if _, pattern := off.Handler(httptest.NewRequest(http.MethodGet, p, nil)); pattern != "" {
			t.Fatalf("%s was registered with the lane OFF (pattern %q)", p, pattern)
		}
	}

	s, _ := secLaneServer(t)
	on := http.NewServeMux()
	s.registerSecurityLaneRoutes(on)
	for _, p := range paths {
		if _, pattern := on.Handler(httptest.NewRequest(http.MethodGet, p, nil)); pattern != p {
			t.Fatalf("%s was NOT registered with the lane on (pattern %q)", p, pattern)
		}
	}
}
