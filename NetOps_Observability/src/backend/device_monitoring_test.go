package backend

// device_monitoring_test.go — the C4 rule: a device consumes one Community
// entitlement when Correlix is CONFIGURED TO MONITOR it, and discovery costs
// nothing.
//
// internal/devmon proves the policy and internal/discovery proves the state
// machine. What only exists HERE, in the wiring, is:
//
//  1. the route is reachable through the real device dispatcher and takes the
//     real permission gates;
//  2. the transition is enforced SERVER-SIDE — a client that hides no button
//     still cannot monitor device 26;
//  3. the count is tenant-scoped, so one tenant filling the ceiling cannot be
//     seen by, or block the view of, another;
//  4. the whole sequence in the owner's definition of done runs end to end.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/internal/discovery"
	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
	"netops/backend/models"
)

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

// monServer builds the minimum server able to serve the device routes and the
// monitoring switch, under the entitlement service `ent` (nil = no ceiling).
//
// The Deps come from devmonDeps(), the SAME function the composition root uses:
// a test-only Deps literal is how a gate ends up proven in a fixture and absent
// in production.
func monServer(t *testing.T, ent *licence.Service, devs ...models.Device) *server {
	t.Helper()
	roles, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	d := discovery.NewDiscoveryAggregator()
	for _, dev := range devs {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("seed %s: %v", dev.ID, err)
		}
	}
	s := &server{roles: roles, discovery: d, entitlements: ent}
	if ent != nil {
		d.SetMonitorGate(func(current int) error {
			return entitlement.CheckCeiling(ent, entitlement.CeilingDevices, current)
		})
	}
	s.devmonAPI = devmon.New(s.devmonDeps())
	return s
}

// monDeclared is a device an operator (or their source of truth) DECLARED:
// monitored by default.
func monDeclared(i int) models.Device {
	return models.Device{
		ID: "dev-" + strconv.Itoa(i), Name: "dev-" + strconv.Itoa(i),
		Address: fmt.Sprintf("10.20.%d.%d", i/250, i%250), Source: "manual",
	}
}

// monDiscovered is a device the subnet SCAN found: a candidate, not monitored.
func monDiscovered(i int) models.Device {
	return models.Device{
		ID: "scan-" + strconv.Itoa(i), Name: "scan-" + strconv.Itoa(i),
		Address: fmt.Sprintf("10.30.%d.%d", i/250, i%250), Source: "snmp",
	}
}

// monSet drives the REAL device dispatcher (handleDeviceByID → the monitoring
// route), so the dispatch in main.go is under test too, not just the module.
func monSet(t *testing.T, s *server, id string, enabled bool, c jwtClaims) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"enabled":` + strconv.FormatBool(enabled) + `}`
	w := httptest.NewRecorder()
	s.handleDeviceByID(w, licReq(http.MethodPut, "/api/devices/"+id+"/monitoring", body, c))
	return w
}

func monGet(t *testing.T, s *server, id string, c jwtClaims) (*httptest.ResponseRecorder, devmon.View) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleDeviceByID(w, licReq(http.MethodGet, "/api/devices/"+id+"/monitoring", "", c))
	var v devmon.View
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatalf("decode monitoring view: %v (%s)", err, w.Body.String())
		}
	}
	return w, v
}

func monMustSet(t *testing.T, s *server, id string, enabled bool) {
	t.Helper()
	if w := monSet(t, s, id, enabled, licClaims()); w.Code != http.StatusOK {
		t.Fatalf("set monitoring %s=%v: %d %s", id, enabled, w.Code, w.Body.String())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The unit: monitored devices, not inventory rows
// ─────────────────────────────────────────────────────────────────────────────

// TestMonitoredUnitIsNotTheInventoryRow is the product decision itself. A
// hundred discovered devices are a hundred inventory rows and zero entitlements.
func TestMonitoredUnitIsNotTheInventoryRow(t *testing.T) {
	k := newLicTestKey(t)
	var fleet []models.Device
	for i := 0; i < 100; i++ {
		fleet = append(fleet, monDiscovered(i))
	}
	s := monServer(t, k.service(t, nil), fleet...)

	if got := len(s.discovery.Devices()); got != 100 {
		t.Fatalf("inventory = %d, want 100 — discovery is never refused", got)
	}
	if got := s.discovery.MonitoredCount(); got != 0 {
		t.Fatalf("monitored = %d, want 0 — a discovered row is a candidate, not a monitored device", got)
	}
	if got := s.licenceUsage(t.Context())[entitlement.CeilingDevices]; got != 0 {
		t.Fatalf("licence usage = %d, want 0 — the bar must count what is monitored", got)
	}

	t.Run("enabling twelve spends exactly twelve", func(t *testing.T) {
		for i := 0; i < 12; i++ {
			monMustSet(t, s, "scan-"+strconv.Itoa(i), true)
		}
		if got := s.licenceUsage(t.Context())[entitlement.CeilingDevices]; got != 12 {
			t.Fatalf("licence usage = %d, want 12 of 25", got)
		}
		if got := len(s.discovery.Devices()); got != 100 {
			t.Fatalf("the inventory must be untouched, got %d", got)
		}
	})
}

// TestMonitoredCountsTheDeviceNotTheCollectors pins the "several methods, one
// device" rule and the release on the LAST one.
func TestMonitoredCountsTheDeviceNotTheCollectors(t *testing.T) {
	k := newLicTestKey(t)
	dev := monDiscovered(1)
	s := monServer(t, k.service(t, nil), dev)

	monMustSet(t, s, dev.ID, true)
	if got := s.discovery.MonitoredCount(); got != 1 {
		t.Fatalf("the first enabled method counts one device, got %d", got)
	}

	t.Run("a second telemetry method adds no entitlement", func(t *testing.T) {
		// SNMP credentials AND a gNMI subscription on the same box.
		with := dev
		with.CredentialRef = "lab-v2c"
		with.Labels = map[string]string{"gnmi": "true"}
		if err := s.discovery.Upsert(with); err != nil {
			t.Fatal(err)
		}
		if got := s.discovery.MonitoredCount(); got != 1 {
			t.Fatalf("monitored = %d, want 1 — the unit is the device", got)
		}
		_, v := monGet(t, s, dev.ID, licClaims())
		if len(v.Methods) != 2 {
			t.Fatalf("both methods must be VISIBLE even though they cost one entitlement: %v", v.Methods)
		}
	})

	t.Run("removing one of two methods keeps the device counted", func(t *testing.T) {
		back := dev
		back.CredentialRef = "lab-v2c" // gnmi label dropped
		if err := s.discovery.Upsert(back); err != nil {
			t.Fatal(err)
		}
		if got := s.discovery.MonitoredCount(); got != 1 {
			t.Fatalf("monitored = %d, want 1 — one method is still monitoring", got)
		}
	})

	t.Run("turning monitoring off releases the entitlement", func(t *testing.T) {
		monMustSet(t, s, dev.ID, false)
		if got := s.discovery.MonitoredCount(); got != 0 {
			t.Fatalf("monitored = %d, want 0", got)
		}
		if got := len(s.discovery.Devices()); got != 1 {
			t.Fatalf("the device itself must stay in the inventory, got %d", got)
		}
	})
}

// TestMonitoredSurvivesUnreachability: the entitlement tracks CONFIGURED
// INTENT, not reachability. A device that stopped answering days ago is still
// being monitored — we are still trying — and freeing its licence on an outage
// would hand a customer capacity exactly when their network is broken.
func TestMonitoredSurvivesUnreachability(t *testing.T) {
	k := newLicTestKey(t)
	dead := monDeclared(1)
	dead.LastSeen = time.Now().Add(-30 * 24 * time.Hour)
	s := monServer(t, k.service(t, nil), dead)

	if got := s.discovery.MonitoredCount(); got != 1 {
		t.Fatalf("monitored = %d, want 1 — an unreachable device is still configured for monitoring", got)
	}
	_, v := monGet(t, s, dead.ID, licClaims())
	if !v.Monitored {
		t.Fatalf("the view must agree: %+v", v)
	}
}

// TestMonitoredReleasedOnDelete: deleting a monitored device frees its
// entitlement, and a device recreated later does not inherit the decision.
func TestMonitoredReleasedOnDelete(t *testing.T) {
	k := newLicTestKey(t)
	dev := monDiscovered(7)
	s := monServer(t, k.service(t, nil), dev)
	monMustSet(t, s, dev.ID, true)
	if got := s.discovery.MonitoredCount(); got != 1 {
		t.Fatalf("monitored = %d, want 1", got)
	}
	if err := s.discovery.Delete(dev.ID); err != nil {
		t.Fatal(err)
	}
	if got := s.discovery.MonitoredCount(); got != 0 {
		t.Fatalf("monitored = %d, want 0 after the device was deleted", got)
	}
	if _, ok := s.discovery.MonitoringDecision(dev.ID); ok {
		t.Fatal("the decision must die with the device — a recreated id must not inherit it")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The ceiling, enforced at the transition
// ─────────────────────────────────────────────────────────────────────────────

// TestMonitoringCeilingAtTheTransition is the owner's definition of done:
// discover far past the ceiling, enable 25, be refused the 26th, and still be
// free to add telemetry to a device that is already counted.
func TestMonitoringCeilingAtTheTransition(t *testing.T) {
	k := newLicTestKey(t)
	var fleet []models.Device
	for i := 0; i < 500; i++ {
		fleet = append(fleet, monDiscovered(i))
	}
	s := monServer(t, k.service(t, nil), fleet...) // Community: 25

	if got := s.discovery.MonitoredCount(); got != 0 {
		t.Fatalf("500 discovered devices must cost nothing, got %d", got)
	}
	for i := 0; i < 25; i++ {
		monMustSet(t, s, "scan-"+strconv.Itoa(i), true)
	}
	if got := s.discovery.MonitoredCount(); got != 25 {
		t.Fatalf("monitored = %d, want 25", got)
	}

	t.Run("the 26th is refused, with a body a card can render", func(t *testing.T) {
		w := monSet(t, s, "scan-25", true, licClaims())
		licAssertRefusal(t, w, entitlement.KindCeiling, entitlement.CeilingDevices, entitlement.TierTeam)
		var body struct {
			Unit    string `json:"unit"`
			Current int    `json:"current"`
			Limit   int    `json:"limit"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Unit != entitlement.UnitMonitoredDevices {
			t.Fatalf("unit = %q, want %q — a client must never render this as a limit on inventory rows",
				body.Unit, entitlement.UnitMonitoredDevices)
		}
		if body.Current != 25 || body.Limit != 25 {
			t.Fatalf("current/limit = %d/%d, want 25/25", body.Current, body.Limit)
		}
		if got := s.discovery.MonitoredCount(); got != 25 {
			t.Fatalf("a refused activation must change nothing, monitored = %d", got)
		}
	})

	t.Run("the refused device is still fully usable", func(t *testing.T) {
		// The cap is on monitoring, not on seeing: the device, its inventory
		// row and its history stay exactly where they were.
		w, v := monGet(t, s, "scan-25", licClaims())
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d %s", w.Code, w.Body.String())
		}
		if v.Monitored {
			t.Fatal("the refused device must not read as monitored")
		}
		if strings.TrimSpace(v.Reason) == "" {
			t.Fatal("every state must say why it is the state")
		}
		if _, ok := s.discovery.Get("scan-25"); !ok {
			t.Fatal("the device must still be in the inventory")
		}
	})

	t.Run("a device already counted may add telemetry", func(t *testing.T) {
		with := monDiscovered(0)
		with.CredentialRef = "lab-v2c"
		with.Labels = map[string]string{"gnmi": "true"}
		if err := s.discovery.Upsert(with); err != nil {
			t.Fatalf("adding a method to a counted device must be allowed: %v", err)
		}
		if got := s.discovery.MonitoredCount(); got != 25 {
			t.Fatalf("monitored = %d, want 25 — still the same 25 devices", got)
		}
	})

	t.Run("turning one off makes room for another", func(t *testing.T) {
		monMustSet(t, s, "scan-0", false)
		if got := s.discovery.MonitoredCount(); got != 24 {
			t.Fatalf("monitored = %d, want 24", got)
		}
		monMustSet(t, s, "scan-25", true)
		if got := s.discovery.MonitoredCount(); got != 25 {
			t.Fatalf("monitored = %d, want 25", got)
		}
	})
}

// TestMonitoringCeilingIsServerSide: the refusal does not depend on the SPA
// hiding a control. The API is driven directly, with a platform-owner token.
func TestMonitoringCeilingIsServerSide(t *testing.T) {
	k := newLicTestKey(t)
	var fleet []models.Device
	for i := 0; i < 25; i++ {
		fleet = append(fleet, monDeclared(i))
	}
	fleet = append(fleet, monDiscovered(99))
	s := monServer(t, k.service(t, nil), fleet...)

	w := monSet(t, s, "scan-99", true, licClaims())
	if w.Code != entitlement.StatusLicence {
		t.Fatalf("status = %d, want 402 — the ceiling must be enforced by the server, not by the UI: %s",
			w.Code, w.Body.String())
	}
}

// TestMonitoringCeilingIgnoresClientSuppliedState: a create that claims to be
// monitored is stamped by the server, never trusted from the body.
func TestMonitoringCeilingIgnoresClientSuppliedState(t *testing.T) {
	k := newLicTestKey(t)
	s := monServer(t, k.service(t, nil))
	w := httptest.NewRecorder()
	// A device with NO address cannot be collected from; claiming `monitored`
	// must not make it so.
	s.handleDevices(w, licReq(http.MethodPost, "/api/devices",
		`{"id":"claimer","name":"claimer","monitored":true,"monitor_reason":"trust me"}`, licClaims()))
	if w.Code != http.StatusCreated {
		t.Fatalf("create = %d %s", w.Code, w.Body.String())
	}
	if got := s.discovery.MonitoredCount(); got != 0 {
		t.Fatalf("monitored = %d, want 0 — monitoring is server state, never request input", got)
	}
	d, ok := s.discovery.Get("claimer")
	if !ok {
		t.Fatal("the device must exist")
	}
	if d.Monitored || d.MonitorReason == "trust me" {
		t.Fatalf("the client's claim must be discarded: %+v", d)
	}
}

// TestMonitoringPaidTierIsNotCappedAtCommunity: the Community number is never
// applied to a licensed deployment.
func TestMonitoringPaidTierIsNotCappedAtCommunity(t *testing.T) {
	k := newLicTestKey(t)
	var fleet []models.Device
	for i := 0; i < 25; i++ {
		fleet = append(fleet, monDeclared(i))
	}
	fleet = append(fleet, monDiscovered(1))
	s := monServer(t, k.service(t, k.issue(t, entitlement.TierTeam, nil, nil)), fleet...)

	if w := monSet(t, s, "scan-1", true, licClaims()); w.Code != http.StatusOK {
		t.Fatalf("a Team licence covers 250 monitored devices: %d %s", w.Code, w.Body.String())
	}
	if got := s.discovery.MonitoredCount(); got != 26 {
		t.Fatalf("monitored = %d, want 26", got)
	}
}

// TestMonitoringConcurrentActivationsCannotExceedTheCeiling. Twenty goroutines
// race for the last slot; exactly one may win.
//
// This is the failure the check-then-write shape produces: two callers both see
// 24 of 25, both decide there is room, and the deployment ends up at 26. The
// registry answers it by taking the capacity question and the write in one hold
// of its lock.
func TestMonitoringConcurrentActivationsCannotExceedTheCeiling(t *testing.T) {
	k := newLicTestKey(t)
	var fleet []models.Device
	for i := 0; i < 24; i++ {
		fleet = append(fleet, monDeclared(i))
	}
	const racers = 20
	for i := 0; i < racers; i++ {
		fleet = append(fleet, monDiscovered(i))
	}
	s := monServer(t, k.service(t, nil), fleet...)
	if got := s.discovery.MonitoredCount(); got != 24 {
		t.Fatalf("monitored = %d, want 24 (one slot left)", got)
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := s.discovery.SetMonitoring("scan-"+strconv.Itoa(i), true, "racer"); err == nil {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if won != 1 {
		t.Fatalf("%d activations succeeded, want exactly 1 — the last slot may be taken once", won)
	}
	if got := s.discovery.MonitoredCount(); got != 25 {
		t.Fatalf("monitored = %d, want 25 — the ceiling must hold under concurrency", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Tenant isolation (CLAUDE.md §3a rule 5 — required with the feature)
// ─────────────────────────────────────────────────────────────────────────────

// TestMonitoringCrossOrgIsolation: the count is per tenant, and one tenant can
// neither see nor change another's monitoring.
func TestMonitoringCrossOrgIsolation(t *testing.T) {
	k := newLicTestKey(t)
	fleet := []models.Device{
		{ID: "acme-1", Name: "acme-1", Address: "10.1.0.1", Source: "manual", TenantID: "acme"},
		{ID: "acme-2", Name: "acme-2", Address: "10.1.0.2", Source: "manual", TenantID: "acme"},
		{ID: "globex-1", Name: "globex-1", Address: "10.2.0.1", Source: "manual", TenantID: "globex"},
		{ID: "platform-1", Name: "platform-1", Address: "10.3.0.1", Source: "manual"},
	}
	s := monServer(t, k.service(t, nil), fleet...)
	acme := licTenantAdminOfClaims("acme")
	globex := licTenantAdminOfClaims("globex")

	t.Run("a tenant may read its own device", func(t *testing.T) {
		w, v := monGet(t, s, "acme-1", acme)
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d %s", w.Code, w.Body.String())
		}
		if !v.Monitored {
			t.Fatalf("acme-1 is a declared device and must read as monitored: %+v", v)
		}
	})

	t.Run("another tenant's device is 404, never 403", func(t *testing.T) {
		w, _ := monGet(t, s, "globex-1", acme)
		if w.Code != http.StatusNotFound {
			t.Fatalf("GET = %d, want 404 — a 403 would confirm the id exists elsewhere", w.Code)
		}
		if w := monSet(t, s, "globex-1", false, acme); w.Code != http.StatusNotFound {
			t.Fatalf("PUT = %d, want 404", w.Code)
		}
		if !mustDevice(t, s, "globex-1").Monitored {
			t.Fatal("a cross-tenant write must not have taken effect")
		}
	})

	t.Run("a platform-owned device is nobody's tenant business", func(t *testing.T) {
		if w, _ := monGet(t, s, "platform-1", acme); w.Code != http.StatusNotFound {
			t.Fatalf("GET = %d, want 404", w.Code)
		}
		if w, _ := monGet(t, s, "platform-1", globex); w.Code != http.StatusNotFound {
			t.Fatalf("GET = %d, want 404", w.Code)
		}
	})

	t.Run("usage is counted per tenant", func(t *testing.T) {
		u, _ := s.licenceTenantUsage(t.Context(), "acme")
		if got := u[entitlement.CeilingDevices]; got != 2 {
			t.Fatalf("acme counts %d monitored devices, want its own 2 — never the platform total", got)
		}
		u, _ = s.licenceTenantUsage(t.Context(), "globex")
		if got := u[entitlement.CeilingDevices]; got != 1 {
			t.Fatalf("globex counts %d, want 1", got)
		}
		u, _ = s.licenceTenantUsage(t.Context(), "initech")
		if got := u[entitlement.CeilingDevices]; got != 0 {
			t.Fatalf("a tenant with nothing counts %d, want a MEASURED zero", got)
		}
	})

	t.Run("one tenant turning monitoring off does not move another's number", func(t *testing.T) {
		if w := monSet(t, s, "acme-1", false, acme); w.Code != http.StatusOK {
			t.Fatalf("PUT = %d %s", w.Code, w.Body.String())
		}
		u, _ := s.licenceTenantUsage(t.Context(), "acme")
		if got := u[entitlement.CeilingDevices]; got != 1 {
			t.Fatalf("acme = %d, want 1", got)
		}
		u, _ = s.licenceTenantUsage(t.Context(), "globex")
		if got := u[entitlement.CeilingDevices]; got != 1 {
			t.Fatalf("globex = %d, want 1 — unchanged", got)
		}
	})
}

func mustDevice(t *testing.T, s *server, id string) models.Device {
	t.Helper()
	d, ok := s.discovery.Get(id)
	if !ok {
		t.Fatalf("device %s not found", id)
	}
	return d
}

// ─────────────────────────────────────────────────────────────────────────────
// The route itself
// ─────────────────────────────────────────────────────────────────────────────

func TestMonitoringRouteContract(t *testing.T) {
	k := newLicTestKey(t)
	s := monServer(t, k.service(t, nil), monDeclared(1))

	t.Run("an unknown device is 404", func(t *testing.T) {
		if w, _ := monGet(t, s, "nope", licClaims()); w.Code != http.StatusNotFound {
			t.Fatalf("GET = %d, want 404", w.Code)
		}
	})

	t.Run("a body without a decision is refused", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleDeviceByID(w, licReq(http.MethodPut, "/api/devices/dev-1/monitoring", `{}`, licClaims()))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("PUT {} = %d, want 400 — a missing field must never be read as 'stop collecting'", w.Code)
		}
		if !mustDevice(t, s, "dev-1").Monitored {
			t.Fatal("the device must still be monitored")
		}
	})

	t.Run("only GET and PUT", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleDeviceByID(w, licReq(http.MethodDelete, "/api/devices/dev-1/monitoring", "", licClaims()))
		if w.Code != http.StatusMethodNotAllowed {
			t.Fatalf("DELETE = %d, want 405", w.Code)
		}
		if got := w.Header().Get("Allow"); got != "GET, PUT" {
			t.Fatalf("Allow = %q", got)
		}
	})

	t.Run("the decision is recorded with who made it", func(t *testing.T) {
		monMustSet(t, s, "dev-1", false)
		_, v := monGet(t, s, "dev-1", licClaims())
		if !v.Decided {
			t.Fatal("an explicit decision must be reported as one, not as a default")
		}
		if v.DecidedBy == "" || v.DecidedAt.IsZero() {
			t.Fatalf("the decision must carry its author and time: %+v", v)
		}
		if v.Monitored {
			t.Fatal("the device must read as not monitored")
		}
	})
}
