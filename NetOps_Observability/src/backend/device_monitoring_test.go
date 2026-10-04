// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// device_monitoring_test.go — the owner's 2026-10-03 rule, end to end in the
// wiring: every inventory device with an address is monitored (whoever found
// it, a subnet scan included), up to the licence ceiling in first-seen order.
// The rest stay in the inventory, marked over the licence limit.
//
// internal/devmon proves the policy and internal/discovery proves the ledger.
// What only exists HERE, in the composition root, is:
//
//  1. the licence count and the collection ceiling come from the real licence
//     service — hard on Community, soft (no cut) on paid tiers;
//  2. the status route is reachable through the real device dispatcher, takes
//     the real permission gate, is read-only, and is honest when no collector
//     for a monitored device's methods is running;
//  3. §3a: a tenant sees only its own devices, its own over-limit devices and
//     its own count — never another tenant's, not even through ?as_tenant.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"netops/backend/collectors"
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
// monitoring status, under the entitlement service `ent`. The collection
// ceiling is the production closure (monitorCollectionLimit) and the Deps come
// from devmonDeps() — a test-only literal is how a gate ends up proven in a
// fixture and absent in production.
func monServer(t *testing.T, ent *licence.Service, devs ...models.Device) *server {
	t.Helper()
	roles, err := newRoleStore(filepath.Join(t.TempDir(), "roles.json"))
	if err != nil {
		t.Fatal(err)
	}
	d := discovery.NewDiscoveryAggregator()
	s := &server{roles: roles, discovery: d, entitlements: ent}
	d.SetMonitorLimit(s.monitorCollectionLimit)
	for _, dev := range devs {
		if err := d.Upsert(dev); err != nil {
			t.Fatalf("seed %s: %v", dev.ID, err)
		}
	}
	s.devmonAPI = devmon.New(s.devmonDeps())
	return s
}

// monDeclared is a device an operator created.
func monDeclared(i int) models.Device {
	return models.Device{
		ID: "dev-" + strconv.Itoa(i), Name: "dev-" + strconv.Itoa(i),
		Address: fmt.Sprintf("10.20.%d.%d", i/250, i%250), Source: "manual",
	}
}

// monScanned is a device the subnet SCAN found.
func monScanned(i int) models.Device {
	return models.Device{
		ID: "scan-" + strconv.Itoa(i), Name: "scan-" + strconv.Itoa(i),
		Address: fmt.Sprintf("10.30.%d.%d", i/250, i%250), Source: "snmp",
	}
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

func mustDevice(t *testing.T, s *server, id string) models.Device {
	t.Helper()
	d, ok := s.discovery.Get(id)
	if !ok {
		t.Fatalf("device %s not found", id)
	}
	return d
}

// ─────────────────────────────────────────────────────────────────────────────
// The licence count
// ─────────────────────────────────────────────────────────────────────────────

// TestScannedDevicesAreMonitoredAndCounted: a subnet scan's finds are
// monitored and consume the licence — there is no "discovery is free" any more.
func TestScannedDevicesAreMonitoredAndCounted(t *testing.T) {
	k := newLicTestKey(t)
	var fleet []models.Device
	for i := 0; i < 12; i++ {
		fleet = append(fleet, monScanned(i))
	}
	fleet = append(fleet, models.Device{ID: "noaddr", Name: "noaddr", Source: "manual"})
	s := monServer(t, k.service(t, nil), fleet...) // Community: 25

	if got := s.licenceUsage(t.Context())[entitlement.CeilingDevices]; got != 12 {
		t.Fatalf("licence usage = %d, want the 12 addressable devices", got)
	}
	if mustDevice(t, s, "noaddr").Monitored {
		t.Fatal("an addressless device is never monitored and never counted")
	}
}

// TestCommunityCeilingCollectsTheFirst25AndListsTheRest is the owner's
// definition of done for the hard ceiling.
func TestCommunityCeilingCollectsTheFirst25AndListsTheRest(t *testing.T) {
	k := newLicTestKey(t)
	var fleet []models.Device
	for i := 0; i < 37; i++ {
		fleet = append(fleet, monScanned(i))
	}
	s := monServer(t, k.service(t, nil), fleet...) // Community: 25, hard

	if got := len(s.discovery.Devices()); got != 37 {
		t.Fatalf("inventory = %d, want 37 — nothing is dropped", got)
	}
	if got := s.licenceUsage(t.Context())[entitlement.CeilingDevices]; got != 37 {
		t.Fatalf("licence usage = %d, want 37 — the bar counts every addressable device, collected or not", got)
	}
	if got := s.discovery.MonitoredCount(); got != 25 {
		t.Fatalf("collected = %d, want the first 25", got)
	}
	if got := s.discovery.MonitoringWithheldCount(); got != 12 {
		t.Fatalf("over the limit = %d, want 12", got)
	}
	// Seeded in order, so the first 25 seen are scan-0..scan-24.
	for i := 0; i < 37; i++ {
		d := mustDevice(t, s, "scan-"+strconv.Itoa(i))
		if want := i < 25; d.Monitored != want {
			t.Fatalf("scan-%d monitored = %v, want %v (first-seen order)", i, d.Monitored, want)
		}
		if i >= 25 && (d.MonitorState != devmon.StateOverLimit || d.MonitorLimit != 25) {
			t.Fatalf("scan-%d must be marked over the limit of 25: %+v", i, d)
		}
	}
	note := s.licenceUsageNotes(t.Context())[entitlement.CeilingDevices]
	if !strings.Contains(note, "12 more device(s)") || !strings.Contains(note, "licence limit of 25") {
		t.Fatalf("the licence page must say how many are not monitored and why: %q", note)
	}

	t.Run("a create past the ceiling is stored, never refused", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleDevices(w, licReq(http.MethodPost, "/api/devices",
			`{"id":"late","name":"late","address":"10.99.0.1"}`, licClaims()))
		if w.Code != http.StatusCreated {
			t.Fatalf("POST = %d %s — the licence never refuses a device", w.Code, w.Body.String())
		}
		var got models.Device
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.Monitored || got.MonitorState != devmon.StateOverLimit {
			t.Fatalf("the create must report the truth — over the limit: %+v", got)
		}
	})

	t.Run("deleting a monitored device promotes the next one", func(t *testing.T) {
		if err := s.discovery.Delete("scan-0"); err != nil {
			t.Fatal(err)
		}
		if !mustDevice(t, s, "scan-25").Monitored {
			t.Fatal("scan-25 is next in first-seen order and must now be collected from")
		}
		if got := s.discovery.MonitoredCount(); got != 25 {
			t.Fatalf("collected = %d, want 25", got)
		}
	})
}

// TestLicenceGrowthPromotesAndSoftTiersCutNothing: installing a bigger licence
// starts collection on the waiting devices with no operator action, and on a
// paid (soft) tier nothing is cut at all — the excess is recorded for true-up.
func TestLicenceGrowthPromotesAndSoftTiersCutNothing(t *testing.T) {
	k := newLicTestKey(t)
	var fleet []models.Device
	for i := 0; i < 30; i++ {
		fleet = append(fleet, monScanned(i))
	}
	team := k.service(t, k.issue(t, entitlement.TierTeam, nil, func(c *entitlement.Ceilings) { c.Devices = 20 }))
	s := monServer(t, team, fleet...)
	if got := s.discovery.MonitoredCount(); got != 30 {
		t.Fatalf("Team is a SOFT ceiling: monitored = %d, want all 30", got)
	}
	if got := s.discovery.MonitoringWithheldCount(); got != 0 {
		t.Fatalf("a soft ceiling withholds nothing, got %d", got)
	}
	if rows := s.licenceOverCeilingDevices(t.Context()); len(rows) != 10 {
		t.Fatalf("the 10 above the allowance are listed for true-up, got %d", len(rows))
	}

	// The same fleet under Community (hard 25), then a licence lifting it.
	community := monServer(t, k.service(t, nil), fleet...)
	if got := community.discovery.MonitoredCount(); got != 25 {
		t.Fatalf("precondition: Community collects 25, got %d", got)
	}
	community.entitlements = k.service(t, k.issue(t, entitlement.TierEnterprise, nil, nil))
	if got := community.discovery.MonitoredCount(); got != 30 {
		t.Fatalf("a licence that grows promotes the waiting devices at once: %d, want 30", got)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The status route
// ─────────────────────────────────────────────────────────────────────────────

func TestMonitoringStatusIsHonestAboutCollectors(t *testing.T) {
	k := newLicTestKey(t)
	s := monServer(t, k.service(t, nil), monScanned(1))

	t.Run("monitored, but no collector for its methods is running", func(t *testing.T) {
		// s.collectors is nil here: nothing is enabled.
		w, v := monGet(t, s, "scan-1", licClaims())
		if w.Code != http.StatusOK {
			t.Fatalf("GET = %d %s", w.Code, w.Body.String())
		}
		if !v.Monitored || v.Collecting {
			t.Fatalf("monitored but not collecting, got %+v", v)
		}
		if !strings.Contains(v.Reason, "no collector for snmp is enabled") {
			t.Fatalf("the status must say nothing is collected: %q", v.Reason)
		}
	})

	t.Run("monitored and its collector is running", func(t *testing.T) {
		pool := collectors.NewPool(func() []collectors.Target { return nil })
		pool.Enable("snmpv2c", true)
		s.collectors = pool
		s.devmonAPI = devmon.New(s.devmonDeps())
		_, v := monGet(t, s, "scan-1", licClaims())
		if !v.Collecting || len(v.CollectingMethods) != 1 || v.CollectingMethods[0] != devmon.MethodSNMP {
			t.Fatalf("SNMP collection is on: %+v", v)
		}
	})

	t.Run("there is no switch", func(t *testing.T) {
		w := httptest.NewRecorder()
		s.handleDeviceByID(w, licReq(http.MethodPut, "/api/devices/scan-1/monitoring", `{"enabled":false}`, licClaims()))
		if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet {
			t.Fatalf("PUT = %d Allow=%q, want 405 GET", w.Code, w.Header().Get("Allow"))
		}
		if !mustDevice(t, s, "scan-1").Monitored {
			t.Fatal("nothing may have changed")
		}
	})

	t.Run("an unknown device is 404", func(t *testing.T) {
		if w, _ := monGet(t, s, "nope", licClaims()); w.Code != http.StatusNotFound {
			t.Fatalf("GET = %d, want 404", w.Code)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Tenant isolation (CLAUDE.md §3a rule 5 — required with the feature)
// ─────────────────────────────────────────────────────────────────────────────

// TestMonitoringCrossOrgIsolation runs through the REAL router and auth
// middleware with two orgs, one tenant and one tenant-scoped operator each,
// under a platform-wide ceiling that leaves devices of BOTH tenants over the
// limit. It asserts own-only lists and counts, cross-tenant get/delete → 404,
// and that ?as_tenant into the other org is ignored.
func TestMonitoringCrossOrgIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	s.devmonAPI = devmon.New(s.devmonDeps())
	// Platform-wide ceiling of 2: the first two devices created are monitored.
	s.discovery.SetMonitorLimit(func() int { return 2 })
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	type org struct{ tenantID, token string }
	orgs := map[string]*org{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tenantID := idOf(t, b)
		user := "mon-user-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantID,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		orgs[name] = &org{tenantID: tenantID, token: login(t, srv, user, "Passw0rd!2345").Token}
	}
	a, b := orgs["A"], orgs["B"]

	// Interleaved creates: a-1, b-1 take the two slots; a-2, b-2 are over.
	// Each create carries the OTHER tenant in its body, which must be ignored.
	create := func(o *org, other *org, id, addr string) {
		t.Helper()
		st, body := do(t, srv, "POST", "/api/devices", o.token, map[string]any{
			"id": id, "name": id, "address": addr, "tenant_id": other.tenantID,
		})
		if st != 201 {
			t.Fatalf("create %s: %d %s", id, st, body)
		}
	}
	create(a, b, "a-1", "10.1.0.1")
	create(b, a, "b-1", "10.2.0.1")
	create(a, b, "a-2", "10.1.0.2")
	create(b, a, "b-2", "10.2.0.2")

	list := func(o *org, asTenant string) map[string]models.Device {
		t.Helper()
		path := "/api/devices"
		if asTenant != "" {
			path += "?as_tenant=" + asTenant
		}
		st, body := do(t, srv, "GET", path, o.token, nil)
		if st != 200 {
			t.Fatalf("GET %s: %d %s", path, st, body)
		}
		var devs []models.Device
		if err := json.Unmarshal(body, &devs); err != nil {
			t.Fatalf("decode devices: %v (%s)", err, body)
		}
		out := map[string]models.Device{}
		for _, d := range devs {
			out[d.ID] = d
		}
		return out
	}

	t.Run("own-only device list, with own over-limit rows only", func(t *testing.T) {
		got := list(a, "")
		if len(got) != 2 || got["a-1"].ID == "" || got["a-2"].ID == "" {
			t.Fatalf("A sees %v, want exactly a-1, a-2", got)
		}
		if !got["a-1"].Monitored || got["a-2"].MonitorState != devmon.StateOverLimit {
			t.Fatalf("A's states: %+v", got)
		}
		if got["a-1"].TenantID != a.tenantID {
			t.Fatalf("the owner is stamped from the token, never the body: %q", got["a-1"].TenantID)
		}
		over := s.discovery.MonitoringWithheldFor(a.tenantID, false)
		if len(over) != 1 || over[0].DeviceID != "a-2" {
			t.Fatalf("A's over-limit list = %+v, want only a-2", over)
		}
	})

	t.Run("?as_tenant into the other org is ignored", func(t *testing.T) {
		got := list(a, b.tenantID)
		if _, leaked := got["b-1"]; leaked || len(got) != 2 {
			t.Fatalf("A with ?as_tenant=B sees %v, want only its own", got)
		}
		st, _ := do(t, srv, "GET", "/api/devices/b-1/monitoring?as_tenant="+b.tenantID, a.token, nil)
		if st != 404 {
			t.Fatalf("A reading B's monitoring status via ?as_tenant: %d, want 404", st)
		}
	})

	t.Run("cross-tenant status, delete and switch attempts are refused", func(t *testing.T) {
		if st, _ := do(t, srv, "GET", "/api/devices/b-2/monitoring", a.token, nil); st != 404 {
			t.Fatalf("A GET B's status: %d, want 404", st)
		}
		if st, body := do(t, srv, "GET", "/api/devices/a-2/monitoring", a.token, nil); st != 200 ||
			!strings.Contains(string(body), devmon.StateOverLimit) {
			t.Fatalf("A GET own over-limit status: %d %s", st, body)
		}
		if st, _ := do(t, srv, "DELETE", "/api/devices/b-1", a.token, nil); st != 404 {
			t.Fatalf("A DELETE B's device: %d, want 404", st)
		}
		if st, _ := do(t, srv, "PUT", "/api/devices/b-1/monitoring", a.token, map[string]any{"enabled": false}); st == 200 {
			t.Fatal("there is no monitoring write, for anyone")
		}
		if got := list(b, ""); !got["b-1"].Monitored {
			t.Fatalf("B's device must be untouched: %+v", got["b-1"])
		}
	})

	t.Run("per-tenant counts never include the other tenant", func(t *testing.T) {
		ua, _ := s.licenceTenantUsage(t.Context(), a.tenantID)
		ub, _ := s.licenceTenantUsage(t.Context(), b.tenantID)
		if ua[entitlement.CeilingDevices] != 2 || ub[entitlement.CeilingDevices] != 2 {
			t.Fatalf("each tenant counts only its own two addressable devices: A=%d B=%d",
				ua[entitlement.CeilingDevices], ub[entitlement.CeilingDevices])
		}
	})

	t.Run("a freed slot goes to the next device in platform first-seen order", func(t *testing.T) {
		if st, body := do(t, srv, "DELETE", "/api/devices/a-1", a.token, nil); st != 204 && st != 200 {
			t.Fatalf("A DELETE own device: %d %s", st, body)
		}
		// a-2 was seen before b-2, so it is next in line.
		if !list(a, "")["a-2"].Monitored {
			t.Fatal("a-2 is next in first-seen order")
		}
		if list(b, "")["b-2"].Monitored {
			t.Fatal("b-2 is still over the limit")
		}
	})
}
