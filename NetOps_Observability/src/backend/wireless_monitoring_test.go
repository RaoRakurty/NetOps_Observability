// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// wireless_monitoring_test.go — tracker 256, owner decision 2026-09-05:
// "wireless controllers and APs count against the monitored-device entitlement
// when monitoring is intentionally enabled. Controller monitored → 1 device;
// AP monitored → 1 device (1 controller + 50 APs = 51)."
//
// What these tests pin is not a second counter — the point of the change is
// that there ISN'T one. Wireless entities an enabled integration polls are
// reported into the device registry by wireless.DeviceSource, and from there
// the SAME definition (internal/devmon), the SAME dedupe and the SAME ceiling
// gate that govern an SNMP or NetBox device govern them. So each test below
// asserts a fact about the ONE definition as seen through the wireless path:
//
//	51 = 1 + 50            the unit is the device, controller and AP alike
//	discovered-only = 0    a WLC an SNMP sweep found is a candidate, not a spend
//	disabled = 0           an integration nobody enabled polls nothing
//	SNMP + NMS = 1         one physical box is one entitlement
//	402 at 26              Community refuses the wireless activation, with unit
//	overage on paid        Team records it instead, and refuses nothing
//	tenant-scoped          identity never crosses a tenant boundary
//	metered identically    tracker 258 reads the same set, with no new code

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/devmon"
	"netops/backend/internal/entitlement"
	"netops/backend/internal/licence"
	"netops/backend/internal/metering"
	"netops/backend/models"
	"netops/backend/nms"
	"netops/backend/wireless"
)

// ─────────────────────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────────────────────

const (
	// wlTenant owns the wireless estate in these tests.
	wlTenant = "acme"
	// wlVendor is a connector that DECLARES wireless AP inventory
	// (nms/specs.go: catalyst_9800, CapAPInventory at doc_claimed). wlNoWiFi
	// declares none — enabling it must add no wireless devices and must not be
	// gated by the device ceiling.
	wlVendor = "catalyst_9800"
	wlNoWiFi = "vmanage"
)

// wlFix is a server able to answer the NMS integration routes and hold a
// wireless estate, plus the device source that joins the two.
type wlFix struct {
	s   *server
	src *wireless.DeviceSource
}

// newWLFix builds the fixture on top of monServer — the SAME harness the C4
// monitored-device tests use, so a wireless device is proven against the same
// registry, gate and dispatcher as every other device.
func newWLFix(t *testing.T, ent *licence.Service, seed ...models.Device) *wlFix {
	t.Helper()
	s := monServer(t, ent, seed...)
	s.wireless = wireless.NewMemStore()
	s.nms = newNMSRuntime(nms.NewMemStore())
	return &wlFix{s: s, src: wireless.NewDeviceSource(s.wireless, s.wirelessActiveTenants, time.Minute)}
}

// integration writes one integration record straight to the store (the
// scheduler's own view), for the tests that are about COUNTING rather than
// about the enable route.
func (f *wlFix) integration(t *testing.T, tenant, vendor string, enabled bool) {
	t.Helper()
	if err := f.s.nms.Store().Upsert(t.Context(), nms.Integration{
		Tenant: tenant, ID: "nmsi-" + vendor + "-" + tenant, Vendor: vendor,
		DisplayName: vendor, Enabled: enabled, PollIntervalS: 300,
	}); err != nil {
		t.Fatalf("seed integration: %v", err)
	}
}

// controller seeds one wireless controller.
func (f *wlFix) controller(t *testing.T, tenant, id, addr string) {
	t.Helper()
	if err := f.s.wireless.UpsertController(t.Context(), wireless.Controller{
		TenantID: tenant, ControllerID: id, Name: id, Vendor: "cisco",
		Model: "C9800-40", ManagementAddress: addr,
	}); err != nil {
		t.Fatalf("seed controller %s: %v", id, err)
	}
}

// aps seeds n access points bound to a controller.
func (f *wlFix) aps(t *testing.T, tenant, ctrlID string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		id := ctrlID + "-ap-" + strconv.Itoa(i)
		if err := f.s.wireless.UpsertAP(t.Context(), wireless.AccessPoint{
			TenantID: tenant, APID: id, Name: id, Vendor: "cisco", Model: "C9130",
			ControllerRef: ctrlID,
			MgmtAddress:   "10.44." + strconv.Itoa(i/250) + "." + strconv.Itoa(i%250),
		}); err != nil {
			t.Fatalf("seed ap %s: %v", id, err)
		}
	}
}

// poll runs one cycle of the wireless source into the registry.
func (f *wlFix) poll(t *testing.T) {
	t.Helper()
	f.s.discovery.PollOnceForTest(t.Context(), f.src)
}

func (f *wlFix) monitored() int { return f.s.discovery.MonitoredCount() }

// ─────────────────────────────────────────────────────────────────────────────
// The unit: a controller is one device and every AP is one device
// ─────────────────────────────────────────────────────────────────────────────

// TestWirelessControllerAndAPsEachCountOneDevice is the owner's arithmetic:
// 1 controller + 50 APs = 51 monitored devices.
func TestWirelessControllerAndAPsEachCountOneDevice(t *testing.T) {
	k := newLicTestKey(t)
	// Enterprise: the arithmetic is the subject here, not the ceiling.
	f := newWLFix(t, k.service(t, k.issue(t, entitlement.TierEnterprise, nil, nil)))
	f.integration(t, wlTenant, wlVendor, true)
	f.controller(t, wlTenant, "wlc-a", "10.44.255.1")
	f.aps(t, wlTenant, "wlc-a", 50)
	f.poll(t)

	if got := f.monitored(); got != 51 {
		t.Fatalf("monitored = %d, want 51 — one controller plus fifty access points", got)
	}
	if got := f.s.licenceUsage(t.Context())[entitlement.CeilingDevices]; got != 51 {
		t.Fatalf("licence usage = %d, want 51 — the bar reads the same count", got)
	}

	t.Run("the reason names the wireless integration, not a devices file", func(t *testing.T) {
		for _, d := range f.s.discovery.Devices() {
			if d.ID != wireless.ControllerDeviceIDPrefix+"wlc-a" {
				continue
			}
			if !d.Monitored || d.MonitorReason != devmon.ReasonWireless {
				t.Fatalf("controller row = %+v, want monitored with the wireless reason", d)
			}
			return
		}
		t.Fatal("the controller is not in the fleet")
	})

	t.Run("several collectors on one controller are still one device", func(t *testing.T) {
		// A second telemetry method on the SAME controller (a gNMI label) is
		// display, never a count — the C4 rule, unchanged by provenance.
		d, ok := f.s.discovery.Get(wireless.ControllerDeviceIDPrefix + "wlc-a")
		if !ok {
			t.Fatal("controller missing from the registry")
		}
		d.Labels = map[string]string{"gnmi": "true"}
		if err := f.s.discovery.Upsert(d); err != nil {
			t.Fatal(err)
		}
		if got := f.monitored(); got != 51 {
			t.Fatalf("monitored = %d, want 51 — the unit is the device", got)
		}
	})
}

// TestWirelessDiscoveredOnlyIsNotCounted: a controller or AP an SNMP sweep
// merely FOUND is a candidate. Discovery is free for wireless exactly as it is
// for everything else.
func TestWirelessDiscoveredOnlyIsNotCounted(t *testing.T) {
	k := newLicTestKey(t)
	scannedWLC := models.Device{
		ID: "scan-wlc", Name: "scan-wlc", Address: "10.44.255.9",
		Type: "wlc", Source: devmon.SourceSubnetScan,
	}
	scannedAP := models.Device{
		ID: "scan-ap", Name: "scan-ap", Address: "10.44.255.10",
		Type: "ap", Source: devmon.SourceSubnetScan,
	}
	f := newWLFix(t, k.service(t, nil), scannedWLC, scannedAP)

	// A wireless store full of inventory with NO enabled integration behind it.
	f.controller(t, wlTenant, "wlc-idle", "10.44.254.1")
	f.aps(t, wlTenant, "wlc-idle", 5)
	f.poll(t)

	if got := f.monitored(); got != 0 {
		t.Fatalf("monitored = %d, want 0 — nothing here was enabled for collection", got)
	}
	if got := len(f.s.discovery.Devices()); got != 2 {
		t.Fatalf("the scanned rows must stay in the inventory, got %d", got)
	}

	t.Run("the idle estate is still visible, and says why it is not monitored", func(t *testing.T) {
		rows := f.s.wirelessDeviceRows(t.Context(), licClaims(), f.s.discovery.Devices())
		if len(rows) != 6 {
			t.Fatalf("projection returned %d rows, want 6 (1 controller + 5 APs)", len(rows))
		}
		for _, r := range rows {
			if r.Monitored {
				t.Fatalf("%s must not be stamped monitored: %+v", r.ID, r)
			}
			if r.MonitorReason != devmon.ReasonWirelessNotPolled {
				t.Fatalf("%s reason = %q, want the not-polled sentence", r.ID, r.MonitorReason)
			}
		}
	})
}

// TestWirelessDisabledIntegrationCountsNothing: switching an integration off
// releases every entitlement its estate held, and deletes nothing.
func TestWirelessDisabledIntegrationCountsNothing(t *testing.T) {
	k := newLicTestKey(t)
	f := newWLFix(t, k.service(t, k.issue(t, entitlement.TierEnterprise, nil, nil)))
	f.integration(t, wlTenant, wlVendor, true)
	f.controller(t, wlTenant, "wlc-b", "10.44.255.2")
	f.aps(t, wlTenant, "wlc-b", 10)
	f.poll(t)
	if got := f.monitored(); got != 11 {
		t.Fatalf("monitored = %d, want 11", got)
	}

	f.integration(t, wlTenant, wlVendor, false)
	f.poll(t)
	if got := f.monitored(); got != 0 {
		t.Fatalf("monitored = %d, want 0 — a disabled integration polls nothing", got)
	}
	rows := f.s.wirelessDeviceRows(t.Context(), licClaims(), f.s.discovery.Devices())
	if len(rows) != 11 {
		t.Fatalf("the estate must remain VISIBLE after the switch-off, got %d rows", len(rows))
	}
}

// TestWirelessIntegrationWithoutAPInventoryCountsNothing: a connector that
// cannot report wireless inventory contributes no wireless devices, however
// enabled it is. FidelityNone/absent is an honest hole, never a healthy tile.
func TestWirelessIntegrationWithoutAPInventoryCountsNothing(t *testing.T) {
	k := newLicTestKey(t)
	f := newWLFix(t, k.service(t, k.issue(t, entitlement.TierEnterprise, nil, nil)))
	f.integration(t, wlTenant, wlNoWiFi, true)
	f.controller(t, wlTenant, "wlc-c", "10.44.255.3")
	f.aps(t, wlTenant, "wlc-c", 3)
	f.poll(t)
	if got := f.monitored(); got != 0 {
		t.Fatalf("monitored = %d, want 0 — %s declares no AP inventory", got, wlNoWiFi)
	}
}

// TestWirelessControllerViaSNMPAndNMSCountsOnce: the dedupe rule. One physical
// controller, seen by the subnet scan AND managed through the integration, is
// one device and one entitlement.
func TestWirelessControllerViaSNMPAndNMSCountsOnce(t *testing.T) {
	k := newLicTestKey(t)
	const addr = "10.44.253.7"
	scanned := models.Device{
		ID: "scan-dup", Name: "scan-dup", Address: addr,
		Type: "wlc", Source: devmon.SourceSubnetScan, TenantID: wlTenant,
	}
	f := newWLFix(t, k.service(t, k.issue(t, entitlement.TierEnterprise, nil, nil)), scanned)
	f.integration(t, wlTenant, wlVendor, true)
	f.controller(t, wlTenant, "wlc-dup", addr)
	f.poll(t)

	if got := len(f.s.discovery.Devices()); got != 1 {
		t.Fatalf("fleet = %d rows, want 1 — the same management address is the same box", got)
	}
	if got := f.monitored(); got != 1 {
		t.Fatalf("monitored = %d, want 1 — two witnesses of one device cost one entitlement", got)
	}
	t.Run("and the projection does not add it back", func(t *testing.T) {
		rows := f.s.wirelessDeviceRows(t.Context(), licClaims(), f.s.discovery.Devices())
		if len(rows) != 0 {
			t.Fatalf("projection duplicated a registered device: %+v", rows)
		}
	})
}

// TestWirelessMonitoredCountIsTenantScoped: identity never crosses a tenant
// boundary, so two tenants running the same RFC1918 controller address are two
// devices — collapsing them would fold one tenant's estate into the other's.
func TestWirelessMonitoredCountIsTenantScoped(t *testing.T) {
	k := newLicTestKey(t)
	f := newWLFix(t, k.service(t, k.issue(t, entitlement.TierEnterprise, nil, nil)))
	const shared = "10.44.252.1"
	for _, tenant := range []string{"acme", "globex"} {
		f.integration(t, tenant, wlVendor, true)
		f.controller(t, tenant, "wlc-"+tenant, shared)
	}
	f.poll(t)

	if got := f.monitored(); got != 2 {
		t.Fatalf("monitored = %d, want 2 — two tenants may legitimately share an address", got)
	}
	for _, d := range f.s.discovery.Devices() {
		if d.TenantID == "" {
			t.Fatalf("a wireless device must carry its owning tenant: %+v", d)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The ceiling, at the wireless transition
// ─────────────────────────────────────────────────────────────────────────────

// wlEnable drives the REAL integration route, which is where an operator turns
// wireless collection on.
func wlEnable(t *testing.T, s *server, id string, enabled bool) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	body := `{"enabled":` + strconv.FormatBool(enabled) + `}`
	s.handleNMSIntegrationItem(w, licReq(http.MethodPut, "/api/nms/integrations/"+id, body, licTenantAdminClaims()))
	return w
}

// TestWirelessActivationRefusedAtCommunityCeiling: at 25 of 25, enabling a
// wireless integration is the 26th monitored device and Community refuses it —
// with the structured 402 the SPA renders, carrying unit monitored_devices.
func TestWirelessActivationRefusedAtCommunityCeiling(t *testing.T) {
	k := newLicTestKey(t)
	var fleet []models.Device
	for i := 0; i < 25; i++ {
		fleet = append(fleet, monDeclared(i))
	}
	f := newWLFix(t, k.service(t, nil), fleet...) // Community: 25
	if got := f.monitored(); got != 25 {
		t.Fatalf("fixture: monitored = %d, want 25", got)
	}
	f.integration(t, wlTenant, wlVendor, false)
	f.controller(t, wlTenant, "wlc-over", "10.44.251.1")

	w := wlEnable(t, f.s, "nmsi-"+wlVendor+"-"+wlTenant, true)
	licAssertRefusal(t, w, entitlement.KindCeiling, entitlement.CeilingDevices, entitlement.TierTeam)
	if !strings.Contains(w.Body.String(), entitlement.UnitMonitoredDevices) {
		t.Fatalf("the 402 must carry unit %q so a client renders the right thing: %s",
			entitlement.UnitMonitoredDevices, w.Body.String())
	}

	t.Run("the refusal actually stopped the activation", func(t *testing.T) {
		ic, found, err := f.s.nms.Store().Get(t.Context(), wlTenant, false, "nmsi-"+wlVendor+"-"+wlTenant)
		if err != nil || !found {
			t.Fatalf("integration lookup: %v found=%v", err, found)
		}
		if ic.Enabled {
			t.Fatal("a refused activation must not have been written")
		}
		f.poll(t)
		if got := f.monitored(); got != 25 {
			t.Fatalf("monitored = %d, want 25 — nothing was collected past the ceiling", got)
		}
	})

	t.Run("turning an integration OFF is never refused", func(t *testing.T) {
		f.integration(t, wlTenant, wlVendor, true)
		if w := wlEnable(t, f.s, "nmsi-"+wlVendor+"-"+wlTenant, false); w.Code != http.StatusOK {
			t.Fatalf("disable = %d %s — freeing capacity cannot be a licence refusal", w.Code, w.Body.String())
		}
	})

	t.Run("a connector with no wireless inventory is not gated", func(t *testing.T) {
		f.integration(t, wlTenant, wlNoWiFi, false)
		if w := wlEnable(t, f.s, "nmsi-"+wlNoWiFi+"-"+wlTenant, true); w.Code != http.StatusOK {
			t.Fatalf("enable %s = %d %s — it adds no wireless devices, so it costs nothing",
				wlNoWiFi, w.Code, w.Body.String())
		}
	})
}

// TestWirelessActivationRecordedAsOverageOnPaidTier: the soft half. A paid tier
// admits the activation and records the overage for true-up — never a kill
// switch during an incident.
func TestWirelessActivationRecordedAsOverageOnPaidTier(t *testing.T) {
	k := newLicTestKey(t)
	// Team, with the device allowance pinned low so the fixture is small and the
	// arithmetic is legible: 3 covered, and a wireless estate of 4 on top.
	raw := k.issue(t, entitlement.TierTeam, nil, func(c *entitlement.Ceilings) { c.Devices = 3 })
	var fleet []models.Device
	for i := 0; i < 3; i++ {
		fleet = append(fleet, monDeclared(i))
	}
	f := newWLFix(t, k.service(t, raw), fleet...)
	f.integration(t, wlTenant, wlVendor, false)
	f.controller(t, wlTenant, "wlc-soft", "10.44.250.1")
	f.aps(t, wlTenant, "wlc-soft", 3)

	if w := wlEnable(t, f.s, "nmsi-"+wlVendor+"-"+wlTenant, true); w.Code != http.StatusOK {
		t.Fatalf("a paid tier must not be blocked at its device allowance: %d %s", w.Code, w.Body.String())
	}
	f.poll(t)
	if got := f.monitored(); got != 7 {
		t.Fatalf("monitored = %d, want 7 — the wireless estate is being collected from", got)
	}
	over := f.s.entitlements.Overages(licence.Usage{entitlement.CeilingDevices: f.monitored()})
	if len(over) != 1 || !over[0].Soft || over[0].Over != 4 {
		t.Fatalf("the overage must be listed as soft and sized 4: %+v", over)
	}
	if !strings.Contains(over[0].Message, "true-up") {
		t.Fatalf("a soft overage is a billing fact, not a fault: %q", over[0].Message)
	}
	if f.s.discovery.MonitoringWithheldCount() != 0 {
		t.Fatal("a soft overage withholds nothing")
	}
	t.Run("the over-ceiling listing names the wireless devices", func(t *testing.T) {
		rows := f.s.licenceOverCeilingDevices(t.Context())
		if len(rows) != 4 {
			t.Fatalf("4 devices over the allowance must produce a 4-row listing: %+v", rows)
		}
	})
}

// TestWirelessDevicesAreMeteredLikeAnyDevice: tracker 258 reads the monitored
// set, so it changes with this decision and needed no code of its own.
func TestWirelessDevicesAreMeteredLikeAnyDevice(t *testing.T) {
	k := newLicTestKey(t)
	f := newWLFix(t, k.service(t, k.issue(t, entitlement.TierEnterprise, nil, nil)))
	f.integration(t, wlTenant, wlVendor, true)
	f.controller(t, wlTenant, "wlc-m", "10.44.249.1")
	f.aps(t, wlTenant, "wlc-m", 4)
	f.poll(t)

	out := map[string][]metering.Reading{}
	add := func(scope string, r metering.Reading) { out[scope] = append(out[scope], r) }
	f.s.meterDevices(out, add, "installation", []string{wlTenant})

	peak := func(scope string) float64 {
		t.Helper()
		for _, r := range out[scope] {
			if r.Meter == metering.MeterMonitoredDevicesPeak {
				if r.Source == metering.SourceNotMeasured {
					t.Fatalf("%s peak is not_measured: %+v", scope, r)
				}
				return r.Value
			}
		}
		t.Fatalf("no %s reading for scope %q", metering.MeterMonitoredDevicesPeak, scope)
		return 0
	}
	if got := peak("installation"); got != 5 {
		t.Fatalf("installation peak = %v, want 5 (1 controller + 4 APs)", got)
	}
	if got := peak(wlTenant); got != 5 {
		t.Fatalf("tenant peak = %v, want 5 — the estate is the tenant's", got)
	}
}
