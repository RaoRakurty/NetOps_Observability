// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

// legacy_scan_id_test.go — scan-id migration safety.
//
// ScanDeviceID gained an address-hash suffix to stop same-name collisions, but
// every consumer keyed by scan id — the F-69 delete tombstones (IsSuppressed)
// and per-device state — predates it. M1's first attempt at a migration re-keyed
// a UNIQUELY-named device back to the address-less legacy id so its tombstone
// still matched. That rewrite caused two regressions (F5/F6): it collided with a
// static-file device that already used the bare name as its id (the SNMP record
// was then dropped as a lower-precedence duplicate), and it still missed
// tombstones written DURING the hashed-id window.
//
// The fix keeps the collision-safe hashed id for EVERY device and instead makes
// suppression order- and era-independent in the aggregator (pollOnce checks both
// the legacy address-less id and the hashed id). These tests lock: hashed ids
// stay unique (no cross-source collision), a legacy-id tombstone still sticks
// (pre-hash delete), a hashed-window tombstone sticks, and a static+SNMP name
// clash no longer drops the SNMP record.

import (
	"context"
	"os"
	"testing"

	"netops/backend/models"
)

// memKV is an in-memory KV for the DevStore (absent key = fresh install).
type memKV map[string][]byte

func (m memKV) Load(key string) ([]byte, error) {
	b, ok := m[key]
	if !ok {
		return nil, os.ErrNotExist
	}
	return b, nil
}
func (m memKV) Save(key string, data []byte) error { m[key] = data; return nil }

func newLegacyIDSource() *SNMPSource {
	cfg := func() ScanSettings {
		return ScanSettings{Enabled: true, Ranges: []string{"10.9.0.0/29"}, Community: "public"}
	}
	s := NewSNMPSource(cfg, nil)
	s.SetProbeForTest(func(_ context.Context, addr, _ string) (string, string, string, bool) {
		switch addr {
		case "10.9.0.1":
			return "core1", "arista", "descr", true // unique name
		case "10.9.0.2", "10.9.0.3":
			return "switch", "cisco", "descr", true // colliding factory default
		}
		return "", "", "", false
	})
	return s
}

// newCore1Source is a single-device SNMP source (only 10.9.0.1 answers, sysName
// "core1", vendor arista) — used for the static-clash and hashed-window cases.
func newCore1Source() *SNMPSource {
	cfg := func() ScanSettings {
		return ScanSettings{Enabled: true, Ranges: []string{"10.9.0.0/29"}, Community: "public"}
	}
	s := NewSNMPSource(cfg, nil)
	s.SetProbeForTest(func(_ context.Context, addr, _ string) (string, string, string, bool) {
		if addr == "10.9.0.1" {
			return "core1", "arista", "descr", true
		}
		return "", "", "", false
	})
	return s
}

// TestScanIDsAlwaysHashedNoBareLegacyID: the collision-safe hashed scan id is
// kept for EVERY device (M1's legacy-id rewrite is reverted). A uniquely-named
// device is under ScanDeviceID(name, addr), never the bare name; the colliding
// pair still gets distinct, address-hashed ids.
func TestScanIDsAlwaysHashedNoBareLegacyID(t *testing.T) {
	s := newLegacyIDSource()
	devs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	byID := map[string]models.Device{}
	for _, d := range devs {
		byID[d.ID] = d
	}
	// The uniquely-named device is under its collision-safe hashed id, not the
	// bare legacy name — no cross-source collision with a static "core1".
	if _, ok := byID[ScanDeviceID("core1", "10.9.0.1")]; !ok {
		t.Fatalf("unique device not under its hashed id: ids=%v", keysOf(byID))
	}
	if _, ok := byID["core1"]; ok {
		t.Fatalf("unique device must not appear under the bare legacy id: ids=%v", keysOf(byID))
	}
	// The colliding pair still gets distinct, address-hashed ids.
	h2 := ScanDeviceID("switch", "10.9.0.2")
	h3 := ScanDeviceID("switch", "10.9.0.3")
	if h2 == h3 {
		t.Fatal("hash form did not disambiguate")
	}
	if _, ok := byID[h2]; !ok {
		t.Fatalf("colliding device 10.9.0.2 not under its hashed id: ids=%v", keysOf(byID))
	}
	if _, ok := byID[h3]; !ok {
		t.Fatalf("colliding device 10.9.0.3 not under its hashed id: ids=%v", keysOf(byID))
	}
	if _, ok := byID["switch"]; ok {
		t.Fatal("colliding name must not also appear under the bare legacy id")
	}
}

// TestM1SuppressedLegacyIDStaysSuppressed: an operator deleted a device before
// the id change (tombstone keyed by the LEGACY address-less id). A rescan
// returning the same name+address must stay suppressed — pollOnce's dual-
// derivation check matches ScanDeviceID(name, "") to the tombstone.
func TestM1SuppressedLegacyIDStaysSuppressed(t *testing.T) {
	st := NewDevStore("devices.json", memKV{}, nil)
	if err := st.Remove("core1"); err != nil { // records the F-69 tombstone under the legacy id
		t.Fatalf("remove: %v", err)
	}
	a := NewDiscoveryAggregator()
	a.SetStore(st)

	s := newLegacyIDSource()
	a.PollOnceForTest(context.Background(), s)

	for _, d := range a.RawDevices() {
		if d.ID == "core1" || d.Name == "core1" {
			t.Fatalf("operator-deleted device resurrected after rescan as %+v", d)
		}
	}
	// The un-deleted devices still arrive.
	if got := len(a.RawDevices()); got != 2 {
		t.Fatalf("want the 2 surviving devices, got %d: %+v", got, a.RawDevices())
	}
}

// TestSameDeviceStaticPlusSnmpMergeLost (F5): a static-file device already owns
// the bare name "core1" as its id and is polled first (higher precedence).
// Under M1's legacy-id rewrite the SNMP record re-keyed to the same "core1" and
// was skipped as a lower-precedence duplicate — losing its vendor/OS/address.
// With the hashed id kept, the SNMP record has a distinct id and survives.
func TestSameDeviceStaticPlusSnmpMergeLost(t *testing.T) {
	a := NewDiscoveryAggregator()
	static := &fakeSource{name: "static", devices: []models.Device{
		{ID: "core1", Name: "core1", Address: "10.1.0.1", Source: "static"},
	}}
	a.PollOnceForTest(context.Background(), static) // static registered/polled first
	a.PollOnceForTest(context.Background(), newCore1Source())

	var arista bool
	for _, d := range a.RawDevices() {
		if d.Vendor == "arista" {
			arista = true
		}
	}
	if !arista {
		t.Fatalf("SNMP record dropped by cross-source id collision; RawDevices=%+v", a.RawDevices())
	}
}

// TestHashWindowTombstoneResurrects (F6): a device deleted while the build keyed
// by the HASHED id has its tombstone under ScanDeviceID(name, addr). A rescan of
// the same unique device must stay suppressed (0 survivors) — pollOnce's dual-
// derivation check matches the hashed id.
func TestHashWindowTombstoneResurrects(t *testing.T) {
	st := NewDevStore("devices.json", memKV{}, nil)
	if err := st.Remove(ScanDeviceID("core1", "10.9.0.1")); err != nil { // tombstone under the hashed id
		t.Fatalf("remove: %v", err)
	}
	a := NewDiscoveryAggregator()
	a.SetStore(st)

	a.PollOnceForTest(context.Background(), newCore1Source())

	if got := len(a.RawDevices()); got != 0 {
		t.Fatalf("hashed-id tombstone did not suppress rescan: %d survivors %+v", got, a.RawDevices())
	}
}

func keysOf(m map[string]models.Device) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
