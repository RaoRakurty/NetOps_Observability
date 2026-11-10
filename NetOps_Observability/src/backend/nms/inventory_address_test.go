// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"testing"

	"netops/backend/models"
)

// The lab's shape (tracker 387 PR 13c'): 192.168.1.1 is Loopback65528 on three
// cEdges and must never name one, even when only ONE of them has been walked.
func TestTrapAddrIndexIgnoresInternalVPN(t *testing.T) {
	devs := []models.Device{
		{ID: "cedge-40", Address: "192.168.222.107"},
		{ID: "cedge-81", Address: "192.168.222.106"},
	}
	ifs := map[string]map[string]string{
		"cedge-40": {"192.168.1.1": "Lo65528", "192.168.200.25": "GigabitEthernet3", "127.0.0.1": "Lo0", "fe80::1": "Gi1"},
		"cedge-81": {"192.168.200.33": "GigabitEthernet3", "192.168.1.2": "Loopback65530", "10.0.0.7": "loopback0"},
	}
	idx := BuildInventoryIndex(devs, nil, ifs)
	for _, ip := range []string{"192.168.1.1", "192.168.1.2", "127.0.0.1", "fe80::1"} {
		if dev, out := idx.DeviceForAddress(ip); out != AddressNoMatch || dev != "" {
			t.Errorf("%s named %q (%s): internal-VPN loopbacks and non-identifying addresses name nobody", ip, dev, out)
		}
	}
	for ip, want := range map[string]string{"192.168.200.33": "cedge-81", "192.168.200.25": "cedge-40", "10.0.0.7": "cedge-81", "192.168.222.106": "cedge-81"} {
		if dev, out := idx.DeviceForAddress(ip); out != AddressMatched || dev != want {
			t.Errorf("%s = %q (%s), want %s", ip, dev, out, want)
		}
	}
	for name, want := range map[string]bool{"Lo65528": true, "loopback65531": true, "Loopback65527": false, "lo0": false, "GigabitEthernet65528": false, "lo": false} {
		if internalLoopback(name) != want {
			t.Errorf("internalLoopback(%q) = %v, want %v", name, !want, want)
		}
	}
}

// Unique across EVERY tenant: an address two tenants' devices hold names
// nobody, and the answer is a device id, never a tenant.
func TestDeviceForAddressUniqueAcrossTenants(t *testing.T) {
	devs := []models.Device{
		{ID: "acme-edge", Address: "10.1.0.1", TenantID: "acme"},
		{ID: "globex-edge", Address: "10.2.0.1", TenantID: "globex"},
		{ID: "acme-edge-2", Address: "10.1.0.2", TenantID: "acme"},
	}
	ifs := map[string]map[string]string{
		"acme-edge":   {"172.16.0.1": "Gi2", "172.16.9.9": "Gi3"},
		"globex-edge": {"172.16.0.1": "Gi2"}, // overlapping customer space
		"acme-edge-2": {"172.16.9.9": "Gi3"}, // shared within one tenant
	}
	idx := BuildInventoryIndex(devs, nil, ifs)
	if dev, out := idx.DeviceForAddress("172.16.0.1"); out != AddressAmbiguous || dev != "" {
		t.Errorf("cross-tenant shared address = %q (%s), want ambiguous", dev, out)
	}
	if dev, out := idx.DeviceForAddress("172.16.9.9"); out != AddressAmbiguous || dev != "" {
		t.Errorf("in-tenant shared address = %q (%s), want ambiguous", dev, out)
	}
	if dev, out := idx.DeviceForAddress("10.2.0.1"); out != AddressMatched || dev != "globex-edge" {
		t.Errorf("globex mgmt address = %q (%s)", dev, out)
	}
	var nilIdx *InventoryIndex
	if _, out := nilIdx.DeviceForAddress("10.2.0.1"); out != AddressNoMatch {
		t.Error("a nil index must resolve nothing")
	}
	if _, out := idx.DeviceForAddress("not-an-ip"); out != AddressNoMatch {
		t.Error("garbage must resolve nothing")
	}
}
