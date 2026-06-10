package main

import (
	"testing"

	"netops/backend/models"
)

// The same physical device seen by SNMP discovery AND NetBox must show ONCE,
// merged (NetBox metadata + SNMP live fields), not as two rows.
func TestDevicesDedupAcrossSources(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.Upsert(models.Device{ID: "snmp-10.0.0.1", Name: "leaf1", Address: "10.0.0.1", Vendor: "Arista", Source: "snmp", CredentialRef: "arista-v2c"})
	a.Upsert(models.Device{ID: "netbox-42", Name: "leaf1", Address: "10.0.0.1", Source: "netbox", Labels: map[string]string{"site": "dc1"}})

	devs := a.Devices()
	if len(devs) != 1 {
		t.Fatalf("same device from two sources should merge to 1, got %d", len(devs))
	}
	d := devs[0]
	if d.Source != "netbox" {
		t.Errorf("merged base should prefer the NetBox record, got source %q", d.Source)
	}
	if d.Vendor != "Arista" {
		t.Errorf("should fold in SNMP-learned vendor, got %q", d.Vendor)
	}
	if d.CredentialRef != "arista-v2c" {
		t.Errorf("should keep the SNMP credential_ref for polling, got %q", d.CredentialRef)
	}
	if d.Labels["site"] != "dc1" {
		t.Errorf("should keep the NetBox site label, got %q", d.Labels["site"])
	}
	if d.Labels["sources"] != "netbox+snmp" {
		t.Errorf("should record both sources, got %q", d.Labels["sources"])
	}

	// A genuinely different device stays separate.
	a.Upsert(models.Device{ID: "snmp-10.0.0.2", Name: "leaf2", Address: "10.0.0.2", Source: "snmp"})
	if got := len(a.Devices()); got != 2 {
		t.Errorf("distinct devices must not merge, got %d", got)
	}
}

// The reported duplicate: an SNMP device (keyed by mgmt IP) and its synced
// NetBox twin (create-only → NO primary IP) share no IP, but DO share the name
// (and, now that NetboxSource reads it, the serial). Multi-identity union must
// still collapse them — a single-key (IP-first) scheme would not.
func TestDedupeNetboxTwinNoSharedIP(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.Upsert(models.Device{ID: "snmp-leaf1", Name: "leaf1", Address: "10.70.0.1", Source: "snmp",
		CredentialRef: "v3-arista", Labels: map[string]string{"serial": "ABC123"}})
	a.Upsert(models.Device{ID: "netbox-7", Name: "leaf1", Source: "netbox", Model: "DCS-7050",
		Labels: map[string]string{"site": "dallas", "serial": "ABC123"}}) // IP-less twin

	devs := a.Devices()
	if len(devs) != 1 {
		t.Fatalf("IP-less NetBox twin must merge with its SNMP record, got %d: %+v", len(devs), devs)
	}
	d := devs[0]
	if d.Address != "10.70.0.1" {
		t.Errorf("merged must keep the SNMP mgmt IP, got %q", d.Address)
	}
	if d.CredentialRef != "v3-arista" {
		t.Errorf("merged must keep the SNMP credential for polling, got %q", d.CredentialRef)
	}
	if d.Model != "DCS-7050" || d.Labels["site"] != "dallas" {
		t.Errorf("merged must keep NetBox metadata, got %+v", d)
	}
}

func TestDedupeBySerialDifferentNames(t *testing.T) {
	a := NewDiscoveryAggregator()
	a.Upsert(models.Device{ID: "snmp-x", Name: "10.0.0.5", Address: "10.0.0.5", Source: "snmp",
		Labels: map[string]string{"serial": "SN-9"}})
	a.Upsert(models.Device{ID: "netbox-2", Name: "core-sw-1", Source: "netbox",
		Labels: map[string]string{"serial": "SN-9"}})
	if got := len(a.Devices()); got != 1 {
		t.Fatalf("serial-based merge expected 1, got %d", got)
	}
}

// Transitive: A shares IP with B, B shares name with C → all one device.
func TestDedupeTransitive(t *testing.T) {
	cache := map[string]models.Device{
		"a": {ID: "a", Name: "r1", Address: "10.0.0.9", Source: "snmp"},
		"b": {ID: "b", Name: "r1-mgmt", Address: "10.0.0.9", Source: "static"},
		"c": {ID: "c", Name: "r1-mgmt", Source: "netbox"},
	}
	if got := len(dedupeDevices(cache)); got != 1 {
		t.Fatalf("transitive union expected 1, got %d", got)
	}
}

// Blank identity fields must never union unrelated devices.
func TestDedupeBlankFieldsDontUnion(t *testing.T) {
	cache := map[string]models.Device{
		"a": {ID: "a", Name: "", Address: "10.0.0.1", Source: "snmp"},
		"b": {ID: "b", Name: "", Address: "10.0.0.2", Source: "snmp"},
	}
	if got := len(dedupeDevices(cache)); got != 2 {
		t.Fatalf("blank names unioned distinct devices: got %d, want 2", got)
	}
}

func TestDeviceIdentities(t *testing.T) {
	got := deviceIdentities(models.Device{Address: "10.0.0.1", Name: "Leaf1", Labels: map[string]string{"serial": "ABC123"}})
	want := map[string]bool{"ip:10.0.0.1": true, "sn:abc123": true, "name:leaf1": true}
	if len(got) != len(want) {
		t.Fatalf("identities = %v, want keys %v", got, want)
	}
	for _, tok := range got {
		if !want[tok] {
			t.Errorf("unexpected identity token %q", tok)
		}
	}
	// No identities at all → empty (can't accidentally union).
	if ids := deviceIdentities(models.Device{}); len(ids) != 0 {
		t.Errorf("empty device should yield no identities, got %v", ids)
	}
}
