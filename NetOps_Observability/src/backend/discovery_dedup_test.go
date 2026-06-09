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

func TestDeviceKey(t *testing.T) {
	if k := deviceKey(models.Device{Address: "10.0.0.1", Name: "x"}); k != "ip:10.0.0.1" {
		t.Errorf("IP should win: %q", k)
	}
	if k := deviceKey(models.Device{Name: "x", Labels: map[string]string{"serial": "ABC123"}}); k != "sn:abc123" {
		t.Errorf("serial fallback: %q", k)
	}
	if k := deviceKey(models.Device{Name: "Leaf1"}); k != "name:leaf1" {
		t.Errorf("name fallback (normalized): %q", k)
	}
}
