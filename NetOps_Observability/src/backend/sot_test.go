package main

import "testing"

// TestActiveSoTAlwaysInternal locks the owner decision (2026-06-20): the
// observability Source-of-Truth authority (inventory placement, sites, geo, drift)
// is ALWAYS the internal provider — the platform's own SNMP-discovered inventory.
// NetBox is an automation connector only and must NEVER become the authority, even
// when fully configured (the condition that used to flip activeSoT to NetBox).
func TestActiveSoTAlwaysInternal(t *testing.T) {
	s := &server{
		netboxCfg: &netboxConfigStore{cfg: &netboxConfig{
			Enabled: true, URL: "https://netbox.example.com", Token: "tok", Direction: "both",
		}},
	}
	p := s.activeSoT()
	if p.Name() != "internal" {
		t.Fatalf("activeSoT().Name() = %q, want \"internal\" — NetBox must never be the SoT authority", p.Name())
	}
	// Internal IS the inventory → no separate declared records → drift inactive
	// (no false "unregistered" flood against NetBox).
	if src := p.DeviceRecordSource(); src != "" {
		t.Fatalf("DeviceRecordSource() = %q, want \"\" (internal is the source of truth, nothing to drift against)", src)
	}
}
