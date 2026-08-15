package discovery

import "testing"

// scan_device_id_test.go — the sysName-collision regression.
//
// ScanDeviceID keyed a device by sysName alone. Two devices sharing a sysName
// then got the SAME id, and the aggregator cache (keyed by id) silently
// overwrote one with the other — a device vanished from inventory, never polled
// or alerted, with no error. The insidious case is not a literal duplicate but
// two DISTINCT names that sanitize alike.
func TestScanDeviceIDDisambiguatesByAddress(t *testing.T) {
	// Distinct real names that fold to the same sanitized string must NOT collide.
	a := ScanDeviceID("core#1", "10.0.0.1")
	b := ScanDeviceID("core@1", "10.0.0.2")
	if a == b {
		t.Fatalf("core#1 and core@1 collided to the same id %q — one would overwrite the other", a)
	}

	// Factory-default name repeated across the fleet must NOT collide either.
	s1 := ScanDeviceID("Switch", "10.0.0.10")
	s2 := ScanDeviceID("Switch", "10.0.0.11")
	if s1 == s2 {
		t.Fatalf("two factory-default 'Switch' devices collided to %q", s1)
	}

	// Stable: the SAME device (same name+address) re-scanned yields the SAME id,
	// so it updates in place rather than duplicating.
	if got := ScanDeviceID("core#1", "10.0.0.1"); got != a {
		t.Fatalf("id not stable across re-scan: %q vs %q", got, a)
	}

	// The human-readable name prefix is preserved for debuggability.
	if a[:6] != "core-1" {
		t.Fatalf("id %q should keep the sanitized-name prefix", a)
	}

	// Empty sysName still falls back to the address (unchanged behavior).
	if got := ScanDeviceID("", "10.0.0.9"); got != "10.0.0.9" {
		t.Fatalf("empty sysName should fall back to the address, got %q", got)
	}
	// Nothing to derive from → empty (the F-8 caller then refuses the row).
	if got := ScanDeviceID("", ""); got != "" {
		t.Fatalf("no name and no address should yield empty, got %q", got)
	}
}
