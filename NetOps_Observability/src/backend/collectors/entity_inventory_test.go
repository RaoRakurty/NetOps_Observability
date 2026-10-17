// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package collectors

import (
	"strings"
	"testing"
)

func TestBuildEntityInfoLines_FRUOnly(t *testing.T) {
	descr := map[string]string{"1": "Chassis", "2": "Power Supply 0", "3": "GigabitEthernet0/0", "10": "Fan Tray"}
	model := map[string]string{"1": "C8000V", "2": "PWR-C1", "10": "FAN-1"}
	serial := map[string]string{"1": "9ABC123", "2": "POW987", "10": "FAN555"}
	class := map[string]string{"1": "3", "2": "6", "3": "10", "10": "7"} // chassis, powerSupply, port, fan

	lines := buildEntityInfoLines("lan-sw1", "cisco", descr, model, serial, class, 1_700_000_000_000)

	// 3 FRUs (chassis, PSU, fan) — the port (idx 3, no serial/model) is skipped.
	if len(lines) != 3 {
		t.Fatalf("expected 3 FRU lines (port skipped), got %d: %v", len(lines), lines)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{
		`device_entity_info{`, `device="lan-sw1"`, `vendor="cisco"`,
		`serial="9ABC123"`, `model="C8000V"`, `class="chassis"`,
		`class="powerSupply"`, `class="fan"`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in:\n%s", want, joined)
		}
	}
	if strings.Contains(joined, `GigabitEthernet0/0`) {
		t.Error("a port with no serial/model must be skipped (not a FRU)")
	}
	// info series carries value 1
	for _, ln := range lines {
		if !strings.Contains(ln, "} 1 1700000000000") {
			t.Errorf("info line must end in value 1 + ts: %q", ln)
		}
	}
}

func TestBuildEntityInfoLines_SanitizesControlChars(t *testing.T) {
	// SNMP strings can carry CR/LF/tabs that would corrupt the exposition line.
	serial := map[string]string{"1": "AB\r\nCD\t12 "}
	model := map[string]string{"1": "X1"}
	lines := buildEntityInfoLines("d", "v", nil, model, serial, nil, 1)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `serial="AB CD 12"`) {
		t.Errorf("serial not sanitized: %q", lines[0])
	}
	if strings.ContainsAny(lines[0], "\r\n\t") {
		t.Errorf("control chars leaked into exposition line: %q", lines[0])
	}
}

func TestBuildEntityInfoLines_EmptyWhenNoInventory(t *testing.T) {
	if lines := buildEntityInfoLines("d", "v", nil, nil, nil, nil, 1); len(lines) != 0 {
		t.Errorf("no ENTITY-MIB data → no lines, got %v", lines)
	}
	// entities with descr/class but no serial/model are not FRUs → skipped.
	descr := map[string]string{"5": "Slot Container"}
	class := map[string]string{"5": "5"}
	if lines := buildEntityInfoLines("d", "v", descr, nil, nil, class, 1); len(lines) != 0 {
		t.Errorf("non-FRU entities must be skipped, got %v", lines)
	}
}

// The device's software revision: chassis first, then the first module (IOS XE
// reports it on the route processor), then any entity that has one.
func TestPickSoftwareRev(t *testing.T) {
	class := map[string]string{"1": "3", "7": "9", "10": "9", "22": "6"}
	if got := pickSoftwareRev(map[string]string{"1": "", "7": "17.03.04a", "10": "17.03.04b", "22": "x"}, class); got != "17.03.04a" {
		t.Fatalf("module fallback: %q", got)
	}
	if got := pickSoftwareRev(map[string]string{"1": "Junos 23.4R1", "7": "x"}, class); got != "Junos 23.4R1" {
		t.Fatalf("chassis first: %q", got)
	}
	if got := pickSoftwareRev(map[string]string{"22": "1.2"}, class); got != "1.2" {
		t.Fatalf("any entity: %q", got)
	}
	if got := pickSoftwareRev(map[string]string{"1": "  "}, class); got != "" {
		t.Fatalf("blank: %q", got)
	}
}
