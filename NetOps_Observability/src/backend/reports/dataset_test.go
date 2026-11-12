// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package reports

import (
	"strings"
	"testing"
)

// atoiSafe parses a leading run of digits and stops at the first non-digit,
// returning whatever it accumulated (never errors).

func TestAtoiSafe(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"0", 0},
		{"42", 42},
		{"  17  ", 17},  // surrounding space trimmed before parsing
		{"123abc", 123}, // stops at first non-digit
		{"abc", 0},      // no leading digits
		{"-5", 0},       // '-' is not a digit, stops immediately
		{"9 8", 9},      // embedded space stops parsing
		{"007", 7},      // leading zeros fine
		{"1000000", 1000000},
	}
	for _, c := range cases {
		if got := atoiSafe(c.in); got != c.want {
			t.Errorf("atoiSafe(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// topDeviceLines ranks a metric map highest-first (name-tiebroken), caps at n,
// and renders "name value<unit>" lines.
func TestTopDeviceLines(t *testing.T) {
	m := map[string]float64{"b": 90, "a": 90, "c": 12, "d": 50}
	got := topDeviceLines(m, 3, "%")
	want := []string{"a 90%", "b 90%", "d 50%"}
	if len(got) != len(want) {
		t.Fatalf("topDeviceLines = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
	if lines := topDeviceLines(nil, 5, "%"); len(lines) != 0 {
		t.Errorf("empty map should yield no lines, got %v", lines)
	}
}

// Tracker 370: a tenant-owned report reads ClickHouse under the all-tenants
// scope, so its predicate is the tenant's stamped rows OR untagged rows claimed
// by an UNAMBIGUOUS key — never a bare device-name match, which would take
// another tenant's stamped rows and other owners' untagged rows naming the same
// device.
func TestDeviceScopeClickHousePredicates(t *testing.T) {
	sc := DeviceScope{Keys: []string{"core-rtr-1", "acme-edge"}, Tenant: "Acme", Claim: []string{"acme-edge"}}
	if got, want := sc.findingsCond(), " AND (tenant_id = 'acme' OR (tenant_id = '' AND (device IN ('acme-edge'))))"; got != want {
		t.Errorf("findingsCond = %q, want %q", got, want)
	}
	if got := sc.tunnelCond(); !strings.Contains(got, "(tenant_id = 'acme' OR (tenant_id = '' AND (local_device IN ('acme-edge') OR remote_device IN ('acme-edge'))))") || strings.Contains(got, "core-rtr-1") {
		t.Errorf("tunnelCond = %q", got)
	}
	// Every key ambiguous → own stamped rows only.
	if got := (DeviceScope{Keys: []string{"x"}, Tenant: "acme"}).findingsCond(); got != " AND (tenant_id = 'acme')" {
		t.Errorf("no claim: findingsCond = %q", got)
	}
	// Unresolved tenant → nothing (default-closed), never an unscoped read.
	if got := (DeviceScope{Keys: []string{"x"}, Claim: []string{"x"}}).findingsCond(); got != " AND (1 = 0)" {
		t.Errorf("no tenant: findingsCond = %q", got)
	}
}
