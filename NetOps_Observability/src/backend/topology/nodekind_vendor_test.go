// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package topology

// nodekind_vendor_test.go — the PARITY GOLDEN for the move of the firewall
// VENDOR HINT into the Vendor Profile registry (tracker 221).
//
// nodeKind used to carry its own list of dedicated firewall / SD-WAN-security
// vendor spellings. That list is vendor identity — the registry's subject — and
// it now lives in the vendor profiles (device_type.vendor_tokens /
// vendor_kind). What stays here is the POLICY: an explicit operator role wins,
// then the inferred type, then the vendor claim, then hostname tokens, and a
// device with no signal renders as a neutral switch rather than a guess.
//
// The deleted switch is preserved here, verbatim, as the golden.

import "testing"

// handWrittenFirewallVendor is the deleted vendor hint, verbatim.
func handWrittenFirewallVendor(vendor string) (string, bool) {
	switch lowerTrim(vendor) {
	case "fortinet", "fortigate", "palo alto", "paloalto", "palo-alto", "panw", "checkpoint", "check point":
		return KindFirewall, true
	}
	return "", false
}

func lowerTrim(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out = append(out, c)
	}
	// trim ASCII space the same way strings.TrimSpace does for these inputs
	start, end := 0, len(out)
	for start < end && (out[start] == ' ' || out[start] == '\t' || out[start] == '\n' || out[start] == '\r') {
		start++
	}
	for end > start && (out[end-1] == ' ' || out[end-1] == '\t' || out[end-1] == '\n' || out[end-1] == '\r') {
		end--
	}
	return string(out[start:end])
}

// TestNodeKindVendorHintIsIdenticalToTheHandWrittenSwitch — every vendor
// spelling resolves to exactly the kind it resolved to before, and no vendor
// that used not to claim a kind starts claiming one.
func TestNodeKindVendorHintIsIdenticalToTheHandWrittenSwitch(t *testing.T) {
	vendors := []string{
		"fortinet", "Fortinet", "FORTINET", " fortinet ", "fortigate", "FortiGate",
		"palo alto", "Palo Alto", "paloalto", "PaloAlto", "palo-alto", "panw", "PANW",
		"checkpoint", "CheckPoint", "check point", "Check Point",
		"cisco", "Cisco", "arista", "juniper", "nokia", "huawei", "f5", "ubiquiti",
		"dell", "hp", "extreme", "mikrotik", "sophos", "aruba", "ruckus", "linux",
		"", " ", "fortinet-lookalike", "not-checkpoint", "palo", "alto", "acme",
	}
	for _, vendor := range vendors {
		// The device carries NO other signal, so nodeKind's answer is the
		// vendor hint's answer (or its neutral default).
		got := nodeKind(DeviceFact{Vendor: vendor})
		want, ok := handWrittenFirewallVendor(vendor)
		if !ok {
			want = KindSwitch // the neutral default the hand-written path fell through to
		}
		if got != want {
			t.Errorf("nodeKind(vendor=%q) = %q, want %q", vendor, got, want)
		}
	}
}

// TestNodeKindPrecedenceIsUnchanged pins the POLICY around the moved hint: an
// explicit role and the inferred type both still outrank the vendor claim, and
// the hostname hints still run after it.
func TestNodeKindPrecedenceIsUnchanged(t *testing.T) {
	cases := []struct {
		name string
		d    DeviceFact
		want string
	}{
		{"explicit role wins over a firewall vendor", DeviceFact{Vendor: "fortinet", Role: "router"}, KindRouter},
		{"inferred type wins over a firewall vendor", DeviceFact{Vendor: "paloalto", Type: "switch"}, KindSwitch},
		{"vendor hint wins over a hostname token", DeviceFact{Vendor: "checkpoint", Name: "core-r1"}, KindFirewall},
		{"hostname token still applies with a neutral vendor", DeviceFact{Vendor: "cisco", Name: "wan-r2"}, KindRouter},
		{"no signal at all is a neutral switch", DeviceFact{}, KindSwitch},
	}
	for _, tc := range cases {
		if got := nodeKind(tc.d); got != tc.want {
			t.Errorf("%s: nodeKind = %q, want %q", tc.name, got, tc.want)
		}
	}
}
