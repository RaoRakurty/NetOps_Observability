// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// helpers_test.go — the package's own prefix boundary.
//
// parsePrefix is the second place a typed resource becomes a prefix (the first
// is the API boundary's bgpNormalizeResource). The two must agree, because the
// watchlist key an evaluation is stored under and the resource an operator was
// shown are the same string or the screen is lying. Owner, 2026-09-08: a host
// address carrying a mask is checked as its NETWORK address, and the page says
// so — this table is the server half of that contract, mirrored on the client
// in src/frontend/src/pages/bgp/prefix.test.ts.

import "testing"

func TestParsePrefixCanonicalizes(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" = must be refused
	}{
		{"1.1.1.1/24", "1.1.1.0/24"}, // host bits masked off — the owner's case
		{"193.0.7.7/21", "193.0.0.0/21"},
		{"203.0.113.0/24", "203.0.113.0/24"},
		{"10.1.2.3/31", "10.1.2.2/31"},
		{"10.1.2.3/0", "0.0.0.0/0"},
		{" 193.0.0.0/21 ", "193.0.0.0/21"},
		{"203.0.113.9", "203.0.113.9/32"}, // a bare address IS its host prefix
		{"2001:db8::1/32", "2001:db8::/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"::ffff:1.1.1.1/120", "::ffff:1.1.1.0/120"},
		{"2001:0DB8:0000:0000:0000:0000:0000:0001/128", "2001:db8::1/128"},
		// Refused, and refused for a reason an operator can be told.
		{"193.0.0.0/33", ""},
		{"1.1.1.01/24", ""}, // a leading zero changes which address is meant
		{"1.1.1.1/024", ""},
		{"3333", ""}, // a bare number is ambiguous between an AS and an address
		{"", ""},
		// A zone id is not routable address space: netip would accept it as a
		// bare address and drop both the zone and any mask beside it, so
		// "fe80::1%eth0/64" would become "fe80::1/128" — a different resource
		// than the one typed. Both boundaries refuse it instead.
		{"fe80::1%eth0", ""},
		{"fe80::1%eth0/64", ""},
	}
	for _, c := range cases {
		p, err := parsePrefix(c.in)
		if c.want == "" {
			if err == nil {
				t.Errorf("parsePrefix(%q) = %q, want a refusal", c.in, p)
			}
			continue
		}
		if err != nil {
			t.Errorf("parsePrefix(%q) failed: %v", c.in, err)
			continue
		}
		if got := p.String(); got != c.want {
			t.Errorf("parsePrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
