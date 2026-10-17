// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package servicecat

import "testing"

// A tenant-authored value ending in a backslash must not escape its own
// closing quote (ClickHouse reads backslash escapes inside literals).
func TestSQLStringLiteralEscapesBackslashAndQuote(t *testing.T) {
	cases := map[string]string{
		`plain`:         `'plain'`,
		`o'brien`:       `'o\'brien'`,
		`x\`:            `'x\\'`,
		`a\' OR 1=1 --`: `'a\\\' OR 1=1 --'`,
	}
	for in, want := range cases {
		if got := SQLStringLiteral(in); got != want {
			t.Errorf("SQLStringLiteral(%q) = %s, want %s", in, got, want)
		}
	}
}

// A service is matched on BOTH halves of its conversations: the request half
// (service port/address as destination) and the reply half (as source).
func TestBuildSelectorConditionMatchesBothDirections(t *testing.T) {
	got, ok := BuildSelectorCondition(map[string]any{
		"ports":        []any{443.0, "8443"},
		"dst_prefixes": []any{"10.0.0.0/8"},
		"protocols":    []any{6.0},
	})
	want := "(dst_port IN (443,8443) OR src_port IN (443,8443)" +
		" OR isIPAddressInRange(dst_addr, '10.0.0.0/8') OR isIPAddressInRange(src_addr, '10.0.0.0/8')" +
		" OR proto IN (6))"
	if !ok || got != want {
		t.Fatalf("got %q,%v\nwant %q", got, ok, want)
	}
}

// Untrusted input never reaches the SQL: out-of-range ports, non-CIDR
// prefixes and injection attempts are dropped; a spec left with nothing is
// unattributed rather than "match everything".
func TestBuildSelectorConditionRejectsHostileSpecs(t *testing.T) {
	for _, spec := range []map[string]any{
		{},
		{"ports": []any{-1.0, 70000.0, "x"}},
		{"dst_prefixes": []any{"10.0.0.0/8') OR 1=1 --", "not-a-prefix"}},
		{"protocols": []any{256.0}},
		{"src_prefixes": []any{"10.0.0.0/8"}}, // unknown key: not acted on
	} {
		if c, ok := BuildSelectorCondition(spec); ok || c != "" {
			t.Errorf("spec %v produced %q", spec, c)
		}
	}
}
