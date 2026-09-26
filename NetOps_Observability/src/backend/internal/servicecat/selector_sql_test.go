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
