// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chschema

import (
	"strings"
	"testing"
)

// S3 (log-time standard): every ClickHouse-backed SELECT renders datetimes as
// explicit-UTC RFC 3339 — never zone-less toString() strings a JS Date would
// parse as browser-local. (Moved from package main's ch_time_wire_test.go when
// the fragment moved here, 2026-07-27.)

func TestISOFragment(t *testing.T) {
	got := ISO("ts")
	want := "concat(replaceOne(toString(ts, 'UTC'), ' ', 'T'), 'Z')"
	if got != want {
		t.Fatalf("ISO(ts) = %q, want %q", got, want)
	}
	// Aggregates pass through as expressions.
	if !strings.Contains(ISO("max(fused_at)"), "toString(max(fused_at), 'UTC')") {
		t.Fatalf("ISO must accept aggregate expressions: %q", ISO("max(fused_at)"))
	}
}
