// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// The runner half of SILENT-CRITICAL-1 (see internal/verify/truncation_test.go
// for the engine half): boundedBuf must RECORD that it dropped bytes so a
// truncated listing can never parse as a complete one.

import "testing"

// boundedBuf must RECORD that it dropped bytes. Before the fix it returned
// len(p), nil unconditionally, so a 256 KiB cap truncated a listing as
// invisibly as a timeout did.
func TestBoundedBufRecordsOverflow(t *testing.T) {
	b := &boundedBuf{cap: 16}
	if _, err := b.Write([]byte("0123456789")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if b.overflowed {
		t.Fatal("a write inside the cap must not report overflow")
	}
	if _, err := b.Write([]byte("abcdefghijklmno")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !b.overflowed {
		t.Error("the cap dropped bytes and did not record it — a truncated listing " +
			"parses as a complete one and becomes false refuting evidence")
	}
	if got := b.Len(); got != 16 {
		t.Errorf("buffer grew past its cap: %d", got)
	}
	// Writes after the cap is full must keep reporting overflow, not reset it.
	if _, err := b.Write([]byte("more")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !b.overflowed {
		t.Error("overflow flag was cleared by a later write")
	}
}
