// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

import (
	"fmt"
	"strings"
	"testing"
)

func TestDiffCountsAndRedacts(t *testing.T) {
	from := "hostname edge-01\nsnmp-server community " + canaryCommunity + " RO\ninterface Gi0/0\n ip address 10.0.0.1 255.255.255.0\n"
	to := "hostname edge-01\nsnmp-server community " + canaryCommunity + "-NEW RO\ninterface Gi0/0\n ip address 10.0.0.2 255.255.255.0\n shutdown\n"

	res := Diff(VendorCisco, from, to)
	if res.Added != 3 || res.Removed != 2 {
		t.Fatalf("added/removed = %d/%d, want 3/2\n%s", res.Added, res.Removed, res.Unified)
	}
	if strings.Contains(res.Unified, canaryCommunity) {
		t.Fatalf("SECRET LEAK: community survived into the diff:\n%s", res.Unified)
	}
	if !strings.Contains(res.Unified, "-"+" ip address 10.0.0.1") ||
		!strings.Contains(res.Unified, "+"+" ip address 10.0.0.2") {
		t.Fatalf("diff did not render the real change:\n%s", res.Unified)
	}
	if res.Truncated {
		t.Error("a small diff must not report truncation")
	}
}

func TestDiffIdenticalIsEmpty(t *testing.T) {
	cfg := "hostname a\ninterface Gi0/0\n"
	res := Diff(VendorCisco, cfg, cfg)
	if res.Added != 0 || res.Removed != 0 {
		t.Fatalf("identical configs produced a diff: %+v", res)
	}
	if strings.TrimSpace(res.Unified) != "" {
		t.Fatalf("identical configs produced hunks:\n%s", res.Unified)
	}
}

func TestDiffFromEmptyCountsEveryLine(t *testing.T) {
	to := "a\nb\nc\n"
	res := Diff(VendorCisco, "", to)
	if res.Added != 3 || res.Removed != 0 {
		t.Fatalf("first capture diff = +%d/-%d, want +3/-0", res.Added, res.Removed)
	}
}

// TestDiffIsBounded is the §9 contract: two very large, very different configs
// must produce a BOUNDED result quickly and say so, never an unbounded
// allocation and never a silently wrong diff.
func TestDiffIsBounded(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < MaxDiffLines+5000; i++ {
		fmt.Fprintf(&a, "interface Gi0/%d\n description A-%d\n", i, i)
		fmt.Fprintf(&b, "interface Te0/%d\n description B-%d\n", i, i)
	}
	res := Diff(VendorCisco, a.String(), b.String())
	if !res.Truncated {
		t.Fatal("an oversized, fully-different diff must report truncation")
	}
	lines := strings.Count(res.Unified, "\n")
	if lines > MaxDiffOutput+2 {
		t.Fatalf("unified output = %d lines, cap is %d", lines, MaxDiffOutput)
	}
}

// TestDiffDegradesHonestlyBeyondEditDistance: past the Myers D cap the result is
// a whole-block replace MARKED truncated — never a plausible-looking wrong diff.
func TestDiffDegradesHonestlyBeyondEditDistance(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < maxEditDistance*2; i++ {
		fmt.Fprintf(&a, "line-a-%d\n", i)
		fmt.Fprintf(&b, "line-b-%d\n", i)
	}
	res := Diff(VendorCisco, a.String(), b.String())
	if !res.Truncated {
		t.Fatal("beyond the edit-distance cap the diff must be marked truncated")
	}
	if res.Added == 0 || res.Removed == 0 {
		t.Fatalf("block replace must count both sides: +%d/-%d", res.Added, res.Removed)
	}
}

func TestDiffContextWindow(t *testing.T) {
	var a strings.Builder
	for i := 0; i < 200; i++ {
		fmt.Fprintf(&a, "line %d\n", i)
	}
	b := strings.Replace(a.String(), "line 100\n", "line 100 changed\n", 1)
	res := Diff(VendorCisco, a.String(), b)
	if res.Added != 1 || res.Removed != 1 {
		t.Fatalf("+%d/-%d, want +1/-1", res.Added, res.Removed)
	}
	// Only the change plus its context should be rendered, not all 200 lines.
	if n := strings.Count(res.Unified, "\n"); n > 2*diffContext+4 {
		t.Fatalf("context window not applied: %d rendered lines\n%s", n, res.Unified)
	}
}
