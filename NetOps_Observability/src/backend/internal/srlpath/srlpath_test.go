// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package srlpath

import (
	"regexp"
	"testing"
)

// The three spellings of ONE statement, which is the whole reason this package
// exists. Every renderer below must match all three; a helper that matched two
// would leave a rule silently dead on the third.
var threeSpellings = []struct {
	name string
	line string
}{
	{"flat `set / system` (the `info … flat` / commit form)", "set / system aaa authentication user bob password $y$REDACTED"},
	{"commit-audit `set /system` (lab, 2026-09-03)", "set /system aaa authentication user bob password $y$REDACTED"},
	{"gNMI-style path", "set /system/aaa/authentication/user/bob/password $y$REDACTED"},
}

// TestSepAndPathAreThePinnedFragments pins the rendered regexp SOURCE, not just
// its behaviour. Two packages build their SR Linux patterns from these strings;
// a change to either is a change to every rule in both, so it has to be
// deliberate rather than incidental.
func TestSepAndPathAreThePinnedFragments(t *testing.T) {
	if Sep != `[\s/]+` {
		t.Errorf("Sep = %q, want %q", Sep, `[\s/]+`)
	}
	if got, want := Path("system", "ntp"), `/\s*system[\s/]+ntp`; got != want {
		t.Errorf("Path = %q, want %q", got, want)
	}
	if got, want := Statement("system", "ntp"), `^\s*set\s+/\s*system[\s/]+ntp`; got != want {
		t.Errorf("Statement = %q, want %q", got, want)
	}
	// A single segment renders without a separator, and no renderer asserts its
	// own end — the caller appends the boundary it needs.
	if got, want := Path("system"), `/\s*system`; got != want {
		t.Errorf("Path(one) = %q, want %q", got, want)
	}
}

// TestStatementMatchesAllThreeSpellings is the invariant every rule in both
// consumers depends on.
func TestStatementMatchesAllThreeSpellings(t *testing.T) {
	re := regexp.MustCompile(Statement("system", "aaa", "authentication", "user", `\S+?`, "password") + Sep + `(\S+)`)
	for _, c := range threeSpellings {
		m := re.FindStringSubmatch(c.line)
		if m == nil {
			t.Errorf("%s: %q did not match", c.name, c.line)
			continue
		}
		if m[1] != "$y$REDACTED" {
			t.Errorf("%s: captured value = %q, want the password token", c.name, m[1])
		}
	}
}

// TestStatementDoesNotMatchAnotherKeyword — the spellings are permissive about
// separators, NOT about what the statement is. `delete` and `info` are different
// operations, and `sets` is not the keyword.
func TestStatementDoesNotMatchAnotherKeyword(t *testing.T) {
	re := regexp.MustCompile(Statement("system", "ntp", "admin-state", "enable") + `\b`)
	for _, line := range []string{
		"delete / system ntp admin-state enable",
		"info / system ntp admin-state enable",
		"sets / system ntp admin-state enable",
		"set system ntp admin-state enable", // Junos shape: no leading slash
		"# set / system ntp admin-state enable",
	} {
		if re.MatchString(line) {
			t.Errorf("%q matched an SR Linux `set /<path>` statement pattern", line)
		}
	}
	if !re.MatchString("set / system ntp admin-state enable") {
		t.Error("the canonical statement itself did not match")
	}
}

// TestIsStatement is the fail-closed test at the dialect boundary: it answers
// "is this text something an SR Linux rule can read at all".
func TestIsStatement(t *testing.T) {
	for _, c := range threeSpellings {
		if !IsStatement(c.line) {
			t.Errorf("%s: IsStatement(%q) = false", c.name, c.line)
		}
	}
	yes := []string{
		"set /  !!! a trailing comment on an otherwise bare set",
		"   set / system ntp admin-state enable", // an indented capture
		"set\t/system/ntp/admin-state enable",
	}
	for _, line := range yes {
		if !IsStatement(line) {
			t.Errorf("IsStatement(%q) = false, want true", line)
		}
	}
	no := []string{
		"",
		"   ",
		"set system ntp admin-state enable", // Junos
		"sets /system",
		"set=/system",
		"settings /system",
		"delete /system/ntp",
		"hostname leaf1",
		"interface Ethernet1",
		`{ "srl_nokia-system:system": {} }`,
	}
	for _, line := range no {
		if IsStatement(line) {
			t.Errorf("IsStatement(%q) = true, want false", line)
		}
	}
}
