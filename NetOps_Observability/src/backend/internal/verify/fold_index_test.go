// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package verify

// fold_index_test.go — the " by <user>" suffix trimmer must measure its offset
// on the string it is going to slice.
//
// stripBySuffix found " by " in a strings.ToLower COPY of a device line and
// then sliced the ORIGINAL. strings.ToLower is not length preserving, so one
// U+023A, U+023E or invalid UTF-8 byte in the line moved the offset. Far enough
// and the slice runs past the end of the string and PANICS, inside the bare
// worker goroutine engine.go starts per target: it takes the process with it.
// The same class panicked the API in internal/showparse.
//
// The line this runs on is device output, which is untrusted by contract.

import (
	"strings"
	"testing"
	"time"
)

var verifyFoldGrowers = []struct{ name, pad string }{
	{"U+023A", "Ⱥ"},
	{"U+023E", "Ⱦ"},
	{"invalid UTF-8", "\xff"},
}

func TestStripBySuffixSurvivesLowercaseGrowth(t *testing.T) {
	for _, g := range verifyFoldGrowers {
		t.Run(g.name, func(t *testing.T) {
			head := strings.Repeat(g.pad, 30) + " 2026-09-09 10:00:00"
			got := stripBySuffix(head + " by admin via cli")
			if want := strings.TrimSpace(head); got != want {
				t.Fatalf("stripBySuffix cut in the wrong place\n  got : %q\n  want: %q", got, want)
			}
		})
	}
}

// A line whose lower-cased copy grows past the original's length is the shape
// that panics rather than merely mis-cutting.
func TestStripBySuffixNeverSlicesPastTheString(t *testing.T) {
	for _, g := range verifyFoldGrowers {
		for n := 1; n <= 40; n++ {
			for _, tail := range []string{" by u", " BY u", "by", " by ", ""} {
				_ = stripBySuffix(strings.Repeat(g.pad, n) + " x" + tail) // must not panic
			}
		}
	}
}

// The whole path: a device that prints one of those bytes on its change line
// must not take the verify worker down with it.
func TestConfigChangeParsingSurvivesAdversarialDeviceBytes(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	for _, g := range verifyFoldGrowers {
		t.Run(g.name, func(t *testing.T) {
			txt := "Building configuration...\n" +
				"! Last configuration change at " + strings.Repeat(g.pad, 30) + " 10:00:00 UTC Wed Sep 9 2026 by admin\n"
			status, observed := parseVerifyModuleOutput("ssh_config_change", "cisco", txt, now, CaseContext{})
			if status == "" {
				t.Fatalf("no status returned: %q", observed)
			}
		})
	}
}
