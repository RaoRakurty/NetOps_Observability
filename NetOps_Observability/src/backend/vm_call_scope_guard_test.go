// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// vm_call_scope_guard_test.go — a STRUCTURAL guard, not a per-lane one.
//
// A table of correct VictoriaMetrics lanes is a snapshot: it says the lanes
// that exist today are scoped, and says nothing about the one somebody adds
// next week. This test walks the package source instead, finds every call into
// a VictoriaMetrics read helper, and fails on any that cannot carry the
// caller's boundary — so a new lane cannot be added unscoped without either
// turning this red or writing itself into the allowlist below, in a diff a
// reviewer reads.
//
// It exists because the per-lane guard missed exactly this. /api/paths/health
// ran eight fleet-wide baseline queries while serving tenant-scoped callers,
// and TestMetricsRoutesCarryCallerScope was pointed at "/api/rca/path/health",
// a route this server does not register: it skipped, quietly, for a year.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// vmUnscopedAllowlist names the ONLY files that may read VictoriaMetrics with
// no tenant boundary, and why. These are platform lanes with no HTTP caller:
// they read VictoriaMetrics' own self-metrics, which carry no tenant label and
// belong to no tenant. A file is not added here to make a test pass — it is
// added when the read genuinely has no principal to scope to.
var vmUnscopedAllowlist = map[string]string{
	"main.go":                  "the storage and telemetry meters: vm_data_size_bytes / vm_rows_inserted_total are VictoriaMetrics' own self-metrics, read on the platform path only",
	"path_health_baselines.go": "the precompute ticker: a background job with no caller, whose rows are written untagged and read back bounded to the caller's own paths",
}

// vmReadHelpers are the entry points that actually reach VictoriaMetrics.
var vmReadHelpers = []string{"vmInstantUnscoped", "vmInstantScoped", "vmRange", "vmQueryRangeByIf", "vmRangeByDst"}

// vmNilFilterExceptions are the exact expressions allowed to pass a literal nil
// filter set. Only the unscoped door's own body qualifies.
var vmNilFilterExceptions = map[string]bool{
	"return s.vmInstantScoped(ctx, query, nil)": true,
}

func packageGoSources(t *testing.T) map[string][]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string][]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = strings.Split(string(b), "\n")
	}
	if len(out) == 0 {
		t.Fatal("the sweep found no package sources — it would pass vacuously")
	}
	return out
}

// isVMCall reports whether the line CALLS helper (rather than declaring it).
func isVMCall(line, helper string) bool {
	if strings.Contains(line, "func (s *server) "+helper+"(") {
		return false
	}
	return regexp.MustCompile(`\b(?:s|srv|d\.srv|q\.s|w)\.` + helper + `\(`).MatchString(line)
}

func TestEveryVictoriaMetricsReadCarriesACallerBoundary(t *testing.T) {
	sources := packageGoSources(t)
	seenHelper := map[string]bool{}

	for file, lines := range sources {
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			for _, helper := range vmReadHelpers {
				if !isVMCall(line, helper) {
					continue
				}
				seenHelper[helper] = true

				// The explicitly unscoped door: platform lanes only.
				if helper == "vmInstantUnscoped" || helper == "vmRangeByDst" {
					if _, ok := vmUnscopedAllowlist[file]; !ok {
						t.Errorf("%s:%d calls %s, which reads VictoriaMetrics with NO tenant boundary.\n"+
							"  %s\n"+
							"  A lane that serves an HTTP caller must use vmInstantScoped with that caller's\n"+
							"  filters (s.metricsScopeFiltersFor, or the metricsScopeFilters derivation).\n"+
							"  If this read genuinely has no principal, add %s to vmUnscopedAllowlist with the reason.",
							file, i+1, helper, trimmed, file)
					}
					continue
				}

				// The scoped helpers, handed a literal nil: same thing wearing a
				// better name.
				if strings.Contains(line, ", nil)") && !vmNilFilterExceptions[trimmed] {
					t.Errorf("%s:%d passes a literal nil filter set to %s — that is a fleet-wide read with extra steps.\n  %s",
						file, i+1, helper, trimmed)
				}
			}
		}
	}

	// A sweep that matches nothing passes for the wrong reason.
	for _, helper := range vmReadHelpers {
		if !seenHelper[helper] {
			t.Errorf("the sweep found no call site for %s — its regex has drifted away from the code and the guard proves nothing", helper)
		}
	}
}
