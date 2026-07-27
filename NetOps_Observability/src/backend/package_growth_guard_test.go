package main

// package_growth_guard_test.go — a RATCHET on the flat `package main`.
//
// THE PROBLEM (2026-07-27 audit, item 9)
// CLAUDE.md §2 mandates /cmd /internal /pkg /api /plugins /config and forbids
// business logic in the entrypoint package. Reality: 296 non-test files and
// ~98k lines of business logic sit in ONE `package main`, and none of those
// directories exist (an empty, untracked cmd/ is the residue of an abandoned
// move). In a single package the compiler cannot enforce ANY boundary — every
// file can reach every other file's unexported state — so §13 "no cross-domain
// imports" and §4 "plugins cannot import core system code" are not merely
// unenforced, they are unenforceable.
//
// WHY IT IS NOT JUST STYLE
// This is the substrate that made the guard-scope bug possible. Because "the
// package" and "the whole product" were the same thing, a guard that scanned
// only the root directory LOOKED like it scanned everything — and its
// anti-vacuity floor passed comfortably on 296 files while 201 subpackage files
// (alerts/, notify/, collectors/, nms/, ai/) went unguarded for months, hiding
// three real defects. A flat package makes "scan everything" ambiguous.
//
// WHAT THIS GUARD IS, AND IS NOT
// It is a RATCHET, not a fix: it fails when the root package GROWS, forcing
// every new domain into a real subpackage from day one. It deliberately does
// NOT attempt the decomposition — that is a multi-sprint program (leaf domains
// first, one per PR, CI green at each step) and a half-migrated tree with
// imports pointing both ways is worse than either endpoint.
//
// HONEST LIMITATIONS (do not mistake this for the §2 rule being satisfied):
//   * existing root files can still grow without bound;
//   * a new subpackage can still import half of package main's behaviour by
//     having package main call INTO it, so coupling can still increase;
//   * it measures files, not dependencies.
// It buys time and stops the bleeding. The decomposition still has to happen.
//
// WORKFLOW WHEN THIS FAILS
//   * Adding a NEW domain? Put it in its own subpackage. That is the point.
//   * Genuinely extending an existing root file? Edit that file — the count is
//     unchanged and this guard stays quiet.
//   * MOVED files out of the root (the direction we want)? Lower the ceiling in
//     the same commit. It only ever goes down.

import (
	"os"
	"strings"
	"testing"
)

// rootPackageCeiling is the number of non-test .go files in the backend root
// package. THIS NUMBER MUST ONLY EVER DECREASE. Lowering it is the whole point;
// raising it defeats the ratchet.
//
//	2026-07-27  296  pinned
//	2026-07-27  290  internal/chschema extracted (6 ClickHouse schema/DDL files)
//	2026-07-27  289  internal/openapi (spec builder) + internal/totp (2FA primitive)
//	2026-07-27  284  internal/rca (5 pure analysis files: independence, observer registry,
//	                  path attribution, recovery, report icons)
//	2026-07-27  283  internal/vault (secret custody; storage+logging now INJECTED)
//	2026-07-27  283  internal/vuln + internal/compliance (~900 LOC of evaluation
//	                  moved; count unchanged because each left a thin *_http.go
//	                  handler behind — the ratchet measures files, not LOC)
const rootPackageCeiling = 283

func TestFlatPackageMainDoesNotGrow(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read backend root: %v", err)
	}
	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files = append(files, name)
	}

	switch {
	case len(files) > rootPackageCeiling:
		t.Errorf("package main grew to %d non-test files (ceiling %d).\n"+
			"CLAUDE.md §2 forbids business logic in the entrypoint package, and this "+
			"package already holds ~98k lines of it. New code belongs in a SUBPACKAGE "+
			"(a real boundary the compiler can enforce), not in the root.\n"+
			"If you genuinely extended an existing file, this guard would not have "+
			"fired — it counts files, so a new file here is a new domain in the wrong "+
			"place. If you MOVED files out, lower rootPackageCeiling in the same commit.",
			len(files), rootPackageCeiling)
	case len(files) < rootPackageCeiling:
		t.Errorf("package main shrank to %d non-test files (ceiling %d) — good, that is "+
			"the direction the §2 decomposition goes. Lower rootPackageCeiling to %d in "+
			"this commit so the ratchet holds at the new position.",
			len(files), rootPackageCeiling, len(files))
	}

	// Anti-vacuity: if the scan stops seeing the package, the guard has broken
	// rather than the decomposition having succeeded overnight.
	if len(files) < 50 {
		t.Fatalf("only %d root .go files seen — the guard is not reading the package", len(files))
	}
}
