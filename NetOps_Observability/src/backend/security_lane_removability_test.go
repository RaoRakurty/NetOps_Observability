package backend

// security_lane_removability_test.go — the REMOVABLE-MODULE guard for the
// Project 3 security PRODUCER (P3-EMIT).
//
// The security producer is a removable module: the platform must build, and
// every other test must pass, with it deleted. That promise decays the moment
// some unrelated file reaches for internal/hardening "just for one type", so it
// is enforced here mechanically rather than by convention.
//
// This file deliberately imports NOTHING security-specific — it reads source
// text — so it survives the very deletion it describes and keeps guarding the
// rule afterwards.
//
// THE REMOVAL RECIPE (kept in sync with internal/seclane's package doc):
//
//	rm -r internal/seclane internal/secbus internal/hardening \
//	      internal/threatlane internal/advisory
//	rm secapi/rules.go secapi/rules_test.go
//	rm security_lane_isolation_test.go security_lane_removability_test.go
//	delete every main.go line between a SECURITY-LANE-BEGIN marker and its
//	matching SECURITY-LANE-END
//
// internal/secfindings deliberately STAYS: it is the finding MODEL the secapi
// READ API (which is not part of the producer) serves, not producer code.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// securityProducerPkgs are the import paths that exist only to PRODUCE security
// evidence. Nothing outside the allowlist below may reference them.
var securityProducerPkgs = []string{
	"netops/backend/internal/secbus",
	"netops/backend/internal/hardening",
	"netops/backend/internal/threatlane",
	"netops/backend/internal/advisory",
	"netops/backend/internal/seclane",
}

// securityImportAllowlist is every file (by module-relative path) permitted to
// import a producer package. Adding an entry here is a deliberate act that
// EXTENDS the removal recipe above — do both in the same commit.
var securityImportAllowlist = map[string]bool{
	"main.go":                               true, // the wiring, inside SECURITY-LANE markers only
	"secapi/rules.go":                       true, // the catalog the read API serves
	"secapi/rules_test.go":                  true,
	"security_lane_isolation_test.go":       true,
	"security_lane_removability_test.go":    true,
	"internal/protocoldiag/protocoldiag.go": false, // (documented non-importer; comments only)
}

// securityAllowedDirs are the producer packages themselves — they may import
// each other freely.
var securityAllowedDirs = []string{
	"internal/secbus/", "internal/hardening/", "internal/threatlane/",
	"internal/advisory/", "internal/seclane/",
}

func TestSecurityProducerIsImportedOnlyFromTheAllowlistedFiles(t *testing.T) {
	files := secLaneGoFiles(t, ".")
	if len(files) < 400 {
		t.Fatalf("only %d source files scanned — the guard is not seeing the module", len(files))
	}
	offenders := map[string][]string{}
	for _, rel := range files {
		if securityImportAllowlist[rel] {
			continue
		}
		inProducer := false
		for _, dir := range securityAllowedDirs {
			if strings.HasPrefix(rel, dir) {
				inProducer = true
				break
			}
		}
		if inProducer {
			continue
		}
		src, err := os.ReadFile(rel) // #nosec G304 -- test walks the module's own tree
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		body := string(src)
		for _, pkg := range securityProducerPkgs {
			if strings.Contains(body, `"`+pkg+`"`) {
				offenders[rel] = append(offenders[rel], pkg)
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("the security PRODUCER is no longer removable — these files import it:\n%v\n"+
			"Either route the dependency through internal/seclane's injected Deps, or add the "+
			"file to securityImportAllowlist AND extend the removal recipe in this file's header "+
			"and in internal/seclane's package doc, in the same commit.", offenders)
	}
}

func TestMainReferencesTheSecurityLaneOnlyInsideRemovalMarkers(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	lines := strings.Split(string(src), "\n")

	depth, blocks := 0, 0
	var outside []string
	for i, ln := range lines {
		switch {
		case strings.Contains(ln, "SECURITY-LANE-BEGIN"):
			if depth != 0 {
				t.Fatalf("main.go:%d nested SECURITY-LANE-BEGIN — markers must not nest", i+1)
			}
			depth++
			blocks++
			continue
		case strings.Contains(ln, "SECURITY-LANE-END"):
			if depth != 1 {
				t.Fatalf("main.go:%d SECURITY-LANE-END without a matching BEGIN", i+1)
			}
			depth--
			continue
		}
		if depth > 0 {
			continue
		}
		if strings.Contains(ln, "seclane.") || strings.Contains(ln, "securityLane") ||
			strings.Contains(ln, "internal/seclane") {
			// A prose mention in a comment is fine; a reference in CODE is not,
			// because the removal recipe deletes only the marked blocks.
			if trimmed := strings.TrimSpace(ln); strings.HasPrefix(trimmed, "//") {
				continue
			}
			outside = append(outside, lines[i])
		}
	}
	if depth != 0 {
		t.Fatal("main.go has an unclosed SECURITY-LANE-BEGIN block")
	}
	if blocks < 5 {
		t.Fatalf("main.go carries only %d SECURITY-LANE blocks; the wiring needs the import, "+
			"the server field, the worker start, the routes and the metrics write", blocks)
	}
	if len(outside) > 0 {
		t.Fatalf("main.go references the security lane OUTSIDE a SECURITY-LANE marker block, so "+
			"deleting the marked blocks would leave main.go uncompilable:\n%s",
			strings.Join(outside, "\n"))
	}
}

// secLaneGoFiles lists module-relative .go paths, skipping vendor/ and testdata/.
func secLaneGoFiles(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case "vendor", "testdata", ".git", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		out = append(out, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}
