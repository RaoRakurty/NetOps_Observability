package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// architecture_guards_test.go — MECHANICAL enforcement of the CLAUDE.md rules
// that the 2026-07-21 audit found violated at class scale.
//
// Why source scanning rather than prose. The audit's one-line diagnosis was
// "remediation was applied to the instance and not the class": the flows lane
// learned type coercion and applogs did not; one ClickHouse write learned to
// check its result and nineteen did not. Prose in CLAUDE.md did not stop that,
// and a reviewer cannot hold 20 sibling call sites in their head. These tests
// fail the build on the NEXT instance of each class, which is the only thing
// that actually holds a line.
//
// These run inside `go test ./...`, which is already merge-blocking in
// .github/workflows/backend-ci.yml — so adding a guard here IS adding a gate.
// See kv_paths_test.go for the first guard in this family (absolute store keys).
//
// If a guard below fires on a legitimate new pattern, fix the pattern. If the
// pattern is genuinely correct, add it to the guard's allowlist WITH a reason —
// never delete the guard.

// stripComments removes // line comments so a guard never fires on the prose
// that EXPLAINS the banned pattern — these tests document the defect they
// prevent, and quoting it must not trip them.
func stripComments(src string) string {
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if idx := strings.Index(l, "//"); idx >= 0 {
			lines[i] = l[:idx]
		}
	}
	return strings.Join(lines, "\n")
}

// goSources returns every non-test .go file in this package directory, with
// comments stripped.
func goSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		out[name] = stripComments(string(b))
	}
	if len(out) < 50 {
		t.Fatalf("only %d source files scanned — the guard is not seeing the package", len(out))
	}
	return out
}

// TestNoVoidSaveLocked guards F-62/F-63: a persist function that returns nothing
// makes every handler above it STRUCTURALLY unable to report a failed write, so
// the API answers 200 for data that was never stored. Nine stores shipped that
// way. A save must return an error.
func TestNoVoidSaveLocked(t *testing.T) {
	voidSave := regexp.MustCompile(`func \([^)]+\) saveLocked\(\) \{`)
	for name, src := range goSources(t) {
		if loc := voidSave.FindString(src); loc != "" {
			t.Errorf("%s: %q returns nothing.\n"+
				"A persist function that cannot fail makes its handler unable to report a failed "+
				"write — the API returns 200 for data that never reached the store (audit F-62/F-63). "+
				"Return error, roll the in-memory change back, and propagate to a 5xx.", name, loc)
		}
	}
}

// TestSaveResultsAreChecked guards the other half of the same class: converting
// saveLocked to return an error achieves nothing if callers drop it on the
// floor. Go permits ignoring a returned error in statement position, so the
// compiler will not catch this — only this test will.
func TestSaveResultsAreChecked(t *testing.T) {
	// A bare `s.saveLocked()` on its own line, not part of `if err := ...`.
	unchecked := regexp.MustCompile(`(?m)^\s*[a-zA-Z_][a-zA-Z0-9_.]*\.saveLocked\(\)\s*$`)
	for name, src := range goSources(t) {
		for _, m := range unchecked.FindAllString(src, -1) {
			t.Errorf("%s: %q discards the persist result.\n"+
				"Check it and propagate: `if err := s.saveLocked(); err != nil { ... }`. "+
				"An unchecked save is the F-62 defect with extra steps.", name, strings.TrimSpace(m))
		}
	}
}

// TestNoSscanfIntParsing guards the parseIntStrict trap found 2026-07-21.
//
// fmt.Sscanf("%d") is NOT strict despite how it reads: it stops at the first
// character that does not fit the verb and reports success for what it
// consumed. "1e3" parsed as 1, "100x" as 100, "5 OR 1=1" as 5 — each silently
// becoming a DIFFERENT number than the caller sent, with no error. Use
// strconv.Atoi/ParseInt, which consume the whole string or fail.
func TestNoSscanfIntParsing(t *testing.T) {
	sscanfInt := regexp.MustCompile(`Sscanf\([^)]*"%d"`)
	for name, src := range goSources(t) {
		if m := sscanfInt.FindString(src); m != "" {
			t.Errorf("%s: %q — Sscanf(\"%%d\") accepts trailing garbage and reports success, "+
				"silently yielding a different number than the caller sent. Use strconv.Atoi.", name, m)
		}
	}
}

// TestBoundedQueryParamsFailClosed guards F-71 at the contract level: the
// shared bounded-int query parser must reject out-of-range and malformed input
// rather than substituting the default.
//
// The behavioural cases live in flows_test.go; this asserts the SIGNATURE,
// because reverting to a single return value is exactly how the fail-open
// behaviour would come back — and it would come back silently, since every
// existing call site would still compile if the error return were dropped.
func TestBoundedQueryParamsFailClosed(t *testing.T) {
	src, ok := goSources(t)["flows.go"]
	if !ok {
		t.Fatal("flows.go not found — intQuery may have moved; update this guard")
	}
	if !strings.Contains(src, "func intQuery(r *http.Request, key string, def, min, max int) (int, error)") {
		t.Error("intQuery must return (int, error) and fail closed on out-of-range/malformed input.\n" +
			"Returning only int means an out-of-range value silently becomes the default: measured " +
			"on /api/flows/top, limit=501 returned 20 rows and never an error, so a client " +
			"paginating by doubling renders a fraction of the traffic as the whole picture (F-71).")
	}
}
