// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package evalsplit

// fitting_path_test.go — commercial review item 13's second rule: "no operator
// feedback ever reaches a fitting path". The RCA verdict register judges the
// engine, so it can be scored against only if nothing is tuned from it. Today the
// only route out of the register is the root package's API and metrics. This
// holds that shape: a new importer must be reviewed, and the correlation engine
// must not read the register at all.

import (
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const rcaFeedbackPkg = "netops/backend/rcafeedback"

// importsOf lists the non-test Go directories under root importing target,
// relative to root. Vendored code is not ours.
func importsOf(t *testing.T, root, target string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == "vendor" || n == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range f.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				return err
			}
			if p == target {
				rel, err := filepath.Rel(root, filepath.Dir(path))
				if err != nil {
					return err
				}
				out[filepath.ToSlash(rel)] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOperatorFeedbackHasNoRouteIntoTuning(t *testing.T) {
	got := importsOf(t, filepath.Join("..", ".."), rcaFeedbackPkg)
	if !got["."] {
		t.Fatalf("the root package no longer imports %s (found %v) — the guard is not looking in the right place", rcaFeedbackPkg, got)
	}
	for dir := range got {
		if dir != "." {
			t.Errorf("%s imports the operator verdict register. Nothing outside the root API may read it: a package that tunes from it turns the held-out field split into training data (commercial review item 13)", dir)
		}
	}
}

func TestCorrelationEngineDoesNotReadTheVerdictRegister(t *testing.T) {
	root := filepath.Join("..", "..", "..", "correlation")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Skipf("correlation source not present (%v) — this runs in the full repo / CI", err)
	}
	scanned := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".py") || strings.HasPrefix(name, "test_") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, name)) // #nosec G304 -- a fixed source directory
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		if strings.Contains(string(raw), "rca_feedback") {
			t.Errorf("%s reads rca_feedback: operator verdicts must never reach the engine (commercial review item 13)", name)
		}
	}
	if scanned < 10 {
		t.Fatalf("scanned %d files — the guard is not looking at the engine", scanned)
	}
}
