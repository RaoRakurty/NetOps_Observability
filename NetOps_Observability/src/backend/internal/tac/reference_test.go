// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// reference_test.go — RULE ZERO, mechanised.
//
// Every id in ai/tac/classes.yaml's `detect:` blocks must ALREADY EXIST in this
// repository: a vmalert alert name, a correlation hypothesis template id, a
// protocoldiag signature or issue id, an Iris skill directory. The loader cannot
// check this (the ids live in other packages and in Python), so this test reads
// the real files and does.
//
// It exists because an invented detection rule is worse than a missing one: it
// is a rule that can never fire, in a taxonomy whose whole value is that it
// says out loud what it can and cannot recognise.

// repoRoot walks up from the package directory to the repository root
// (NetOps_Observability), so the test works from `go test ./...` anywhere.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "src", "config", "rules.yaml")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Skip("repository root not reachable from the test working directory")
	return ""
}

func readFileOrSkip(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("%s not readable: %v", path, err)
	}
	return string(b)
}

func TestEveryDetectionReferenceExists(t *testing.T) {
	root := repoRoot(t)
	c, err := Default()
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// vmalert alert names.
	alertRE := regexp.MustCompile(`(?m)^\s*-?\s*alert:\s*([A-Za-z0-9_]+)`)
	alerts := map[string]bool{}
	for _, f := range []string{"src/config/rules.yaml", "src/config/rules-scale-slo.yaml"} {
		for _, m := range alertRE.FindAllStringSubmatch(readFileOrSkip(t, filepath.Join(root, f)), -1) {
			alerts[m[1]] = true
		}
	}

	// correlation hypothesis template ids.
	hypRE := regexp.MustCompile(`sig\.ent\.[a-z0-9.-]+`)
	hyps := map[string]bool{}
	for _, m := range hypRE.FindAllString(readFileOrSkip(t, filepath.Join(root, "src/correlation/catalog.py")), -1) {
		hyps[strings.TrimSuffix(m, ".")] = true
	}

	// protocoldiag signature and issue ids.
	idRE := regexp.MustCompile(`ID:\s*"([a-z0-9-]+)"`)
	sigs := map[string]bool{}
	for _, m := range idRE.FindAllStringSubmatch(readFileOrSkip(t, filepath.Join(root, "src/backend/internal/protocoldiag/analyze.go")), -1) {
		sigs[m[1]] = true
	}
	issues := map[string]bool{}
	for _, m := range idRE.FindAllStringSubmatch(readFileOrSkip(t, filepath.Join(root, "src/backend/internal/protocoldiag/catalog.go")), -1) {
		issues[m[1]] = true
	}

	// Iris skills.
	skills := map[string]bool{}
	ents, err := os.ReadDir(filepath.Join(root, "src/backend/ai/skills"))
	if err != nil {
		t.Skipf("skills directory not readable: %v", err)
	}
	for _, e := range ents {
		if e.IsDir() {
			skills[e.Name()] = true
		}
	}

	check := func(class, kind string, have map[string]bool, want []string) {
		for _, id := range want {
			if !have[id] {
				t.Errorf("class %s references %s %q, which does not exist in this repository", class, kind, id)
			}
		}
	}
	for _, cl := range c.Classes() {
		check(cl.ID, "alert", alerts, cl.Detect.Alerts)
		check(cl.ID, "hypothesis template", hyps, cl.Detect.Hypotheses)
		check(cl.ID, "protocoldiag signature", sigs, cl.Detect.Signatures)
		check(cl.ID, "protocoldiag issue", issues, cl.Detect.Issues)
		check(cl.ID, "Iris skill", skills, cl.Detect.Skills)
	}
}

// TestEveryPlanProfileIsAKnownPlatform proves a plan file cannot claim a
// platform the vendorprofile registry does not carry.
func TestEveryPlanProfileIsAKnownPlatform(t *testing.T) {
	c, err := Default()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, d := range c.Dialects() {
		p, _ := c.PlanFor(d)
		if p.Profile == "" {
			t.Errorf("plan %s declares no vendorprofile id", d)
		}
		if DialectSlug(p.Profile) != d {
			t.Errorf("plan %s declares profile %q, which slugs to %q", d, p.Profile, DialectSlug(p.Profile))
		}
	}
}
