// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package hardening

import (
	"regexp"
	"strings"
	"testing"
)

// controlTagShape is what a Controls entry may now be: a canonical NIST 800-53
// Rev5 control id and nothing else. Framework requirement ids (PCI-8.2.1) and
// invented benchmark sections (CIS-NET-9.3) are what this shape excludes.
var controlTagShape = regexp.MustCompile(`^[A-Z]{2}-[0-9]{1,2}(\([0-9]{1,2}\))?$`)

// TestControlTagsAreCanonical800_53Only is the regression for the bug the owner
// reported: because the Compliance page built its framework list from the
// distinct standards tags on findings, every `CIS-NET-x.y` section rendered as
// its own framework — thirty-odd "CIS versions" that do not exist — while HIPAA,
// which is a projection and never a tag, could never appear.
//
// Frameworks are now COMPUTED by projecting these control ids through
// internal/compliancemodel, so a framework a tenant sees is a framework that
// tenant enabled. A tag that is not a control id would put that back.
func TestControlTagsAreCanonical800_53Only(t *testing.T) {
	c := DefaultCatalog()
	check := func(kind, id string, tags []string) {
		t.Helper()
		if len(tags) == 0 {
			t.Errorf("%s %q carries no control tag", kind, id)
			return
		}
		for _, tag := range tags {
			if strings.HasPrefix(tag, "CIS-NET-") {
				t.Errorf("%s %q carries the invented benchmark tag %q — cite a real benchmark section in benchmark.go instead", kind, id, tag)
			}
			if !controlTagShape.MatchString(tag) {
				t.Errorf("%s %q: %q is not a canonical 800-53 control id; framework requirement ids belong in a compliancemodel crosswalk, not on a rule", kind, id, tag)
			}
		}
	}
	for _, r := range c.Rules() {
		check("rule", r.ID, r.Controls)
	}
	for _, p := range c.Probes() {
		check("probe", p.ID, p.Controls)
	}
}

// TestBenchmarkCitationsResolve pins the two halves of an honest citation: the
// rule id exists, and the section it names has a published heading in a
// benchmark whose taxonomy was actually read.
func TestBenchmarkCitationsResolve(t *testing.T) {
	c := DefaultCatalog()
	known := map[string]bool{}
	for _, r := range c.Rules() {
		known[r.ID] = true
	}
	for _, p := range c.Probes() {
		known[p.ID] = true
	}

	verified := map[string]Benchmark{}
	for _, b := range Benchmarks() {
		if b.ID == "" || b.Title == "" || b.Version == "" || b.Platform == "" {
			t.Errorf("benchmark descriptor is incomplete: %+v", b)
		}
		if !strings.HasPrefix(b.Version, "v") {
			t.Errorf("benchmark %q version %q should be the published vX.Y.Z form", b.ID, b.Version)
		}
		if b.SectionsVerified {
			verified[b.ID] = b
		} else if b.Note == "" {
			t.Errorf("benchmark %q claims no verified section taxonomy but says nothing about why", b.ID)
		}
	}
	if len(verified) == 0 {
		t.Fatal("no benchmark has a verified section taxonomy — the guard would pass vacuously")
	}

	cited := 0
	for ruleID := range ruleBenchmarkSections {
		if !known[ruleID] {
			t.Errorf("benchmark citation names %q, which is not a rule or probe in the catalog", ruleID)
			continue
		}
		refs := BenchmarkSections(ruleID)
		if len(refs) == 0 {
			t.Errorf("rule %q is listed in the citation table but resolves to no section", ruleID)
		}
		for _, ref := range refs {
			cited++
			b, ok := verified[ref.BenchmarkID]
			if !ok {
				t.Errorf("rule %q cites %q, whose section taxonomy is NOT verified — an unverified section number is an invented one",
					ruleID, ref.BenchmarkID)
				continue
			}
			if ref.Title == "" {
				t.Errorf("rule %q cites %s §%s with no published heading", ruleID, b.Label(), ref.Section)
			}
			// The Cisco IOS / IOS-XE taxonomy never exceeds top-level 3 (the
			// proof the old CIS-NET-5.1 / -9.3 tags were not Cisco sections).
			if plane := strings.SplitN(ref.Section, ".", 2)[0]; plane != "1" && plane != "2" && plane != "3" {
				t.Errorf("rule %q cites %s §%s — the Cisco benchmark has only planes 1, 2 and 3",
					ruleID, b.Label(), ref.Section)
			}
		}
	}
	if cited == 0 {
		t.Fatal("no rule cites a benchmark section — the guard would pass vacuously")
	}
	if got := BenchmarkSections("not-a-rule"); got != nil {
		t.Errorf("an unknown rule id must cite nothing, got %v", got)
	}
	if got := BenchmarkSections("no-control-plane-protection"); got != nil {
		t.Errorf("a concept with no published benchmark section must cite nothing, got %v", got)
	}
}
