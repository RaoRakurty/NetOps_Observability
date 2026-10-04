// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// golden_nav_coverage_test.go — N-G1 (tracker 337): every console screen has a
// golden question, and the corpus answers it.
//
// The list of screens is not written down here. It is READ from the frontend's
// navigation tree (src/frontend/src/nav.tsx, through the same extractor
// docs_routes_links_test.go uses), so the count is mechanical:
//
//   - every nav leaf: "section/leaf";
//   - every in-page view a leaf declares in subItems: "section/leaf/sub" —
//     except a sub-item that carries its own `route:`, which is a link to
//     another leaf (Cloud → Cloud Logs opens Explore → Logs) and is covered
//     by that leaf's own item.
//
// A golden docs item claims a screen with its "nav" field. A new screen with no
// item, an item naming a screen that no longer exists, or a screen whose every
// item misses at hit@3 fails here — so "Iris can answer a question about every
// page" stays a gate, not a count someone keeps by hand.

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// navCoverageTargets returns every screen that needs a golden item, sorted.
func navCoverageTargets(idx *navIndex) []string {
	var out []string
	for section, leaves := range idx.leaves {
		for leaf := range leaves {
			out = append(out, section+"/"+leaf)
			for sub := range idx.subs[section+"/"+leaf] {
				key := section + "/" + leaf + "/" + sub
				if _, linksElsewhere := idx.subRoutes[key]; linksElsewhere {
					continue
				}
				out = append(out, key)
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestNavCoverageTargetsExtracted keeps the coverage gate from passing
// vacuously: the extractor must find the tree, the in-page views, and the
// sub-items that only link elsewhere.
func TestNavCoverageTargetsExtracted(t *testing.T) {
	idx := loadNavIndex(t)
	targets := navCoverageTargets(idx)
	if len(targets) < 90 {
		t.Fatalf("only %d nav coverage targets extracted — the extractor is not reading the tree", len(targets))
	}
	have := map[string]bool{}
	for _, k := range targets {
		have[k] = true
	}
	for _, want := range []string{
		"overview/home", "platform/quarantine",
		"operations/digital-experience/journeys", "infrastructure/applications/appmap",
		"operations/cloud/datasources", "admin/api/token",
	} {
		if !have[want] {
			t.Errorf("coverage target %s not extracted", want)
		}
	}
	// A sub-item with its own route is a link, not a view of its leaf.
	for _, linked := range []string{"operations/cloud/logs", "analytics/dashboards/device-metric"} {
		if have[linked] {
			t.Errorf("%s carries its own route in nav.tsx and must not be a coverage target", linked)
		}
		if idx.subRoutes[linked] == "" {
			t.Errorf("%s: the extractor lost its route override", linked)
		}
	}
	t.Logf("nav coverage targets: %d", len(targets))
}

// TestGoldenCoversEveryNavLeaf — one golden question per screen, each naming a
// real screen, and for every screen at least one of its questions retrieves an
// accepted page in the top three.
func TestGoldenCoversEveryNavLeaf(t *testing.T) {
	gs := loadGolden(t)
	idx := loadNavIndex(t)
	ix := goldenIndex()
	targets := navCoverageTargets(idx)
	isTarget := map[string]bool{}
	for _, k := range targets {
		isTarget[k] = true
	}

	byNav := map[string][]GoldenItem{}
	for _, it := range gs.Category(GoldenDocs) {
		if it.Nav == "" {
			continue
		}
		if !isTarget[it.Nav] {
			t.Errorf("%s names nav %q, which is not a screen in nav.tsx — renamed, removed, or a sub-item that links elsewhere", it.ID, it.Nav)
			continue
		}
		byNav[it.Nav] = append(byNav[it.Nav], it)
	}

	missing, unanswered := 0, 0
	for _, key := range targets {
		items := byNav[key]
		if len(items) == 0 {
			missing++
			t.Errorf("nav screen %s has no golden docs question — add one to docs/ai/golden-examples/golden-qa.json with \"nav\": %q", key, key)
			continue
		}
		answered := false
		for _, it := range items {
			if hitSlugs(ix.Search(it.Question, 3), it.Expect.Slugs, 3) {
				answered = true
				break
			}
		}
		if !answered {
			unanswered++
			t.Errorf("nav screen %s: none of its golden questions retrieves an accepted page in the top 3 (%s: %q)", key, items[0].ID, items[0].Question)
		}
	}
	t.Logf("nav screens %d, covered %d, unanswered %d", len(targets), len(targets)-missing, unanswered)
}

// TestLoadGoldenSetValidatesNav — a malformed or misplaced nav address fails
// loading rather than silently counting toward (or escaping) coverage.
func TestLoadGoldenSetValidatesNav(t *testing.T) {
	write := func(t *testing.T, item string) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "golden.json")
		if err := os.WriteFile(p, []byte(`{"version":1,"items":[`+item+`]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for name, tc := range map[string]struct {
		item string
		ok   bool
	}{
		"leaf":      {`{"id":"a","category":"docs","question":"q","expect":{"slugs":["s"]},"nav":"operations/alerts"}`, true},
		"sub-item":  {`{"id":"a","category":"docs","question":"q","expect":{"slugs":["s"]},"nav":"operations/cloud/resources"}`, true},
		"no nav":    {`{"id":"a","category":"docs","question":"q","expect":{"slugs":["s"]}}`, true},
		"one seg":   {`{"id":"a","category":"docs","question":"q","expect":{"slugs":["s"]},"nav":"operations"}`, false},
		"four segs": {`{"id":"a","category":"docs","question":"q","expect":{"slugs":["s"]},"nav":"a/b/c/d"}`, false},
		"hash":      {`{"id":"a","category":"docs","question":"q","expect":{"slugs":["s"]},"nav":"#/operations/alerts"}`, false},
		"upper":     {`{"id":"a","category":"docs","question":"q","expect":{"slugs":["s"]},"nav":"Operations/Alerts"}`, false},
		"traversal": {`{"id":"a","category":"docs","question":"q","expect":{"slugs":["s"]},"nav":"operations/../admin"}`, false},
		"not docs":  {`{"id":"a","category":"intent","question":"q","expect":{"intent":"x"},"nav":"operations/alerts"}`, false},
		"known gap": {`{"id":"a","category":"docs","question":"q","expect":{"slugs":["s"]},"nav":"operations/alerts","known_gap":true}`, false},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadGoldenSet(write(t, tc.item))
			if (err == nil) != tc.ok {
				t.Fatalf("LoadGoldenSet ok=%v, want ok=%v (err %v)", err == nil, tc.ok, err)
			}
		})
	}
}
