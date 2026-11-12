// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// phrasing_heldout_test.go — the held-out split of the phrasing eval
// (testdata/phrasing_golden.json, scored by the root's
// iris_phrasing_eval_test.go). Its rules live in three places — the router
// (this package), the grammar and normaliser (internal/nlquery) and the data
// arm (root ai_*.go) — so the leak guard scans all three: a held-out id or
// utterance in any of them means a rule was fitted to the case it is meant to
// measure (N-H3).

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/evalsplit"
)

// PhrasingCorpus is the evalsplit corpus name of the phrasing eval.
const phrasingCorpus = "phrasing"

type phrasingItem struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Q      string `json:"q"`
}

func loadPhrasing(t *testing.T) []phrasingItem {
	t.Helper()
	raw, err := os.ReadFile("testdata/phrasing_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Items []phrasingItem `json:"items"`
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	return set.Items
}

func phrasingSplit(it phrasingItem) evalsplit.Split {
	src, err := evalsplit.ParseSource(it.Source)
	if err != nil {
		return evalsplit.HeldOut
	}
	return evalsplit.Assign(phrasingCorpus, it.ID, src)
}

func phrasingHeldOut(t *testing.T) []evalsplit.Case {
	t.Helper()
	var out []evalsplit.Case
	for _, it := range loadPhrasing(t) {
		if phrasingSplit(it) == evalsplit.HeldOut {
			out = append(out, evalsplit.Case{ID: it.ID, Texts: []string{it.Q}})
		}
	}
	return out
}

func TestPhrasingSplitIsReal(t *testing.T) {
	items := loadPhrasing(t)
	held := 0
	for _, it := range items {
		sp := phrasingSplit(it)
		if it.Source == string(evalsplit.SourceLab) && sp != evalsplit.Dev {
			t.Errorf("%s: a lab case is fixed against by construction and must be dev", it.ID)
		}
		if sp == evalsplit.HeldOut {
			held++
		}
	}
	t.Logf("phrasing: %d cases, %d held out", len(items), held)
	if len(items) < 120 {
		t.Errorf("the phrasing eval needs at least 120 utterances, has %d", len(items))
	}
	if share := float64(held) / float64(len(items)); share < 0.10 || share > 0.35 {
		t.Errorf("held-out share %.3f is far from %d %%", share, evalsplit.HeldOutPercent)
	}
}

// phrasingSources are the files the phrasing rules are tuned through.
func phrasingSources(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	add := func(path string) {
		raw, err := os.ReadFile(path) // #nosec G304 -- this module's own source tree
		if err != nil {
			t.Fatal(err)
		}
		out[filepath.ToSlash(path)] = string(raw)
	}
	for _, root := range []string{".", "../internal/nlquery"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(path, "_test.go") {
				return nil
			}
			switch filepath.Ext(path) {
			case ".go", ".md", ".yaml", ".yml", ".json":
				add(path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	roots, err := filepath.Glob("../ai_*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range roots {
		if !strings.HasSuffix(p, "_test.go") {
			add(p)
		}
	}
	return out
}

// phrasingKnownContamination: held-out utterances that were ALREADY in the
// sources, as canonical examples, before the phrasing eval existed (found by
// this guard when the set was written, 2026-11-12). They are kept and named, so
// the held-out score can be read with and without them; entries are removed
// when the source changes and never added to make a new leak pass.
var phrasingKnownContamination = map[string]string{
	"ph-hist-001|toolspec.go":         "a tool description's example question, older than the eval",
	"ph-hist-001|../ai_datasource.go": "a comment's example question, older than the eval",
	"ph-hist-001|orchestrator.go":     "the historical-intent rule's own example, older than the eval",
	"ph-hist-001|tools.go":            "a comment's example question, older than the eval",
	"ph-help-004|orchestrator.go":     "the product-intent rule's own example, older than the eval",
	"ph-ts-003|orchestrator.go":       "the playbook-intent rule's own example, older than the eval",
}

func TestPhrasingHeldOutCasesAreAbsentFromSources(t *testing.T) {
	held := phrasingHeldOut(t)
	srcs := phrasingSources(t)
	if len(srcs) < 50 {
		t.Fatalf("scanned %d files — the guard is not looking at the source tree", len(srcs))
	}
	var leaks []evalsplit.Leak
	for where, text := range srcs {
		leaks = append(leaks, evalsplit.FindLeaksInText(held, where, text)...)
	}
	unrecorded, stale := evalsplit.Recorded(leaks, phrasingKnownContamination)
	for _, l := range unrecorded {
		t.Error(l)
	}
	for _, k := range stale {
		t.Errorf("phrasingKnownContamination entry %q no longer occurs: remove it", k)
	}
}

// Negative control: a planted held-out id and utterance are reported.
func TestPhrasingLeakGuardCatchesAPlantedCase(t *testing.T) {
	held := phrasingHeldOut(t)
	if len(held) == 0 {
		t.Fatal("no held-out cases")
	}
	if len(evalsplit.FindLeaksInText(held, "planted", "// tuned against "+held[0].ID)) == 0 {
		t.Error("a held-out id in a source was not reported")
	}
	for _, h := range held {
		if len(strings.Fields(evalsplit.Normalize(h.Texts[0]))) >= 4 {
			if len(evalsplit.FindLeaksInText(held, "planted", `var x = "`+strings.ToUpper(h.Texts[0])+`"`)) == 0 {
				t.Error("a held-out utterance in a source was not reported")
			}
			return
		}
	}
	t.Fatal("no held-out utterance of four words or more to plant")
}
