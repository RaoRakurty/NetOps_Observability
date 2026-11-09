// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nlquery_test

// heldout_test.go — the held-out split of the NL query corpus (tracker 337
// N-H3). The model fallback's few-shot library is derived from this corpus, so
// these tests hold the line between what the model is shown and what it is
// scored on. The rule itself lives in internal/evalsplit.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/evalsplit"
	"netops/backend/internal/nlquery/modelc"
)

// nlqCorpus names this corpus in the split's hash.
const nlqCorpus = "nlquery"

// splitGroup keeps the turns of one scripted conversation together: each turn's
// prior_ast is the previous turn's answer, so a split inside a script would show
// the model part of a held-out conversation.
func (c *goldenCase) splitGroup() string {
	if c.Context.Script != "" {
		return "script:" + c.Context.Script
	}
	return c.ID
}

// split is the case's partition. A field turn holds out its whole script through
// TestHeldOutSplitKeepsScriptsTogether; loadCases has refused an unknown source.
func (c *goldenCase) split() evalsplit.Split {
	src := evalsplit.SourceSynthetic
	if c.Source != "" {
		src = evalsplit.Source(c.Source)
	}
	return evalsplit.Assign(nlqCorpus, c.splitGroup(), src)
}

// heldOutCases lists the held-out cases as the leak checks see them.
func heldOutCases(cases []*goldenCase) []evalsplit.Case {
	var out []evalsplit.Case
	for _, c := range cases {
		if c.split() == evalsplit.HeldOut {
			out = append(out, evalsplit.Case{ID: c.ID, Texts: append([]string{c.Question}, c.Paraphrases...)})
		}
	}
	return out
}

// exampleLeaks checks a few-shot library against the held-out cases. The test
// and its negative control share it, so the control proves this exact check.
func exampleLeaks(held []evalsplit.Case, lib []modelc.Example) []evalsplit.Leak {
	tuning := make([]evalsplit.Tuning, 0, len(lib))
	for _, e := range lib {
		tuning = append(tuning, evalsplit.Tuning{Where: "modelc/examples.v1.json", ID: e.ID, Text: e.Question})
	}
	return evalsplit.FindLeaks(held, tuning)
}

func TestHeldOutSplitIsReal(t *testing.T) {
	cases := loadCases(t)
	held := len(heldOutCases(cases))
	share := float64(held) / float64(len(cases))
	t.Logf("%d cases: %d dev, %d held out (%.1f %%)", len(cases), len(cases)-held, held, share*100)
	if share < 0.10 || share > 0.35 {
		t.Errorf("held-out share %.3f is far from %d %%: the split is not doing what it says", share, evalsplit.HeldOutPercent)
	}
	answerable := map[evalsplit.Split]int{}
	for _, c := range cases {
		if len(c.Expect.AST) > 0 {
			answerable[c.split()]++
		}
	}
	if answerable[evalsplit.Dev] == 0 || answerable[evalsplit.HeldOut] == 0 {
		t.Errorf("both splits need answerable cases: %v", answerable)
	}
}

func TestHeldOutSplitKeepsScriptsTogether(t *testing.T) {
	bySplit := map[string]evalsplit.Split{}
	fields := map[string]bool{}
	for _, c := range loadCases(t) {
		if c.Context.Script == "" {
			continue
		}
		if c.Source == string(evalsplit.SourceField) {
			fields[c.Context.Script] = true
		}
		if prev, ok := bySplit[c.Context.Script]; ok && prev != c.split() {
			t.Errorf("script %s: case %s is %s, an earlier turn is %s", c.Context.Script, c.ID, c.split(), prev)
		}
		bySplit[c.Context.Script] = c.split()
	}
	if len(bySplit) == 0 {
		t.Fatal("no scripted conversations found — the test is not looking at them")
	}
	for s := range fields {
		if bySplit[s] != evalsplit.HeldOut {
			t.Errorf("script %s has a field turn but is in the dev split", s)
		}
	}
}

// TestHeldOutCasesNeverReachTheExampleLibrary is the leak guard: nothing the
// model is shown as an example may be a held-out case, by id or by text.
func TestHeldOutCasesNeverReachTheExampleLibrary(t *testing.T) {
	held := heldOutCases(loadCases(t))
	lib := modelc.EmbeddedExamples()
	if len(lib) == 0 {
		t.Fatal("the example library did not load — the guard is checking nothing")
	}
	for _, l := range exampleLeaks(held, lib) {
		t.Error(l)
	}
}

// The guard's negative control: plant a held-out case in the library, by id and
// by reworded case, and the same check must report it.
func TestHeldOutLeakGuardCatchesAPlantedCase(t *testing.T) {
	held := heldOutCases(loadCases(t))
	if len(held) == 0 {
		t.Fatal("no held-out cases")
	}
	lib := modelc.EmbeddedExamples()
	byID := append(append([]modelc.Example{}, lib...), modelc.Example{ID: held[0].ID, Question: "reworded so only the id matches"})
	if len(exampleLeaks(held, byID)) == 0 {
		t.Error("a held-out id in the library was not reported")
	}
	byText := append(append([]modelc.Example{}, lib...), modelc.Example{ID: "renamed", Question: strings.ToUpper(held[0].Texts[0])})
	if len(exampleLeaks(held, byText)) == 0 {
		t.Error("a held-out question under another id was not reported")
	}
}

// The generator's rule can never select a held-out case, so a regeneration
// cannot reintroduce a leak.
func TestExampleSelectionExcludesHeldOut(t *testing.T) {
	selected := 0
	for _, c := range loadCases(t) {
		if !exampleCandidate(c) {
			continue
		}
		selected++
		if c.split() != evalsplit.Dev {
			t.Errorf("%s: selected for the library but is %s", c.ID, c.split())
		}
	}
	if selected == 0 {
		t.Fatal("the selection rule selects nothing")
	}
}

// knownContamination records fitting that predates the split (N-H3). The whole
// grammar was written against the whole corpus; this is the part a text scan can
// see. Entries are removed when the source changes, and never added to make the
// guard pass: rewording the source would hide the fact, not undo it.
var knownContamination = map[string]string{
	"dns-004|compile/compile.go": "the presence rule's comment quotes this question: the rule was written with it in view",
}

// TestHeldOutCasesAreAbsentFromSources scans what the model and the grammar are
// built from: the catalog the prompt is assembled from and every non-test file
// under internal/nlquery. A case id in a comment or a held-out question in a
// grammar table means someone fitted to that case.
func TestHeldOutCasesAreAbsentFromSources(t *testing.T) {
	held := heldOutCases(loadCases(t))
	scanned := 0
	var leaks []evalsplit.Leak
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
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
		if ext := filepath.Ext(path); ext != ".go" && ext != ".json" {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- walking this package's own source tree
		if err != nil {
			return err
		}
		scanned++
		leaks = append(leaks, evalsplit.FindLeaksInText(held, filepath.ToSlash(path), string(raw))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 10 {
		t.Fatalf("scanned %d files — the guard is not looking at the source tree", scanned)
	}
	unrecorded, stale := evalsplit.Recorded(leaks, knownContamination)
	for _, l := range unrecorded {
		t.Error(l)
	}
	for _, k := range stale {
		t.Errorf("knownContamination entry %q no longer occurs: remove it", k)
	}
}

func TestCapPerSplit(t *testing.T) {
	var dev, held []*goldenCase
	for _, c := range loadCases(t) {
		if c.split() == evalsplit.Dev {
			dev = append(dev, c)
		} else {
			held = append(held, c)
		}
	}
	mk := func(nDev, nHeld int) []phrasing {
		var out []phrasing
		for i := 0; i < nDev; i++ {
			out = append(out, phrasing{c: dev[i%len(dev)]})
		}
		for i := 0; i < nHeld; i++ {
			out = append(out, phrasing{c: held[i%len(held)]})
		}
		return out
	}
	for _, tc := range []struct{ nDev, nHeld, limit, wantDev, wantHeld int }{
		{100, 100, 60, 30, 30},
		{100, 5, 60, 55, 5},
		{5, 100, 60, 5, 55},
		{3, 4, 60, 3, 4},
		{100, 100, 1, 1, 0},
		{0, 100, 10, 0, 10},
	} {
		got := capPerSplit(mk(tc.nDev, tc.nHeld), tc.limit)
		if d, h := len(phrasingsOfSplit(got, evalsplit.Dev)), len(phrasingsOfSplit(got, evalsplit.HeldOut)); d != tc.wantDev || h != tc.wantHeld {
			t.Errorf("%+v: got dev %d, held %d", tc, d, h)
		}
	}
}
