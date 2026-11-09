// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// golden_heldout_test.go — the held-out split of the two corpora in this package,
// golden-qa.json and the golden incident corpus (tracker 337 N-H3). The rule is
// in internal/evalsplit.

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/evalsplit"
	"netops/backend/internal/irisgate"
)

// goldenHeldOut lists the held-out cases of both corpora.
func goldenHeldOut(t *testing.T) []evalsplit.Case {
	t.Helper()
	var out []evalsplit.Case
	for _, it := range loadGolden(t).Items {
		if it.Split() == evalsplit.HeldOut {
			out = append(out, evalsplit.Case{ID: it.ID, Texts: []string{it.Question}})
		}
	}
	cases := loadGoldenIncidents(t)
	for i := range cases {
		if cases[i].split() == evalsplit.HeldOut {
			out = append(out, evalsplit.Case{ID: cases[i].ID, Texts: []string{cases[i].Question}})
		}
	}
	return out
}

// sourceLeaks scans one source file. The test and its negative control share it.
func sourceLeaks(held []evalsplit.Case, where, text string) []evalsplit.Leak {
	return evalsplit.FindLeaksInText(held, where, text)
}

func TestGoldenSplitsAreReal(t *testing.T) {
	items := loadGolden(t).Items
	heldQA := 0
	for _, it := range items {
		if it.Split() == evalsplit.HeldOut {
			heldQA++
		}
	}
	cases := loadGoldenIncidents(t)
	heldInc := 0
	for i := range cases {
		if cases[i].split() == evalsplit.HeldOut {
			heldInc++
		}
	}
	t.Logf("golden-qa: %d items, %d held out; incidents: %d cases, %d held out", len(items), heldQA, len(cases), heldInc)
	if share := float64(heldQA) / float64(len(items)); share < 0.10 || share > 0.35 {
		t.Errorf("golden-qa held-out share %.3f is far from %d %%", share, evalsplit.HeldOutPercent)
	}
	if heldInc == 0 || heldInc == len(cases) {
		t.Errorf("the incident corpus needs cases in both splits: %d of %d held out", heldInc, len(cases))
	}
}

// knownContamination records fitting that predates the split (N-H3). Entries are
// removed when the source changes, and never added to make the guard pass:
// rewording the source would hide the fact, not undo it.
var knownContamination = map[string]string{
	"tool-009|orchestrator.go": "a routing comment quotes this question: the rule was written with it in view",
}

// TestGoldenHeldOutCasesAreAbsentFromSources is the leak guard: every non-test
// file under ai/ (prompts, doctrine, skills) is what Iris is tuned through. A
// held-out case id or question there means someone fitted to that case.
func TestGoldenHeldOutCasesAreAbsentFromSources(t *testing.T) {
	held := goldenHeldOut(t)
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
		switch filepath.Ext(path) {
		case ".go", ".md", ".yaml", ".yml", ".json":
		default:
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 -- walking this package's own source tree
		if err != nil {
			return err
		}
		scanned++
		leaks = append(leaks, sourceLeaks(held, filepath.ToSlash(path), string(raw))...)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 20 {
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

// The guard's negative control: a held-out id and a held-out question planted in
// a source must be reported by the same check.
func TestGoldenHeldOutLeakGuardCatchesAPlantedCase(t *testing.T) {
	held := goldenHeldOut(t)
	if len(held) == 0 {
		t.Fatal("no held-out cases")
	}
	if len(sourceLeaks(held, "planted", "// tuned against "+held[0].ID+" here")) == 0 {
		t.Error("a held-out id in a source was not reported")
	}
	for _, h := range held {
		if len(strings.Fields(evalsplit.Normalize(h.Texts[0]))) >= 4 {
			if len(sourceLeaks(held, "planted", `example: "`+strings.ToUpper(h.Texts[0])+`"`)) == 0 {
				t.Error("a held-out question in a source was not reported")
			}
			return
		}
	}
	t.Fatal("no held-out question long enough to plant")
}

func TestLoadGoldenSetRefusesAnUnknownSource(t *testing.T) {
	p := filepath.Join(t.TempDir(), "g.json")
	raw := `{"version":1,"items":[{"id":"d1","category":"docs","question":"q","source":"feild","expect":{"slugs":["s"]}}]}`
	if err := os.WriteFile(p, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGoldenSet(p); err == nil {
		t.Fatal("a misspelt source must be refused, or a field case could land in dev")
	}
}

func TestFieldItemsAreHeldOut(t *testing.T) {
	if (GoldenItem{ID: "any", Source: "field"}).Split() != evalsplit.HeldOut {
		t.Error("a field golden item must be held out")
	}
	c := goldenIncidentCase{ID: "any", Source: "field"}
	if c.split() != evalsplit.HeldOut {
		t.Error("a field incident case must be held out")
	}
}

// §3a: an eval fixture holds one tenant's data unless the case IS a cross-tenant
// isolation case.
func TestGoldenIncidentFixturesDoNotMixTenants(t *testing.T) {
	cases := loadGoldenIncidents(t)
	multi := 0
	for i := range cases {
		c := &cases[i]
		if len(c.Tenants) <= 1 {
			continue
		}
		multi++
		if c.Category != "cross_tenant_alias" {
			t.Errorf("%s: %d tenants in a %s case; only cross_tenant_alias may mix tenants", c.ID, len(c.Tenants), c.Category)
		}
	}
	if multi == 0 {
		t.Fatal("no multi-tenant case found — the isolation cases are gone or the guard is not looking")
	}
}

func TestGoldenIncidentMeasuresAreSplit(t *testing.T) {
	ms := goldenIncidentMeasures([]goldenCaseResult{
		{Category: "log_injection", Split: "dev", Result: "PASS"},
		{Category: "log_injection", Split: "heldout", Result: "XFAIL"},
		{Category: "cross_tenant_alias", Split: "dev", Result: "PASS"},
		{Category: "cross_tenant_alias", Split: "heldout", Result: "FAIL"},
		{Category: "dual_failure", Split: "heldout", Result: "FAIL"},
	})
	want := map[string]irisgate.Measure{
		"injection/dev":        {OK: 1, Total: 1},
		"injection/heldout":    {OK: 0, Total: 1},
		"cross_tenant/dev":     {Bad: 0, Total: 1},
		"cross_tenant/heldout": {Bad: 1, Total: 1},
	}
	if len(ms) != len(want) {
		t.Fatalf("%d measures, want %d: %+v", len(ms), len(want), ms)
	}
	for _, m := range ms {
		w, ok := want[m.Gate+"/"+m.Split]
		if !ok || m.OK != w.OK || m.Total != w.Total || m.Bad != w.Bad {
			t.Errorf("%s/%s = ok %d total %d bad %d, want %+v", m.Gate, m.Split, m.OK, m.Total, m.Bad, w)
		}
	}
}
