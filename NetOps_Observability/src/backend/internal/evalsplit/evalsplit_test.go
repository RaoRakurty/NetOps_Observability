// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package evalsplit

import (
	"fmt"
	"strings"
	"testing"
)

func TestParseSource(t *testing.T) {
	for in, want := range map[string]Source{"": SourceSynthetic, "synthetic": SourceSynthetic, "field": SourceField} {
		got, err := ParseSource(in)
		if err != nil || got != want {
			t.Errorf("ParseSource(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"feild", "FIELD", " field", "dev"} {
		if _, err := ParseSource(in); err == nil {
			t.Errorf("ParseSource(%q) must be refused", in)
		}
	}
}

func TestFieldCasesAreAlwaysHeldOut(t *testing.T) {
	for i := 0; i < 500; i++ {
		if got := Assign("c", fmt.Sprintf("id-%d", i), SourceField); got != HeldOut {
			t.Fatalf("field case id-%d assigned %s", i, got)
		}
	}
}

func TestUnknownSourceFailsClosed(t *testing.T) {
	for i := 0; i < 500; i++ {
		if got := Assign("c", fmt.Sprintf("id-%d", i), Source("mystery")); got != HeldOut {
			t.Fatalf("a case of unknown origin must never reach dev: id-%d assigned %s", i, got)
		}
	}
}

// The rule is a contract with every score recorded against it: a changed salt,
// modulus or percentage silently moves cases that were tuned on into the
// held-out set. These vectors were computed independently, with Python's
// hashlib, from the rule in the package doc. Never regenerate them to make this
// test pass.
func TestAssignVectorsArePinned(t *testing.T) {
	if HeldOutPercent != 20 {
		t.Fatalf("HeldOutPercent = %d: changing it contaminates the held-out set", HeldOutPercent)
	}
	for _, v := range []struct {
		corpus, group string
		want          Split
	}{
		{"nlquery", "sites-001", HeldOut},
		{"nlquery", "sites-002", Dev},
		{"nlquery", "docs-004", Dev},
		{"nlquery", "inject-005", Dev},
		{"nlquery", "metrics-010", Dev},
		{"nlquery", "N-S1", Dev},
		{"nlquery", "a", Dev},
		{"nlquery", "b", HeldOut},
		{"qa", "sites-001", HeldOut},
		{"qa", "sites-002", Dev},
		{"qa", "docs-004", Dev},
		{"qa", "inject-005", Dev},
		{"qa", "metrics-010", Dev},
		{"qa", "N-S1", HeldOut},
		{"qa", "a", Dev},
		{"qa", "b", Dev},
		{"incidents", "sites-001", Dev},
		{"incidents", "sites-002", Dev},
		{"incidents", "docs-004", Dev},
		{"incidents", "inject-005", Dev},
		{"incidents", "metrics-010", HeldOut},
		{"incidents", "N-S1", Dev},
		{"incidents", "a", HeldOut},
		{"incidents", "b", Dev},
	} {
		if got := Assign(v.corpus, v.group, SourceSynthetic); got != v.want {
			t.Errorf("Assign(%q, %q) = %s, pinned %s", v.corpus, v.group, got, v.want)
		}
	}
}

func TestAssignIsStableAndNearItsShare(t *testing.T) {
	const n = 20000
	held := 0
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("case-%d", i)
		a := Assign("corpus", id, SourceSynthetic)
		if a != Assign("corpus", id, SourceSynthetic) {
			t.Fatalf("%s: not deterministic", id)
		}
		if a == HeldOut {
			held++
		}
	}
	if share := float64(held) / n; share < 0.18 || share > 0.22 {
		t.Fatalf("held-out share %.3f is not near %d %%", share, HeldOutPercent)
	}
}

func TestValidSplit(t *testing.T) {
	for s, want := range map[string]bool{"dev": true, "heldout": true, "": false, "HeldOut": false, "test": false} {
		if got := ValidSplit(s); got != want {
			t.Errorf("ValidSplit(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"Show WAN loss, in Dallas?": "show wan loss in dallas",
		"  a--b  c ":                "a b c",
		"":                          "",
		"?!":                        "",
		"Düsseldorf CPU":            "düsseldorf cpu",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFindLeaks(t *testing.T) {
	held := []Case{{ID: "sites-007", Texts: []string{"Show WAN loss in Dallas.", "dallas wan loss"}}}

	clean := []Tuning{{Where: "lib", ID: "sites-001", Text: "Show WAN loss in Austin."}}
	if got := FindLeaks(held, clean); len(got) != 0 {
		t.Fatalf("no leak expected, got %v", got)
	}
	for name, tc := range map[string]Tuning{
		"same id":         {Where: "lib", ID: "sites-007", Text: "reworded"},
		"same question":   {Where: "lib", ID: "other", Text: "show wan loss in dallas"},
		"same paraphrase": {Where: "lib", ID: "other", Text: "DALLAS WAN LOSS!"},
	} {
		got := FindLeaks(held, []Tuning{tc})
		if len(got) != 1 || got[0].CaseID != "sites-007" || !strings.Contains(got[0].String(), "sites-007") {
			t.Errorf("%s: want one leak of sites-007, got %v", name, got)
		}
	}
	if got := FindLeaks(held, []Tuning{{Where: "lib", Text: ""}}); len(got) != 0 {
		t.Errorf("an empty entry is not a leak: %v", got)
	}
	if got := FindLeaks([]Case{{ID: "x", Texts: []string{"?!"}}}, []Tuning{{Where: "lib", Text: "..."}}); len(got) != 0 {
		t.Errorf("text that normalizes to nothing must not match: %v", got)
	}
}

func TestFindLeaksInText(t *testing.T) {
	held := []Case{{ID: "docs-004", Texts: []string{"How do I add a device?", "add device"}}}
	for name, text := range map[string]string{
		"id in a comment":    "// the floor is calibrated from docs-004 here",
		"question in prompt": `example: "how do I add a device" answers with the wizard`,
	} {
		if got := FindLeaksInText(held, "src", text); len(got) != 1 {
			t.Errorf("%s: want one leak, got %v", name, got)
		}
	}
	for name, text := range map[string]string{
		"a longer id":     "docs-0041 is another case",
		"a short phrase":  "you can add device groups",
		"a partial word":  "how do I add a devices",
		"unrelated":       "nothing to see",
		"text run broken": "how do I add a new device",
	} {
		if got := FindLeaksInText(held, "src", text); len(got) != 0 {
			t.Errorf("%s: want no leak, got %v", name, got)
		}
	}
}

func TestRecorded(t *testing.T) {
	leaks := []Leak{{CaseID: "a", Where: "x.go"}, {CaseID: "b", Where: "y.go"}}
	un, stale := Recorded(leaks, map[string]string{"a|x.go": "why", "c|z.go": "fixed since"})
	if len(un) != 1 || un[0].CaseID != "b" {
		t.Errorf("unrecorded = %v, want only b", un)
	}
	if len(stale) != 1 || stale[0] != "c|z.go" {
		t.Errorf("stale = %v, want only c|z.go", stale)
	}
	un, stale = Recorded(leaks, map[string]string{"a|other.go": "another file"})
	if len(un) != 2 || len(stale) != 1 {
		t.Errorf("a record covers one case in one source only: %v %v", un, stale)
	}
}
