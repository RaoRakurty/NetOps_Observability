// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/lex"
	"netops/backend/internal/nlquery/resolve"
)

// ruleFragments are letter runs inside this package's regular expressions
// that are suffixes or stems, not words an operator types (deploy(?:ed|ment)).
var ruleFragments = map[string]bool{
	"ment": true, "ments": true, "couldn": true,
	// Site names the actor guard (isKnownWord) refuses as actor names. Names
	// are never vocabulary: a misspelt name is OFFERED (rung 6b), never
	// auto-corrected.
	"dallas": true, "austin": true,
}

var (
	rawRegexRe = regexp.MustCompile("regexp\\.MustCompile\\(`([^`]*)`\\)")
	escapeRe   = regexp.MustCompile(`\\[a-zA-Z]`)
	classRe    = regexp.MustCompile(`\[[^\]]*\]`)
	atomRe     = regexp.MustCompile(`[a-z]+\??`)
)

// ruleWords extracts the whole words the package's regular expressions
// read: letter runs of four or more, bounded by non-letters, with an optional
// trailing "s?" read as the singular and the plural.
func ruleWords(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		raw, err := os.ReadFile(f) // #nosec G304 -- this package's own source
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range rawRegexRe.FindAllStringSubmatch(string(raw), -1) {
			src := classRe.ReplaceAllString(escapeRe.ReplaceAllString(m[1], " "), " ")
			for _, loc := range atomRe.FindAllStringIndex(src, -1) {
				a := src[loc[0]:loc[1]]
				before, after := byte(' '), byte(' ')
				if loc[0] > 0 {
					before = src[loc[0]-1]
				}
				if loc[1] < len(src) {
					after = src[loc[1]]
				}
				// A run glued to a group or an optional letter is a stem or
				// a suffix ("neighbou?rs?", "deploy(?:ed|ment)").
				if after == '(' || before == ')' || strings.Count(a, "?") > 0 && !strings.HasSuffix(a, "s?") {
					continue
				}
				w := strings.TrimSuffix(a, "?")
				if strings.HasSuffix(a, "s?") {
					w = strings.TrimSuffix(w, "s")
				}
				if len(w) >= lex.MinTypoLen && !ruleFragments[w] {
					seen[w] = true
				}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for w := range seen {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}

// Every word a grammar rule reads is in the closed vocabulary, so the typo
// repair can never "correct" one rule word into another. A new rule word
// that fails here belongs in grammarWords.
func TestVocabularyCoversEveryRuleWord(t *testing.T) {
	v := Vocabulary(cat)
	words := ruleWords(t)
	if len(words) < 150 {
		t.Fatalf("found only %d rule words — the scan is not reading the rules", len(words))
	}
	for _, w := range words {
		if !v.Has(w) {
			t.Errorf("rule word %q is not in the grammar's vocabulary", w)
		}
	}
}

// A misspelt vocabulary word is repaired AND disclosed; the query is exactly
// the plain question's.
func TestTypoRepairIsDisclosed(t *testing.T) {
	plain := run(t, "show cpu on edge-1", cx)
	r := run(t, "shwo cpu on edge-1", cx)
	if r.AST == nil || r.AST.Hash() != plain.AST.Hash() {
		t.Fatalf("shwo must compile like show: %+v", r)
	}
	if len(r.Readings) != 1 || r.Readings[0] != (lex.Reading{From: "shwo", To: "show", Kind: lex.KindTypo}) {
		t.Fatalf("the repair must be disclosed: %+v", r.Readings)
	}
	if r := run(t, "show cpu on edge-1", cx); len(r.Readings) != 0 {
		t.Errorf("nothing repaired, nothing disclosed: %+v", r.Readings)
	}
}

// A misspelt action is still an action.
func TestMisspeltActionIsDeclined(t *testing.T) {
	for _, q := range []string{"restrat edge-1", "plese reboot edge-1"} {
		if r := run(t, q, cx); r.Decline != DeclineNotAQuery {
			t.Errorf("%q must be declined, got %+v", q, r)
		}
	}
}

// A misspelt NAME is never repaired: it is offered as a did-you-mean from the
// caller's own scope and the question stays not understood.
func TestMisspeltNameIsOfferedNotApplied(t *testing.T) {
	r := run(t, "open incidents at dalas", cx)
	if r.AST != nil || !r.Unparsed {
		t.Fatalf("a fuzzy name must never be applied: %+v", r)
	}
	if len(r.DidYouMean) != 1 || r.DidYouMean[0].Word != "dalas" || len(r.DidYouMean[0].Refs) != 1 {
		t.Fatalf("did-you-mean = %+v", r.DidYouMean)
	}
	ref := r.DidYouMean[0].Refs[0]
	if ref.EntityID != "site:dfw-hq" || !ref.NeedsConfirmation {
		t.Fatalf("candidate = %+v", ref)
	}
	if len(r.Readings) != 0 {
		t.Fatalf("a name is not a reading: %+v", r.Readings)
	}
}

// Free-text values are data: an owner's name is copied as typed, never
// "corrected" into a vocabulary word.
func TestValuesAreNeverRepaired(t *testing.T) {
	r := run(t, "show incidents owned by Netwrk Team this week", cx)
	if r.AST == nil || len(r.AST.Filters) == 0 || r.AST.Filters[len(r.AST.Filters)-1].Values[0] != "Netwrk Team" {
		t.Fatalf("owner value must be kept as typed: %+v", r.AST)
	}
	for _, rd := range r.Readings {
		if rd.From == "netwrk" {
			t.Fatalf("a value word was repaired: %+v", rd)
		}
	}
}

// A word the caller's resolver places is never repaired, even when it sits
// one edit from a vocabulary word.
func TestResolvableWordsAreNeverRepaired(t *testing.T) {
	cc := Compiler{Cat: cat, R: resolve.Resolver{Cat: cat, L: lkWith{names: []resolve.Named{{Type: "device", ID: "device:shwo", Names: []string{"shwo"}}}}}}
	r, err := cc.Compile(context.Background(), "cpu on shwo", cx)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Readings) != 0 || r.AST == nil || len(r.AST.Refs) != 1 || r.AST.Refs[0].ID != "device:shwo" {
		t.Fatalf("a visible name must stay a name: %+v", r)
	}
}

type lkWith struct{ names []resolve.Named }

func (lkWith) Aliases(context.Context) ([]resolve.Alias, error) { return nil, nil }
func (l lkWith) Inventory(context.Context, []string) ([]resolve.Named, error) {
	return l.names, nil
}
func (lkWith) Visible(context.Context, string, string) (bool, error) { return false, nil }

// The generated word table: an inflection or an en-GB spelling of a catalog
// word reads as that word (not a reinterpretation, so no reading); a vendor's
// VRF word is vocabulary, never "repaired".
func TestGeneratedVariantsReadAsTheCatalogWord(t *testing.T) {
	for _, c := range []struct{ variant, plain string }{
		{"show latencies on edge-1", "show latency on edge-1"},
		{"interface utilisation on edge-1", "interface utilization on edge-1"},
	} {
		v, p := run(t, c.variant, cx), run(t, c.plain, cx)
		if p.AST == nil || v.AST == nil || v.AST.Hash() != p.AST.Hash() {
			t.Errorf("%q must compile like %q: %+v vs %+v", c.variant, c.plain, v.AST, p.AST)
		}
		if len(v.Readings) != 0 {
			t.Errorf("%q: a variant is the same word, not a reading: %+v", c.variant, v.Readings)
		}
	}
	voc := Vocabulary(cat)
	for _, term := range []string{"routing-instance", "vprn", "vrf-lite"} {
		if !voc.Has(term) {
			t.Errorf("vendor term %q must be vocabulary", term)
		}
	}
}
