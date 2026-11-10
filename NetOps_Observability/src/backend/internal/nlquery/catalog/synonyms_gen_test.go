// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package catalog_test

// synonyms_gen_test.go — GENERATES synonyms.v1.json (hybrid NLU plan A3) and
// fails when the committed file is stale. Regenerate with
//
//	NLQ_WRITE_SYNONYMS=1 go test -mod=vendor -run TestSynonymTableIsGenerated ./internal/nlquery/catalog/
//
// The rules are mechanical and closed (no hand-typed phrasing):
//   - variant: the regular plural of every singular NOUN of the catalog
//     (metric and entity aliases) and the singular of every plural one, plus
//     the en-GB spelling of every en-US catalog word (-ization/-isation,
//     -ize/-ise, -yze/-yse, -bor/-bour), where the variant is not already a
//     word;
//   - term:    every vendor dialect's VRF term and synonyms (vendorprofile),
//     protected as vocabulary for every vendor (multi-vendor rule).
//
// Short forms ("mem", "util") are NOT generated: a prefix rule produced more
// noise than abbreviations people type ("not" → notification). They belong in
// the catalog's own aliases, where a reviewer sees them.

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/lex"
	"netops/backend/internal/vendorprofile"
)

// catalogWords are the single words of every catalog alias, name and enum
// value, letters only, four letters or more, with where each came from.
// nounsOnly keeps the metric and entity words (the nouns an operator
// pluralises), leaving out dimension names and enum values.
func catalogWords(cat *catalog.Catalog, nounsOnly bool) map[string]string {
	out := map[string]string{}
	add := func(src string, phrases ...string) {
		for _, p := range phrases {
			for _, w := range strings.Fields(lex.Fold(strings.NewReplacer("_", " ", "-", " ").Replace(p))) {
				if len(w) < lex.MinTypoLen || strings.Trim(w, "abcdefghijklmnopqrstuvwxyz") != "" {
					continue
				}
				if _, ok := out[w]; !ok {
					out[w] = src
				}
			}
		}
	}
	for _, m := range cat.Metrics {
		add("catalog:metric:"+m.Name, m.Aliases...)
	}
	for _, e := range cat.Entities {
		add("catalog:entity:"+e.Name, append([]string{e.Name}, e.Aliases...)...)
	}
	if nounsOnly {
		return out
	}
	for _, d := range cat.Dimensions {
		add("catalog:dimension:"+d.Entity+"."+d.Name, append([]string{d.Name}, d.Aliases...)...)
		for _, ev := range d.Enum {
			add("catalog:enum:"+d.Entity+"."+d.Name, append([]string{strings.ToLower(ev.Value)}, ev.Aliases...)...)
		}
	}
	return out
}

var spellings = []struct{ us, gb string }{
	{"ization", "isation"}, {"izations", "isations"}, {"ize", "ise"}, {"izes", "ises"}, {"yze", "yse"},
	{"bor", "bour"}, {"bors", "bours"},
}

func generateSynonyms(t *testing.T) catalog.SynonymTable {
	t.Helper()
	cat := catalog.MustLoad()
	vocab := compile.BaseVocabulary(cat)
	words := catalogWords(cat, false)
	nouns := catalogWords(cat, true)
	entries := map[string]catalog.SynonymEntry{}
	put := func(e catalog.SynonymEntry) {
		if vocab.Exact(e.From) || cat.IsVocabulary(e.From) || len(e.From) < lex.MinTypoLen {
			return // a word already means something: never remapped
		}
		if prev, ok := entries[e.From]; ok && prev.To != e.To {
			delete(entries, e.From) // two catalog words claim it: ambiguous, dropped
			entries["\x00"+e.From] = catalog.SynonymEntry{}
			return
		}
		if _, dropped := entries["\x00"+e.From]; dropped {
			return
		}
		entries[e.From] = e
	}
	keys := make([]string, 0, len(words))
	for w := range words {
		keys = append(keys, w)
	}
	sort.Strings(keys)
	for _, w := range keys {
		src := words[w]
		if _, noun := nouns[w]; noun && !strings.HasSuffix(w, "ed") && !strings.HasSuffix(w, "ing") {
			if sg := lex.Singular(w); sg == w {
				put(catalog.SynonymEntry{From: lex.Plural(w), To: w, Kind: catalog.SynVariant, Source: src + " (plural)"})
			} else {
				put(catalog.SynonymEntry{From: sg, To: w, Kind: catalog.SynVariant, Source: src + " (singular)"})
			}
		}
		for _, sp := range spellings {
			if strings.HasSuffix(w, sp.us) && len(w) > len(sp.us)+2 {
				put(catalog.SynonymEntry{From: strings.TrimSuffix(w, sp.us) + sp.gb, To: w, Kind: catalog.SynVariant, Source: src + " (en-GB spelling)"})
			}
		}
	}
	// Vendor dialect terms (multi-vendor rule): every vendor's word for a VRF.
	reg := vendorprofile.Default()
	if len(reg.Profiles()) == 0 {
		t.Fatal("vendorprofile: no profiles loaded")
	}
	for _, p := range reg.Profiles() {
		name := p.ID
		terms := append([]string{p.Dialect.VRFTerm}, p.Dialect.VRFSynonyms...)
		for _, term := range terms {
			for _, w := range strings.Fields(strings.ToLower(term)) {
				if w != "" && w != "vrf" && lex.Squash(w) != "" {
					put(catalog.SynonymEntry{From: w, To: "vrf", Kind: catalog.SynTerm, Source: "vendorprofile:" + name})
				}
			}
		}
	}
	var out []catalog.SynonymEntry
	for k, e := range entries {
		if !strings.HasPrefix(k, "\x00") {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].From < out[j].From })
	return catalog.SynonymTable{Schema: catalog.SynonymsSchema,
		Note:    "GENERATED by internal/nlquery/catalog/synonyms_gen_test.go from catalog.v1.json and internal/vendorprofile — do not edit by hand.",
		Entries: out}
}

func encodeSynonyms(t *testing.T, tab catalog.SynonymTable) []byte {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(tab); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestSynonymTableIsGenerated(t *testing.T) {
	want := encodeSynonyms(t, generateSynonyms(t))
	if os.Getenv("NLQ_WRITE_SYNONYMS") == "1" {
		if err := os.WriteFile("synonyms.v1.json", want, 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(catalog.EmbeddedSynonyms(), want) {
		t.Fatal("synonyms.v1.json is stale: regenerate with NLQ_WRITE_SYNONYMS=1 go test -mod=vendor -run TestSynonymTableIsGenerated ./internal/nlquery/catalog/")
	}
	if len(catalog.Synonyms()) < 10 {
		t.Fatalf("the generated table has %d entries — the generator is not reading the catalog", len(catalog.Synonyms()))
	}
}

// The catalog collision rule holds for generated words: no entry remaps a
// word the catalog or the grammar already gives a meaning to, and every
// target is a catalog word (or the VRF concept).
func TestSynonymsNeverShadowAWord(t *testing.T) {
	cat := catalog.MustLoad()
	vocab := compile.BaseVocabulary(cat)
	words := catalogWords(cat, false)
	for _, e := range catalog.Synonyms() {
		if vocab.Exact(e.From) || cat.IsVocabulary(e.From) {
			t.Errorf("%q already means something; it must not be remapped to %q", e.From, e.To)
		}
		if _, ok := words[e.To]; !ok && e.To != "vrf" {
			t.Errorf("%q maps to %q, which is not a catalog word", e.From, e.To)
		}
	}
}

func TestParseSynonymsRejectsBadEntries(t *testing.T) {
	for name, raw := range map[string]string{
		"kind":     `{"schema":"correlix.nlquery.synonyms/v1","note":"","entries":[{"from":"a1","to":"b","kind":"guess","source":"x"}]}`,
		"self":     `{"schema":"correlix.nlquery.synonyms/v1","note":"","entries":[{"from":"mem","to":"mem","kind":"abbrev","source":"x"}]}`,
		"phrase":   `{"schema":"correlix.nlquery.synonyms/v1","note":"","entries":[{"from":"two words","to":"b","kind":"abbrev","source":"x"}]}`,
		"dup":      `{"schema":"correlix.nlquery.synonyms/v1","note":"","entries":[{"from":"mem","to":"memory","kind":"abbrev","source":"x"},{"from":"mem","to":"members","kind":"abbrev","source":"x"}]}`,
		"schema":   `{"schema":"v0","note":"","entries":[]}`,
		"unknown":  `{"schema":"correlix.nlquery.synonyms/v1","note":"","entries":[],"extra":1}`,
		"trailing": `{"schema":"correlix.nlquery.synonyms/v1","note":"","entries":[]} {}`,
	} {
		if _, err := catalog.ParseSynonyms([]byte(raw)); err == nil {
			t.Errorf("%s: must be refused", name)
		}
	}
}
