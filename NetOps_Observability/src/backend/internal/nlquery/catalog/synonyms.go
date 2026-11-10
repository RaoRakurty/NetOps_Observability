// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package catalog

// synonyms.go — the GENERATED word table (tracker 337 hybrid NLU plan A3).
//
// synonyms.v1.json is written by a test (synonyms_gen_test.go), never by hand:
// every entry is derived from this catalog's own aliases and from the vendor
// dialect terms in internal/vendorprofile, so the grammar's vocabulary grows
// with the catalog and nobody can type a phrasing in. A drift test fails when
// the file is stale, and the generator's test runs the held-out leak check
// (N-H3) over every entry.
//
// Kinds:
//   - variant: a regular inflection or an en-GB/en-US spelling of a catalog
//     word ("latencies" → "latency", "utilisation" → "utilization"). Not a
//     change of meaning, so it is applied without a disclosure line.
//   - abbrev:  a short form of a catalog word. Reserved: the generator emits
//     none today (short forms live in the catalog's own aliases); when it
//     does, an abbreviation is applied AND disclosed.
//   - term:    a vendor's word for a concept ("routing-instance" is Juniper's
//     VRF). Vocabulary only — protected from typo repair — until the catalog
//     has a dimension to map it to.

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

//go:embed synonyms.v1.json
var embeddedSynonyms []byte

// SynonymsSchema is the generated file's schema tag.
const SynonymsSchema = "correlix.nlquery.synonyms/v1"

// Synonym kinds (closed).
const (
	SynVariant = "variant"
	SynAbbrev  = "abbrev"
	SynTerm    = "term"
)

// SynonymEntry is one generated word mapping.
type SynonymEntry struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	Source string `json:"source"`
}

// SynonymTable is the generated file.
type SynonymTable struct {
	Schema  string         `json:"schema"`
	Note    string         `json:"note"`
	Entries []SynonymEntry `json:"entries"`
}

// ParseSynonyms decodes a synonym table strictly and validates it: closed
// kinds, single lower-case words, no duplicate source word, no self-mapping.
func ParseSynonyms(raw []byte) (*SynonymTable, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var t SynonymTable
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("synonyms: %w", err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("synonyms: trailing data")
	}
	if t.Schema != SynonymsSchema {
		return nil, fmt.Errorf("synonyms: schema %q", t.Schema)
	}
	seen := map[string]bool{}
	for _, e := range t.Entries {
		switch {
		case e.Kind != SynVariant && e.Kind != SynAbbrev && e.Kind != SynTerm:
			return nil, fmt.Errorf("synonyms: %q has unknown kind %q", e.From, e.Kind)
		case e.From == "" || e.To == "" || e.From == e.To:
			return nil, fmt.Errorf("synonyms: entry %q → %q is empty or maps to itself", e.From, e.To)
		case strings.ContainsAny(e.From+e.To, " \t") || strings.ToLower(e.From+e.To) != e.From+e.To:
			return nil, fmt.Errorf("synonyms: %q → %q must be single lower-case words", e.From, e.To)
		case seen[e.From]:
			return nil, fmt.Errorf("synonyms: %q appears twice", e.From)
		}
		seen[e.From] = true
	}
	return &t, nil
}

// Synonyms returns the embedded generated table. A table that does not parse
// is a build defect the drift test catches; at run time it degrades to no
// synonyms rather than failing every question.
func Synonyms() []SynonymEntry {
	t, err := ParseSynonyms(embeddedSynonyms)
	if err != nil {
		return nil
	}
	return append([]SynonymEntry(nil), t.Entries...)
}

// EmbeddedSynonyms is the raw embedded file (the drift test compares it).
func EmbeddedSynonyms() []byte { return append([]byte(nil), embeddedSynonyms...) }

// WordTable is the generated word table (synonyms.v1.json), reachable from a
// catalog so a caller holding one needs nothing else. (Catalog.Synonyms is
// the PUBLIC NAME groups for providers and applications — a different thing.)
func (c *Catalog) WordTable() []SynonymEntry { return Synonyms() }
