package tac

import (
	"strings"
	"testing"
)

// yamlmin_test.go — the parser's own guard.
//
// It is 500 lines of hand-rolled parsing standing between reviewed data and a
// device, so it gets tested as a parser, not merely as a side effect of loading
// classes.yaml. Two properties matter equally:
//
//   · what it ACCEPTS, it parses correctly (a subtly wrong list is worse than a
//     refused file — it ships a plan nobody reviewed);
//   · what it does NOT understand, it REFUSES with a line number, rather than
//     skipping it. Silence would turn a typo into missing data.

func TestYAMLAcceptedSubset(t *testing.T) {
	const src = `
# a leading comment
schema_version: 1
version: v1
scalar_quoted: 'it''s quoted'
scalar_double: "with \"escapes\""
flow_seq: [a, b, 'c d']
empty_seq: []
block_literal: |
  line one
  line two
block_folded: >
  folded one
  folded two
mapping:
  nested: yes
  deeper:
    key: value
list_of_maps:
  - id: first
    title: The first one
    tags: [x, y]
  - id: second
    title: The second one
list_of_scalars:
  - alpha
  - beta   # trailing comment
flow_map_items:
  - {title: T, url: 'https://example.invalid/a'}
`
	doc, err := parseYAML(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !doc.isMap() {
		t.Fatal("document is not a mapping")
	}
	get := func(key string) string {
		v, err := ystr(doc, key)
		if err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		return v
	}
	if got := get("scalar_quoted"); got != "it's quoted" {
		t.Errorf("single-quoted scalar = %q", got)
	}
	if got := get("scalar_double"); got != `with "escapes"` {
		t.Errorf("double-quoted scalar = %q", got)
	}
	if got := get("block_literal"); got != "line one\nline two" {
		t.Errorf("literal block = %q", got)
	}
	if got := get("block_folded"); got != "folded one folded two" {
		t.Errorf("folded block = %q", got)
	}
	flow, err := ystrs(doc, "flow_seq")
	if err != nil || len(flow) != 3 || flow[2] != "c d" {
		t.Errorf("flow sequence = %v (%v)", flow, err)
	}
	empty, err := ystrs(doc, "empty_seq")
	if err != nil || len(empty) != 0 {
		t.Errorf("empty flow sequence = %v (%v)", empty, err)
	}
	nested, err := ymap(doc, "mapping")
	if err != nil || nested == nil {
		t.Fatalf("nested mapping: %v", err)
	}
	if v, _ := ystr(nested, "nested"); v != "yes" {
		t.Errorf("nested scalar = %q", v)
	}
	deeper, err := ymap(nested, "deeper")
	if err != nil || deeper == nil {
		t.Fatalf("deeper mapping: %v", err)
	}
	if v, _ := ystr(deeper, "key"); v != "value" {
		t.Errorf("deeper scalar = %q", v)
	}
	items, err := ylist(doc, "list_of_maps")
	if err != nil || len(items) != 2 {
		t.Fatalf("list of maps = %d items (%v)", len(items), err)
	}
	if v, _ := ystr(items[0], "id"); v != "first" {
		t.Errorf("first item id = %q", v)
	}
	if v, _ := ystr(items[1], "title"); v != "The second one" {
		t.Errorf("second item title = %q", v)
	}
	tags, err := ystrs(items[0], "tags")
	if err != nil || len(tags) != 2 || tags[1] != "y" {
		t.Errorf("nested flow sequence = %v (%v)", tags, err)
	}
	scalars, err := ystrs(doc, "list_of_scalars")
	if err != nil || len(scalars) != 2 || scalars[1] != "beta" {
		t.Errorf("list of scalars = %v (%v) — a trailing comment must not survive", scalars, err)
	}
	flowMaps, err := ylist(doc, "flow_map_items")
	if err != nil || len(flowMaps) != 1 {
		t.Fatalf("flow mapping items = %d (%v)", len(flowMaps), err)
	}
	if v, _ := ystr(flowMaps[0], "url"); v != "https://example.invalid/a" {
		t.Errorf("flow mapping value = %q", v)
	}
}

// TestYAMLPreservesAuthoringOrder — the order in the file is the order the
// operator sees, so it is load-bearing.
func TestYAMLPreservesAuthoringOrder(t *testing.T) {
	doc, err := parseYAML("b: 1\na: 2\nc: 3\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []string{"b", "a", "c"}
	if len(doc.keys) != len(want) {
		t.Fatalf("keys = %v", doc.keys)
	}
	for i := range want {
		if doc.keys[i] != want[i] {
			t.Fatalf("key order = %v, want %v", doc.keys, want)
		}
	}
}

// TestYAMLRefusals — everything outside the subset fails with a line number,
// never silently.
func TestYAMLRefusals(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"tab indentation", "a:\n\tb: 1\n", "tab in indentation"},
		{"duplicate key", "a: 1\na: 2\n", "duplicate key"},
		{"multiple documents", "a: 1\n---\nb: 2\n", "multiple documents"},
		{"not a mapping entry", "a: 1\njust some words\n", "expected `key: value`"},
		{"unterminated flow sequence", "a: [x, y\n", "unterminated flow sequence"},
		{"unterminated flow mapping", "a: {k: v\n", "unterminated flow mapping"},
		{"nested flow collections", "a: [[x]]\n", "nested flow collections"},
		{"unterminated single quote", "a: 'oops\n", "unterminated single-quoted"},
		{"empty sequence item", "a:\n  -\n", "empty sequence item"},
		{"bad indentation in a mapping", "a: 1\n   b: 2\n", "unexpected indentation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseYAML(tc.src)
			if err == nil {
				t.Fatal("expected a refusal, got none")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), tc.want)
			}
			if !strings.Contains(err.Error(), "line ") {
				t.Fatalf("refusal %q carries no line number", err.Error())
			}
		})
	}
}

// TestYAMLBoundsAreEnforced — §9: everything is bounded.
func TestYAMLBoundsAreEnforced(t *testing.T) {
	if _, err := parseYAML(strings.Repeat("x", maxYAMLBytes+1)); err == nil ||
		!strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("an oversized document was accepted: %v", err)
	}
	deep := ""
	for i := 0; i < maxYAMLDepth+4; i++ {
		deep += strings.Repeat("  ", i) + "k:\n"
	}
	if _, err := parseYAML(deep); err == nil || !strings.Contains(err.Error(), "nesting deeper") {
		t.Fatalf("an over-nested document was accepted: %v", err)
	}
}

// TestYONLYRejectsUnknownFields is the "a typo is a refusal, not silence" rule.
func TestYONLYRejectsUnknownFields(t *testing.T) {
	doc, err := parseYAML("id: x\ntilte: typo\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	err = yonly(doc, "a thing", "id", "title")
	if err == nil || !strings.Contains(err.Error(), "tilte") {
		t.Fatalf("unknown field was not refused: %v", err)
	}
	if err := yonly(doc, "a thing", "id", "title", "tilte"); err != nil {
		t.Fatalf("a declared field was refused: %v", err)
	}
}

// TestYAMLTypeMismatchesAreErrors — a scalar where a list is expected is a
// refusal, not an empty list.
func TestYAMLTypeMismatchesAreErrors(t *testing.T) {
	doc, err := parseYAML("a: scalar\nb:\n  - 1\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := ystrs(doc, "a"); err == nil || !strings.Contains(err.Error(), "must be a list") {
		t.Fatalf("a scalar was accepted where a list was expected: %v", err)
	}
	if _, err := ystr(doc, "b"); err == nil || !strings.Contains(err.Error(), "must be a scalar") {
		t.Fatalf("a list was accepted where a scalar was expected: %v", err)
	}
	if _, err := ymap(doc, "b"); err == nil || !strings.Contains(err.Error(), "must be a mapping") {
		t.Fatalf("a list was accepted where a mapping was expected: %v", err)
	}
	if _, err := ylist(doc, "b"); err == nil || !strings.Contains(err.Error(), "list of mappings") {
		t.Fatalf("a list of scalars was accepted where mappings were expected: %v", err)
	}
}
