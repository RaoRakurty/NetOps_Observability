// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// ledger_hash_test.go — the decision ledger's fingerprints (tracker 337 N-A6)
// are canonical: equal arguments hash equally whatever the map order, nil and
// empty are the same thing, any change to what a tool returned changes the
// hash, and the hash never contains the values it fingerprints.

import (
	"strings"
	"testing"
)

func TestHashToolArgsIsCanonical(t *testing.T) {
	a := HashToolArgs(ToolArgs{"device": "edge-a", "window": "1h"})
	b := HashToolArgs(ToolArgs{"window": "1h", "device": "edge-a"})
	if a != b || len(a) != 64 {
		t.Fatalf("map order changed the hash: %s %s", a, b)
	}
	if HashToolArgs(nil) != HashToolArgs(ToolArgs{}) {
		t.Fatal("nil and empty arguments must hash the same")
	}
	if a == HashToolArgs(ToolArgs{"device": "edge-b", "window": "1h"}) {
		t.Fatal("different arguments, same hash")
	}
	if strings.Contains(a, "edge") {
		t.Fatal("a hash must not carry the value")
	}
}

func TestHashToolResultCoversEverythingReturned(t *testing.T) {
	base := ToolResult{Items: []EvidenceItem{{CitationID: "e1", Text: "peer down"}}, Notes: []string{"n"}, Signals: []string{"s=1"}}
	h := HashToolResult(base)
	if len(h) != 64 || h != HashToolResult(base) {
		t.Fatalf("unstable: %s", h)
	}
	if HashToolResult(ToolResult{}) != HashToolResult(ToolResult{Items: []EvidenceItem{}, Notes: []string{}, Signals: []string{}}) {
		t.Fatal("nil and empty results must hash the same")
	}
	for name, mut := range map[string]func(*ToolResult){
		"items":     func(r *ToolResult) { r.Items = []EvidenceItem{{CitationID: "e2", Text: "peer down"}} },
		"truncated": func(r *ToolResult) { r.Truncated = true },
		"notes":     func(r *ToolResult) { r.Notes = []string{"other"} },
		"signals":   func(r *ToolResult) { r.Signals = []string{"s=2"} },
	} {
		r := base
		mut(&r)
		if HashToolResult(r) == h {
			t.Errorf("changing %s did not change the hash", name)
		}
	}
}
