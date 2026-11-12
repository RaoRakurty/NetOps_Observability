// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package lex

import (
	"reflect"
	"testing"
)

// Two questions joined by "and" inside one sentence are two questions (live
// 2026-11-12); a plain "and" between two things is not a boundary.
func TestSplitClauses(t *testing.T) {
	for q, want := range map[string][]string{
		"tell me which tenant are we in and how many devices are connected and how are they discovereD?": {
			"tell me which tenant are we in", "how many devices are connected", "how are they discovereD?"},
		"which tenant am I in and how many devices do we have":        {"which tenant am I in", "how many devices do we have"},
		"how many sites do we have, and also which tenant are we in?": {"how many sites do we have", "which tenant are we in?"},
		"show devices in austin and dallas":                           {"show devices in austin and dallas"},
		"which devices are down and why":                              {"which devices are down and why"}, // "why" alone is not a question
		"cpu and memory on edge-1":                                    {"cpu and memory on edge-1"},
		"what is going on right now? what should the NOC focus on first?": {
			"what is going on right now?", "what should the NOC focus on first?"}, // Split's boundary still applies
		"a and how b and what c and which d e": {"a and how b and what c and which d e"}, // more than MaxParts: read whole
	} {
		if got := SplitClauses(q); !reflect.DeepEqual(got, want) {
			t.Errorf("SplitClauses(%q) = %q, want %q", q, got, want)
		}
	}
}
