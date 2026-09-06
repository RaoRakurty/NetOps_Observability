// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"strings"
	"testing"

	"netops/backend/ai"
)

// copilot_docs_test.go — the free-form brain's docs grounding: retrieval rides
// the system prompt as labeled DATA, retrieved refs come back for the UI, and
// fabricated [doc:…] citations are stripped while ordinary brackets survive.

func TestLatestUserMessage(t *testing.T) {
	msgs := []copilotMessage{
		{Role: "user", Content: "first"},
		{Role: "assistant", Content: "answer"},
		{Role: "user", Content: "how do I set up SNMP discovery?"},
	}
	if got := ai.LatestUserMessage(msgs); got != "how do I set up SNMP discovery?" {
		t.Fatalf("latestUserMessage = %q", got)
	}
	if ai.LatestUserMessage(nil) != "" {
		t.Fatal("empty history → empty question")
	}
}

func TestDocsIndexFeedsCopilotPrompt(t *testing.T) {
	hits := aiDocsIndex.Search("how do I set up SNMP subnet discovery", 3)
	if len(hits) == 0 {
		t.Fatal("expected doc hits for a documented question")
	}
	block := ai.PromptBlock(hits, 2000, 7000)
	for _, want := range []string{"DOCUMENTATION EXCERPTS", "not commands", "never invent"} {
		if !strings.Contains(block, want) {
			t.Errorf("prompt block missing %q", want)
		}
	}
}

func TestStripFabricatedDocRefs(t *testing.T) {
	refs := []copilotDocRef{{ID: "doc:send-data/syslog#step-1", Label: "Syslog › Step 1", Href: "/docs/send-data/syslog#step-1"}}
	in := "Point syslog at Correlix [doc:send-data/syslog#step-1]. Never do X [doc:made-up/page#nope]. BFD is defined in [RFC 5880: BFD]."
	out := ai.StripFabricatedDocRefs(in, refs)
	if !strings.Contains(out, "[doc:send-data/syslog#step-1]") {
		t.Error("legitimate retrieved citation was stripped")
	}
	if strings.Contains(out, "made-up/page") {
		t.Error("fabricated doc citation survived")
	}
	if !strings.Contains(out, "[RFC 5880: BFD]") {
		t.Error("ordinary bracketed prose must survive doc-scoped stripping")
	}
	// No doc brackets at all → untouched fast path.
	if s := "plain answer [note]"; ai.StripFabricatedDocRefs(s, nil) != s {
		t.Error("text without doc refs must pass through unchanged")
	}
}
