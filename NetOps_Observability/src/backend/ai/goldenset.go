// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"encoding/json"
	"fmt"
	"os"
)

// goldenset.go — loader for the versioned golden Q&A set (intelligence plan
// P3). The fixtures live in docs/ai/golden-examples/golden-qa.json so the eval
// corpus is reviewed like documentation, not buried in test code; this loader
// is the one shared seam the ai-package evals, the server-side agent-loop
// evals, and a future live eval runner all consume. Validation is strict:
// a malformed or miscategorized fixture fails loading (a silently-skipped
// golden item would report a greener eval than actually ran).

// Golden categories. Each maps to a distinct guarantee:
//
//	docs       — retrieval must rank the expected page (hit@k) and the product
//	             answer must cite it (citation-correctness).
//	intent     — the deterministic router must classify to the expected intent.
//	agent_tool — the bounded loop must expose the expected tool and execute it
//	             correctly (mock mode); the model must CHOOSE it (live mode).
//	decline    — out-of-scope questions must hit the honesty floor (no hits,
//	             explicit "docs don't cover that", zero citations).
//	injection  — adversarial content must be contained (fenced as data,
//	             fabricated citations stripped, undeclared tools refused).
const (
	GoldenDocs      = "docs"
	GoldenIntent    = "intent"
	GoldenAgentTool = "agent_tool"
	GoldenDecline   = "decline"
	GoldenInjection = "injection"
)

// GoldenExpect is the per-category expected outcome.
type GoldenExpect struct {
	Slugs  []string          `json:"slugs,omitempty"`  // docs: acceptable portal page slugs (any counts as a hit)
	Anchor string            `json:"anchor,omitempty"` // docs: optional section anchor on the expected page
	Intent string            `json:"intent,omitempty"` // intent: Classify() Plan.Intent
	Tool   string            `json:"tool,omitempty"`   // agent_tool: the tool the model should reach for
	Args   map[string]string `json:"args,omitempty"`   // agent_tool: the args the scripted call runs with
}

// GoldenItem is one eval fixture.
type GoldenItem struct {
	ID       string       `json:"id"`
	Category string       `json:"category"`
	Question string       `json:"question"`
	Target   string       `json:"target,omitempty"`  // injection: which containment layer the probe attacks
	Payload  string       `json:"payload,omitempty"` // injection: the adversarial content
	Expect   GoldenExpect `json:"expect"`
	KnownGap bool         `json:"known_gap,omitempty"` // report-only: tracked, not gated (e.g. the payroll relevance case)
	Notes    string       `json:"notes,omitempty"`
}

// GoldenSet is the parsed fixture file.
type GoldenSet struct {
	Version int          `json:"version"`
	Items   []GoldenItem `json:"items"`
}

// Category returns the items of one category, preserving file order.
func (g *GoldenSet) Category(name string) []GoldenItem {
	var out []GoldenItem
	for _, it := range g.Items {
		if it.Category == name {
			out = append(out, it)
		}
	}
	return out
}

// LoadGoldenSet reads and validates the golden fixture file. Every item must
// carry the fields its category's assertions need — an underspecified fixture
// is an error, never a silent skip.
func LoadGoldenSet(path string) (*GoldenSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("golden set: %w", err)
	}
	var gs GoldenSet
	if err := json.Unmarshal(raw, &gs); err != nil {
		return nil, fmt.Errorf("golden set: parse: %w", err)
	}
	if gs.Version != 1 {
		return nil, fmt.Errorf("golden set: unsupported version %d", gs.Version)
	}
	if len(gs.Items) == 0 {
		return nil, fmt.Errorf("golden set: no items")
	}
	seen := make(map[string]bool, len(gs.Items))
	for i, it := range gs.Items {
		if it.ID == "" || it.Question == "" {
			return nil, fmt.Errorf("golden set: item %d: id and question are required", i)
		}
		if seen[it.ID] {
			return nil, fmt.Errorf("golden set: duplicate id %q", it.ID)
		}
		seen[it.ID] = true
		switch it.Category {
		case GoldenDocs:
			if len(it.Expect.Slugs) == 0 {
				return nil, fmt.Errorf("golden set: %s: docs item needs expect.slugs", it.ID)
			}
		case GoldenIntent:
			if it.Expect.Intent == "" {
				return nil, fmt.Errorf("golden set: %s: intent item needs expect.intent", it.ID)
			}
		case GoldenAgentTool:
			if it.Expect.Tool == "" {
				return nil, fmt.Errorf("golden set: %s: agent_tool item needs expect.tool", it.ID)
			}
		case GoldenDecline:
			// The expectation IS the absence of a match — nothing extra to declare.
		case GoldenInjection:
			if it.Target == "" || it.Payload == "" {
				return nil, fmt.Errorf("golden set: %s: injection item needs target and payload", it.ID)
			}
		default:
			return nil, fmt.Errorf("golden set: %s: unknown category %q", it.ID, it.Category)
		}
	}
	return &gs, nil
}
