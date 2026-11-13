// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package iristriage classifies every Iris miss (model-first decision point 5,
// owner 2026-11-13) so the fix for a family of questions is a tool, data, a
// route or a description — never a phrase regex for one wording.
//
// Classes (closed):
//
//	no_tool        — nothing in this deployment can answer it (a module with
//	                 no tools, a not-yet-built answer mode)
//	no_data        — the right arm ran and its source had nothing (no doc,
//	                 no playbook, no feature page, an empty query result)
//	wrong_route    — the operator said the answer was not what they meant,
//	                 and it was not a data-query detail
//	wrong_tool     — the operator corrected a data answer's entity, metric,
//	                 window or filter: the right arm, the wrong reading
//	wording        — nothing understood the words: the deterministic layer
//	                 could not read them and no model routed them
//	provider_error — model-first was on and the model did not answer
//
// The classifier is pure and reads only server-side signals; the question text
// is never classified by pattern.
package iristriage

import (
	"sort"
	"strings"
	"unicode/utf8"
)

// Miss classes (closed).
const (
	NoTool        = "no_tool"
	NoData        = "no_data"
	WrongRoute    = "wrong_route"
	WrongTool     = "wrong_tool"
	Wording       = "wording"
	ProviderError = "provider_error"
)

// Classes is the closed set, in display order.
var Classes = []string{NoTool, NoData, WrongRoute, WrongTool, Wording, ProviderError}

// Valid reports a known class.
func Valid(c string) bool {
	for _, k := range Classes {
		if k == c {
			return true
		}
	}
	return false
}

// Dead-end kinds an answer can carry (Signals.DeadEndKind).
const (
	EndNone          = ""
	EndCapability    = "capability"     // "I didn't quite catch that"
	EndNotBuilt      = "not_built"      // a module with no tools / an unbuilt mode
	EndNoDocs        = "no_docs"        // the docs had no match
	EndNoPlaybook    = "no_playbook"    // no curated playbook
	EndNoFeature     = "no_feature"     // the feature finder placed nothing
	EndDenied        = "denied"         // a permission / enablement denial — the honest answer, not a miss
	EndUnavailableIO = "source_failure" // the module's data source did not respond
)

// Signals are the server-side facts about one answered question.
type Signals struct {
	ModelFirst         bool     // the planner was on for this caller
	PlannerUnavailable bool     // model-first was on and the model did not route it
	DeadEndKind        string   // one of the End* kinds
	DataOutcome        string   // the data arm's query-log outcome, if it ran ("unparsed", "not_found", …)
	DataRows           int      // rows the data arm returned (when it answered)
	DataAnswered       bool     // the data arm answered
	Corrections        []string // correction kinds the operator attached
}

// Classify returns the miss class, or ok=false when the question was not a
// miss. First match wins; the order puts the operator's own verdict first.
func Classify(s Signals) (string, bool) {
	for _, k := range s.Corrections {
		switch k {
		case "wrong_entity", "wrong_metric", "wrong_window", "wrong_filter":
			return WrongTool, true
		}
	}
	if len(s.Corrections) > 0 {
		return WrongRoute, true
	}
	if s.PlannerUnavailable {
		return ProviderError, true
	}
	switch s.DeadEndKind {
	case EndNotBuilt:
		return NoTool, true
	case EndNoDocs, EndNoPlaybook, EndNoFeature, EndUnavailableIO:
		return NoData, true
	case EndCapability:
		return Wording, true
	case EndDenied:
		return "", false // the denial is the answer
	}
	switch s.DataOutcome {
	case "unparsed", "invalid":
		return Wording, true
	case "not_found":
		return NoData, true
	}
	if s.DataAnswered && s.DataRows == 0 && s.DataOutcome == "answered" {
		return NoData, true
	}
	return "", false
}

// Example is one stored miss shown on the triage view.
type Example struct {
	Question string `json:"question"`
	Route    string `json:"route,omitempty"`
	Tenant   string `json:"tenant,omitempty"` // set only on a cross-tenant (platform) view
}

// ClassSummary is one class's line on the triage view.
type ClassSummary struct {
	Class    string    `json:"class"`
	Count    int       `json:"count"`
	Examples []Example `json:"examples"`
}

// Item is one stored miss fed to Summarize.
type Item struct {
	Class, Question, Route, Tenant string
}

// MaxExamples bounds the example questions per class; MaxExampleRunes each.
const (
	MaxExamples     = 5
	MaxExampleRunes = 200
)

// Summarize folds stored misses into per-class counts with a few examples,
// largest class first. withTenant keeps the tenant id on examples (a platform
// view); otherwise it is dropped.
func Summarize(items []Item, withTenant bool) []ClassSummary {
	by := map[string]*ClassSummary{}
	for _, it := range items {
		if !Valid(it.Class) {
			continue
		}
		cs := by[it.Class]
		if cs == nil {
			cs = &ClassSummary{Class: it.Class, Examples: []Example{}}
			by[it.Class] = cs
		}
		cs.Count++
		if len(cs.Examples) < MaxExamples {
			ex := Example{Question: clip(it.Question), Route: it.Route}
			if withTenant {
				ex.Tenant = it.Tenant
			}
			cs.Examples = append(cs.Examples, ex)
		}
	}
	out := make([]ClassSummary, 0, len(by))
	for _, cs := range by {
		out = append(out, *cs)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Class < out[j].Class
	})
	return out
}

func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if utf8.RuneCountInString(s) > MaxExampleRunes {
		return string([]rune(s)[:MaxExampleRunes]) + "…"
	}
	return s
}

// Candidate is one review-gated eval case exported from the field: a miss or
// a correction, never auto-committed to a corpus.
type Candidate struct {
	Question  string `json:"question"`
	Class     string `json:"class,omitempty"`
	Route     string `json:"route,omitempty"`
	Source    string `json:"source"`                    // "miss" | "correction"
	Kind      string `json:"correction_kind,omitempty"` // the operator's correction kind
	Note      string `json:"note,omitempty"`            // the operator's note, clipped
	Corrected string `json:"corrected_query_hash,omitempty"`
}

// CandidateFile is the export: a header that says it must be reviewed, and
// the de-duplicated candidates.
type CandidateFile struct {
	Review     string      `json:"review"`
	Candidates []Candidate `json:"candidates"`
}

// ReviewNotice heads every export.
const ReviewNotice = "Candidates only. Review each question (remove anything customer-identifying, check the route) before adding it to docs/ai/golden-examples; nothing here is committed automatically."

// Candidates de-duplicates (case- and space-insensitively) and bounds the
// export.
func Candidates(in []Candidate, max int) CandidateFile {
	seen := map[string]bool{}
	out := []Candidate{}
	for _, c := range in {
		c.Question = clip(c.Question)
		c.Note = clip(c.Note)
		k := strings.ToLower(c.Question) + "\x00" + c.Source + "\x00" + c.Kind
		if c.Question == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, c)
		if len(out) == max {
			break
		}
	}
	return CandidateFile{Review: ReviewNotice, Candidates: out}
}
