// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package present is the SERVER half of the Iris presentation contract
// (tracker 337 N-E1; design: docs/architecture/iris-natural-language-platform.md
// §4.1 decision 7). The client half is src/frontend/src/iris/presentation.ts.
//
// The server chooses how an answer is drawn: Select reads the validated query
// and the ResultSet it produced and returns a PresentationPlan whose views come
// from a CLOSED enum. The choice is deterministic — the same query and result
// shape always give the same plan.
//
// The AI model may only SUGGEST a view. A suggestion is untrusted data (§3,
// §15 LLM02): it is accepted only when it is exactly one enum member AND that
// view can honestly draw this result's shape. Anything else — an unknown
// name, a non-string, oversized input, a view that does not fit — is ignored
// and the plan carries a fixed, server-written disclosure. The model's text is
// never copied into the plan.
//
// §3a: the plan describes the ResultSet; it carries no data of its own. Its
// title is built from catalog names (the metric, the group-by dimension) only,
// never from a row value, an entity id or anything the model wrote.
package present

import (
	"bytes"
	"encoding/json"
	"strings"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/plan"
)

// View is one layout from the closed set.
type View string

// The closed view enum. src/frontend/src/iris/presentation.ts VIEW_TYPES is
// the same list in the same order; TestViewEnumMatchesClient fails on drift.
const (
	Summary            View = "SUMMARY"
	Table              View = "TABLE"
	TimeSeries         View = "TIME_SERIES"
	Timeline           View = "TIMELINE"
	Bar                View = "BAR"
	Topology           View = "TOPOLOGY"
	Path               View = "PATH"
	Diff               View = "DIFF"
	EvidenceList       View = "EVIDENCE_LIST"
	IncidentCard       View = "INCIDENT_CARD"
	ChangeCard         View = "CHANGE_CARD"
	RecommendationCard View = "RECOMMENDATION_CARD"
)

// Views returns the closed enum in its canonical order (a fresh slice).
func Views() []View {
	return []View{Summary, Table, TimeSeries, Timeline, Bar, Topology, Path, Diff,
		EvidenceList, IncidentCard, ChangeCard, RecommendationCard}
}

// Valid reports whether v is an enum member.
func (v View) Valid() bool {
	for _, k := range Views() {
		if v == k {
			return true
		}
	}
	return false
}

// HighlightKind is one of the moments the UI standard allows an accent for.
type HighlightKind string

// The closed highlight enum (presentation.ts HIGHLIGHT_KINDS).
const (
	RootCause      HighlightKind = "root_cause"
	CriticalChange HighlightKind = "critical_change"
	IncidentStart  HighlightKind = "incident_start"
	Recovery       HighlightKind = "recovery"
	HighConfidence HighlightKind = "high_confidence"
)

// HighlightKinds returns the closed highlight enum in canonical order.
func HighlightKinds() []HighlightKind {
	return []HighlightKind{RootCause, CriticalChange, IncidentStart, Recovery, HighConfidence}
}

// Highlight accents the rows / changes / incidents named by IDs.
type Highlight struct {
	Kind HighlightKind `json:"kind"`
	IDs  []string      `json:"ids"`
}

// Who chose the primary view.
const (
	ChosenByServer = "server"
	ChosenByModel  = "model_suggestion"
)

// Disclosures for an ignored suggestion. Fixed server text: the model's own
// words never reach the operator through the plan.
const (
	DisclosureNotAView = "The AI model suggested a layout Iris does not have, so it was ignored and the standard layout is shown."
	DisclosureNoFit    = "The AI model suggested a layout that does not fit this answer, so it was ignored and the standard layout is shown."
)

// MaxSuggestionBytes bounds the raw suggestion read at all; the longest enum
// member quoted is 21 bytes.
const MaxSuggestionBytes = 64

// Plan is the PresentationPlan sent with a ResultSet. The first five fields are
// the client contract (presentation.ts PresentationPlan); ChosenBy and
// Disclosure say how the view was chosen.
type Plan struct {
	PrimaryView   View        `json:"primary_view"`
	SecondaryView View        `json:"secondary_view,omitempty"`
	Title         string      `json:"title"`
	Highlight     []Highlight `json:"highlight,omitempty"`
	TableColumns  []string    `json:"table_columns,omitempty"`
	ChosenBy      string      `json:"chosen_by"`
	Disclosure    string      `json:"disclosure,omitempty"`
}

// Suggestion is the model's raw view suggestion. An empty Raw (or JSON null)
// means none was offered.
type Suggestion struct {
	Raw json.RawMessage
}

func (s Suggestion) offered() bool {
	t := bytes.TrimSpace(s.Raw)
	return len(t) > 0 && !bytes.Equal(t, []byte("null"))
}

// view decodes the suggestion: ok only for a JSON string naming an enum member.
func (s Suggestion) view() (View, bool) {
	t := bytes.TrimSpace(s.Raw)
	if len(t) > MaxSuggestionBytes {
		return "", false
	}
	var name string
	if err := json.Unmarshal(t, &name); err != nil {
		return "", false
	}
	v := View(name)
	return v, v.Valid()
}

// Select chooses the plan for one answer. q is the VALIDATED query that ran and
// rs its result; a nil query or result gets the SUMMARY plan. s is the model's
// suggestion (zero value: none). Select never mutates q or rs.
func Select(q *ast.AST, rs *plan.ResultSet, s Suggestion) Plan {
	p := Default(q, rs)
	if !s.offered() {
		return p
	}
	v, ok := s.view()
	if !ok {
		p.Disclosure = DisclosureNotAView
		return p
	}
	if !Fits(v, q, rs) {
		p.Disclosure = DisclosureNoFit
		return p
	}
	if v == p.PrimaryView {
		p.ChosenBy = ChosenByModel
		return p
	}
	// The suggestion leads; the server's own choice stays as the second view
	// so nothing the server would have shown is lost.
	second := p.PrimaryView
	if second == Summary {
		second = ""
	}
	p.PrimaryView, p.SecondaryView, p.ChosenBy = v, second, ChosenByModel
	return p
}

// Default is the server's deterministic plan from the query and the result's
// shape (design Part 2 §31):
//
//	"how did X change"            → TIME_SERIES             (metric_series)
//	"which are highest"           → BAR + TABLE             (metric_topk)
//	"which match"                 → TABLE                   (metric_filter)
//	"compare this week with last" → BAR with delta + TABLE  (compare_windows)
//	"who made the most changes"   → BAR + TABLE             (change_list grouped)
//	"show exactly what changed"   → DIFF + CHANGE_CARD      (one change with before/after)
//	"what changed"                → TIMELINE + TABLE        (change_list)
//	"which incidents"             → TABLE + TIMELINE        (incident_list)
//	"why did incident X happen"   → INCIDENT_CARD + EVIDENCE_LIST (incident_explain)
func Default(q *ast.AST, rs *plan.ResultSet) Plan {
	p := Plan{PrimaryView: Summary, Title: fallbackTitle, ChosenBy: ChosenByServer}
	if q == nil || rs == nil {
		return p
	}
	metric := Humanize(rs.Metric)
	titled := func(with, without string) string {
		if metric == "" {
			return without
		}
		return metric + with
	}
	switch q.Type {
	case ast.MetricSeries:
		p.PrimaryView, p.SecondaryView, p.Title = TimeSeries, Table, titled(" over time", "Over time")
	case ast.MetricTopK:
		p.PrimaryView, p.SecondaryView = Bar, Table
		if metric != "" {
			p.Title = "Highest " + metric
		} else {
			p.Title = "Highest values"
		}
	case ast.MetricFilter:
		p.PrimaryView, p.Title = Table, titled(" matching the condition", "Matching values")
	case ast.CompareWindows:
		p.PrimaryView, p.SecondaryView = Bar, Table
		p.Title = titled(": this window against the earlier one", "This window against the earlier one")
	case ast.ChangeList:
		switch {
		case len(q.GroupBy) > 0 && fieldName(q.GroupBy[0]):
			p.PrimaryView, p.SecondaryView, p.Title = Bar, Table, "Changes by "+Humanize(q.GroupBy[0])
		case len(rs.Rows) == 1 && hasBeforeAfter(rs.Rows[0]):
			p.PrimaryView, p.SecondaryView, p.Title = Diff, ChangeCard, "What changed"
		default:
			p.PrimaryView, p.SecondaryView, p.Title = Timeline, Table, "Changes in this window"
		}
	case ast.IncidentList:
		p.PrimaryView, p.SecondaryView, p.Title = Table, Timeline, "Incidents in this window"
	case ast.IncidentExplain:
		p.PrimaryView, p.SecondaryView, p.Title = IncidentCard, EvidenceList, "Why this incident happened"
	}
	return p
}

// Fits reports whether view v can honestly draw this result: a chart over the
// shape the query returns, a card only for the one thing it describes. SUMMARY
// always fits. TOPOLOGY, PATH and RECOMMENDATION_CARD fit no shape the query
// engine returns today, so a suggestion of them is ignored.
func Fits(v View, q *ast.AST, rs *plan.ResultSet) bool {
	if v == Summary {
		return true
	}
	if q == nil || rs == nil {
		return false
	}
	switch q.Type {
	case ast.MetricSeries:
		return v == TimeSeries || v == Table
	case ast.MetricTopK, ast.MetricFilter:
		return v == Bar || v == Table || v == EvidenceList
	case ast.CompareWindows:
		return v == Bar || v == Table
	case ast.ChangeList:
		switch v {
		case Timeline, Table, Bar, EvidenceList:
			return true
		case ChangeCard:
			return len(rs.Rows) == 1
		case Diff:
			return len(rs.Rows) == 1 && (hasBeforeAfter(rs.Rows[0]) || hasUnified(rs.Rows[0]))
		}
	case ast.IncidentList:
		switch v {
		case Table, Timeline, Bar, EvidenceList:
			return true
		case IncidentCard:
			return len(rs.Rows) == 1
		}
	case ast.IncidentExplain:
		return v == IncidentCard || v == EvidenceList
	}
	return false
}

const fallbackTitle = "Answer"

func hasBeforeAfter(r plan.Row) bool {
	return r["before"] != nil && r["after"] != nil
}

func hasUnified(r plan.Row) bool {
	_, ok := r["unified"].(string)
	return ok
}

// fieldName mirrors the client's isFieldName: a lower-case catalog identifier.
func fieldName(s string) bool {
	if s == "" || len(s) > 64 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}

// Humanize turns a catalog name into words: "object_kind" → "Object kind",
// "wan_rtt" → "WAN RTT". It mirrors presentation.ts humanize. A name that is
// not a catalog identifier gives "" — the title then omits it.
func Humanize(field string) string {
	if !fieldName(field) {
		return ""
	}
	words := strings.FieldsFunc(field, func(r rune) bool { return r == '_' })
	for i, w := range words {
		if up, ok := acronym(w); ok {
			words[i] = up
		}
	}
	if len(words) == 0 {
		return ""
	}
	first := words[0]
	if first != strings.ToUpper(first) {
		words[0] = strings.ToUpper(first[:1]) + first[1:]
	}
	return strings.Join(words, " ")
}

func acronym(w string) (string, bool) {
	switch w {
	case "id", "ip", "bgp", "cpu", "wan", "lan", "vpn", "rtt":
		return strings.ToUpper(w), true
	}
	return "", false
}
