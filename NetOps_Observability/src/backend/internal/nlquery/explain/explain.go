// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package explain says, in plain language, what one compiled query does
// (tracker 337 N-C5: GET /api/ai/query/{id}/explain; Part 2 §33 "Interpreted
// Query"). It reads the query and the catalog only — no data, no model, no
// tenant — so the explanation is deterministic and the same query always
// reads the same way.
//
// Every slot the query fills becomes one Part: what kind of question it is,
// the metric and how it is aggregated, the entities it is about, the filters,
// the value condition, the time window (and the comparison window), grouping,
// ordering, the result limit and the incident it is anchored to. Values come
// from the query verbatim; nothing is inferred and nothing is hidden.
package explain

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/validate"
)

// Facets (closed) — the slot each Part explains, in display order.
const (
	FacetWhat      = "what"
	FacetMetric    = "metric"
	FacetEntities  = "entities"
	FacetFilters   = "filters"
	FacetCondition = "condition"
	FacetWindow    = "window"
	FacetCompare   = "compare"
	FacetGrouping  = "grouping"
	FacetOrder     = "order"
	FacetLimit     = "limit"
	FacetIncident  = "incident"
)

// Default incident-anchored span, mirrored from the planner (plan.DefaultBefore
// / DefaultAfter) — explain may not import plan's executor, so the explain
// test pins the two against each other.
const (
	DefaultBefore = "30m"
	DefaultAfter  = "10m"
)

// Part is one slot of the query, in words.
type Part struct {
	Facet string `json:"facet"`
	Text  string `json:"text"`
}

// Explanation is the plain-language reading of one query.
type Explanation struct {
	Summary string `json:"summary"`
	Parts   []Part `json:"parts"`
}

// Namer returns a display name for an entity reference, or "" when none is
// known (the reference is then shown by its id). The caller decides what may
// be named — explain never looks anything up.
type Namer func(ast.EntityRef) string

// Explain returns the plain-language reading of q. cat and name may be nil.
func Explain(cat *catalog.Catalog, q *ast.AST, name Namer) Explanation {
	if q == nil {
		return Explanation{Parts: []Part{}}
	}
	x := explainer{cat: cat, name: name}
	var parts []Part
	add := func(facet, text string) {
		if text != "" {
			parts = append(parts, Part{Facet: facet, Text: text})
		}
	}
	add(FacetWhat, x.what(q))
	add(FacetMetric, x.metric(q))
	if q.Type != ast.IncidentExplain { // one incident, named below
		add(FacetEntities, x.refs(q.Refs, q.Target))
	}
	add(FacetFilters, x.filters(q.Target, q.Filters))
	add(FacetCondition, x.condition(q))
	win := x.window(q.Time)
	if q.Type != ast.IncidentExplain || q.Time.Kind != "" {
		add(FacetWindow, "Time window: "+win+".")
	}
	if q.CompareTo != nil {
		add(FacetCompare, "Compared with: "+x.window(*q.CompareTo)+".")
	}
	add(FacetGrouping, x.grouping(q.Target, q.GroupBy))
	add(FacetOrder, x.order(q.Target, q.OrderBy))
	if q.Limit > 0 && q.Type != ast.MetricTopK { // a top-k says its k in "what"
		add(FacetLimit, fmt.Sprintf("At most %d result%s.", q.Limit, plural(q.Limit)))
	}
	if q.IncidentID != "" {
		add(FacetIncident, "About incident "+q.IncidentID+".")
	}
	return Explanation{Summary: x.summary(q, win), Parts: parts}
}

type explainer struct {
	cat  *catalog.Catalog
	name Namer
}

// ---- what -------------------------------------------------------------------

func (x explainer) what(q *ast.AST) string {
	m := x.metricLabel(q.Metric)
	t := x.entityPlural(q.Target)
	switch q.Type {
	case ast.MetricSeries:
		return fmt.Sprintf("Shows %s over time.", m)
	case ast.MetricTopK:
		return fmt.Sprintf("Ranks %s by %s and lists the top %d.", t, m, q.LimitOr(validate.DefaultTopK))
	case ast.MetricFilter:
		return fmt.Sprintf("Lists the %s whose %s meets a condition.", t, m)
	case ast.CompareWindows:
		return fmt.Sprintf("Compares %s between two time windows and ranks what changed most.", m)
	case ast.ChangeList:
		return "Lists changes (configuration and other recorded changes)."
	case ast.IncidentList:
		return "Lists incidents."
	case ast.IncidentExplain:
		return "Explains one incident: what happened and the likely cause."
	case ast.FlowTop, ast.LogSearch:
		return fmt.Sprintf("A %s question — this kind of query is not supported yet.", strings.ReplaceAll(string(q.Type), "_", " "))
	}
	return fmt.Sprintf("A %q query.", string(q.Type))
}

func (x explainer) summary(q *ast.AST, win string) string {
	head := strings.TrimSuffix(x.what(q), ".")
	if len(q.Refs) > 0 {
		head += " for " + x.refList(q.Refs)
	}
	if q.Type == ast.IncidentExplain {
		if q.IncidentID != "" {
			head += " (incident " + q.IncidentID + ")"
		}
		return head + "."
	}
	return head + " — " + win + "."
}

// ---- metric -----------------------------------------------------------------

var aggWords = map[string]string{
	"avg": "the average", "max": "the maximum", "min": "the minimum", "p95": "the 95th percentile",
	"last": "the latest value", "sum": "the total",
}

func (x explainer) metric(q *ast.AST) string {
	if q.Metric == "" {
		return ""
	}
	s := "Metric: " + x.metricLabel(q.Metric) + " (" + q.Metric + ")"
	if x.cat != nil {
		if m, ok := x.cat.Metric(q.Metric); ok {
			if m.Description != "" {
				s += " — " + strings.TrimSuffix(m.Description, ".")
			}
			if u := unitWord(m.Unit); u != "" {
				s += ", in " + u
			}
		}
	}
	s += "."
	if q.Agg != "" {
		w, ok := aggWords[q.Agg]
		if !ok {
			w = q.Agg
		}
		s += " Each value is " + w + " over the window."
	}
	return s
}

func (x explainer) metricLabel(name string) string {
	if name == "" {
		return "the metric"
	}
	if x.cat != nil {
		if m, ok := x.cat.Metric(name); ok && len(m.Aliases) > 0 {
			return m.Aliases[0]
		}
	}
	return strings.ReplaceAll(name, "_", " ")
}

func unitWord(u string) string {
	switch u {
	case "percent", "pct", "%":
		return "percent"
	case "bps":
		return "bits per second"
	case "ms":
		return "milliseconds"
	case "", "count", "score", "state", "bool":
		return "" // a plain number or a state code: no unit worth naming
	}
	return u
}

// ---- entities ---------------------------------------------------------------

func (x explainer) refs(refs []ast.EntityRef, target string) string {
	if len(refs) == 0 {
		if target == "" {
			return ""
		}
		return "About every " + x.entitySingular(target) + " you can see — no specific one was named."
	}
	return "About " + x.refList(refs) + "."
}

// refList: refs of one type are OR'd, refs of different types AND'd (ast).
func (x explainer) refList(refs []ast.EntityRef) string {
	var order []string
	byType := map[string][]string{}
	for _, r := range refs {
		if _, ok := byType[r.Type]; !ok {
			order = append(order, r.Type)
		}
		byType[r.Type] = append(byType[r.Type], x.refName(r))
	}
	groups := make([]string, 0, len(order))
	for _, t := range order {
		groups = append(groups, x.entitySingular(t)+" "+join(byType[t], "or"))
	}
	return strings.Join(groups, ", and ")
}

func (x explainer) refName(r ast.EntityRef) string {
	id := r.ID
	if x.cat != nil {
		if e, ok := x.cat.Entity(r.Type); ok && e.IDPrefix != "" {
			id = strings.TrimPrefix(id, e.IDPrefix)
		}
	}
	if x.name != nil {
		if n := strings.TrimSpace(x.name(r)); n != "" && n != id {
			return n + " (" + id + ")"
		}
	}
	return id
}

func (x explainer) entitySingular(t string) string {
	switch t {
	case "bgp_peer":
		return "BGP peer"
	case "probe_target":
		return "probe target"
	case "":
		return "item"
	}
	return strings.ReplaceAll(t, "_", " ")
}

func (x explainer) entityPlural(t string) string {
	s := x.entitySingular(t)
	switch {
	case strings.HasSuffix(s, "y") && !strings.HasSuffix(s, "ey"):
		return s[:len(s)-1] + "ies"
	case strings.HasSuffix(s, "s"):
		return s + "es"
	}
	return s + "s"
}

// ---- filters, condition -----------------------------------------------------

func (x explainer) dimLabel(target, field string) string {
	if x.cat != nil {
		if d, ok := x.cat.Dimension(target, field); ok && len(d.Aliases) > 0 {
			return d.Aliases[0]
		}
	}
	return strings.ReplaceAll(field, "_", " ")
}

func (x explainer) filters(target string, fs []ast.Filter) string {
	if len(fs) == 0 {
		return ""
	}
	var out []string
	for _, f := range fs {
		label := x.dimLabel(target, f.Field)
		vals := quoteAll(f.Values)
		switch f.Op {
		case "eq":
			out = append(out, label+" is "+join(vals, "or"))
		case "ne":
			out = append(out, label+" is not "+join(vals, "or"))
		case "in":
			out = append(out, label+" is one of "+join(vals, "or"))
		default:
			out = append(out, label+" "+f.Op+" "+join(vals, "or"))
		}
	}
	return "Only where " + strings.Join(out, ", and ") + "."
}

var cmpWords = map[string]string{"gt": "is above", "ge": "is at least", "lt": "is below", "le": "is at most",
	"eq": "equals", "ne": "is not"}

func (x explainer) condition(q *ast.AST) string {
	p := q.Predicate
	if p == nil {
		return ""
	}
	m := x.metricLabel(q.Metric)
	unit := ""
	var enum map[string]float64
	if x.cat != nil {
		if mm, ok := x.cat.Metric(q.Metric); ok {
			unit, enum = mm.Unit, mm.ValueEnum
		}
	}
	switch p.Op {
	case "gt", "ge", "lt", "le", "eq", "ne":
		v := num(p.Value, unit)
		if name := enumName(enum, p.Value); name != "" { // a state code reads as its state
			v = name + " (" + v + ")"
		}
		return fmt.Sprintf("Keeps only results where %s %s %s.", m, cmpWords[p.Op], v)
	case "between":
		return fmt.Sprintf("Keeps only results where %s is between %s and %s.", m, num(p.Value, unit), num(p.Value2, unit))
	case "above_baseline":
		return fmt.Sprintf("Keeps only results where %s is above its usual level (the 95th percentile of the previous 7 days).", m)
	case "increased_by":
		return fmt.Sprintf("Keeps only results where %s rose by more than %s compared with the window just before.", m, num(p.Value, unit))
	}
	return fmt.Sprintf("Keeps only results where %s %s %s.", m, p.Op, num(p.Value, unit))
}

// enumName is the catalog's name for a state value ("" when it has none, or
// more than one name maps to it — then the number is shown alone).
func enumName(enum map[string]float64, v float64) string {
	var names []string
	for k, ev := range enum {
		if ev == v {
			names = append(names, k)
		}
	}
	if len(names) != 1 {
		return ""
	}
	return strings.ReplaceAll(names[0], "_", " ")
}

func num(v float64, unit string) string {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	switch unit {
	case "percent", "pct", "%":
		return s + "%"
	case "", "count", "score", "state", "bool":
		return s
	}
	return s + " " + unit
}

// ---- time -------------------------------------------------------------------

// window is a noun phrase for t: "the last 2 hours", "2026-09-01 10:00 UTC to
// 2026-09-01 11:00 UTC", "30 minutes before to 10 minutes after incident X
// began".
func (x explainer) window(t ast.TimeRange) string {
	switch t.Kind {
	case ast.TimeRelative:
		if t.Offset != "" {
			return "a " + durationAdj(t.Last) + " window ending " + duration(t.Offset) + " ago"
		}
		if strings.HasPrefix(t.Last, "1") && len(t.Last) == 2 { // "1h" → "the last hour"
			return "the last " + strings.TrimPrefix(duration(t.Last), "1 ")
		}
		return "the last " + duration(t.Last)
	case ast.TimeAbsolute:
		if t.From != nil && t.To != nil {
			return stamp(*t.From) + " to " + stamp(*t.To)
		}
	case ast.TimeIncident:
		if t.Anchor != nil && t.Anchor.IncidentID != "" {
			b, a := anchorSpan(t.Anchor)
			return fmt.Sprintf("%s before to %s after incident %s began", duration(b), duration(a), t.Anchor.IncidentID)
		}
	case ast.TimeIncidents:
		if t.Anchor != nil && t.Anchor.Incidents != nil {
			b, a := anchorSpan(t.Anchor)
			set := t.Anchor.Incidents
			s := fmt.Sprintf("%s before to %s after each incident", duration(b), duration(a))
			var sel []string
			if len(set.Refs) > 0 {
				sel = append(sel, "about "+x.refList(set.Refs))
			}
			if f := x.filters("incident", set.Filters); f != "" {
				sel = append(sel, "where "+strings.TrimSuffix(strings.TrimPrefix(f, "Only where "), "."))
			}
			sel = append(sel, "that began in "+x.window(set.Time))
			if set.Max > 0 {
				sel = append(sel, fmt.Sprintf("at most %d incidents", set.Max))
			}
			return s + " " + strings.Join(sel, ", ")
		}
	}
	if t.Kind == "" {
		return "the default window"
	}
	return "a " + t.Kind + " window"
}

func anchorSpan(a *ast.Anchor) (string, string) {
	b, af := DefaultBefore, DefaultAfter
	if a.Before != "" {
		b = a.Before
	}
	if a.After != "" {
		af = a.After
	}
	return b, af
}

// duration renders the AST's closed duration token ("15m", "2h", "7d").
func duration(s string) string {
	if d, err := ast.ParseDuration(s); err != nil || d <= 0 {
		return s // a malformed token is shown exactly as written
	}
	n := s[:len(s)-1]
	unit := map[byte]string{'m': "minute", 'h': "hour", 'd': "day"}[s[len(s)-1]]
	if n == "1" {
		return "1 " + unit
	}
	return n + " " + unit + "s"
}

// durationAdj is duration as an adjective: "2-hour".
func durationAdj(s string) string {
	d := duration(s)
	if d == s { // malformed: shown as written
		return s
	}
	return strings.TrimSuffix(strings.Replace(d, " ", "-", 1), "s")
}

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") }

// ---- grouping, order --------------------------------------------------------

func (x explainer) grouping(target string, by []string) string {
	if len(by) == 0 {
		return ""
	}
	labels := make([]string, 0, len(by))
	for _, g := range by {
		labels = append(labels, x.dimLabel(target, g))
	}
	return "Grouped by " + join(labels, "and") + "."
}

func (x explainer) order(target string, keys []ast.OrderKey) string {
	if len(keys) == 0 {
		return ""
	}
	var out []string
	for _, k := range keys {
		dir := "highest first"
		if k.Dir == "asc" {
			dir = "lowest first"
		}
		if k.Field == "event_at" || k.Field == "created_at" || k.Field == "time" {
			dir = "newest first"
			if k.Dir == "asc" {
				dir = "oldest first"
			}
		}
		out = append(out, x.dimLabel(target, k.Field)+", "+dir)
	}
	return "Sorted by " + strings.Join(out, "; ") + "."
}

// ---- words ------------------------------------------------------------------

func join(xs []string, conj string) string {
	switch len(xs) {
	case 0:
		return ""
	case 1:
		return xs[0]
	case 2:
		return xs[0] + " " + conj + " " + xs[1]
	}
	return strings.Join(xs[:len(xs)-1], ", ") + " " + conj + " " + xs[len(xs)-1]
}

func quoteAll(vs []string) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, strconv.Quote(v))
	}
	sort.Strings(out)
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
