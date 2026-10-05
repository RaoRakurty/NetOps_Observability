// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package chips turns a VALIDATED query into the editable filter chips an
// answer shows, and turns one chip edit back into a query (tracker 337 N-C7,
// Part 2 §34: "changing a chip should regenerate the Query AST
// deterministically").
//
// The chips are always derived on the SERVER from the query the server holds
// (the conversation's last answered query). A client never sends a query: it
// names a chip by id, an operation (set / remove) and — for set — a value,
// and that value must be one of the options the server itself offers for that
// chip. Apply rebuilds the chips from the held query, looks the chip up,
// checks the value against the offered list and rewrites a COPY of the query.
// The result is NOT trusted: the caller validates it exactly like a compiled
// query (validate.Validate in the caller's current scope) before it runs.
//
// Everything is deterministic: the same query, options and edit always give
// the same chips and the same regenerated query — no model is involved.
package chips

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
)

// Bounds.
const (
	MaxChips   = 12 // = the chip bar's own cap (src/frontend/src/iris/FilterChipBar.tsx)
	MaxOptions = 50
	maxLabel   = 80
	maxValue   = 128
)

// Ops (closed).
const (
	OpSet    = "set"
	OpRemove = "remove"
)

// Chip ids for the query-wide chips. Entity chips are "ref:<i>", list
// filters are "filter:<i>" (one chip per filter) or "filter:<i>:<j>" (one
// chip per value of an enum filter).
const (
	IDMetric = "metric"
	IDWindow = "window"
)

// Errors. Each is a malformed or stale edit, never a data error.
var (
	ErrUnknownChip  = errors.New("that filter is not on this answer")
	ErrNotOffered   = errors.New("that value is not one of the choices for this filter")
	ErrNotRemovable = errors.New("this filter cannot be removed")
	ErrNotEditable  = errors.New("this filter cannot be changed")
	ErrBadOp        = errors.New("op is set or remove")
)

// Option is one value a chip may be changed to.
type Option struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// Chip is one editable filter of an answer. The JSON shape is the chip bar's
// (src/frontend/src/iris/FilterChipBar.tsx FilterChip).
type Chip struct {
	ID         string   `json:"id"`
	Field      string   `json:"field"`
	Label      string   `json:"label"`
	Value      string   `json:"value"`
	ValueLabel string   `json:"valueLabel,omitempty"`
	Options    []Option `json:"options,omitempty"`
	Removable  bool     `json:"removable"`
}

// Edit is one operator change to one chip.
type Edit struct {
	Chip  string
	Op    string
	Value string
}

// Known lists the entities of one type the operator may pick for an entity
// chip — the caller's OWN visible entities (bounded); the caller builds it
// from the conversation and its scoped inventory. nil offers nothing beyond
// the chip's current value.
type Known func(entityType string) []Option

// windowGrid is the closed set of windows a time chip offers. Lists may look
// back 30 days, metric queries 7 (the validator's limits).
var windowGrid = []Option{
	{"15m", "Last 15 minutes"}, {"1h", "Last hour"}, {"6h", "Last 6 hours"},
	{"24h", "Last 24 hours"}, {"7d", "Last 7 days"}, {"30d", "Last 30 days"},
}

var acronyms = map[string]bool{"wan": true, "dns": true, "isp": true, "vpn": true, "sdwan": true}

var entityLabel = map[string]string{
	"device": "Device", "site": "Site", "interface": "Interface", "circuit": "Circuit", "bgp_peer": "BGP peer",
	"provider": "Provider", "application": "Application", "probe_target": "Probe target", "incident": "Incident", "change": "Change",
}

// Build returns the chips of a validated query, in a stable order: metric,
// time, entities, filters — at most MaxChips.
func Build(cat *catalog.Catalog, q *ast.AST, known Known) []Chip {
	if cat == nil || q == nil {
		return nil
	}
	var out []Chip
	if q.Type.IsMetric() && q.Metric != "" {
		out = append(out, metricChip(cat, q))
	}
	if c, ok := windowChip(q); ok {
		out = append(out, c)
	}
	for i, r := range q.Refs {
		out = append(out, refChip(i, r, known))
	}
	for i, f := range q.Filters {
		out = append(out, filterChips(cat, q, i, f)...)
	}
	if len(out) > MaxChips {
		out = out[:MaxChips]
	}
	return out
}

func metricChip(cat *catalog.Catalog, q *ast.AST) Chip {
	c := Chip{ID: IDMetric, Field: "metric", Label: "Metric", Value: q.Metric, ValueLabel: metricLabel(cat, q.Metric)}
	// A threshold is in the metric's own unit ("cpu above 80"): swapping the
	// metric under it would ask a different question with a meaningless
	// number, so a query with a predicate keeps its metric fixed.
	if q.Predicate != nil {
		return c
	}
	var opts []Option
	for _, m := range cat.Metrics {
		if contains(m.EntityTypes, q.Target) {
			opts = append(opts, Option{Value: m.Name, Label: metricLabel(cat, m.Name)})
		}
	}
	sort.Slice(opts, func(i, j int) bool { return opts[i].Label < opts[j].Label })
	c.Options = boundOptions(opts, q.Metric)
	return c
}

func metricLabel(cat *catalog.Catalog, name string) string {
	if m, ok := cat.Metric(name); ok && m.Description != "" {
		return clip(m.Description, maxLabel)
	}
	return name
}

func windowChip(q *ast.AST) (Chip, bool) {
	c := Chip{ID: IDWindow, Field: "window", Label: "Time"}
	max := 7 * 24 * 60 // minutes
	if q.Type == ast.ChangeList || q.Type == ast.IncidentList {
		max = 30 * 24 * 60
	}
	switch q.Time.Kind {
	case ast.TimeRelative:
		c.Value = q.Time.Last
		c.ValueLabel = windowLabel(q.Time.Last)
	case ast.TimeAbsolute:
		if q.Time.From == nil || q.Time.To == nil {
			return Chip{}, false
		}
		c.Value = "absolute"
		c.ValueLabel = q.Time.From.UTC().Format("Jan 2 15:04") + " – " + q.Time.To.UTC().Format("Jan 2 15:04") + " UTC"
	case ast.TimeIncident, ast.TimeIncidents:
		// Anchored to incidents: the window IS the incident's; shown, not edited.
		c.Value, c.ValueLabel = q.Time.Kind, "Around the incident"
		if q.Time.Kind == ast.TimeIncidents {
			c.ValueLabel = "Around each incident"
		}
		return c, true
	default:
		return Chip{}, false
	}
	// A comparison keeps two windows of equal length; only a relative pair
	// can be re-sized together.
	if q.CompareTo != nil && (q.Time.Kind != ast.TimeRelative || q.CompareTo.Kind != ast.TimeRelative) {
		return c, true
	}
	var opts []Option
	for _, o := range windowGrid {
		if d, err := ast.ParseDuration(o.Value); err == nil && int(d.Minutes()) <= max {
			opts = append(opts, o)
		}
	}
	c.Options = opts
	return c, true
}

func windowLabel(last string) string {
	for _, o := range windowGrid {
		if o.Value == last {
			return o.Label
		}
	}
	return "Last " + last
}

func refChip(i int, r ast.EntityRef, known Known) Chip {
	label := entityLabel[r.Type]
	if label == "" {
		label = r.Type
	}
	c := Chip{ID: "ref:" + strconv.Itoa(i), Field: r.Type, Label: label, Value: r.ID, Removable: true}
	var opts []Option
	if known != nil {
		opts = known(r.Type)
	}
	for _, o := range opts {
		if o.Value == r.ID {
			c.ValueLabel = clip(o.Label, maxLabel)
		}
	}
	if c.ValueLabel == "" {
		c.ValueLabel = clip(tail(r.ID), maxLabel)
	}
	// Incidents are named by id, not picked from a list.
	if r.Type != "incident" {
		c.Options = boundOptions(opts, r.ID)
	}
	return c
}

func filterChips(cat *catalog.Catalog, q *ast.AST, i int, f ast.Filter) []Chip {
	label := humanize(f.Field)
	if f.Op == "ne" {
		label = "Not " + strings.ToLower(label)
	}
	dim, _ := cat.Dimension(q.Target, f.Field)
	if dim == nil || dim.Type != "enum" || len(dim.Enum) == 0 {
		// A free-form dimension (actor, object, the "else" exclusion): one
		// chip for the whole filter, removable, not changeable — there is no
		// closed list to pick a value from.
		v := strings.Join(f.Values, ", ")
		if f.Field == "id" {
			v = fmt.Sprintf("%d earlier change(s)", len(f.Values))
			label = "Excluding"
		}
		return []Chip{{ID: "filter:" + strconv.Itoa(i), Field: f.Field, Label: clip(label, maxLabel), Value: clip(v, maxValue), Removable: true}}
	}
	var opts []Option
	for _, e := range dim.Enum {
		opts = append(opts, Option{Value: e.Value, Label: enumLabel(e)})
	}
	var out []Chip
	for j, v := range f.Values {
		out = append(out, Chip{ID: "filter:" + strconv.Itoa(i) + ":" + strconv.Itoa(j), Field: f.Field, Label: clip(label, maxLabel),
			Value: v, ValueLabel: labelOf(opts, v), Options: boundOptions(opts, v), Removable: true})
	}
	return out
}

// enumLabel: an acronym stays one ("SDWAN", "DIA"); a snake-case constant
// reads as words ("NETWORK_CHANGE" → "Network change").
func enumLabel(e catalog.EnumValue) string {
	if strings.ToUpper(e.Value) == e.Value && !strings.Contains(e.Value, "_") {
		return e.Value
	}
	if acronyms[e.Value] {
		return strings.ToUpper(e.Value)
	}
	return humanize(strings.ToLower(e.Value))
}

// Apply regenerates the query from one edit. q is the SERVER-held query the
// chips were built from; the edit is checked against the chips Build gives for
// it (so an id or value the server did not offer is refused). The returned
// query must still be validated by the caller before it runs.
func Apply(cat *catalog.Catalog, q *ast.AST, known Known, e Edit) (*ast.AST, Chip, error) {
	if e.Op != OpSet && e.Op != OpRemove {
		return nil, Chip{}, ErrBadOp
	}
	var chip *Chip
	all := Build(cat, q, known)
	for i := range all {
		if all[i].ID == e.Chip {
			chip = &all[i]
		}
	}
	if chip == nil {
		return nil, Chip{}, ErrUnknownChip
	}
	switch e.Op {
	case OpRemove:
		if !chip.Removable {
			return nil, *chip, ErrNotRemovable
		}
	case OpSet:
		if len(chip.Options) == 0 {
			return nil, *chip, ErrNotEditable
		}
		if !offered(chip.Options, e.Value) {
			return nil, *chip, ErrNotOffered
		}
	}
	out := q.Clone()
	if out == nil {
		return nil, *chip, errors.New("the query could not be copied")
	}
	if err := rewrite(cat, out, *chip, e); err != nil {
		return nil, *chip, err
	}
	return out, *chip, nil
}

func rewrite(cat *catalog.Catalog, q *ast.AST, c Chip, e Edit) error {
	switch {
	case c.ID == IDMetric:
		q.Metric = e.Value
		if m, ok := cat.Metric(e.Value); ok && q.Agg != "" && !contains(m.Aggregations, q.Agg) {
			q.Agg = "" // the validator applies the new metric's default
		}
	case c.ID == IDWindow:
		q.Time = ast.TimeRange{Kind: ast.TimeRelative, Last: e.Value}
		if q.CompareTo != nil {
			q.CompareTo.Last = e.Value
		}
	case strings.HasPrefix(c.ID, "ref:"):
		i, err := strconv.Atoi(strings.TrimPrefix(c.ID, "ref:"))
		if err != nil || i < 0 || i >= len(q.Refs) {
			return ErrUnknownChip
		}
		if e.Op == OpRemove {
			q.Refs = append(q.Refs[:i], q.Refs[i+1:]...)
			if len(q.Refs) == 0 {
				q.Refs = nil
			}
			return nil
		}
		q.Refs[i] = ast.EntityRef{Type: q.Refs[i].Type, ID: e.Value}
		q.Refs = dedupeRefs(q.Refs)
	case strings.HasPrefix(c.ID, "filter:"):
		parts := strings.Split(strings.TrimPrefix(c.ID, "filter:"), ":")
		i, err := strconv.Atoi(parts[0])
		if err != nil || i < 0 || i >= len(q.Filters) {
			return ErrUnknownChip
		}
		if len(parts) == 1 { // a whole-filter chip: remove only
			q.Filters = append(q.Filters[:i], q.Filters[i+1:]...)
			if len(q.Filters) == 0 {
				q.Filters = nil
			}
			return nil
		}
		j, err := strconv.Atoi(parts[1])
		if err != nil || j < 0 || j >= len(q.Filters[i].Values) {
			return ErrUnknownChip
		}
		f := &q.Filters[i]
		if e.Op == OpRemove {
			f.Values = append(f.Values[:j], f.Values[j+1:]...)
		} else {
			f.Values[j] = e.Value
			f.Values = dedupe(f.Values)
		}
		switch {
		case len(f.Values) == 0:
			q.Filters = append(q.Filters[:i], q.Filters[i+1:]...)
			if len(q.Filters) == 0 {
				q.Filters = nil
			}
		case len(f.Values) == 1 && f.Op == "in":
			f.Op = "eq"
		case len(f.Values) > 1 && f.Op == "eq":
			f.Op = "in"
		}
	default:
		return ErrUnknownChip
	}
	return nil
}

// Describe is the plain-language record of an edit, used as the turn's text
// ("Changed Site to Austin", "Removed Device edge-a").
func Describe(c Chip, e Edit) string {
	cur := c.ValueLabel
	if cur == "" {
		cur = c.Value
	}
	if e.Op == OpRemove {
		return clip(fmt.Sprintf("Removed %s: %s", c.Label, cur), 200)
	}
	return clip(fmt.Sprintf("Changed %s from %s to %s", c.Label, cur, labelOf(c.Options, e.Value)), 200)
}

func offered(opts []Option, v string) bool {
	for _, o := range opts {
		if o.Value == v {
			return true
		}
	}
	return false
}

func labelOf(opts []Option, v string) string {
	for _, o := range opts {
		if o.Value == v {
			return o.Label
		}
	}
	return v
}

// boundOptions deduplicates and caps a list, keeping the current value in it.
func boundOptions(in []Option, current string) []Option {
	var out []Option
	seen := map[string]bool{}
	add := func(o Option) {
		if o.Value == "" || len(o.Value) > maxValue || seen[o.Value] {
			return
		}
		seen[o.Value] = true
		o.Label = clip(o.Label, maxLabel)
		if o.Label == "" {
			o.Label = tail(o.Value)
		}
		out = append(out, o)
	}
	for _, o := range in {
		if o.Value == current {
			add(o)
		}
	}
	for _, o := range in {
		if len(out) == MaxOptions {
			break
		}
		add(o)
	}
	if len(out) == 1 && out[0].Value == current {
		return nil // nothing else to pick: the chip is read-only
	}
	return out
}

func dedupe(vs []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range vs {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func dedupeRefs(rs []ast.EntityRef) []ast.EntityRef {
	var out []ast.EntityRef
	seen := map[ast.EntityRef]bool{}
	for _, r := range rs {
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

func humanize(s string) string {
	s = strings.ReplaceAll(s, "_", " ")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func tail(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		return id[i+1:]
	}
	return id
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
