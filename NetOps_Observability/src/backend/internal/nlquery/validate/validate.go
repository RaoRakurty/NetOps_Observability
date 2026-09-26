// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package validate

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
)

// Limits (design §3). Exported so the golden corpus and the UI can state them.
const (
	MaxMetricWindow     = 7 * 24 * time.Hour
	MaxListWindow       = 30 * 24 * time.Hour
	DefaultMetricWin    = "1h"
	DefaultListWin      = "24h"
	MaxRefs             = 20
	MaxEstimatedSeries  = 2000
	MaxTopK             = 100
	DefaultTopK         = 10
	DefaultChangeRows   = 100
	MaxChangeRows       = 500
	DefaultIncidentRows = 20
	MaxIncidentRows     = 200
	MaxCompareOffset    = 30 * 24 * time.Hour
	MaxAnchorIncidents  = 50
	MaxAnchorSpan       = 24 * time.Hour
	MaxGroupBy          = 2
	MaxOrderBy          = 1
	MaxFilterValues     = 20
	MaxValueLen         = 128
	FutureSkew          = 5 * time.Minute
)

// Scope is what the validator asks of the ROOT, which answers from the
// authenticated principal. The validator never sees a tenant.
type Scope interface {
	// Visible reports whether the caller may see this entity. A missing and a
	// foreign id MUST answer the same (false, nil).
	Visible(ctx context.Context, ref ast.EntityRef) (bool, error)
	// Count estimates how many `target` entities the refs select (for cost).
	Count(ctx context.Context, target string, refs []ast.EntityRef) (int, error)
	// CrossTenant reports a platform-operator (Global) principal.
	CrossTenant() bool
	Now() time.Time
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type checker struct {
	ctx context.Context
	cat *catalog.Catalog
	sc  Scope
	q   *ast.AST
	res Result
}

func (c *checker) fail(path, code, got, msg string, sugg ...string) {
	c.res.Errors = append(c.res.Errors, Error{Path: path, Code: code, Got: clip(got), Message: msg, Suggestions: sugg})
}

func (c *checker) constrain(path, from, to, reason string) {
	c.res.Constraints = append(c.res.Constraints, Constraint{Path: path, From: from, To: to, Reason: reason})
}

// Validate checks q against the catalog and the caller's scope. On success it
// returns a CONSTRAINED COPY of q (defaults and clamps applied, each reported);
// q itself is never modified.
func Validate(ctx context.Context, cat *catalog.Catalog, sc Scope, q *ast.AST) (*ast.AST, Result) {
	if q == nil {
		return nil, Result{Errors: []Error{{Path: "", Code: CodeMissingField, Message: "no query"}}}
	}
	c := &checker{ctx: ctx, cat: cat, sc: sc, q: q.Clone()}
	if c.q == nil {
		return nil, Result{Errors: []Error{{Code: CodeInvalidValue, Message: "query could not be copied"}}}
	}
	c.run()
	c.res.Valid = len(c.res.Errors) == 0
	if !c.res.Valid {
		return nil, c.res
	}
	return c.q, c.res
}

func (c *checker) run() {
	q := c.q
	if q.V != ast.Version {
		c.fail("v", CodeInvalidValue, strconv.Itoa(q.V), "only AST version 1 is supported")
		return
	}
	if !q.Type.Known() {
		c.fail("query_type", CodeUnknownQueryType, string(q.Type), "", suggest(string(q.Type), queryTypes(), nil)...)
		return
	}
	if q.Type == ast.FlowTop || q.Type == ast.LogSearch {
		c.fail("query_type", CodeUnsupportedQueryType, string(q.Type), "flow and log queries are not available through Iris NL yet")
		return
	}
	c.fieldMatrix()
	if len(c.res.Errors) > 0 {
		return // shape errors first: the rest would only add noise
	}
	switch {
	case q.Type.IsMetric():
		c.metric()
	case q.Type == ast.ChangeList, q.Type == ast.IncidentList:
		c.list()
	case q.Type == ast.IncidentExplain:
		c.incidentID("incident_id", q.IncidentID)
	}
	c.refs()
	c.times()
	c.groupOrder()
	c.limits()
}

func queryTypes() []string {
	return []string{string(ast.MetricSeries), string(ast.MetricTopK), string(ast.MetricFilter), string(ast.CompareWindows),
		string(ast.ChangeList), string(ast.IncidentList), string(ast.IncidentExplain)}
}

// fieldMatrix enforces which fields each query type requires and forbids.
func (c *checker) fieldMatrix() {
	q := c.q
	need := func(ok bool, path string) {
		if !ok {
			c.fail(path, CodeMissingField, "", path+" is required for "+string(q.Type))
		}
	}
	forbid := func(present bool, path string) {
		if present {
			c.fail(path, CodeForbiddenFieldForType, "", path+" is not allowed for "+string(q.Type))
		}
	}
	switch {
	case q.Type.IsMetric():
		need(q.Target != "", "target")
		need(q.Metric != "", "metric")
		forbid(len(q.Filters) > 0, "filters")
		forbid(q.IncidentID != "", "incident_id")
		need(q.Type != ast.MetricFilter || q.Predicate != nil, "predicate")
		need(q.Type != ast.CompareWindows || q.CompareTo != nil, "compare_to")
		forbid(q.Type != ast.CompareWindows && q.CompareTo != nil, "compare_to")
	case q.Type == ast.ChangeList || q.Type == ast.IncidentList:
		want := "change"
		if q.Type == ast.IncidentList {
			want = "incident"
		}
		if q.Target != want {
			c.fail("target", CodeInvalidValue, q.Target, "target must be "+want+" for "+string(q.Type))
		}
		forbid(q.Metric != "" || q.Agg != "", "metric")
		forbid(q.Predicate != nil, "predicate")
		forbid(q.CompareTo != nil, "compare_to")
		forbid(q.IncidentID != "", "incident_id")
	case q.Type == ast.IncidentExplain:
		need(q.IncidentID != "", "incident_id")
		forbid(q.Metric != "" || q.Predicate != nil || q.CompareTo != nil || len(q.Filters) > 0 || len(q.GroupBy) > 0, "fields")
		if q.Target != "" && q.Target != "incident" {
			c.fail("target", CodeInvalidValue, q.Target, "target must be incident")
		}
		c.q.Target = "incident"
	}
	if q.Target != "" {
		if _, ok := c.cat.Entity(q.Target); !ok {
			c.fail("target", CodeInvalidValue, q.Target, "unknown entity type", suggest(q.Target, entityNames(c.cat), nil)...)
		}
	}
}

func entityNames(cat *catalog.Catalog) []string {
	var out []string
	for _, e := range cat.Entities {
		out = append(out, e.Name)
	}
	return out
}

// metric checks the metric, its applicability, aggregation, predicate and scope.
func (c *checker) metric() {
	q := c.q
	m, ok := c.cat.Metric(q.Metric)
	if !ok {
		// An alias is not a canonical name — say which canonical name it means.
		var sugg []string
		pref := map[string]bool{}
		for _, h := range c.cat.Lookup(q.Metric) {
			if h.Kind == "metric" {
				sugg = append(sugg, h.Name)
				if strings.Contains(","+h.For+",", ","+q.Target+",") {
					pref[h.Name] = true
				}
			}
		}
		if len(sugg) == 0 {
			var names []string
			for _, mm := range c.cat.Metrics {
				names = append(names, mm.Name)
				if contains(mm.EntityTypes, q.Target) {
					pref[mm.Name] = true
				}
			}
			sugg = suggest(q.Metric, names, pref)
		}
		c.fail("metric", CodeUnknownMetric, q.Metric, "", sugg...)
		return
	}
	if !contains(m.EntityTypes, q.Target) {
		c.fail("metric", CodeMetricNotApplicable, q.Metric, fmt.Sprintf("%s applies to %s, not %s", m.Name, strings.Join(m.EntityTypes, ", "), q.Target))
		return
	}
	if m.Scope == "gated:N-B5" && !c.sc.CrossTenant() {
		// Never an empty result: that would read as "no loss".
		c.fail("metric", CodeScopeUnavailable, q.Metric, "this measurement is not yet visible to a workspace-scoped user")
		return
	}
	if q.Agg == "" {
		q.Agg = m.DefaultAgg
	} else if !contains(m.Aggregations, q.Agg) {
		c.fail("aggregation", CodeAggregationNotAllowed, q.Agg, "", m.Aggregations...)
	}
	if p := q.Predicate; p != nil {
		switch {
		case !contains(m.Operators, p.Op):
			c.fail("predicate.op", CodeOperatorNotAllowed, p.Op, "", m.Operators...)
		case p.Op == "above_baseline" && !m.BaselineOK:
			c.fail("predicate.op", CodeOperatorNotAllowed, p.Op, m.Name+" has no meaningful baseline")
		case p.Op == "between" && !(p.Value < p.Value2):
			c.fail("predicate.value", CodeInvalidValue, "", "between needs value < value2")
		case len(m.ValueEnum) > 0 && !enumValue(m.ValueEnum, p.Value):
			c.fail("predicate.value", CodeInvalidValue, strconv.FormatFloat(p.Value, 'f', -1, 64), m.Name+" takes one of its state values", enumKeys(m.ValueEnum)...)
		case m.Unit == "percent" && (p.Value < 0 || p.Value > 100 || p.Value2 > 100):
			c.fail("predicate.value", CodeInvalidValue, strconv.FormatFloat(p.Value, 'f', -1, 64), "a percentage is between 0 and 100")
		case p.Value < 0 || p.Value2 < 0:
			c.fail("predicate.value", CodeInvalidValue, strconv.FormatFloat(p.Value, 'f', -1, 64), "must not be negative")
		}
	}
}

func enumValue(e map[string]float64, v float64) bool {
	for _, x := range e {
		if x == v {
			return true
		}
	}
	return false
}

func enumKeys(e map[string]float64) []string {
	var out []string
	for k := range e {
		out = append(out, k)
	}
	return sortStrings(out)
}

// list checks change/incident filters.
func (c *checker) list() {
	for i, f := range c.q.Filters {
		path := fmt.Sprintf("filters[%d]", i)
		d, ok := c.cat.Dimension(c.q.Target, f.Field)
		if !ok {
			c.fail(path+".field", CodeUnknownDimension, f.Field, "", suggest(f.Field, c.dimNames(false), nil)...)
			continue
		}
		if !d.Filterable {
			c.fail(path+".field", CodeUnknownDimension, f.Field, f.Field+" is display-only")
			continue
		}
		if !contains(d.Operators, f.Op) {
			c.fail(path+".op", CodeOperatorNotAllowed, f.Op, "", d.Operators...)
			continue
		}
		if len(f.Values) == 0 || len(f.Values) > MaxFilterValues {
			c.fail(path+".values", CodeInvalidValue, "", fmt.Sprintf("1 to %d values", MaxFilterValues))
			continue
		}
		for _, v := range f.Values {
			if !printable(v) {
				c.fail(path+".values", CodeInvalidValue, v, fmt.Sprintf("values are printable and at most %d characters", MaxValueLen))
				break
			}
			switch d.Type {
			case "enum":
				if !enumHas(d, v) {
					c.fail(path+".values", CodeInvalidValue, v, "", suggest(v, enumValues(d), nil)...)
				}
			case "number":
				x, err := strconv.ParseFloat(v, 64)
				if err != nil || x < 0 || x > 1 {
					c.fail(path+".values", CodeInvalidValue, v, "a confidence is a number between 0 and 1")
				}
			}
		}
	}
}

func (c *checker) dimNames(groupable bool) []string {
	var out []string
	for _, d := range c.cat.Dimensions {
		if d.Entity == c.q.Target && (!groupable || d.Groupable) {
			out = append(out, d.Name)
		}
	}
	return out
}

func enumHas(d *catalog.Dimension, v string) bool {
	for _, e := range d.Enum {
		if e.Value == v {
			return true
		}
	}
	return false
}

func enumValues(d *catalog.Dimension) []string {
	var out []string
	for _, e := range d.Enum {
		out = append(out, e.Value)
	}
	return out
}

func printable(s string) bool {
	if s == "" || len([]rune(s)) > MaxValueLen {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// refs checks each entity reference: known type, well-formed id, reachable
// from the target, and VISIBLE to the caller. Missing and foreign ids produce
// the byte-identical error, so the validator is not an existence oracle.
func (c *checker) refs() {
	if len(c.q.Refs) > MaxRefs {
		c.fail("entities", CodeTooBroad, strconv.Itoa(len(c.q.Refs)), fmt.Sprintf("at most %d entities per query", MaxRefs))
		return
	}
	for i, r := range c.q.Refs {
		c.ref(fmt.Sprintf("entities[%d]", i), r, c.q.Target)
	}
}

func (c *checker) ref(path string, r ast.EntityRef, target string) {
	et, ok := c.cat.Entity(r.Type)
	if !ok {
		c.fail(path+".type", CodeInvalidValue, r.Type, "unknown entity type", suggest(r.Type, entityNames(c.cat), nil)...)
		return
	}
	if !regexp.MustCompile(et.IDPattern).MatchString(r.ID) {
		c.fail(path+".id", CodeInvalidEntityID, r.ID, "not a valid "+r.Type+" id")
		return
	}
	if target != "" && !c.cat.Reachable(target, r.Type) {
		c.fail(path+".type", CodeRelationshipNotAllowed, r.Type, r.Type+" cannot narrow a "+target+" query")
		return
	}
	vis, err := c.sc.Visible(c.ctx, r)
	if err != nil || !vis {
		c.fail(path+".id", CodeUnknownEntity, r.ID, "no such "+r.Type+" is visible to you")
	}
}

func (c *checker) incidentID(path, id string) {
	if !uuidRe.MatchString(id) {
		c.fail(path, CodeInvalidEntityID, id, "not an incident id")
		return
	}
	vis, err := c.sc.Visible(c.ctx, ast.EntityRef{Type: "incident", ID: "incident:" + id})
	if err != nil || !vis {
		c.fail(path, CodeUnknownEntity, id, "no such incident is visible to you")
	}
}

// times checks the window (and compare window) and applies the default.
func (c *checker) times() {
	q := c.q
	max, def := MaxListWindow, DefaultListWin
	if q.Type.IsMetric() {
		max, def = MaxMetricWindow, DefaultMetricWin
	}
	if q.Type == ast.IncidentExplain && q.Time.Kind == "" {
		return // the incident's own window
	}
	if q.Time.Kind == "" {
		q.Time = ast.TimeRange{Kind: ast.TimeRelative, Last: def}
		c.constrain("time_range", "none", "last "+def, "default_window")
	}
	c.window("time_range", &q.Time, max, q.Type == ast.ChangeList)
	if q.CompareTo != nil {
		c.window("compare_to", q.CompareTo, max, false)
		c.compare()
	}
}

func (c *checker) window(path string, t *ast.TimeRange, max time.Duration, allowIncidents bool) {
	now := c.sc.Now()
	span := func(d time.Duration) {
		if d > max {
			c.fail(path, CodeWindowTooLarge, d.String(), fmt.Sprintf("at most %s for this query", max), fmtDur(max))
		}
	}
	switch t.Kind {
	case ast.TimeRelative:
		d, err := ast.ParseDuration(t.Last)
		if err != nil {
			c.fail(path+".last", CodeInvalidTime, t.Last, err.Error())
			return
		}
		span(d)
		if t.Offset != "" {
			od, err := ast.ParseDuration(t.Offset)
			if err != nil || od > MaxCompareOffset {
				c.fail(path+".offset", CodeInvalidTime, t.Offset, "offset is at most 30d")
			}
		}
	case ast.TimeAbsolute:
		if t.From == nil || t.To == nil || !t.From.Before(*t.To) {
			c.fail(path, CodeInvalidTime, "", "absolute windows need from < to")
			return
		}
		if t.To.After(now.Add(FutureSkew)) {
			c.fail(path+".to", CodeInvalidTime, t.To.UTC().Format(time.RFC3339), "the window cannot end in the future")
			return
		}
		span(t.To.Sub(*t.From))
	case ast.TimeIncident:
		if t.Anchor == nil || t.Anchor.IncidentID == "" {
			c.fail(path+".anchor", CodeMissingField, "", "an incident window needs an incident")
			return
		}
		c.incidentID(path+".anchor.incident_id", t.Anchor.IncidentID)
		c.anchorSpan(path, t.Anchor)
	case ast.TimeIncidents:
		if !allowIncidents {
			c.fail(path+".kind", CodeInvalidTime, t.Kind, "a per-incident window is only for change lists")
			return
		}
		if t.Anchor == nil || t.Anchor.Incidents == nil {
			c.fail(path+".anchor", CodeMissingField, "", "a per-incident window needs an incident set")
			return
		}
		set := t.Anchor.Incidents
		if set.Time.Kind != ast.TimeRelative && set.Time.Kind != ast.TimeAbsolute {
			c.fail(path+".anchor.incidents.time_range", CodeInvalidTime, set.Time.Kind, "the incident set needs a relative or absolute window")
			return
		}
		c.window(path+".anchor.incidents.time_range", &set.Time, MaxListWindow, false)
		saveT, saveF := c.q.Target, c.q.Filters
		c.q.Target, c.q.Filters = "incident", set.Filters
		c.list()
		for i, r := range set.Refs {
			c.ref(fmt.Sprintf("%s.anchor.incidents.entities[%d]", path, i), r, "incident")
		}
		c.q.Target, c.q.Filters = saveT, saveF
		if set.Max <= 0 || set.Max > MaxAnchorIncidents {
			c.constrain(path+".anchor.incidents.max", strconv.Itoa(set.Max), strconv.Itoa(MaxAnchorIncidents), "max_anchor_incidents")
			set.Max = MaxAnchorIncidents
		}
		c.anchorSpan(path, t.Anchor)
	default:
		c.fail(path+".kind", CodeInvalidTime, t.Kind, "", ast.TimeRelative, ast.TimeAbsolute, ast.TimeIncident, ast.TimeIncidents)
	}
}

func (c *checker) anchorSpan(path string, a *ast.Anchor) {
	for _, x := range []struct{ name, v string }{{"before", a.Before}, {"after", a.After}} {
		if x.v == "" {
			continue
		}
		d, err := ast.ParseDuration(x.v)
		if err != nil || d > MaxAnchorSpan {
			c.fail(path+".anchor."+x.name, CodeInvalidTime, x.v, "at most 24h either side of an incident")
		}
	}
}

func (c *checker) compare() {
	a, b := c.q.Time, c.q.CompareTo
	if a.Kind != b.Kind || (a.Kind != ast.TimeRelative && a.Kind != ast.TimeAbsolute) {
		c.fail("compare_to", CodeInvalidTime, "", "both windows must be the same kind (relative or absolute)")
		return
	}
	if a.Kind == ast.TimeRelative && a.Last != b.Last {
		c.fail("compare_to.last", CodeInvalidTime, b.Last, "compared windows must be the same length", a.Last)
	}
	if a.Kind == ast.TimeAbsolute && a.From != nil && a.To != nil && b.From != nil && b.To != nil {
		if a.To.Sub(*a.From) != b.To.Sub(*b.From) {
			c.fail("compare_to", CodeInvalidTime, "", "compared windows must be the same length")
		}
		gap := a.From.Sub(*b.From)
		if gap < 0 {
			gap = -gap
		}
		if gap > MaxCompareOffset {
			c.fail("compare_to", CodeInvalidTime, "", "compared windows are at most 30d apart")
		}
	}
	if a.Kind == ast.TimeRelative && b.Offset == "" {
		c.fail("compare_to.offset", CodeMissingField, "", "the comparison window needs an offset (e.g. 1d for yesterday)")
	}
}

// groupOrder checks grouping and ordering fields.
func (c *checker) groupOrder() {
	q := c.q
	if len(q.GroupBy) > MaxGroupBy {
		c.fail("group_by", CodeTooBroad, strconv.Itoa(len(q.GroupBy)), fmt.Sprintf("at most %d group-by fields", MaxGroupBy))
	}
	for i, g := range q.GroupBy {
		path := fmt.Sprintf("group_by[%d]", i)
		if q.Type.IsMetric() {
			if _, ok := c.cat.Entity(g); !ok || !c.cat.Reachable(q.Target, g) {
				c.fail(path, CodeUnknownDimension, g, "metrics group by a related entity type (e.g. site, device)")
			}
			continue
		}
		if d, ok := c.cat.Dimension(q.Target, g); !ok || !d.Groupable {
			c.fail(path, CodeUnknownDimension, g, "", suggest(g, c.dimNames(true), nil)...)
		}
	}
	if len(q.OrderBy) > MaxOrderBy {
		c.fail("order_by", CodeTooBroad, strconv.Itoa(len(q.OrderBy)), "at most one order-by field")
	}
	for i, o := range q.OrderBy {
		path := fmt.Sprintf("order_by[%d]", i)
		if o.Dir != "asc" && o.Dir != "desc" {
			c.fail(path+".dir", CodeInvalidValue, o.Dir, "", "asc", "desc")
		}
		switch {
		case q.Type.IsMetric():
			if o.Field != "value" && !(o.Field == "delta" && q.Type == ast.CompareWindows) {
				c.fail(path+".field", CodeUnknownDimension, o.Field, "metrics order by value (or delta when comparing)")
			}
		default:
			if d, ok := c.cat.Dimension(q.Target, o.Field); !ok || !d.Display {
				c.fail(path+".field", CodeUnknownDimension, o.Field, "", suggest(o.Field, c.dimNames(false), nil)...)
			}
		}
	}
}

// limits clamps row limits and rejects a query too broad to run.
func (c *checker) limits() {
	if len(c.res.Errors) > 0 {
		return
	}
	q := c.q
	clamp := func(def, max int, reason string) {
		switch {
		case q.Limit <= 0:
			q.Limit = def
		case q.Limit > max:
			c.constrain("limit", strconv.Itoa(q.Limit), strconv.Itoa(max), reason)
			q.Limit = max
		}
	}
	switch q.Type {
	case ast.MetricTopK, ast.CompareWindows:
		clamp(DefaultTopK, MaxTopK, "max_topk")
	case ast.ChangeList:
		clamp(DefaultChangeRows, MaxChangeRows, "max_rows")
	case ast.IncidentList:
		clamp(DefaultIncidentRows, MaxIncidentRows, "max_rows")
	}
	if q.Type.IsMetric() {
		m, _ := c.cat.Metric(q.Metric)
		n, err := c.sc.Count(c.ctx, q.Target, q.Refs)
		if err != nil {
			c.fail("entities", CodeTooBroad, "", "the query scope could not be sized")
			return
		}
		if n*m.FanoutHint > MaxEstimatedSeries {
			c.fail("entities", CodeTooBroad, strconv.Itoa(n*m.FanoutHint),
				fmt.Sprintf("about %d series — narrow it to a site, device or circuit", n*m.FanoutHint))
		}
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func fmtDur(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
	return strconv.Itoa(int(d/time.Hour)) + "h"
}
