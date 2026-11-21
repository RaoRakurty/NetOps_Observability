// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/mql"
	"netops/backend/internal/nlquery/validate"
)

// Limits the planner enforces on top of the validator's.
const (
	MaxSeries      = 50
	MaxPoints      = 360
	DefaultRateWin = 5 * time.Minute
	BaselineWindow = 7 * 24 * time.Hour
	DefaultBefore  = 30 * time.Minute
	DefaultAfter   = 10 * time.Minute
	MaxMatchValues = 500
)

var stepGrid = []time.Duration{30 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute, time.Hour, 6 * time.Hour}

// ErrEmptyScope is returned when the refs resolve to nothing the caller can
// see — the answer is "nothing visible there", never an unscoped read.
var ErrEmptyScope = errors.New("the entities in the question resolve to nothing visible to you")

// Planner executes validated queries against a Scope.
type Planner struct {
	Cat *catalog.Catalog
	// EstateTimeout bounds the estate-wide seasonal read (0 =
	// EstateReadTimeout).
	EstateTimeout time.Duration
}

// Execute runs one VALIDATED query. The caller must have run validate.Validate
// and pass its constrained AST and constraints; Execute re-checks nothing the
// validator owns, but it never widens scope: an empty resolution is an error.
func (p Planner) Execute(ctx context.Context, sc Scope, q *ast.AST, constraints []validate.Constraint) (*ResultSet, error) {
	started := sc.Now()
	rs := &ResultSet{ASTHash: q.Hash(), CatalogVersion: p.Cat.Version(), Type: q.Type, Constraints: constraints}
	rs.QueryID = "q-" + rs.ASTHash[:16]
	rs.Provenance.Entities = q.Refs
	var err error
	switch q.Type {
	case ast.MetricSeries, ast.MetricTopK, ast.MetricFilter, ast.CompareWindows:
		err = p.metric(ctx, sc, q, rs)
	case ast.ChangeList:
		err = p.changes(ctx, sc, q, rs)
	case ast.IncidentList:
		err = p.incidents(ctx, sc, q, rs)
	case ast.IncidentExplain:
		err = p.explain(ctx, sc, q, rs)
	case ast.EntityCount, ast.EntityList:
		err = p.inventory(ctx, sc, q, rs)
	case ast.FlowTop:
		err = p.flows(ctx, sc, q, rs)
	case ast.LogSearch:
		err = p.logs(ctx, sc, q, rs)
	case ast.SeasonalOutliers:
		err = p.seasonalOutliers(ctx, sc, q, rs)
	default:
		err = fmt.Errorf("plan: query type %q is not executable", q.Type)
	}
	if err != nil {
		return nil, err
	}
	rs.Provenance.ExecutedAt = started
	rs.Provenance.DurationMs = sc.Now().Sub(started).Milliseconds()
	return rs, nil
}

// ---- time ---------------------------------------------------------------------

func (p Planner) window(ctx context.Context, sc Scope, t ast.TimeRange) (time.Time, time.Time, error) {
	now := sc.Now().UTC()
	switch t.Kind {
	case ast.TimeRelative:
		d, err := ast.ParseDuration(t.Last)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		to := now
		if t.Offset != "" {
			od, err := ast.ParseDuration(t.Offset)
			if err != nil {
				return time.Time{}, time.Time{}, err
			}
			to = now.Add(-od)
		}
		return to.Add(-d), to, nil
	case ast.TimeAbsolute:
		return t.From.UTC(), t.To.UTC(), nil
	case ast.TimeIncident:
		inc, err := sc.Incident(ctx, t.Anchor.IncidentID)
		if err != nil {
			return time.Time{}, time.Time{}, err
		}
		before, after := anchorSpan(t.Anchor)
		return inc.Row.CreatedAt.Add(-before), inc.Row.CreatedAt.Add(after), nil
	}
	return time.Time{}, time.Time{}, fmt.Errorf("plan: time kind %q needs its own path", t.Kind)
}

func anchorSpan(a *ast.Anchor) (time.Duration, time.Duration) {
	before, after := DefaultBefore, DefaultAfter
	if a == nil {
		return before, after
	}
	if d, err := ast.ParseDuration(a.Before); err == nil {
		before = d
	}
	if d, err := ast.ParseDuration(a.After); err == nil {
		after = d
	}
	return before, after
}

func stepFor(span time.Duration) time.Duration {
	for _, s := range stepGrid {
		if span/s <= MaxPoints {
			return s
		}
	}
	return stepGrid[len(stepGrid)-1]
}

// ---- entity resolution ----------------------------------------------------------

type resolved struct {
	matchers []mql.Matcher
	// pairs restrict interface / bgp_peer series to exact (device, x) pairs,
	// applied after the fetch (a matcher cross-product would over-include).
	pairLabel string
	pairs     map[string]bool // device-id-or-name + "\x1f" + ifName|peer
	// capped: the selection resolved to more values than one matcher may
	// carry (MaxMatchValues), so only the first ones were read — the answer
	// is partial and must say so.
	capped bool
	// checkNames maps a Digital Experience check id (the series' `target`
	// label) to the name its workspace gave it, so an answer names the check,
	// not its opaque id. Set only for tenant-labeled metrics.
	checkNames map[string]string
}

// tenantLabeledReads routes a tenant-labeled metric's reads through the
// tenant-label filter; every other Scope method is the caller's own.
type tenantLabeledReads struct {
	Scope
	tl TenantLabeledScope
}

func (r tenantLabeledReads) MetricRange(ctx context.Context, e mql.Expr, from, to time.Time, step time.Duration, maxSeries int) ([]Series, bool, error) {
	return r.tl.TenantMetricRange(ctx, e, from, to, step, maxSeries)
}

func (r tenantLabeledReads) MetricInstant(ctx context.Context, e mql.Expr, at time.Time, maxSeries int) ([]Sample, bool, error) {
	return r.tl.TenantMetricInstant(ctx, e, at, maxSeries)
}

// resolveChecks narrows a tenant-labeled read to the caller's OWN checks the
// question names. Ownership is the scope's tenant filter, not this function:
// with no check named, the read covers every check the caller owns; a named
// check the caller does not own resolves to nothing visible.
func (p Planner) resolveChecks(ctx context.Context, tl TenantLabeledScope, refs []ast.EntityRef, rs *ResultSet) (resolved, error) {
	var keys []string
	other := map[string]bool{}
	for _, r := range refs {
		if r.Type == "probe_target" {
			keys = append(keys, stripPrefix(r.ID))
		} else {
			other[r.Type] = true
		}
	}
	if len(other) > 0 {
		types := make([]string, 0, len(other))
		for t := range other {
			types = append(types, t)
		}
		sort.Strings(types)
		rs.Notes = append(rs.Notes, "Your Digital Experience checks cannot be narrowed by "+strings.Join(types, ", ")+
			"; this answer covers the checks named, or all of yours when none is.")
	}
	checks, err := tl.ProbeTargets(ctx, keys)
	if err != nil {
		return resolved{}, err
	}
	out := resolved{checkNames: map[string]string{}}
	var ids []string
	for _, c := range checks {
		ids = append(ids, c.ID)
		if c.Name != "" {
			out.checkNames[c.ID] = c.Name
		}
	}
	if len(checks) == 0 {
		return out, ErrEmptyScope
	}
	if len(keys) > 0 {
		out.matchers = append(out.matchers, mql.Matcher{Label: "target", Op: "=~", Values: out.cap(ids)})
	}
	return out, nil
}

// nameChecks replaces each check id in the answer with its workspace name.
func (r resolved) nameChecks(rs *ResultSet) {
	if len(r.checkNames) == 0 {
		return
	}
	for i := range rs.Series {
		if n, ok := r.checkNames[rs.Series[i].Entity["probe_target"]]; ok {
			rs.Series[i].Entity["probe_target"] = n
		}
	}
	for i := range rs.Rows {
		if id, _ := rs.Rows[i]["probe_target"].(string); id != "" {
			if n, ok := r.checkNames[id]; ok {
				rs.Rows[i]["probe_target"] = n
			}
		}
	}
}

func stripPrefix(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		return id[i+1:]
	}
	return id
}

// splitPair splits "<device_id>/<second>" at the FIRST slash: interface names
// contain slashes (Gi0/0/1); device ids never do (the catalog id pattern for a
// device admits them only inside the interface/bgp_peer compound form).
func splitPair(id string) (string, string) {
	rest := stripPrefix(id)
	i := strings.IndexByte(rest, '/')
	if i < 0 {
		return rest, ""
	}
	second := rest[i+1:]
	if j := strings.IndexByte(second, '@'); j >= 0 {
		second = second[:j] // vrf is informational in v1
	}
	return rest[:i], second
}

func (p Planner) resolve(ctx context.Context, sc Scope, target string, refs []ast.EntityRef) (resolved, error) {
	var sites, devIDs, circuitIDs, providers, probes []string
	var pairIDs [][2]string
	pairLabel := ""
	for _, r := range refs {
		switch r.Type {
		case "site":
			sites = append(sites, stripPrefix(r.ID))
		case "device":
			devIDs = append(devIDs, stripPrefix(r.ID))
		case "interface", "bgp_peer":
			d, x := splitPair(r.ID)
			devIDs = append(devIDs, d)
			pairIDs = append(pairIDs, [2]string{d, x})
			pairLabel = map[string]string{"interface": "ifName", "bgp_peer": "peer"}[r.Type]
		case "circuit":
			circuitIDs = append(circuitIDs, stripPrefix(r.ID))
		case "provider":
			providers = append(providers, stripPrefix(r.ID))
		case "probe_target":
			probes = append(probes, stripPrefix(r.ID))
		}
	}
	var out resolved
	switch target {
	case "circuit":
		if len(sites)+len(devIDs)+len(circuitIDs)+len(providers) == 0 {
			return out, nil
		}
		cs, err := sc.Circuits(ctx, CircuitFilter{IDs: circuitIDs, Sites: sites, Devices: devIDs, Providers: providers})
		if err != nil {
			return out, err
		}
		if len(cs) == 0 {
			return out, ErrEmptyScope
		}
		var ids []string
		for _, c := range cs {
			ids = append(ids, c.ID)
		}
		out.matchers = append(out.matchers, mql.Matcher{Label: "circuit", Op: "=~", Values: out.cap(ids)})
	case "probe_target":
		if len(probes) > 0 {
			out.matchers = append(out.matchers, mql.Matcher{Label: "dst", Op: "=~", Values: out.cap(probes)})
		}
	default: // device, interface, bgp_peer
		if len(providers) > 0 {
			cs, err := sc.Circuits(ctx, CircuitFilter{Providers: providers})
			if err != nil {
				return out, err
			}
			if len(cs) == 0 {
				return out, ErrEmptyScope
			}
			names := map[string]bool{}
			for _, c := range cs {
				names[c.LocalDevice] = true
			}
			devs, err := sc.Devices(ctx, DeviceFilter{})
			if err != nil {
				return out, err
			}
			// A provider NARROWS: "the Comcast peer on dfw-edge-1" is the
			// devices named AND terminating a Comcast circuit — never the
			// union, which would read every Comcast-connected device.
			named := map[string]bool{}
			for _, id := range devIDs {
				named[id] = true
			}
			var narrowed []string
			for _, d := range devs {
				if names[d.Name] && (len(devIDs) == 0 || named[d.ID]) {
					narrowed = append(narrowed, d.ID)
				}
			}
			if len(narrowed) == 0 {
				return out, ErrEmptyScope
			}
			devIDs = narrowed
		}
		if len(sites)+len(devIDs) == 0 {
			return out, nil
		}
		devs, err := sc.Devices(ctx, DeviceFilter{IDs: devIDs, Sites: sites})
		if err != nil {
			return out, err
		}
		if len(devs) == 0 {
			return out, ErrEmptyScope
		}
		// Series may carry the device id (SNMP) or its name (gNMI target).
		var vals []string
		idToName := map[string]string{}
		for _, d := range devs {
			vals = append(vals, d.ID)
			if d.Name != "" && d.Name != d.ID {
				vals = append(vals, d.Name)
			}
			idToName[d.ID] = d.Name
		}
		out.matchers = append(out.matchers, mql.Matcher{Label: "device", Op: "=~", Values: out.cap(vals)})
		if len(pairIDs) > 0 {
			out.pairLabel = pairLabel
			out.pairs = map[string]bool{}
			var seconds []string
			for _, pr := range pairIDs {
				out.pairs[pr[0]+"\x1f"+pr[1]] = true
				if n := idToName[pr[0]]; n != "" {
					out.pairs[n+"\x1f"+pr[1]] = true
				}
				seconds = append(seconds, pr[1])
			}
			out.matchers = append(out.matchers, mql.Matcher{Label: pairLabel, Op: "=~", Values: out.cap(seconds)})
		}
	}
	return out, nil
}

// cap bounds one matcher's values and records when it had to.
func (r *resolved) cap(v []string) []string {
	out := capValues(v)
	if len(out) < len(uniqueCount(v)) {
		r.capped = true
	}
	return out
}

func uniqueCount(v []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range v {
		m[x] = true
	}
	return m
}

func capValues(v []string) []string {
	sort.Strings(v)
	uniq := v[:0]
	for i, x := range v {
		if i == 0 || x != v[i-1] {
			uniq = append(uniq, x)
		}
	}
	if len(uniq) > MaxMatchValues {
		uniq = uniq[:MaxMatchValues]
	}
	return uniq
}

func (r resolved) keep(labels map[string]string) bool {
	if r.pairs == nil {
		return true
	}
	return r.pairs[labels["device"]+"\x1f"+labels[r.pairLabel]]
}

// ---- metrics ----------------------------------------------------------------------

func (p Planner) metric(ctx context.Context, sc Scope, q *ast.AST, rs *ResultSet) error {
	m, ok := p.Cat.Metric(q.Metric)
	t, tok := templates[q.Metric]
	if !ok || !tok {
		return fmt.Errorf("plan: metric %q has no template", q.Metric)
	}
	rs.Metric, rs.Unit = m.Name, m.Unit
	from, to, err := p.window(ctx, sc, q.Time)
	if err != nil {
		return err
	}
	var res resolved
	if t.tenantLabeled {
		// N-B5: the workspace's own checks, read through the tenant-label
		// filter — never the device filter, which these series cannot match.
		tl, ok := sc.(TenantLabeledScope)
		if !ok {
			return fmt.Errorf("plan: metric %q needs the workspace check scope, which this deployment does not provide", q.Metric)
		}
		sc = tenantLabeledReads{Scope: sc, tl: tl}
		res, err = p.resolveChecks(ctx, tl, q.Refs, rs)
	} else {
		res, err = p.resolve(ctx, sc, q.Target, q.Refs)
	}
	if err == nil && res.capped {
		rs.Truncated = true
		rs.Notes = append(rs.Notes, fmt.Sprintf("The selection named more than %d entities; only the first %d were read, so this answer is partial.", MaxMatchValues, MaxMatchValues))
	}
	if errors.Is(err, ErrEmptyScope) {
		rs.Window = Window{From: from, To: to}
		rs.Notes = append(rs.Notes, ErrEmptyScope.Error())
		return nil
	}
	if err != nil {
		return err
	}
	step := stepFor(to.Sub(from))
	rateWin := DefaultRateWin
	if step > rateWin {
		rateWin = step
	}
	c := tctx{
		sel: func(phys string) (mql.Expr, error) {
			if !contains(m.PhysicalMetrics, phys) {
				return mql.Expr{}, fmt.Errorf("plan: template for %s reads undeclared metric %s", m.Name, phys)
			}
			return mql.Selector(phys, res.matchers...)
		},
		rateWin: rateWin, win: to.Sub(from),
	}
	rs.Window = Window{From: from, To: to, Step: step}
	switch q.Type {
	case ast.MetricSeries:
		e, err := t.series(c)
		if err != nil {
			return err
		}
		e, err = mql.LimitK(MaxSeries+1, e)
		if err != nil {
			return err
		}
		rs.Provenance.Physical = append(rs.Provenance.Physical, e.String())
		series, trunc, err := sc.MetricRange(ctx, e, from, to, step, MaxSeries)
		if err != nil {
			return err
		}
		for _, s := range series {
			if !res.keep(s.Labels) {
				continue
			}
			if len(rs.Series) == MaxSeries {
				trunc = true
				break
			}
			rs.Series = append(rs.Series, OutSeries{Entity: entityOf(t.labels, s.Labels), Points: s.Points})
		}
		rs.Truncated = trunc
	case ast.MetricFilter:
		if q.Predicate != nil && q.Predicate.Op == "above_baseline" {
			// N-H6: judged per entity against its seasonal profile, the
			// flat 7-day p95 standing in where history is too short.
			if err := p.aboveBaseline(ctx, sc, q, t, c, res, rs, step, m.Unit); err != nil {
				return err
			}
			res.nameChecks(rs)
			return p.applyGrouping(ctx, sc, q, rs)
		}
		fallthrough
	case ast.MetricTopK:
		e, err := aggregate(t, c, q.Agg, step)
		if err != nil {
			return err
		}
		if q.Type == ast.MetricFilter {
			if e, err = p.predicate(t, c, e, q.Predicate, step); err != nil {
				return err
			}
			e, err = mql.LimitK(q.LimitOr(MaxSeries)+1, e)
		} else {
			e, err = mql.TopK(q.LimitOr(10), e)
		}
		if err != nil {
			return err
		}
		rs.Provenance.Physical = append(rs.Provenance.Physical, e.String())
		samples, trunc, err := sc.MetricInstant(ctx, e, to, q.LimitOr(MaxSeries))
		if err != nil {
			return err
		}
		rs.Rows, rs.Truncated = samplesToRows(t.labels, samples, res, "value"), trunc
		sortRows(rs.Rows, "value", q.Type == ast.MetricTopK || orderDesc(q))
	case ast.CompareWindows:
		if err := p.compare(ctx, sc, q, t, c, res, rs, step, m.Unit); err != nil {
			return err
		}
		res.nameChecks(rs)
		return nil
	}
	res.nameChecks(rs)
	if err := p.applyGrouping(ctx, sc, q, rs); err != nil {
		return err
	}
	source(rs, "victoriametrics")
	return nil
}

func (p Planner) predicate(t template, c tctx, e mql.Expr, pr *ast.Predicate, step time.Duration) (mql.Expr, error) {
	switch pr.Op {
	case "gt", "ge", "lt", "le", "eq", "ne":
		op := map[string]string{"gt": ">", "ge": ">=", "lt": "<", "le": "<=", "eq": "==", "ne": "!="}[pr.Op]
		return mql.Cmp(e, op, mql.Scalar(pr.Value))
	case "between":
		lo, err := mql.Cmp(e, ">=", mql.Scalar(pr.Value))
		if err != nil {
			return mql.Expr{}, err
		}
		return mql.Cmp(lo, "<=", mql.Scalar(pr.Value2))
	case "above_baseline":
		s, err := t.series(c)
		if err != nil {
			return mql.Expr{}, err
		}
		base, err := mql.QuantileSubquery(0.95, s, BaselineWindow, step)
		if err != nil {
			return mql.Expr{}, err
		}
		base, err = mql.Offset(base, c.win)
		if err != nil {
			return mql.Expr{}, err
		}
		return mql.Cmp(e, ">", base)
	case "increased_by":
		prev, err := mql.Offset(e, c.win)
		if err != nil {
			return mql.Expr{}, err
		}
		delta, err := mql.Bin(e, "-", prev)
		if err != nil {
			return mql.Expr{}, err
		}
		return mql.Cmp(delta, ">", mql.Scalar(pr.Value))
	}
	return mql.Expr{}, fmt.Errorf("plan: predicate %q has no template", pr.Op)
}

// compare evaluates the SAME windowed value at the end of each window and
// ranks entities by the absolute change — computed here, from two scoped
// instant reads, so the delta is exactly what the two windows show.
func (p Planner) compare(ctx context.Context, sc Scope, q *ast.AST, t template, c tctx, res resolved, rs *ResultSet, step time.Duration, unit string) error {
	e, err := aggregate(t, c, q.Agg, step)
	if err != nil {
		return err
	}
	_, cto, err := p.window(ctx, sc, *q.CompareTo)
	if err != nil {
		return err
	}
	cmpFrom := cto.Add(-c.win)
	rs.Compare = &Window{From: cmpFrom, To: cto, Step: step}
	rs.Provenance.Physical = append(rs.Provenance.Physical, e.String())
	now, trunc1, err := sc.MetricInstant(ctx, e, rs.Window.To, MaxMatchValues)
	if err != nil {
		return err
	}
	then, trunc2, err := sc.MetricInstant(ctx, e, cto, MaxMatchValues)
	if err != nil {
		return err
	}
	prev := map[string]float64{}
	for _, s := range then {
		prev[entityKey(t.labels, s.Labels)] = s.Value
	}
	var keys []string
	keyLabels := map[string]map[string]string{}
	for _, s := range now {
		if !res.keep(s.Labels) {
			continue
		}
		row := Row{}
		for k, v := range entityOf(t.labels, s.Labels) {
			row[k] = v
		}
		row["value"] = s.Value
		k := entityKey(t.labels, s.Labels)
		if pv, ok := prev[k]; ok {
			row["previous"] = pv
			row["delta"] = s.Value - pv
		}
		rs.Rows = append(rs.Rows, row)
		keys, keyLabels[k] = append(keys, k), s.Labels
	}
	// N-H6: each row also says how its value sits against its usual level
	// for this time of week (or day) — the same windowed value read at the
	// same hour in earlier weeks and days, through the same scoped reads.
	if len(keys) > 0 {
		prof, err := seasonalProfiles(ctx, sc, q.Metric, t, e, rs.Window.To, c.win, unit, keyLabels, rs)
		if err != nil {
			return err
		}
		if note := seasonalNote(annotateSeasonal(rs.Rows, keys, prof), ""); note != "" {
			rs.Notes = append(rs.Notes, note)
		}
	}
	sort.SliceStable(rs.Rows, func(i, j int) bool { return absDelta(rs.Rows[i]) > absDelta(rs.Rows[j]) })
	if n := q.LimitOr(10); len(rs.Rows) > n {
		rs.Rows, rs.Truncated = rs.Rows[:n], true
	}
	rs.Truncated = rs.Truncated || trunc1 || trunc2
	if hasLabel(t.labels, "circuit") {
		if err := nameCircuitInterfaces(ctx, sc, rs); err != nil {
			return err
		}
	}
	source(rs, "victoriametrics")
	return nil
}

func hasLabel(labels []string, want string) bool {
	for _, l := range labels {
		if l == want {
			return true
		}
	}
	return false
}

// nameCircuitInterfaces puts on each compared circuit row the interface that
// circuit ends on (catalog relationship circuit → interface, n:1 via
// wan_circuit_local). Circuit loss, latency, jitter and QoE are measured per
// CIRCUIT — no series is keyed by interface — so "which interfaces changed
// most?" is answered by the circuits, each named with its own interface, and
// a note says so. A circuit whose interface the WAN inventory does not record
// is counted, never given a guessed one. The lookup goes through the caller's
// scope, so it can only name circuits the caller can already see.
func nameCircuitInterfaces(ctx context.Context, sc Scope, rs *ResultSet) error {
	var ids []string
	for _, r := range rs.Rows {
		if id, _ := r["circuit"].(string); id != "" {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	cs, err := sc.Circuits(ctx, CircuitFilter{IDs: ids})
	if err != nil {
		return err
	}
	ifOf := map[string]string{}
	for _, c := range cs {
		if c.LocalIf != "" {
			ifOf[c.ID] = c.LocalIf
		}
	}
	missing := 0
	for _, r := range rs.Rows {
		id, _ := r["circuit"].(string)
		if itf := ifOf[id]; itf != "" {
			r["interface"] = itf
		} else {
			missing++
		}
	}
	note := "This is measured per circuit, not per interface; each row names the interface its circuit ends on."
	switch {
	case missing == len(ids):
		note = "This is measured per circuit, not per interface, and the WAN inventory records no interface for these circuits."
	case missing > 0:
		note += fmt.Sprintf(" %d circuit%s ha%s no recorded interface.", missing, plural(missing, "", "s"), plural(missing, "s", "ve"))
	}
	rs.Notes = append(rs.Notes, note)
	return nil
}

func absDelta(r Row) float64 {
	if d, ok := r["delta"].(float64); ok {
		return math.Abs(d)
	}
	return -1 // no comparison value: after every compared entity
}

// entityOf maps physical labels to catalog entity dimensions and DROPS every
// other label (incl. the circuit series' own `tenant`).
func entityOf(labels []string, raw map[string]string) map[string]string {
	name := map[string]string{"device": "device", "ifName": "interface", "peer": "bgp_peer",
		"circuit": "circuit", "local_device": "device", "dst": "probe_target", "target": "probe_target"}
	out := map[string]string{}
	for _, l := range labels {
		if v := raw[l]; v != "" {
			out[name[l]] = v
		}
	}
	return out
}

func entityKey(labels []string, raw map[string]string) string {
	var parts []string
	for _, l := range labels {
		parts = append(parts, raw[l])
	}
	return strings.Join(parts, "\x1f")
}

func samplesToRows(labels []string, ss []Sample, res resolved, valueCol string) []Row {
	var rows []Row
	for _, s := range ss {
		if !res.keep(s.Labels) {
			continue
		}
		row := Row{valueCol: s.Value}
		for k, v := range entityOf(labels, s.Labels) {
			row[k] = v
		}
		rows = append(rows, row)
	}
	return rows
}

func sortRows(rows []Row, col string, desc bool) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, _ := rows[i][col].(float64)
		b, _ := rows[j][col].(float64)
		if desc {
			return a > b
		}
		return a < b
	})
}

func orderDesc(q *ast.AST) bool {
	return len(q.OrderBy) == 0 || q.OrderBy[0].Dir != "asc"
}

func source(rs *ResultSet, s string) {
	if rs.Provenance.Source == "" {
		rs.Provenance.Source = s
	} else if !strings.Contains(rs.Provenance.Source, s) {
		rs.Provenance.Source += "+" + s
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
