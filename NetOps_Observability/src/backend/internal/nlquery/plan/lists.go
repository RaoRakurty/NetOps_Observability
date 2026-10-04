// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"

	"netops/backend/internal/nlquery/ast"
)

// physical maps an AST filter on an enum dimension to its stored values
// (a catalog class such as change class "wan" covers several stored types).
// A NEGATED enum filter ("ne") becomes its exact COMPLEMENT — every stored
// value of the dimension except the excluded ones — so the Scope only ever
// receives a positive list and a "not closed" filter can never be read as
// "closed" or dropped.
func (p Planner) physical(entity string, f ast.Filter) []string {
	d, ok := p.Cat.Dimension(entity, f.Field)
	if !ok || d.Type != "enum" {
		return f.Values
	}
	picked := map[string]bool{}
	for _, v := range f.Values {
		for _, e := range d.Enum {
			if e.Value == v {
				for _, ph := range e.Physical {
					picked[ph] = true
				}
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, e := range d.Enum {
		for _, ph := range e.Physical {
			if seen[ph] {
				continue
			}
			seen[ph] = true
			if picked[ph] != (f.Op == "ne") {
				out = append(out, ph)
			}
		}
	}
	return out
}

// ---- changes ------------------------------------------------------------------------

func (p Planner) changeQuery(q *ast.AST, filters []ast.Filter) ChangeQuery {
	cq := ChangeQuery{Limit: q.LimitOr(100)}
	for _, f := range filters {
		vals := p.physical("change", f)
		if f.Field == "id" { // the only non-enum negation: "what ELSE did they change"
			cq.ExcludeIDs = append(cq.ExcludeIDs, vals...)
			continue
		}
		switch f.Field {
		case "type", "class":
			cq.Types = append(cq.Types, vals...)
		case "actor":
			cq.Actors = append(cq.Actors, vals...)
		case "object":
			cq.Objects = append(cq.Objects, vals...)
		case "object_kind":
			cq.ObjectKinds = append(cq.ObjectKinds, vals...)
		case "site":
			cq.Sites = append(cq.Sites, vals...)
		case "app":
			cq.Apps = append(cq.Apps, vals...)
		case "seam":
			cq.Seams = append(cq.Seams, vals...)
		case "source":
			cq.Sources = append(cq.Sources, vals...)
		}
	}
	for _, r := range q.Refs {
		switch r.Type {
		case "site":
			cq.Sites = append(cq.Sites, stripPrefix(r.ID))
		case "application":
			cq.Apps = append(cq.Apps, stripPrefix(r.ID))
		case "device":
			cq.Objects = append(cq.Objects, stripPrefix(r.ID))
		}
	}
	return cq
}

func (p Planner) changes(ctx context.Context, sc Scope, q *ast.AST, rs *ResultSet) error {
	base := p.changeQuery(q, q.Filters)
	if q.Time.Kind == ast.TimeIncidents {
		return p.changesAroundIncidents(ctx, sc, q, base, rs)
	}
	from, to, err := p.window(ctx, sc, q.Time)
	if err != nil {
		return err
	}
	base.From, base.To = from, to
	rs.Window = Window{From: from, To: to}
	rows, trunc, err := sc.Changes(ctx, base)
	if err != nil {
		return err
	}
	for _, c := range rows {
		rs.Rows = append(rs.Rows, changeRow(c, ""))
	}
	rs.Truncated = trunc
	rs.Notes = append(rs.Notes, "a change that happened before a problem is only CORRELATED with it; only the engine's causal chain can say it caused it")
	source(rs, "change_ledger")
	return nil
}

// changesAroundIncidents answers "what changed N minutes before every X
// incident": the incident set is read once (bounded), then one bounded change
// read per incident window; every row names the incident it was found near.
func (p Planner) changesAroundIncidents(ctx context.Context, sc Scope, q *ast.AST, base ChangeQuery, rs *ResultSet) error {
	set := q.Time.Anchor.Incidents
	from, to, err := p.window(ctx, sc, set.Time)
	if err != nil {
		return err
	}
	rs.Window = Window{From: from, To: to}
	iq := p.incidentQuery(set.Filters, set.Refs, from, to, set.Max)
	incs, trunc, err := sc.Incidents(ctx, iq)
	if err != nil {
		return err
	}
	rs.Truncated = trunc
	before, after := anchorSpan(q.Time.Anchor)
	for _, inc := range incs {
		cq := base
		cq.From, cq.To = inc.CreatedAt.Add(-before), inc.CreatedAt.Add(after)
		rows, t2, err := sc.Changes(ctx, cq)
		if err != nil {
			return err
		}
		rs.Truncated = rs.Truncated || t2
		for _, c := range rows {
			r := changeRow(c, inc.ID)
			r["minutes_before_incident"] = int(inc.CreatedAt.Sub(c.At).Minutes())
			rs.Rows = append(rs.Rows, r)
		}
	}
	sort.SliceStable(rs.Rows, func(i, j int) bool {
		a, _ := rs.Rows[i]["time"].(time.Time)
		b, _ := rs.Rows[j]["time"].(time.Time)
		return a.After(b)
	})
	if len(incs) == 0 {
		rs.Notes = append(rs.Notes, "no matching incidents in the window")
	}
	rs.Notes = append(rs.Notes, fmt.Sprintf("changes shown are those within %s before / %s after each of %d incidents — correlated in time, not established as causes",
		before, after, len(incs)))
	source(rs, "change_ledger")
	source(rs, "clickhouse:corr_current")
	return nil
}

func changeRow(c ChangeRow, incident string) Row {
	r := Row{"change_id": c.ID, "time": c.At, "type": c.Type, "actor": c.Actor, "source": c.Source,
		"object": c.Object, "object_kind": c.ObjectKind, "site": c.Site, "app": c.App,
		"summary": c.Summary, "ticket": c.Ticket, "has_diff": c.HasDiff, "relation": "temporal"}
	if incident != "" {
		r["incident_id"] = incident
	}
	return r
}

// ---- incidents -------------------------------------------------------------------------

func (p Planner) incidentQuery(filters []ast.Filter, refs []ast.EntityRef, from, to time.Time, limit int) IncidentQuery {
	iq := IncidentQuery{From: from, To: to, Limit: limit, NewestFirst: true}
	for _, f := range filters {
		vals := p.physical("incident", f)
		switch f.Field {
		case "state":
			iq.States = append(iq.States, vals...)
		case "verdict_tier":
			iq.Tiers = append(iq.Tiers, vals...)
		case "seam_class":
			iq.SeamTypes = append(iq.SeamTypes, vals...)
		case "owner":
			iq.Owners = append(iq.Owners, vals...)
		case "top_confidence":
			if len(vals) > 0 {
				if x, err := strconv.ParseFloat(vals[0], 64); err == nil {
					iq.MinConf = x
				}
			}
		}
	}
	for _, r := range refs {
		switch r.Type {
		case "site":
			iq.Sites = append(iq.Sites, stripPrefix(r.ID))
		case "device":
			iq.Devices = append(iq.Devices, stripPrefix(r.ID))
		case "application":
			iq.Apps = append(iq.Apps, stripPrefix(r.ID))
		}
	}
	return iq
}

func (p Planner) incidents(ctx context.Context, sc Scope, q *ast.AST, rs *ResultSet) error {
	from, to, err := p.window(ctx, sc, q.Time)
	if err != nil {
		return err
	}
	rs.Window = Window{From: from, To: to}
	iq := p.incidentQuery(q.Filters, q.Refs, from, to, q.LimitOr(20))
	if len(q.OrderBy) == 1 && q.OrderBy[0].Dir == "asc" {
		iq.NewestFirst = false
	}
	rows, trunc, err := sc.Incidents(ctx, iq)
	if err != nil {
		return err
	}
	for _, r := range rows {
		rs.Rows = append(rs.Rows, Row{"incident_id": r.ID, "display_id": r.DisplayID, "title": r.Title, "state": r.State,
			"verdict_tier": r.Tier, "seam_type": r.SeamType, "owner": r.Owner, "confidence": r.Confidence,
			"created_at": r.CreatedAt, "sites": r.Sites, "devices": r.Devices})
	}
	rs.Truncated = trunc
	source(rs, "clickhouse:corr_current")
	return nil
}

func (p Planner) explain(ctx context.Context, sc Scope, q *ast.AST, rs *ResultSet) error {
	inc, err := sc.Incident(ctx, q.IncidentID)
	if err != nil {
		return err
	}
	rs.Detail = inc.Detail
	rs.Rows = []Row{{"incident_id": inc.Row.ID, "display_id": inc.Row.DisplayID, "title": inc.Row.Title,
		"state": inc.Row.State, "verdict_tier": inc.Row.Tier, "created_at": inc.Row.CreatedAt}}
	source(rs, "rca_report")
	return nil
}
