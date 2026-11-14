// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"context"
	"errors"
	"time"

	"netops/backend/internal/nlquery/ast"
)

// Flows and device syslog (tracker 337 N-C4).
//
// Both are OPTIONAL Scope seams, like ReachabilityScope: a Scope without them
// answers "not available here" instead of guessing, and every existing Scope
// keeps compiling. Neither seam receives text a model wrote — only resolved
// device ids, a window, a closed grouping or closed severity/topic values.

// ErrFlowsUnavailable / ErrLogsUnavailable: the deployment's Scope cannot read
// flows / syslog. The answer says so; nothing is invented.
var (
	ErrFlowsUnavailable = errors.New("flow data is not available to Iris in this deployment")
	ErrLogsUnavailable  = errors.New("device syslog is not available to Iris in this deployment")
)

// FlowQuery is a typed flow read. Devices are visible device ids (empty = the
// caller's whole view); By is ast.FlowGroupTalker or ast.FlowGroupService.
type FlowQuery struct {
	From, To time.Time
	Devices  []string
	By       string
	Limit    int
}

// FlowRow is one ranked conversation (A ↔ B) or service (Port).
type FlowRow struct {
	A, B    string
	Port    int
	Service string
	Bytes   float64
	Flows   float64
}

// FlowAnswer is what the Scope read: the rows, the sampling basis
// (flowquery Sampling*), and the notes the answer must carry (an excluded
// traffic class, a device with no flow address).
type FlowAnswer struct {
	Rows     []FlowRow
	Sampling string
	Notes    []string
}

// FlowScope reads flows in the caller's scope.
type FlowScope interface {
	FlowTop(ctx context.Context, q FlowQuery) (FlowAnswer, error)
}

// LogQuery is a typed syslog read. MinSeverity ("at or above") and Severities
// (exactly those) are ast.LogSeverities values; Topics are ast.LogTopics.
type LogQuery struct {
	From, To    time.Time
	Devices     []string
	MinSeverity string
	Severities  []string
	Topics      []string
	Limit       int
}

// LogRow is one syslog line, already redacted and capped by the Scope.
type LogRow struct {
	At                                time.Time
	Device, Severity, EventType, Text string
}

// LogAnswer is the newest matching lines, how many matched in all, and the
// notes the answer must carry (routine sessions left out).
type LogAnswer struct {
	Rows  []LogRow
	Total int
	Notes []string
}

// LogScope reads device syslog in the caller's scope.
type LogScope interface {
	LogSearch(ctx context.Context, q LogQuery) (LogAnswer, error)
}

// deviceIDs resolves device and site refs to visible device ids. No refs is
// nil (the whole view); refs that resolve to nothing are ErrEmptyScope — an
// unscoped read is never the fallback.
func (p Planner) deviceIDs(ctx context.Context, sc Scope, refs []ast.EntityRef) ([]string, error) {
	var ids, sites []string
	for _, r := range refs {
		switch r.Type {
		case "device":
			ids = append(ids, stripPrefix(r.ID))
		case "site":
			sites = append(sites, stripPrefix(r.ID))
		}
	}
	if len(ids)+len(sites) == 0 {
		return nil, nil
	}
	devs, err := sc.Devices(ctx, DeviceFilter{IDs: ids, Sites: sites})
	if err != nil {
		return nil, err
	}
	if len(devs) == 0 {
		return nil, ErrEmptyScope
	}
	out := make([]string, 0, len(devs))
	for _, d := range devs {
		out = append(out, d.ID)
	}
	return out, nil
}

// flows executes a flow_top query.
func (p Planner) flows(ctx context.Context, sc Scope, q *ast.AST, rs *ResultSet) error {
	fs, ok := sc.(FlowScope)
	if !ok {
		return ErrFlowsUnavailable
	}
	from, to, err := p.window(ctx, sc, q.Time)
	if err != nil {
		return err
	}
	devs, err := p.deviceIDs(ctx, sc, q.Refs)
	if errors.Is(err, ErrEmptyScope) {
		rs.Window = Window{From: from, To: to}
		rs.Notes = append(rs.Notes, ErrEmptyScope.Error())
		return nil
	}
	if err != nil {
		return err
	}
	by := ast.FlowGroupTalker
	if len(q.GroupBy) == 1 {
		by = q.GroupBy[0]
	}
	ans, err := fs.FlowTop(ctx, FlowQuery{From: from, To: to, Devices: devs, By: by, Limit: q.LimitOr(10)})
	if err != nil {
		return err
	}
	rs.Window = Window{From: from, To: to}
	rs.Unit = "bytes"
	for _, r := range ans.Rows {
		row := Row{"bytes": r.Bytes, "flows": r.Flows}
		if by == ast.FlowGroupService {
			row["service"], row["port"] = r.Service, r.Port
		} else {
			row["talker_a"], row["talker_b"] = r.A, r.B
		}
		rs.Rows = append(rs.Rows, row)
	}
	rs.Truncated = len(ans.Rows) >= q.LimitOr(10)
	rs.Notes = append(rs.Notes, ans.Notes...)
	source(rs, "flows")
	return nil
}

// logs executes a log_search query.
func (p Planner) logs(ctx context.Context, sc Scope, q *ast.AST, rs *ResultSet) error {
	ls, ok := sc.(LogScope)
	if !ok {
		return ErrLogsUnavailable
	}
	from, to, err := p.window(ctx, sc, q.Time)
	if err != nil {
		return err
	}
	devs, err := p.deviceIDs(ctx, sc, q.Refs)
	if errors.Is(err, ErrEmptyScope) {
		rs.Window = Window{From: from, To: to}
		rs.Notes = append(rs.Notes, ErrEmptyScope.Error())
		return nil
	}
	if err != nil {
		return err
	}
	lq := LogQuery{From: from, To: to, Devices: devs, Limit: q.LimitOr(20)}
	for _, f := range q.Filters {
		switch f.Field {
		case ast.FilterSeverity:
			if f.Op == "gte" {
				lq.MinSeverity = f.Values[0]
			} else {
				lq.Severities = append(lq.Severities, f.Values...)
			}
		case ast.FilterTopic:
			lq.Topics = append(lq.Topics, f.Values...)
		}
	}
	ans, err := ls.LogSearch(ctx, lq)
	if err != nil {
		return err
	}
	rs.Window = Window{From: from, To: to}
	for _, r := range ans.Rows {
		rs.Rows = append(rs.Rows, Row{"time": r.At, "device": r.Device, "severity": r.Severity, "event_type": r.EventType, "summary": r.Text})
	}
	rs.Truncated = ans.Total > len(ans.Rows)
	rs.Notes = append(rs.Notes, ans.Notes...)
	source(rs, "syslog")
	return nil
}

// SeveritiesAtOrAbove expands a minimum level to the levels it admits, most
// severe first; an unknown level admits nothing.
func SeveritiesAtOrAbove(min string) []string {
	for i, s := range ast.LogSeverities {
		if s == min {
			return append([]string(nil), ast.LogSeverities[:i+1]...)
		}
	}
	return nil
}
