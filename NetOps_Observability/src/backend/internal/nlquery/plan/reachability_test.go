// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
)

// reachScope is fakeScope with the optional liveness seam.
type reachScope struct {
	fakeScope
	verdicts map[string]string
	err      error
	asked    [][]string
}

func (r *reachScope) DeviceReachability(_ context.Context, ids []string) (map[string]string, error) {
	r.asked = append(r.asked, append([]string(nil), ids...))
	return r.verdicts, r.err
}

func runReach(t *testing.T, sc Scope, q *ast.AST) *ResultSet {
	t.Helper()
	rs, err := Planner{Cat: cat}.Execute(context.Background(), sc, q, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

var downOnly = []ast.Filter{{Field: ast.FilterReachability, Op: "eq", Values: []string{"down"}}}

// "which devices are down": the caller's visible devices, filtered by the
// collectors' verdict, said as the current state; a device with no verdict is
// unknown — never down.
func TestReachabilityFiltersAndSaysItIsCurrent(t *testing.T) {
	sc := &reachScope{verdicts: map[string]string{"d1": "down"}} // d2: no verdict
	q := &ast.AST{V: 1, Type: ast.EntityList, Target: "device", Filters: downOnly, Limit: 100}
	rs := runReach(t, sc, q)
	if len(rs.Rows) != 1 || rs.Rows[0]["device"] != "edge-1" || rs.Rows[0]["reachability"] != "down" {
		t.Fatalf("down list = %+v", rs.Rows)
	}
	if len(sc.asked) != 1 || strings.Join(sc.asked[0], ",") != "d1,d2" {
		t.Fatalf("liveness must be read for the visible devices only: %v", sc.asked)
	}
	got := Summarize(cat, q, rs)
	if !strings.HasPrefix(got, "1 device is down:") || !strings.Contains(got, "edge-1 (dfw-hq)") || !strings.Contains(got, NoteReachabilityNow) {
		t.Fatalf("summary = %q", got)
	}
	// Unknown is not down.
	unk := &ast.AST{V: 1, Type: ast.EntityList, Target: "device", Filters: []ast.Filter{{Field: ast.FilterReachability, Op: "eq", Values: []string{"unknown"}}}, Limit: 100}
	if rs := runReach(t, sc, unk); len(rs.Rows) != 1 || rs.Rows[0]["device"] != "edge-2" {
		t.Fatalf("a device with no verdict is unknown: %+v", rs.Rows)
	}
	// The count says the state it counted.
	cnt := &ast.AST{V: 1, Type: ast.EntityCount, Target: "device", Filters: downOnly}
	if got := Summarize(cat, cnt, runReach(t, sc, cnt)); !strings.HasPrefix(got, "1 device you can see is down.") {
		t.Fatalf("count summary = %q", got)
	}
	// Nobody down: said plainly.
	none := &reachScope{verdicts: map[string]string{"d1": "up", "d2": "up"}}
	if got := Summarize(cat, q, runReach(t, none, q)); !strings.HasPrefix(got, "No device you can see is down.") {
		t.Fatalf("empty summary = %q", got)
	}
	// An unfiltered list carries the tally and each device's verdict.
	all := &ast.AST{V: 1, Type: ast.EntityList, Target: "device", Limit: 100}
	if got := Summarize(cat, all, runReach(t, sc, all)); !strings.Contains(got, "1 down, 1 unknown") || !strings.Contains(got, "edge-2 (dfw-hq): unknown") {
		t.Fatalf("tally summary = %q", got)
	}
}

// A failed or missing liveness read answers every device unknown and says why;
// it never reports a device down that it could not read.
func TestReachabilityUnreadIsUnknownAndSaid(t *testing.T) {
	q := &ast.AST{V: 1, Type: ast.EntityList, Target: "device", Filters: downOnly, Limit: 100}
	for name, sc := range map[string]Scope{"read failed": &reachScope{err: errors.New("vm down")}, "no seam": &fakeScope{}} {
		rs := runReach(t, sc, q)
		if len(rs.Rows) != 0 {
			t.Errorf("%s: nothing may read as down: %+v", name, rs.Rows)
		}
		if !strings.Contains(strings.Join(rs.Notes, " "), NoteReachabilityUnread) {
			t.Errorf("%s: the answer must say liveness was unread: %v", name, rs.Notes)
		}
	}
	// A count without a liveness filter reads no liveness at all.
	sc := &reachScope{}
	runReach(t, sc, &ast.AST{V: 1, Type: ast.EntityCount, Target: "device"})
	if len(sc.asked) != 0 {
		t.Fatalf("a plain count must not read liveness: %v", sc.asked)
	}
}

// The device-type filter keeps only that type, and the answer names it.
func TestDeviceTypeFilter(t *testing.T) {
	sc := &typedScope{}
	q := &ast.AST{V: 1, Type: ast.EntityCount, Target: "device", Filters: []ast.Filter{{Field: ast.FilterDeviceType, Op: "eq", Values: []string{"router"}}}}
	rs := runReach(t, sc, q)
	if rs.Rows[0]["count"] != 1 {
		t.Fatalf("router count = %+v", rs.Rows)
	}
	if got := Summarize(cat, q, rs); got != "You can see 1 router." {
		t.Fatalf("summary = %q", got)
	}
}

type typedScope struct{ fakeScope }

func (typedScope) Devices(context.Context, DeviceFilter) ([]DeviceRef, error) {
	return []DeviceRef{{ID: "d1", Name: "edge-1", Type: "router"}, {ID: "d2", Name: "sw-1", Type: "switch"}}, nil
}
