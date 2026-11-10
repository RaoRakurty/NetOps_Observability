// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"context"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
)

func runInventory(t *testing.T, q *ast.AST) *ResultSet {
	t.Helper()
	rs, err := Planner{Cat: cat}.Execute(context.Background(), &fakeScope{}, q, nil)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

// The answer is read ONLY through Scope.Devices / Scope.Circuits — the root's
// visibility sets — so the count is the caller's own.
func TestInventoryCountsAndLists(t *testing.T) {
	rs := runInventory(t, &ast.AST{V: 1, Type: ast.EntityCount, Target: "device"})
	if len(rs.Rows) != 1 || rs.Rows[0]["count"] != 2 || rs.Provenance.Source != SourceInventory {
		t.Fatalf("device count = %+v", rs)
	}
	if got := Summarize(cat, &ast.AST{Type: ast.EntityCount, Target: "device"}, rs); got != "You can see 2 devices." {
		t.Fatalf("summary = %q", got)
	}
	grouped := &ast.AST{V: 1, Type: ast.EntityCount, Target: "device", GroupBy: []string{"site"}}
	rs = runInventory(t, grouped)
	if len(rs.Rows) != 1 || rs.Rows[0]["site"] != "dfw-hq" || rs.Rows[0]["count"] != 2 {
		t.Fatalf("grouped = %+v", rs.Rows)
	}
	if got := Summarize(cat, grouped, rs); !strings.HasPrefix(got, "You can see 2 devices across 1 site:") {
		t.Fatalf("grouped summary = %q", got)
	}
	narrowed := &ast.AST{V: 1, Type: ast.EntityList, Target: "device", Refs: []ast.EntityRef{{Type: "device", ID: "device:d2"}}, Limit: 100}
	rs = runInventory(t, narrowed)
	if len(rs.Rows) != 1 || rs.Rows[0]["device"] != "edge-2" || rs.Rows[0]["site"] != "dfw-hq" {
		t.Fatalf("list = %+v", rs.Rows)
	}
	if got := Summarize(cat, narrowed, rs); !strings.Contains(got, "edge-2 (dfw-hq)") {
		t.Fatalf("list summary = %q", got)
	}
	site := runInventory(t, &ast.AST{V: 1, Type: ast.EntityCount, Target: "site"})
	if site.Rows[0]["count"] != 1 || len(site.Notes) == 0 || site.Notes[0] != NoteSitesFromDevices {
		t.Fatalf("a site count says how sites were counted: %+v", site)
	}
	circ := runInventory(t, &ast.AST{V: 1, Type: ast.EntityList, Target: "circuit", Refs: []ast.EntityRef{{Type: "site", ID: "site:dfw-hq"}}, Limit: 10})
	if len(circ.Rows) != 1 || circ.Rows[0]["circuit"] != "c-dfw-1" {
		t.Fatalf("circuits = %+v", circ.Rows)
	}
	// A list longer than its limit is truncated, and says so.
	short := runInventory(t, &ast.AST{V: 1, Type: ast.EntityList, Target: "device", Limit: 1})
	if len(short.Rows) != 1 || !short.Truncated {
		t.Fatalf("truncation = %+v", short)
	}
	// Zero is a count, said as zero.
	none := &ast.AST{V: 1, Type: ast.EntityCount, Target: "device", Refs: []ast.EntityRef{{Type: "site", ID: "site:nowhere"}}}
	if got := Summarize(cat, none, runInventory(t, none)); got != "You can see 0 devices." {
		t.Fatalf("zero = %q", got)
	}
}
