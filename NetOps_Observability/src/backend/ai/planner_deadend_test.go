// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// deadEndFloorPath is the ratchet: the most dead ends each planned route may
// produce over the paraphrase corpus. Lower it when a change removes dead
// ends; a change that raises any count fails.
//
// Measured 2026-11-13: before model-first phase 2 — playbook 4, product 3,
// module 10 (17 of 340); after — module 10, every other route 0. The module
// ten are honest outcomes of this harness's data, not routing: the mock data
// source cannot read app identification or integrations (the "data source
// didn't respond" disclosure), and Cloud App Observability is not enabled.
var deadEndFloorPath = filepath.Join("testdata", "planner_deadend_floor.json")

// deadEndCounts routes every corpus phrasing through its own route (the stub
// model is always right about the route and offers no restatement — the
// hardest case for the arms' lexical lookups) over the real docs index,
// playbook library and feature finder, with a data grammar that cannot parse
// anything and a model that can answer. It counts the answers that left the
// operator with nothing (IsDeadEnd).
func deadEndCounts(t *testing.T) (map[string]int, map[string]int, map[string][]string) {
	t.Helper()
	c := loadParaphrases(t)
	type item struct{ q, route, module string }
	var items []item
	for route, qs := range c.Routes {
		for _, q := range qs {
			items = append(items, item{q, route, ""})
		}
	}
	for _, it := range c.ModuleItems {
		items = append(items, item{it.Q, PlanRouteModule, it.Module})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].q < items[j].q })
	docs, kb := LoadDocsIndex(), LoadKB()
	dead, total := map[string]int{}, map[string]int{}
	examples := map[string][]string{}
	for _, it := range items {
		reply := "ROUTE: " + it.route
		if it.module != "" {
			reply += "\nMODULE: " + it.module
		}
		llm := &plannerLLM{route: func(string) string { return reply }}
		o := plannerOrch(llm)
		o.Tools = Tools(o.DS) // the production module tools, as the server wires them
		o.Docs, o.KB = docs, kb
		o.NLQuery = func(context.Context, Principal, string, DataOpts) (DataAnswer, error) {
			return DataAnswer{Status: DataNotData}, nil // the grammar cannot read it
		}
		o.AgentAnswer = func(context.Context, Principal, string, []string) (Answer, error) {
			return Answer{Mode: ModeModelAnswer, Text: "from the tools"}, nil
		}
		ans, err := o.Ask(context.Background(), deadEndPrincipal(), it.q, nil)
		if err != nil {
			t.Fatalf("%q: %v", it.q, err)
		}
		total[it.route]++
		if it.route != PlanRouteOutOfScope && IsDeadEnd(ans) {
			dead[it.route]++
			if len(examples[it.route]) < 3 {
				examples[it.route] = append(examples[it.route], it.q)
			}
		}
	}
	return dead, total, examples
}

// TestPlannedRoutesDoNotDeadEnd is the ratchet over the paraphrase corpus.
func TestPlannedRoutesDoNotDeadEnd(t *testing.T) {
	dead, total, examples := deadEndCounts(t)
	routes := make([]string, 0, len(total))
	for r := range total {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	var report []string
	for _, r := range routes {
		report = append(report, fmt.Sprintf("%s %d/%d", r, dead[r], total[r]))
	}
	t.Logf("dead ends per planned route (stub model, no restatement): %s", strings.Join(report, " · "))
	raw, err := os.ReadFile(deadEndFloorPath)
	if err != nil {
		t.Fatalf("read the ratchet %s: %v", deadEndFloorPath, err)
	}
	var floor map[string]int
	if err := json.Unmarshal(raw, &floor); err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if dead[r] > floor[r] {
			t.Errorf("route %s: %d dead ends > ratchet %d (e.g. %q)", r, dead[r], floor[r], examples[r])
		}
	}
	for r, n := range floor {
		if dead[r] < n {
			t.Logf("route %s improved to %d dead ends (ratchet %d): lower %s", r, dead[r], n, deadEndFloorPath)
		}
	}
}

// deadEndPrincipal holds every module read permission: a permission denial is
// an honest answer, not a routing dead end, and is not what this ratchet
// measures.
func deadEndPrincipal() Principal {
	perms := map[string]bool{}
	for _, p := range []string{"administration:read", "applications:read", "correlations:read", "events:read",
		"flows:read", "incident:read", "infrastructure:read", "logs:read", "reports:read"} {
		perms[p] = true
	}
	return Principal{Tenant: "t-a", Perms: perms}
}
