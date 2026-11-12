// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// phrasing_test.go — the rules added for the way a NOC actually asks
// (tracker 337 phrasing eval, 2026-11-12). Each rule is pinned with a positive
// AND a negative: a wording the rule must NOT capture. The eval itself
// (iris_phrasing_eval_test.go, root) scores the whole router; these pin the
// grammar's half in isolation. Utterances here are written for the test, not
// copied from the eval's held-out slice (N-H3).

import (
	"testing"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/lex"
)

func reach(q *ast.AST) string {
	for _, f := range q.Filters {
		if f.Field == ast.FilterReachability {
			return f.Values[0]
		}
	}
	return ""
}

// Device liveness is the inventory's answer, never an incident list and never
// a troubleshooting walk.
func TestDeviceLivenessIsAnInventoryQuestion(t *testing.T) {
	for q, want := range map[string]struct {
		typ   ast.QueryType
		state string
		role  string
	}{
		"which devices are offline":            {ast.EntityList, "down", ""},
		"list devices that are not responding": {ast.EntityList, "down", ""},
		"count devices that are down":          {ast.EntityCount, "down", ""},
		"anything offline":                     {ast.EntityList, "down", ""},
		"devices up":                           {ast.EntityList, "up", ""},
		"which firewalls are unreachable":      {ast.EntityList, "down", "firewall"},
		"how many switches are down":           {ast.EntityCount, "down", "switch"},
		"are all the devices up":               {ast.EntityList, "", ""}, // the tally answers it
	} {
		r := run(t, q, cx)
		if r.AST == nil || r.AST.Type != want.typ || r.AST.Target != "device" || reach(r.AST) != want.state {
			t.Errorf("%q → %+v", q, r)
			continue
		}
		if want.role != "" && !hasFilter(r.AST, ast.FilterDeviceType, want.role) {
			t.Errorf("%q: missing the %s type filter: %+v", q, want.role, r.AST.Filters)
		}
		if r.AST.Time.Kind != "" {
			t.Errorf("%q: the inventory has no window: %+v", q, r.AST.Time)
		}
	}
	// One named device: listed with its verdict, never filtered out of its
	// own answer.
	for _, q := range []string{"is edge-1 up", "is edge-2 reachable", "is edge-1 ok", "status of edge-2", "is edge-1 down"} {
		r := run(t, q, cx)
		if r.AST == nil || r.AST.Type != ast.EntityList || len(r.AST.Refs) != 1 || r.AST.Refs[0].Type != "device" || len(r.AST.Filters) != 0 {
			t.Errorf("%q → %+v", q, r)
		}
	}
	// Not liveness: an interface, a session, an incident, a phrasal "up".
	for q, notType := range map[string]ast.QueryType{
		"which interfaces are down":   ast.EntityList,
		"which bgp sessions are down": ast.EntityList,
		"open incidents on edge-1":    ast.EntityList,
		"what is down":                ast.EntityList, // a bare "down" also fits an incident
	} {
		if r := run(t, q, cx); r.AST != nil && r.AST.Type == notType {
			t.Errorf("%q must not be a device list: %+v", q, r.AST)
		}
	}
	if r := run(t, "show up devices list", cx); r.AST != nil && reach(r.AST) != "" {
		t.Errorf("a phrasal up is not a state: %+v", r)
	}
	if r := run(t, "how many routers are on fire", cx); r.AST != nil {
		t.Errorf("a word the grammar cannot place stays not understood: %+v", r.AST)
	}
}

// "lately" / "recently" are a real window, disclosed; an explicit window wins;
// "the 5 most recent" counts items, it is not a window.
func TestRecencyWordsReadAsTheLastDay(t *testing.T) {
	r := run(t, "any bgp peers flapping lately", cx)
	if r.AST == nil || r.AST.Metric != "bgp_flaps" || r.AST.Time.Last != RecencyWindow || len(r.AST.Refs) != 0 {
		t.Fatalf("flapping lately → %+v", r)
	}
	if rd := readingOf(r, lex.KindWindow); rd == nil || rd.From != "lately" {
		t.Fatalf("the window reading must be disclosed: %+v", r.Readings)
	}
	if r := run(t, "interfaces flapping recently on edge-1", cx); r.AST == nil || r.AST.Time.Last != RecencyWindow || r.AST.Metric != "if_flaps" {
		t.Errorf("recently → %+v", r)
	}
	if r := run(t, "bgp flaps in the last 6 hours lately", cx); r.AST == nil || r.AST.Time.Last != "6h" || readingOf(r, lex.KindWindow) != nil {
		t.Errorf("an explicit window wins: %+v", r)
	}
	if r := run(t, "the 5 most recent changes", cx); r.AST == nil || r.AST.Limit != 5 || readingOf(r, lex.KindWindow) != nil {
		t.Errorf("most recent counts items: %+v", r)
	}
}

// A BGP question with no measure asks for the sessions' state; "flapping"
// next to a BGP word is BGP flaps, without one an interface's.
func TestBGPStateAndFlapping(t *testing.T) {
	for _, q := range []string{"bgp status on edge-1", "is bgp ok on edge-1", "show bgp peers on edge-1", "check bgp on edge-1", "how is bgp doing on edge-1", "whats up with bgp on edge-1"} {
		r := run(t, q, cx)
		if r.AST == nil || r.AST.Metric != "bgp_session_state" || r.AST.Target != "bgp_peer" || len(r.AST.Refs) != 1 {
			t.Errorf("%q → %+v", q, r)
		}
		if r.AST != nil && r.AST.Predicate != nil && q == "whats up with bgp on edge-1" {
			t.Errorf("\"what's up with\" is an idiom, not the state up: %+v", r.AST.Predicate)
		}
	}
	for q, op := range map[string]string{"bgp neighbours that aren't established": "ne", "bgp sessions not established": "ne", "established bgp sessions on edge-1": "eq"} {
		r := run(t, q, cx)
		if r.AST == nil || r.AST.Predicate == nil || r.AST.Predicate.Op != op || r.AST.Predicate.Value != 6 {
			t.Errorf("%q → %+v", q, r)
		}
	}
	if r := run(t, "bgp sessions flapping", cx); r.AST == nil || r.AST.Metric != "bgp_flaps" {
		t.Errorf("bgp flapping → %+v", r)
	}
	if r := run(t, "ports flapping", cx); r.AST == nil || r.AST.Metric != "if_flaps" {
		t.Errorf("port flapping → %+v", r)
	}
	if r := run(t, "how many prefixes is edge-1 receiving", cx); r.AST == nil || r.AST.Metric != "bgp_prefixes_received" {
		t.Errorf("every alias of the metric names it: %+v", r)
	}
}

// A device contains its interfaces and sessions; a ranking that names devices
// over an interface metric ranks the devices.
func TestDeviceContainmentAndDeviceRanking(t *testing.T) {
	r := run(t, "crc errors on edge-2", cx)
	if r.AST == nil || r.AST.Target != "interface" || len(r.AST.Refs) != 1 || r.AST.Refs[0].ID != "device:edge-2" {
		t.Fatalf("crc errors on a device are its interfaces' errors: %+v", r)
	}
	r = run(t, "top 3 devices by interface errors", cx)
	if r.AST == nil || r.AST.Type != ast.MetricTopK || r.AST.Limit != 3 || len(r.AST.GroupBy) != 1 || r.AST.GroupBy[0] != "device" {
		t.Fatalf("devices ranked by an interface metric: %+v", r)
	}
	r = run(t, "noisiest devices", cx)
	if r.AST == nil || r.AST.Type != ast.MetricTopK || r.AST.Metric != "if_flaps" || r.AST.GroupBy[0] != "device" || r.AST.Limit != DefaultSuperlativeN {
		t.Fatalf("noisiest devices → %+v", r)
	}
	if rd := readingOf(r, lex.KindSynonym); rd == nil || rd.From != "noisiest" || rd.To != "interface flaps" {
		t.Fatalf("the superlative's metric must be disclosed: %+v", r.Readings)
	}
	if r := run(t, "which box is the busiest", cx); r.AST == nil || r.AST.Metric != "cpu_util_pct" || r.AST.Target != "device" {
		t.Errorf("box is a device word: %+v", r)
	}
	// A role word cannot rank a metric (no role filter there): not understood.
	if r := run(t, "top 3 routers by interface errors", cx); r.AST != nil {
		t.Errorf("a role word must not rank every device: %+v", r.AST)
	}
	// A named device never becomes a grouping.
	if r := run(t, "top 3 interfaces by errors on edge-1", cx); r.AST == nil || len(r.AST.GroupBy) != 0 {
		t.Errorf("named device: %+v", r)
	}
}

// Shorthand reaches the grammar and is disclosed with the answer.
func TestShorthandReachesTheGrammar(t *testing.T) {
	r := run(t, "which links are down rn", cx)
	if r.AST == nil || r.AST.Metric != "if_oper_status" {
		t.Fatalf("rn → %+v", r)
	}
	if rd := readingOf(r, lex.KindAbbreviation); rd == nil || rd.From != "rn" {
		t.Fatalf("the shorthand must be disclosed: %+v", r.Readings)
	}
}
