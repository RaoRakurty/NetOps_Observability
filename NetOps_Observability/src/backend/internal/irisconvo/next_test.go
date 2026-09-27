// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisconvo

import (
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/plan"
)

var cat = catalog.MustLoad()

func ids(rs []ast.EntityRef) string {
	var out []string
	for _, r := range rs {
		out = append(out, r.ID)
	}
	return strings.Join(out, ",")
}

func TestNextOrdersByTheQuestionThenTheAnswerThenEarlierTurns(t *testing.T) {
	prev := State{Entities: []ast.EntityRef{{Type: "site", ID: "site:dfw-hq"}}}
	q := &ast.AST{V: 1, Type: ast.MetricTopK, Refs: []ast.EntityRef{{Type: "circuit", ID: "circuit:c9"}}}
	rs := &plan.ResultSet{Rows: []plan.Row{
		{"device": "edge-1", "interface": "ge-0/0/1", "value": 91.0},
		{"device": "edge-2", "value": 88.0},
	}}
	st := Next(cat, prev, q, rs)
	want := "circuit:c9,device:edge-1,interface:edge-1/ge-0/0/1,device:edge-2,site:dfw-hq"
	if got := ids(st.Entities); got != want {
		t.Fatalf("entities\n got  %s\n want %s", got, want)
	}
	if st.LastAST != q && st.LastAST.Hash() != q.Hash() {
		t.Fatal("the answered query becomes the prior query")
	}
}

func TestNextKeepsOnlyCatalogShapedIDs(t *testing.T) {
	rs := &plan.ResultSet{Rows: []plan.Row{
		{"device": "bad id with spaces"}, {"site": "Not A Slug!"}, {"incident_id": "not-a-uuid"},
		{"device": 42}, {"circuit": "c1"},
	}}
	st := Next(cat, State{}, &ast.AST{V: 1, Type: ast.MetricTopK}, rs)
	if got := ids(st.Entities); got != "circuit:c1" {
		t.Fatalf("only valid canonical ids may enter state, got %s", got)
	}
}

func TestAChangeListRedefinesTheyAndElse(t *testing.T) {
	prev := State{Actors: []string{"old"}, ChangeIDs: []string{"chg-old"}}
	rs := &plan.ResultSet{Rows: []plan.Row{
		{"change_id": "chg-1", "actor": "alice", "object": "edge-1", "object_kind": "device"},
		{"change_id": "chg-2", "actor": "alice", "object": "arn:aws:x", "object_kind": "cloud_resource"},
	}}
	st := Next(cat, prev, &ast.AST{V: 1, Type: ast.ChangeList}, rs)
	if strings.Join(st.Actors, ",") != "alice" || strings.Join(st.ChangeIDs, ",") != "chg-1,chg-2" {
		t.Fatalf("actors %v ids %v", st.Actors, st.ChangeIDs)
	}
	if ids(st.Entities) != "device:edge-1" {
		t.Fatalf("a device object is an entity; a cloud resource is not a catalog device: %s", ids(st.Entities))
	}
	// A metric turn in between leaves "they" alone.
	st2 := Next(cat, st, &ast.AST{V: 1, Type: ast.MetricTopK}, &plan.ResultSet{})
	if strings.Join(st2.Actors, ",") != "alice" {
		t.Fatalf("a non-change turn must not forget who made the changes: %v", st2.Actors)
	}
}

func TestSeriesEntitiesFeedTheState(t *testing.T) {
	rs := &plan.ResultSet{Series: []plan.OutSeries{{Entity: map[string]string{"circuit": "c1"}}, {Entity: map[string]string{"circuit": "c2"}}}}
	if got := ids(Next(cat, State{}, &ast.AST{V: 1, Type: ast.MetricTopK}, rs).Entities); got != "circuit:c1,circuit:c2" {
		t.Fatalf("got %s", got)
	}
}
