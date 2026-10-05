// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisconvo

// next.go — the state an answered turn leaves for the next one.
//
// Salience order (most recent first): what the question named, then what the
// answer returned, then what earlier turns carried. "Which devices have high
// CPU" → "those devices" are the ones the answer listed; "CPU on edge-1" →
// "that device" is edge-1.
//
// Every entity is built as a catalog canonical id and kept only if it matches
// the catalog's id pattern; it is re-checked for visibility by the validator
// whenever a later query uses it (cached state is never trusted as-is).

import (
	"regexp"
	"sync"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/plan"
)

// maxRowsScanned bounds how much of one answer feeds the state.
const maxRowsScanned = 50

var idPatterns sync.Map // entity type → *regexp.Regexp

func validRef(cat *catalog.Catalog, r ast.EntityRef) bool {
	if cat == nil || r.Type == "" || r.ID == "" || len(r.ID) > MaxIDLen {
		return false
	}
	if re, ok := idPatterns.Load(r.Type); ok {
		return re.(*regexp.Regexp).MatchString(r.ID)
	}
	et, ok := cat.Entity(r.Type)
	if !ok {
		return false
	}
	re, err := regexp.Compile(et.IDPattern)
	if err != nil {
		return false
	}
	idPatterns.Store(r.Type, re)
	return re.MatchString(r.ID)
}

// Next returns the state after an ANSWERED turn that ran q and got rs. A turn
// that was not answered leaves the previous state unchanged (the caller keeps
// prev).
func Next(cat *catalog.Catalog, prev State, q *ast.AST, rs *plan.ResultSet) State {
	var ents []ast.EntityRef
	add := func(r ast.EntityRef) {
		if validRef(cat, r) {
			ents = append(ents, r)
		}
	}
	// LastLogID is the caller's to set: it belongs to the record of THIS
	// answer, which is written after the state is computed.
	st := State{LastAST: prev.LastAST, Actors: prev.Actors, ChangeIDs: prev.ChangeIDs}
	if q != nil {
		st.LastAST = q
		for _, r := range q.Refs {
			add(r)
		}
	}
	if rs != nil {
		for i, row := range rs.Rows {
			if i == maxRowsScanned {
				break
			}
			for _, r := range rowEntities(row) {
				add(r)
			}
		}
		for i, s := range rs.Series {
			if i == maxRowsScanned {
				break
			}
			for _, r := range rowEntities(stringsToRow(s.Entity)) {
				add(r)
			}
		}
		// A change list redefines who "they" are and what "else" excludes.
		if q != nil && q.Type == ast.ChangeList {
			st.Actors, st.ChangeIDs = nil, nil
			for i, row := range rs.Rows {
				if i == maxRowsScanned {
					break
				}
				if a := str(row["actor"]); a != "" {
					st.Actors = append(st.Actors, a)
				}
				if id := str(row["change_id"]); id != "" {
					st.ChangeIDs = append(st.ChangeIDs, id)
				}
			}
		}
	}
	st.Entities = append(ents, prev.Entities...)
	return NormalizeState(st)
}

// rowEntities maps one result row's catalog fields to canonical entity ids.
func rowEntities(row plan.Row) []ast.EntityRef {
	var out []ast.EntityRef
	dev := str(row["device"])
	if dev == "" && str(row["object_kind"]) == "device" {
		dev = str(row["object"])
	}
	if dev != "" {
		out = append(out, ast.EntityRef{Type: "device", ID: "device:" + dev})
	}
	if v := str(row["interface"]); v != "" && dev != "" {
		out = append(out, ast.EntityRef{Type: "interface", ID: "interface:" + dev + "/" + v})
	}
	if v := str(row["bgp_peer"]); v != "" && dev != "" {
		out = append(out, ast.EntityRef{Type: "bgp_peer", ID: "bgp_peer:" + dev + "/" + v})
	}
	if v := str(row["circuit"]); v != "" {
		out = append(out, ast.EntityRef{Type: "circuit", ID: "circuit:" + v})
	}
	if v := str(row["probe_target"]); v != "" {
		out = append(out, ast.EntityRef{Type: "probe_target", ID: "probe:" + v})
	}
	if v := str(row["site"]); v != "" {
		out = append(out, ast.EntityRef{Type: "site", ID: "site:" + v})
	}
	if v := str(row["incident_id"]); v != "" {
		out = append(out, ast.EntityRef{Type: "incident", ID: "incident:" + v})
	}
	return out
}

func stringsToRow(m map[string]string) plan.Row {
	r := plan.Row{}
	for k, v := range m {
		r[k] = v
	}
	return r
}

func str(v any) string {
	s, _ := v.(string) // a non-string cell is not an id
	return s
}
