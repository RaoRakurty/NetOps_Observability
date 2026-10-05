// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package chips

import (
	"errors"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
)

func mustAST(t *testing.T, s string) *ast.AST {
	t.Helper()
	q, err := ast.Decode([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func known(typ string) []Option {
	switch typ {
	case "device":
		return []Option{{"device:dev-a", "edge-a"}, {"device:dev-a2", "edge-a2"}}
	case "site":
		return []Option{{"site:dfw-hq", "Dallas"}, {"site:aus-br", "Austin"}}
	}
	return nil
}

func chipByID(cs []Chip, id string) *Chip {
	for i := range cs {
		if cs[i].ID == id {
			return &cs[i]
		}
	}
	return nil
}

const metricQ = `{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","aggregation":"avg",
 "entities":[{"type":"device","id":"device:dev-a"}],"time_range":{"kind":"relative","last":"1h"}}`

const changeQ = `{"v":1,"query_type":"change_list","target":"change","entities":[{"type":"site","id":"site:dfw-hq"}],
 "filters":[{"field":"type","op":"in","values":["NETWORK_CHANGE","CONFIG_CHANGE"]},{"field":"actor","op":"eq","values":["John Smith"]},
 {"field":"id","op":"ne","values":["c1","c2"]}],"time_range":{"kind":"relative","last":"24h"}}`

func TestBuildDerivesChipsFromTheQuery(t *testing.T) {
	cat := catalog.MustLoad()
	cs := Build(cat, mustAST(t, metricQ), known)
	if len(cs) != 3 || cs[0].ID != IDMetric || cs[1].ID != IDWindow || cs[2].ID != "ref:0" {
		t.Fatalf("chips = %+v", cs)
	}
	if cs[0].Removable || cs[1].Removable || !cs[2].Removable {
		t.Fatal("metric and time are required; an entity can be removed")
	}
	if cs[2].ValueLabel != "edge-a" || len(cs[2].Options) != 2 {
		t.Fatalf("entity chip = %+v", cs[2])
	}
	for _, o := range cs[0].Options {
		m, _ := cat.Metric(o.Value)
		if m == nil || !contains(m.EntityTypes, "device") {
			t.Errorf("metric option %q does not apply to devices", o.Value)
		}
	}
	for _, o := range cs[1].Options {
		if o.Value == "30d" {
			t.Fatal("a metric query is offered no window past its 7-day limit")
		}
	}

	cs = Build(cat, mustAST(t, changeQ), known)
	if c := chipByID(cs, "filter:0:1"); c == nil || c.Value != "CONFIG_CHANGE" || c.ValueLabel != "Config change" || len(c.Options) != 9 {
		t.Fatalf("an enum filter value is one editable chip: %+v", c)
	}
	if c := chipByID(cs, "filter:1"); c == nil || len(c.Options) != 0 || !c.Removable || c.Value != "John Smith" {
		t.Fatalf("a free-form filter is one removable, unchangeable chip: %+v", c)
	}
	if c := chipByID(cs, "filter:2"); c == nil || c.Label != "Excluding" || strings.Contains(c.Value, "c1") {
		t.Fatalf("the 'else' exclusion is summarised, not listed: %+v", c)
	}
	if c := chipByID(cs, IDWindow); c == nil || c.Options[len(c.Options)-1].Value != "30d" {
		t.Fatalf("a list may look back 30 days: %+v", c)
	}
}

func TestBuildIsDeterministicAndBounded(t *testing.T) {
	cat := catalog.MustLoad()
	q := mustAST(t, metricQ)
	for i := 0; i < 30; i++ {
		q.Refs = append(q.Refs, ast.EntityRef{Type: "device", ID: "device:x" + strings.Repeat("y", i)})
	}
	a, b := Build(cat, q, known), Build(cat, q, known)
	if len(a) != MaxChips {
		t.Fatalf("chips not capped: %d", len(a))
	}
	for i := range a {
		if a[i].ID != b[i].ID || a[i].Value != b[i].Value {
			t.Fatal("Build is not deterministic")
		}
	}
	if Build(cat, nil, known) != nil || Build(nil, q, known) != nil {
		t.Fatal("no query, no chips")
	}
}

func TestApplyRegeneratesTheQuery(t *testing.T) {
	cat := catalog.MustLoad()
	for name, tc := range map[string]struct {
		q    string
		e    Edit
		want string // substring of the regenerated canonical query
		not  string
	}{
		"change device": {metricQ, Edit{"ref:0", OpSet, "device:dev-a2"}, `"id":"device:dev-a2"`, "dev-a\""},
		"remove device": {metricQ, Edit{"ref:0", OpRemove, ""}, `"query_type":"metric_series"`, "entities"},
		"change window": {metricQ, Edit{IDWindow, OpSet, "24h"}, `"last":"24h"`, `"last":"1h"`},
		"change metric": {metricQ, Edit{IDMetric, OpSet, "mem_util_pct"}, `"metric":"mem_util_pct"`, "cpu_util_pct"},
		"change type":   {changeQ, Edit{"filter:0:0", OpSet, "ROUTE_CHANGE"}, `"values":["ROUTE_CHANGE","CONFIG_CHANGE"]`, "NETWORK_CHANGE"},
		"remove value":  {changeQ, Edit{"filter:0:0", OpRemove, ""}, `{"field":"type","op":"eq","values":["CONFIG_CHANGE"]}`, "NETWORK_CHANGE"},
		"remove actor":  {changeQ, Edit{"filter:1", OpRemove, ""}, `"field":"id"`, "John Smith"},
		"site to list":  {changeQ, Edit{"ref:0", OpSet, "site:aus-br"}, `"id":"site:aus-br"`, "dfw-hq"},
	} {
		t.Run(name, func(t *testing.T) {
			q := mustAST(t, tc.q)
			before, _ := q.Canonical()
			out, chip, err := Apply(cat, q, known, tc.e)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := out.Canonical()
			if !strings.Contains(string(raw), tc.want) || strings.Contains(string(raw), tc.not) {
				t.Fatalf("regenerated %s", raw)
			}
			if after, _ := q.Canonical(); string(after) != string(before) {
				t.Fatal("Apply must rewrite a COPY, never the held query")
			}
			if d := Describe(chip, tc.e); d == "" {
				t.Fatal("an edit is described")
			}
			// Same edit, same query: deterministic.
			again, _, _ := Apply(cat, mustAST(t, tc.q), known, tc.e)
			if again.Hash() != out.Hash() {
				t.Fatal("Apply is not deterministic")
			}
		})
	}
}

func TestApplyRefusesWhatTheServerDidNotOffer(t *testing.T) {
	cat := catalog.MustLoad()
	for name, tc := range map[string]struct {
		q    string
		e    Edit
		want error
	}{
		"unknown chip":         {metricQ, Edit{"ref:9", OpSet, "device:dev-a2"}, ErrUnknownChip},
		"forged entity":        {metricQ, Edit{"ref:0", OpSet, "device:dev-b"}, ErrNotOffered},
		"free-text window":     {metricQ, Edit{IDWindow, OpSet, "9999d"}, ErrNotOffered},
		"window past limit":    {metricQ, Edit{IDWindow, OpSet, "30d"}, ErrNotOffered},
		"remove required":      {metricQ, Edit{IDMetric, OpRemove, ""}, ErrNotRemovable},
		"remove time":          {metricQ, Edit{IDWindow, OpRemove, ""}, ErrNotRemovable},
		"set free-form filter": {changeQ, Edit{"filter:1", OpSet, "Mallory"}, ErrNotEditable},
		"bad op":               {metricQ, Edit{"ref:0", "replace", "x"}, ErrBadOp},
		"enum not in catalog":  {changeQ, Edit{"filter:0:0", OpSet, "DROP TABLE"}, ErrNotOffered},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Apply(cat, mustAST(t, tc.q), known, tc.e); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAPredicateKeepsItsMetric(t *testing.T) {
	cat := catalog.MustLoad()
	q := mustAST(t, `{"v":1,"query_type":"metric_filter","target":"device","metric":"cpu_util_pct","predicate":{"op":"gt","value":80},"time_range":{"kind":"relative","last":"1h"}}`)
	c := chipByID(Build(cat, q, known), IDMetric)
	if c == nil || len(c.Options) != 0 {
		t.Fatalf("a threshold is in its metric's unit — the metric chip must be read-only: %+v", c)
	}
	if _, _, err := Apply(cat, q, known, Edit{IDMetric, OpSet, "mem_util_pct"}); !errors.Is(err, ErrNotEditable) {
		t.Fatalf("err = %v", err)
	}
}

func TestAnIncidentAnchoredWindowIsReadOnly(t *testing.T) {
	cat := catalog.MustLoad()
	q := mustAST(t, `{"v":1,"query_type":"change_list","target":"change","time_range":{"kind":"incident","anchor":{"incident_id":"11111111-2222-4333-8444-555555555555","before":"2h"}}}`)
	c := chipByID(Build(cat, q, known), IDWindow)
	if c == nil || len(c.Options) != 0 || c.Removable {
		t.Fatalf("an incident window is shown, not edited: %+v", c)
	}
}
