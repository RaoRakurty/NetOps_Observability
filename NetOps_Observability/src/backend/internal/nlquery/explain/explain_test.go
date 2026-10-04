// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package explain

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/plan"
)

func decode(t *testing.T, js string) *ast.AST {
	t.Helper()
	q, err := ast.Decode([]byte(js))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return q
}

func part(e Explanation, facet string) string {
	for _, p := range e.Parts {
		if p.Facet == facet {
			return p.Text
		}
	}
	return ""
}

func TestExplainSaysWhatEachSlotDoes(t *testing.T) {
	cat := catalog.MustLoad()
	q := decode(t, `{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","aggregation":"p95",
		"entities":[{"type":"device","id":"device:dev-a"},{"type":"device","id":"device:dev-b"},{"type":"site","id":"site:dfw-hq"}],
		"time_range":{"kind":"relative","last":"2h","offset":"1d"},"group_by":["site"]}`)
	names := func(r ast.EntityRef) string {
		if r.ID == "device:dev-a" {
			return "edge-a"
		}
		return ""
	}
	e := Explain(cat, q, names)
	for facet, want := range map[string][]string{
		FacetWhat:     {"Shows"},
		FacetMetric:   {"cpu_util_pct", "95th percentile"},
		FacetEntities: {"device edge-a (dev-a) or dev-b", ", and site dfw-hq"},
		FacetWindow:   {"a 2-hour window ending 1 day ago"},
		FacetGrouping: {"Grouped by"},
	} {
		got := part(e, facet)
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%s: %q does not say %q", facet, got, w)
			}
		}
	}
	if !strings.Contains(e.Summary, "edge-a") || !strings.Contains(e.Summary, "2-hour") {
		t.Errorf("summary: %q", e.Summary)
	}
	q.Time = ast.TimeRange{Kind: ast.TimeRelative, Last: "1h"}
	if w := part(Explain(cat, q, nil), FacetWindow); w != "Time window: the last hour." {
		t.Errorf("one unit reads naturally: %q", w)
	}
	// Slots the query does not fill are not invented.
	for _, f := range []string{FacetFilters, FacetCondition, FacetCompare, FacetOrder, FacetLimit, FacetIncident} {
		if got := part(e, f); got != "" {
			t.Errorf("%s explained for a query without it: %q", f, got)
		}
	}
}

func TestExplainListsFiltersConditionsAndAnchors(t *testing.T) {
	cat := catalog.MustLoad()
	ch := Explain(cat, decode(t, `{"v":1,"query_type":"change_list","target":"change",
		"filters":[{"field":"actor","op":"eq","values":["bob"]},{"field":"type","op":"in","values":["config","acl"]}],
		"time_range":{"kind":"incident","anchor":{"incident_id":"inc-7"}},"order_by":[{"field":"event_at","dir":"desc"}],"limit":50}`), nil)
	if f := part(ch, FacetFilters); !strings.Contains(f, `"bob"`) || !strings.Contains(f, `one of "acl" or "config"`) {
		t.Errorf("filters: %q", f)
	}
	if w := part(ch, FacetWindow); !strings.Contains(w, "30 minutes before to 10 minutes after incident inc-7") {
		t.Errorf("incident window must state the default span: %q", w)
	}
	if o := part(ch, FacetOrder); !strings.Contains(o, "newest first") {
		t.Errorf("order: %q", o)
	}
	if l := part(ch, FacetLimit); l != "At most 50 results." {
		t.Errorf("limit: %q", l)
	}

	f := Explain(cat, decode(t, `{"v":1,"query_type":"metric_filter","target":"interface","metric":"if_util_in_pct",
		"predicate":{"op":"between","value":50,"value2":80.5},"time_range":{"kind":"relative","last":"15m"}}`), nil)
	if c := part(f, FacetCondition); !strings.Contains(c, "between 50% and 80.5%") {
		t.Errorf("condition: %q", c)
	}
	if e := part(f, FacetEntities); !strings.Contains(e, "every interface you can see") {
		t.Errorf("no refs must say it is about everything visible: %q", e)
	}

	abs := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	to := abs.Add(time.Hour)
	cmp := &ast.AST{V: 1, Type: ast.CompareWindows, Target: "device", Metric: "cpu_util_pct",
		Time:      ast.TimeRange{Kind: ast.TimeAbsolute, From: &abs, To: &to},
		CompareTo: &ast.TimeRange{Kind: ast.TimeRelative, Last: "1h", Offset: "7d"}}
	ce := Explain(cat, cmp, nil)
	if w := part(ce, FacetWindow); w != "Time window: 2026-09-01 10:00 UTC to 2026-09-01 11:00 UTC." {
		t.Errorf("absolute window: %q", w)
	}
	if c := part(ce, FacetCompare); !strings.Contains(c, "ending 7 days ago") {
		t.Errorf("compare: %q", c)
	}

	inc := Explain(cat, &ast.AST{V: 1, Type: ast.IncidentExplain, Target: "incident", IncidentID: "inc-9"}, nil)
	if part(inc, FacetIncident) != "About incident inc-9." || strings.Contains(inc.Summary, "window") ||
		part(inc, FacetEntities) != "" || part(inc, FacetWindow) != "" || !strings.Contains(inc.Summary, "inc-9") {
		t.Errorf("incident explain: %+v", inc)
	}

	// A state code reads as its catalog name.
	st := Explain(cat, decode(t, `{"v":1,"query_type":"metric_filter","target":"bgp_peer","metric":"bgp_session_state",
		"predicate":{"op":"ne","value":6},"time_range":{"kind":"relative","last":"5m"}}`), nil)
	if c := part(st, FacetCondition); !strings.Contains(c, "is not established (6)") {
		t.Errorf("enum condition: %q", c)
	}
	if m := part(st, FacetMetric); strings.Contains(m, " in state") {
		t.Errorf("a state code has no unit to name: %q", m)
	}
}

func TestExplainNeverInventsANameItWasNotGiven(t *testing.T) {
	q := &ast.AST{V: 1, Type: ast.MetricSeries, Target: "device", Metric: "cpu_util_pct",
		Refs: []ast.EntityRef{{Type: "device", ID: "device:dev-b"}}, Time: ast.TimeRange{Kind: ast.TimeRelative, Last: "1h"}}
	e := Explain(catalog.MustLoad(), q, func(ast.EntityRef) string { return "" })
	if got := part(e, FacetEntities); got != "About device dev-b." {
		t.Fatalf("an unnamed entity is shown by id: %q", got)
	}
	if got := Explain(nil, nil, nil); got.Summary != "" || len(got.Parts) != 0 {
		t.Fatalf("no query, no explanation: %+v", got)
	}
}

// The explanation's incident-anchored span must be the planner's.
func TestDefaultSpanMatchesThePlanner(t *testing.T) {
	b, err := ast.ParseDuration(DefaultBefore)
	if err != nil || b != plan.DefaultBefore {
		t.Errorf("DefaultBefore %s, planner %s", DefaultBefore, plan.DefaultBefore)
	}
	a, err := ast.ParseDuration(DefaultAfter)
	if err != nil || a != plan.DefaultAfter {
		t.Errorf("DefaultAfter %s, planner %s", DefaultAfter, plan.DefaultAfter)
	}
}

// Every query in the golden corpus explains cleanly: no format artifacts, and
// every value the query carries — metric, entity ids, filter values, limit —
// appears in the words.
func TestEveryGoldenQueryExplains(t *testing.T) {
	cat := catalog.MustLoad()
	files, err := filepath.Glob("../testdata/golden/*.json")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, f := range files {
		if filepath.Base(f) == "fixture.json" {
			continue
		}
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Cases []struct {
				ID     string `json:"id"`
				Expect struct {
					AST json.RawMessage `json:"ast"`
				} `json:"expect"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, c := range doc.Cases {
			if len(c.Expect.AST) == 0 || string(c.Expect.AST) == "null" {
				continue
			}
			q, err := ast.Decode(c.Expect.AST)
			if err != nil {
				t.Fatalf("%s: %v", c.ID, err)
			}
			n++
			e := Explain(cat, q, nil)
			all := e.Summary
			for _, p := range e.Parts {
				all += "\n" + p.Text
			}
			if e.Summary == "" || len(e.Parts) < 2 || strings.Contains(all, "%!") {
				t.Errorf("%s: %q", c.ID, all)
				continue
			}
			var want []string
			if q.Metric != "" {
				want = append(want, q.Metric)
			}
			for _, r := range q.Refs {
				want = append(want, r.ID[strings.Index(r.ID, ":")+1:])
			}
			for _, fl := range q.Filters {
				for _, v := range fl.Values {
					want = append(want, strconv.Quote(v))
				}
			}
			if q.Limit > 0 {
				want = append(want, strconv.Itoa(q.Limit))
			}
			for _, w := range want {
				if !strings.Contains(all, w) {
					t.Errorf("%s: the explanation omits %q:\n%s", c.ID, w, all)
				}
			}
		}
	}
	if n < 100 {
		t.Fatalf("only %d golden queries explained — the corpus is not being read", n)
	}
}
