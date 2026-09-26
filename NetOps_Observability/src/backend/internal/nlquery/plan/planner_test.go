// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/mql"
	"netops/backend/internal/nlquery/validate"
)

var (
	cat = catalog.MustLoad()
	now = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
)

// fakeScope records every call; tenant A owns site dfw-hq with edge-1/edge-2.
type fakeScope struct {
	exprs      []string
	ranges     int
	instants   []time.Time
	series     []Series
	samples    map[time.Time][]Sample
	changeQs   []ChangeQuery
	incidentQs []IncidentQuery
	incs       []IncidentRow
}

func (f *fakeScope) MetricRange(_ context.Context, e mql.Expr, _, _ time.Time, _ time.Duration, _ int) ([]Series, bool, error) {
	f.exprs, f.ranges = append(f.exprs, e.String()), f.ranges+1
	return f.series, false, nil
}
func (f *fakeScope) MetricInstant(_ context.Context, e mql.Expr, at time.Time, _ int) ([]Sample, bool, error) {
	f.exprs, f.instants = append(f.exprs, e.String()), append(f.instants, at)
	return f.samples[at], false, nil
}
func (f *fakeScope) Incidents(_ context.Context, q IncidentQuery) ([]IncidentRow, bool, error) {
	f.incidentQs = append(f.incidentQs, q)
	return f.incs, false, nil
}
func (f *fakeScope) Incident(_ context.Context, id string) (IncidentDetail, error) {
	if id != "11111111-2222-3333-4444-555555555555" {
		return IncidentDetail{}, ErrNotFound
	}
	return IncidentDetail{Row: IncidentRow{ID: id, CreatedAt: now.Add(-time.Hour)}, Detail: "rca"}, nil
}
func (f *fakeScope) Changes(_ context.Context, q ChangeQuery) ([]ChangeRow, bool, error) {
	f.changeQs = append(f.changeQs, q)
	return []ChangeRow{{ID: "chg-1", Type: "NETWORK_CHANGE", Actor: "John Smith", At: q.To.Add(-time.Minute)}}, false, nil
}
func (f *fakeScope) Devices(_ context.Context, df DeviceFilter) ([]DeviceRef, error) {
	all := []DeviceRef{{ID: "d1", Name: "edge-1", Site: "dfw-hq"}, {ID: "d2", Name: "edge-2", Site: "dfw-hq"}}
	var out []DeviceRef
	for _, d := range all {
		if (len(df.IDs) == 0 && len(df.Sites) == 0) || contains(df.IDs, d.ID) || contains(df.Sites, d.Site) {
			out = append(out, d)
		}
	}
	return out, nil
}
func (f *fakeScope) Circuits(_ context.Context, cf CircuitFilter) ([]CircuitRef, error) {
	if contains(cf.Providers, "comcast") || contains(cf.Sites, "dfw-hq") {
		return []CircuitRef{{ID: "c-dfw-1", LocalDevice: "edge-1", Site: "dfw-hq", Provider: "comcast"}}, nil
	}
	return nil, nil
}
func (f *fakeScope) Now() time.Time { return now }

type visAll struct{}

func (visAll) Visible(context.Context, ast.EntityRef) (bool, error)        { return true, nil }
func (visAll) Count(context.Context, string, []ast.EntityRef) (int, error) { return 5, nil }
func (visAll) CrossTenant() bool                                           { return true }
func (visAll) Now() time.Time                                              { return now }

func run(t *testing.T, sc *fakeScope, js string) *ResultSet {
	t.Helper()
	a, err := ast.Decode([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	v, res := validate.Validate(context.Background(), cat, visAll{}, a)
	if !res.Valid {
		t.Fatalf("fixture invalid: %+v", res.Errors)
	}
	rs, err := Planner{Cat: cat}.Execute(context.Background(), sc, v, res.Constraints)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestTemplatesMatchTheCatalogExactly(t *testing.T) {
	var tk, ck []string
	for k := range templates {
		tk = append(tk, k)
	}
	for _, m := range cat.Metrics {
		ck = append(ck, m.Name)
	}
	sort.Strings(tk)
	sort.Strings(ck)
	if strings.Join(tk, ",") != strings.Join(ck, ",") {
		t.Fatalf("templates %v\ncatalog   %v", tk, ck)
	}
	// Each template may read only the physical metrics its catalog entry
	// declares (the selector factory refuses anything else).
	for _, m := range cat.Metrics {
		m := m
		c := tctx{rateWin: 5 * time.Minute, win: time.Hour, sel: func(phys string) (mql.Expr, error) {
			if !contains(m.PhysicalMetrics, phys) {
				t.Errorf("template %s reads undeclared %s", m.Name, phys)
			}
			return mql.Selector(phys)
		}}
		if _, err := templates[m.Name].series(c); err != nil {
			t.Errorf("template %s: %v", m.Name, err)
		}
		for _, agg := range m.Aggregations {
			if _, err := aggregate(templates[m.Name], c, agg, time.Minute); err != nil {
				t.Errorf("template %s agg %s: %v", m.Name, agg, err)
			}
		}
	}
}

func TestSeriesExpandsSiteAndStripsRawLabels(t *testing.T) {
	sc := &fakeScope{series: []Series{{Labels: map[string]string{"device": "edge-1", "tenant": "t-a", "job": "snmp"}, Points: []Point{{T: 1, V: 42}}}}}
	rs := run(t, sc, `{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"site","id":"site:dfw-hq"}],"time_range":{"kind":"relative","last":"2h"}}`)
	if len(sc.exprs) != 1 || !strings.Contains(sc.exprs[0], `device=~"d1|d2|edge-1|edge-2"`) {
		t.Fatalf("expr = %v", sc.exprs)
	}
	if !strings.HasPrefix(sc.exprs[0], "limitk(51, ") {
		t.Fatalf("series read must carry the limitk safety net: %s", sc.exprs[0])
	}
	if len(rs.Series) != 1 || rs.Series[0].Entity["device"] != "edge-1" || len(rs.Series[0].Entity) != 1 {
		t.Fatalf("series entity = %+v — raw labels (tenant, job) must be stripped", rs.Series)
	}
	if rs.Window.Step != 30*time.Second || rs.Provenance.Source != "victoriametrics" || rs.CatalogVersion != cat.Version() {
		t.Fatalf("window/provenance = %+v %+v", rs.Window, rs.Provenance)
	}
}

// A site that resolves to no visible device answers "nothing visible" — it
// must NEVER fall back to an unscoped metric read.
func TestEmptyResolutionNeverReadsUnscoped(t *testing.T) {
	sc := &fakeScope{}
	rs := run(t, sc, `{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"site","id":"site:aus"}],"time_range":{"kind":"relative","last":"2h"}}`)
	if len(sc.exprs) != 0 {
		t.Fatalf("an empty scope issued a metric read: %v", sc.exprs)
	}
	if len(rs.Notes) == 0 || !strings.Contains(rs.Notes[0], "nothing visible") {
		t.Fatalf("notes = %v", rs.Notes)
	}
}

func TestInterfacePairsAreExact(t *testing.T) {
	sc := &fakeScope{series: []Series{
		{Labels: map[string]string{"device": "d1", "ifName": "Gi0/0"}, Points: []Point{{1, 1}}},
		{Labels: map[string]string{"device": "d2", "ifName": "Gi0/0"}, Points: []Point{{1, 2}}}, // same ifName, other device
	}}
	rs := run(t, sc, `{"v":1,"query_type":"metric_series","target":"interface","metric":"if_in_bps","entities":[{"type":"interface","id":"interface:d1/Gi0/0"}],"time_range":{"kind":"relative","last":"1h"}}`)
	if len(rs.Series) != 1 || rs.Series[0].Entity["device"] != "d1" {
		t.Fatalf("only the named (device, interface) pair may survive: %+v", rs.Series)
	}
}

func TestFilterPredicateGolden(t *testing.T) {
	sc := &fakeScope{samples: map[time.Time][]Sample{now: {{Labels: map[string]string{"device": "edge-1", "ifName": "Gi0/0"}, Value: 91}}}}
	rs := run(t, sc, `{"v":1,"query_type":"metric_filter","target":"interface","metric":"if_util_max_pct","aggregation":"max","predicate":{"op":"gt","value":80},"entities":[{"type":"site","id":"site:dfw-hq"}],"time_range":{"kind":"relative","last":"1h"}}`)
	e := sc.exprs[0]
	for _, want := range []string{"limitk(51, ", "max_over_time(", "[1h:30s]", "> 80)", "device_if_speed", `device=~"d1|d2|edge-1|edge-2"`} {
		if !strings.Contains(e, want) {
			t.Errorf("filter expr missing %q:\n%s", want, e)
		}
	}
	if len(rs.Rows) != 1 || rs.Rows[0]["value"] != 91.0 || rs.Rows[0]["interface"] != "Gi0/0" {
		t.Fatalf("rows = %+v", rs.Rows)
	}
}

func TestAboveBaselineUsesAnOffsetSevenDayQuantile(t *testing.T) {
	sc := &fakeScope{}
	run(t, sc, `{"v":1,"query_type":"metric_filter","target":"interface","metric":"if_in_bps","predicate":{"op":"above_baseline"},"entities":[{"type":"device","id":"device:d1"}],"time_range":{"kind":"relative","last":"1h"}}`)
	if !strings.Contains(sc.exprs[0], "quantile_over_time(0.95, ") || !strings.Contains(sc.exprs[0], "[7d:30s]) offset 1h)") {
		t.Fatalf("baseline expr = %s", sc.exprs[0])
	}
}

func TestCompareRanksByAbsoluteChange(t *testing.T) {
	yest := now.Add(-24 * time.Hour)
	lbl := func(d string) map[string]string { return map[string]string{"device": d} }
	sc := &fakeScope{samples: map[time.Time][]Sample{
		now:  {{Labels: lbl("edge-1"), Value: 50}, {Labels: lbl("edge-2"), Value: 10}},
		yest: {{Labels: lbl("edge-1"), Value: 45}, {Labels: lbl("edge-2"), Value: 60}},
	}}
	rs := run(t, sc, `{"v":1,"query_type":"compare_windows","target":"device","metric":"cpu_util_pct","time_range":{"kind":"relative","last":"2h"},"compare_to":{"kind":"relative","last":"2h","offset":"1d"}}`)
	if len(sc.instants) != 2 || !sc.instants[1].Equal(yest) {
		t.Fatalf("compare must read both window ends: %v", sc.instants)
	}
	if rs.Rows[0]["device"] != "edge-2" || rs.Rows[0]["delta"] != -50.0 || rs.Compare == nil {
		t.Fatalf("largest |Δ| first: %+v", rs.Rows)
	}
}

func TestChangeListMapsClassesAndSaysCorrelationIsNotCause(t *testing.T) {
	sc := &fakeScope{}
	rs := run(t, sc, `{"v":1,"query_type":"change_list","target":"change","filters":[{"field":"class","op":"eq","values":["wan"]},{"field":"actor","op":"eq","values":["John Smith"]}],"time_range":{"kind":"relative","last":"7d"}}`)
	q := sc.changeQs[0]
	sort.Strings(q.Types)
	if strings.Join(q.Types, ",") != "NETWORK_CHANGE,ROUTE_CHANGE" || q.Actors[0] != "John Smith" || q.Limit != 100 {
		t.Fatalf("change query = %+v", q)
	}
	if rs.Rows[0]["relation"] != "temporal" || !strings.Contains(strings.Join(rs.Notes, " "), "only CORRELATED") {
		t.Fatalf("rows/notes = %+v %v", rs.Rows, rs.Notes)
	}
}

func TestChangesAroundEveryIncident(t *testing.T) {
	inc := func(id string, ago time.Duration) IncidentRow { return IncidentRow{ID: id, CreatedAt: now.Add(-ago)} }
	sc := &fakeScope{incs: []IncidentRow{inc("i1", time.Hour), inc("i2", 30*time.Hour)}}
	rs := run(t, sc, `{"v":1,"query_type":"change_list","target":"change","time_range":{"kind":"incidents","anchor":{"before":"30m","after":"1m","incidents":{"filters":[{"field":"seam_class","op":"eq","values":["sdwan"]}],"time_range":{"kind":"relative","last":"7d"}}}}}`)
	if len(sc.incidentQs) != 1 || sc.incidentQs[0].SeamTypes[0] != "SDWAN" || sc.incidentQs[0].Limit != validate.MaxAnchorIncidents {
		t.Fatalf("incident set query = %+v", sc.incidentQs)
	}
	if len(sc.changeQs) != 2 || !sc.changeQs[0].To.Equal(now.Add(-time.Hour+time.Minute)) || !sc.changeQs[0].From.Equal(now.Add(-90*time.Minute)) {
		t.Fatalf("one bounded change read per incident window: %+v", sc.changeQs)
	}
	if rs.Rows[0]["incident_id"] == nil || !strings.Contains(strings.Join(rs.Notes, " "), "not established as causes") {
		t.Fatalf("rows/notes = %+v %v", rs.Rows, rs.Notes)
	}
}

func TestIncidentAnchoredWindowAndExplain(t *testing.T) {
	sc := &fakeScope{}
	run(t, sc, `{"v":1,"query_type":"change_list","target":"change","time_range":{"kind":"incident","anchor":{"incident_id":"11111111-2222-3333-4444-555555555555"}}}`)
	q := sc.changeQs[0]
	if !q.From.Equal(now.Add(-time.Hour-DefaultBefore)) || !q.To.Equal(now.Add(-time.Hour+DefaultAfter)) {
		t.Fatalf("incident window = %v → %v", q.From, q.To)
	}
	rs := run(t, &fakeScope{}, `{"v":1,"query_type":"incident_explain","incident_id":"11111111-2222-3333-4444-555555555555"}`)
	if rs.Detail != "rca" || rs.Provenance.Source != "rca_report" {
		t.Fatalf("explain = %+v", rs)
	}
}

func TestStepKeepsPointsBounded(t *testing.T) {
	for span, want := range map[time.Duration]time.Duration{time.Hour: 30 * time.Second, 2 * time.Hour: 30 * time.Second, 4 * time.Hour: time.Minute,
		24 * time.Hour: 5 * time.Minute, 7 * 24 * time.Hour: time.Hour} {
		if got := stepFor(span); got != want || span/got > MaxPoints {
			t.Errorf("stepFor(%v) = %v want %v", span, got, want)
		}
	}
}

func TestSplitPairKeepsSlashesInTheSecondPart(t *testing.T) {
	for id, want := range map[string][2]string{
		"interface:d1/Gi0/0/1":     {"d1", "Gi0/0/1"},
		"interface:d1/Ethernet1":   {"d1", "Ethernet1"},
		"bgp_peer:d1/10.0.0.1@red": {"d1", "10.0.0.1"},
		"bgp_peer:d1/2001:db8::1":  {"d1", "2001:db8::1"},
	} {
		if d, x := splitPair(id); d != want[0] || x != want[1] {
			t.Errorf("splitPair(%q) = %q,%q want %v", id, d, x, want)
		}
	}
}

// A negated enum filter is its exact complement — never dropped, never read
// as the positive value (found by the golden corpus, 2026-09-26).
func TestNegatedFiltersBecomeTheirComplement(t *testing.T) {
	sc := &fakeScope{}
	run(t, sc, `{"v":1,"query_type":"incident_list","target":"incident","filters":[{"field":"state","op":"ne","values":["closed"]}],"time_range":{"kind":"relative","last":"7d"}}`)
	st := sc.incidentQs[0].States
	sort.Strings(st)
	if strings.Join(st, ",") != "merged,open" {
		t.Fatalf("state ne closed → %v, want merged,open", st)
	}
	sc = &fakeScope{}
	run(t, sc, `{"v":1,"query_type":"change_list","target":"change","filters":[{"field":"type","op":"ne","values":["DNS_CHANGE"]},{"field":"id","op":"ne","values":["chg-1"]}],"time_range":{"kind":"relative","last":"24h"}}`)
	q := sc.changeQs[0]
	if len(q.Types) != 8 || contains(q.Types, "DNS_CHANGE") || q.ExcludeIDs[0] != "chg-1" {
		t.Fatalf("type ne DNS → %v, exclude %v", q.Types, q.ExcludeIDs)
	}
	sc = &fakeScope{}
	run(t, sc, `{"v":1,"query_type":"change_list","target":"change","filters":[{"field":"class","op":"ne","values":["wan"]}],"time_range":{"kind":"relative","last":"24h"}}`)
	if contains(sc.changeQs[0].Types, "NETWORK_CHANGE") || contains(sc.changeQs[0].Types, "ROUTE_CHANGE") || len(sc.changeQs[0].Types) != 7 || !contains(sc.changeQs[0].Types, "DNS_CHANGE") {
		t.Fatalf("class ne wan → %v", sc.changeQs[0].Types)
	}
}
