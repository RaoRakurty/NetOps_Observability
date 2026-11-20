// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

// estate_test.go — N-H6 step 3: the estate-wide seasonal answer. Tier honesty
// (A/B ranked, C counted and said), ranking by robust z, the K bound, the
// read bounds and timeout, maintenance exclusion, and naming by the caller's
// own inventory (an unseen device is dropped before anything is counted).

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/seasonal"
)

// estateHour is the judged hour for `now` (the roll-up's latest closed hour).
var estateHour = now.Truncate(time.Hour).Add(-time.Hour)

type estateScope struct {
	*fakeScope
	// workspace makes the scope a workspace-scoped (not cross-tenant) caller.
	workspace bool
	read      EstateRead
	err       error
	block     bool
	queries   []EstateQuery
	cover     map[string][]time.Time // device label → covered instants
}

func (e *estateScope) CrossTenant() bool { return !e.workspace }

func (e *estateScope) SeasonalEstate(ctx context.Context, q EstateQuery) (EstateRead, error) {
	e.queries = append(e.queries, q)
	if e.block {
		<-ctx.Done()
		return EstateRead{}, ctx.Err()
	}
	return e.read, e.err
}

type estateMaintScope struct{ *estateScope }

func (m estateMaintScope) MaintenanceCoverer(context.Context) (func(string, time.Time) bool, error) {
	return func(device string, at time.Time) bool {
		for _, c := range m.cover[device] {
			if c.Equal(at) {
				return true
			}
		}
		return false
	}, nil
}

// hist builds a series' hourly medians: cur at the judged hour, weeks[i] at
// i+1 weeks back and days[i] at i+1 days back (NaN-free; a missing entry is
// simply left out).
func hist(cur float64, weeks, days []float64) map[int64]float64 {
	out := map[int64]float64{estateHour.Unix(): cur}
	for i, v := range days {
		out[estateHour.Add(-time.Duration(i+1)*24*time.Hour).Unix()] = v
	}
	for i, v := range weeks {
		out[estateHour.Add(-time.Duration(i+1)*7*24*time.Hour).Unix()] = v
	}
	return out
}

var (
	steadyWeeks = []float64{100, 102, 98, 101}
	steadyDays  = []float64{99, 101, 100, 102, 98, 100, 100}
	// Traffic in bits/s: the bps scale floor (1 kb/s) must not swamp it.
	mbpsWeeks = scaled(steadyWeeks, 1e6)
	mbpsDays  = scaled(steadyDays, 1e6)
)

func scaled(xs []float64, k float64) []float64 {
	out := make([]float64, len(xs))
	for i, x := range xs {
		out[i] = x * k
	}
	return out
}

func estateExec(t *testing.T, sc Scope, js string) (*ResultSet, error) {
	t.Helper()
	return execute(t, sc, js)
}

func TestEstateRanksTiersAAndBAndCountsC(t *testing.T) {
	sc := &estateScope{fakeScope: &fakeScope{}, read: EstateRead{Hour: estateHour, Series: []EstateSeries{
		// tier A, far above: interface on edge-1 (series keyed by device id).
		{Metric: "if_in_bps", EntityKey: "d1\x1fGi0/1", P50: hist(200e6, mbpsWeeks, mbpsDays)},
		// tier A, normal: not listed.
		{Metric: "if_out_bps", EntityKey: "d1\x1fGi0/1", P50: hist(101e6, mbpsWeeks, mbpsDays)},
		// tier B (one week only), far below: a circuit on edge-2 (by name).
		{Metric: "circuit_qoe", EntityKey: "c-77\x1fedge-2", P50: hist(10, nil, steadyDays)},
		// tier C: two days of history — counted, never ranked, however far off.
		{Metric: "cpu_util_pct", EntityKey: "d2", P50: hist(99, nil, []float64{5, 5})},
		// a device the caller cannot see: dropped before counting.
		{Metric: "cpu_util_pct", EntityKey: "d9", P50: hist(500, steadyWeeks, steadyDays)},
		// a malformed key (an interface series with one label): dropped.
		{Metric: "if_in_errors", EntityKey: "d1", P50: hist(500, steadyWeeks, steadyDays)},
	}}}
	rs, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":""}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rows) != 2 {
		t.Fatalf("rows = %+v, want the two unusual tier A/B series", rs.Rows)
	}
	// Ranked by |z|: QoE 10 vs ~100 (z ≈ -18) and traffic 200 vs ~100 (z ≈ 19.8).
	first, second := rs.Rows[0], rs.Rows[1]
	if first["metric"] != "if_in_bps" || first["device"] != "edge-1" || first["interface"] != "Gi0/1" || first["direction"] != "above" {
		t.Errorf("first row %+v", first)
	}
	if !strings.Contains(first["baseline"].(string), "for this time of week") {
		t.Errorf("tier A wording: %q", first["baseline"])
	}
	if second["metric"] != "circuit_qoe" || second["circuit"] != "c-77" || second["device"] != "edge-2" || second["direction"] != "below" {
		t.Errorf("second row %+v", second)
	}
	b := second["baseline"].(string)
	if !strings.Contains(b, "for this time of day") || strings.Contains(strings.ToLower(b), "monday") {
		t.Errorf("tier B wording must be time of day, never a weekday: %q", b)
	}
	for _, r := range rs.Rows {
		if r["device"] == "d9" || r["metric"] == "if_in_errors" {
			t.Errorf("an unseen or malformed series leaked: %+v", r)
		}
		if _, ok := r["expected"].(float64); !ok {
			t.Errorf("row has no typical value: %+v", r)
		}
	}
	notes := strings.Join(rs.Notes, "\n")
	for _, want := range []string{"Not enough history for 1 series", "3 series checked", "2 against their usual level for this time of week", "1 against their usual level for this time of day"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	if !rs.Window.From.Equal(estateHour) || !rs.Window.To.Equal(estateHour.Add(time.Hour)) {
		t.Errorf("window %+v, want the judged hour", rs.Window)
	}
	q := sc.queries[0]
	if len(q.Metrics) != len(seasonal.RolledMetrics) || q.MaxSeries != MaxEstateSeries || len(q.Devices) != 0 {
		t.Errorf("query %+v: every rolled metric, bounded, unnarrowed", q)
	}
	if !q.Since.Equal(now.Truncate(time.Hour).Add(-EstateFreshness)) {
		t.Errorf("since %s", q.Since)
	}
	for _, m := range q.Metrics {
		want := 0
		if seasonal.RolledMetrics[m.Name] == "circuit" {
			want = 1
		}
		if m.DeviceAt != want {
			t.Errorf("%s device label at %d, want %d", m.Name, m.DeviceAt, want)
		}
	}
	sum := Summarize(cat, &ast.AST{V: 1, Type: ast.SeasonalOutliers}, rs)
	if !strings.Contains(sum, "2 series are unusual for the time right now") || !strings.Contains(sum, "edge-1 Gi0/1") ||
		!strings.Contains(sum, "circuit c-77 on edge-2") || !strings.Contains(sum, "robust deviations below") ||
		!strings.Contains(sum, "200.0 Mb/s now vs 100.5 Mb/s, its usual level for this time of week") {
		t.Errorf("summary:\n%s", sum)
	}
}

func TestEstateAboveOnlyTargetsAndFilters(t *testing.T) {
	read := EstateRead{Hour: estateHour, Series: []EstateSeries{
		{Metric: "if_in_bps", EntityKey: "d1\x1fGi0/1", P50: hist(200e6, mbpsWeeks, mbpsDays)},
		{Metric: "if_out_bps", EntityKey: "d1\x1fGi0/2", P50: hist(5e6, mbpsWeeks, mbpsDays)},
		// not asked for: never trusted.
		{Metric: "cpu_util_pct", EntityKey: "d1", P50: hist(500, steadyWeeks, steadyDays)},
	}}
	sc := &estateScope{fakeScope: &fakeScope{}, read: read}
	rs, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":"interface","predicate":{"op":"above_baseline"},
		"filters":[{"field":"metric","op":"in","values":["if_out_bps","if_in_bps"]}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rows) != 1 || rs.Rows[0]["interface"] != "Gi0/1" {
		t.Fatalf("above-only rows = %+v", rs.Rows)
	}
	var names []string
	for _, m := range sc.queries[0].Metrics {
		names = append(names, m.Name)
	}
	if !reflect.DeepEqual(names, []string{"if_in_bps", "if_out_bps"}) {
		t.Errorf("read metrics %v", names)
	}
	if !strings.Contains(Summarize(cat, &ast.AST{V: 1, Type: ast.SeasonalOutliers, Predicate: &ast.Predicate{Op: "above_baseline"}}, rs), "unusually high") {
		t.Error("above-only summary must say unusually high")
	}

	sc = &estateScope{fakeScope: &fakeScope{}, read: read}
	if _, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":"device"}`); err != nil {
		t.Fatal(err)
	}
	for _, m := range sc.queries[0].Metrics {
		if seasonal.RolledMetrics[m.Name] != "device" {
			t.Errorf("a device question read %s", m.Name)
		}
	}
}

func TestEstateNarrowsToNamedPlaces(t *testing.T) {
	sc := &estateScope{fakeScope: &fakeScope{}, read: EstateRead{Hour: estateHour}}
	if _, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":"","entities":[{"type":"device","id":"device:d1"}]}`); err != nil {
		t.Fatal(err)
	}
	if got := sc.queries[0].Devices; !reflect.DeepEqual(got, []string{"d1", "edge-1"}) {
		t.Errorf("devices %v, want edge-1's id and name", got)
	}
	// A site that resolves to no visible device is "nothing visible", never
	// an unnarrowed read.
	sc = &estateScope{fakeScope: &fakeScope{}, read: EstateRead{Hour: estateHour}}
	_, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":"","entities":[{"type":"site","id":"site:nowhere"}]}`)
	if !errors.Is(err, ErrEmptyScope) || len(sc.queries) != 0 {
		t.Fatalf("err %v, queries %d", err, len(sc.queries))
	}
}

func TestEstateLimitBound(t *testing.T) {
	var ss []EstateSeries
	for i := 0; i < 70; i++ {
		ss = append(ss, EstateSeries{Metric: "if_in_bps", EntityKey: fmt.Sprintf("d1\x1fGi0/%d", i), P50: hist((200+float64(i))*1e6, mbpsWeeks, mbpsDays)})
	}
	sc := &estateScope{fakeScope: &fakeScope{}, read: EstateRead{Hour: estateHour, Series: ss}}
	rs, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":"interface","limit":500}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rows) != MaxSeries || !rs.Truncated {
		t.Fatalf("%d rows, truncated=%v; want the K bound %d", len(rs.Rows), rs.Truncated, MaxSeries)
	}
	if rs.Rows[0]["interface"] != "Gi0/69" {
		t.Errorf("largest z first, got %+v", rs.Rows[0])
	}
	// Default limit.
	rs, err = estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":"interface"}`)
	if err != nil || len(rs.Rows) != 10 {
		t.Fatalf("default limit: %d rows, %v", len(rs.Rows), err)
	}
}

func TestEstateReadBoundsAndTimeout(t *testing.T) {
	// A read that returns more than it was allowed is cut to the bound.
	var ss []EstateSeries
	for i := 0; i < MaxEstateSeries+5; i++ {
		ss = append(ss, EstateSeries{Metric: "cpu_util_pct", EntityKey: "d1", P50: hist(100, steadyWeeks, steadyDays)})
	}
	sc := &estateScope{fakeScope: &fakeScope{}, read: EstateRead{Hour: estateHour, Series: ss}}
	rs, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":"device"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !rs.Truncated || !strings.Contains(strings.Join(rs.Notes, " "), fmt.Sprintf("only the first %d were judged", MaxEstateSeries)) {
		t.Errorf("over-bound read: truncated=%v notes=%v", rs.Truncated, rs.Notes)
	}
	if !strings.Contains(strings.Join(rs.Notes, " "), fmt.Sprintf("%d series checked", MaxEstateSeries)) {
		t.Errorf("checked count not bounded: %v", rs.Notes)
	}

	// A read that outlives its deadline is an error naming the bound.
	blk := &estateScope{fakeScope: &fakeScope{}, block: true}
	a, _ := ast.Decode([]byte(`{"v":1,"query_type":"seasonal_outliers","target":"device"}`))
	start := time.Now()
	_, err = Planner{Cat: cat, EstateTimeout: 50 * time.Millisecond}.Execute(context.Background(), blk, a, nil)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "took longer than 50ms") {
		t.Fatalf("timeout err = %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the timeout did not bound the read")
	}

	// An hour the read was not asked for is refused.
	bad := &estateScope{fakeScope: &fakeScope{}, read: EstateRead{Hour: estateHour.Add(-10 * time.Hour)}}
	if _, err := estateExec(t, bad, `{"v":1,"query_type":"seasonal_outliers","target":"device"}`); err == nil {
		t.Fatal("a stale hour must be refused")
	}
}

func TestEstateNoHistoryNoScope(t *testing.T) {
	// The roll-up holds no recent hour.
	sc := &estateScope{fakeScope: &fakeScope{}, read: EstateRead{}}
	rs, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":""}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rows) != 0 || !strings.Contains(strings.Join(rs.Notes, " "), "no closed hour in the last 3 hours") {
		t.Fatalf("no-hour answer: %+v", rs)
	}
	if s := Summarize(cat, &ast.AST{V: 1, Type: ast.SeasonalOutliers}, rs); !strings.HasPrefix(s, "Iris cannot say what is unusual right now.") {
		t.Errorf("summary %q", s)
	}
	// A deployment without the seam says so and reads nothing.
	f := &fakeScope{}
	rs, err = estateExec(t, f, `{"v":1,"query_type":"seasonal_outliers","target":""}`)
	if err != nil || !strings.Contains(strings.Join(rs.Notes, " "), "keeps no hourly seasonal history") || len(f.exprs) != 0 {
		t.Fatalf("no seam: %+v %v", rs, err)
	}
	// Nothing unusual: said as such, about the series checked.
	sc = &estateScope{fakeScope: &fakeScope{}, read: EstateRead{Hour: estateHour, Series: []EstateSeries{
		{Metric: "cpu_util_pct", EntityKey: "d1", P50: hist(100, steadyWeeks, steadyDays)}}}}
	rs, _ = estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":""}`)
	if s := Summarize(cat, &ast.AST{V: 1, Type: ast.SeasonalOutliers}, rs); !strings.HasPrefix(s, "Nothing is unusual for the time right now: no series checked is 3 or more") {
		t.Errorf("summary %q", s)
	}
}

func TestEstateMaintenanceExclusion(t *testing.T) {
	// Two of edge-1's four weekly references fell in maintenance (by device
	// id, the series label), leaving two weeks — below tier A, so the series
	// falls back to tier B and says so; the judged hour itself was also under
	// maintenance and is marked.
	base := &estateScope{fakeScope: &fakeScope{}, read: EstateRead{Hour: estateHour, Series: []EstateSeries{
		{Metric: "cpu_util_pct", EntityKey: "d1", P50: hist(300, steadyWeeks, steadyDays)}}}}
	base.cover = map[string][]time.Time{"d1": {
		estateHour.Add(-14*24*time.Hour + 30*time.Minute),
		estateHour.Add(-21*24*time.Hour + 30*time.Minute),
		estateHour.Add(30 * time.Minute),
	}}
	rs, err := estateExec(t, estateMaintScope{base}, `{"v":1,"query_type":"seasonal_outliers","target":"device"}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rows) != 1 {
		t.Fatalf("rows %+v", rs.Rows)
	}
	r := rs.Rows[0]
	if b := r["baseline"].(string); !strings.Contains(b, "for this time of day") {
		t.Errorf("two weeks left after exclusion must fall back to time of day: %q", b)
	}
	if r["maintenance"] != true || !strings.Contains(strings.Join(rs.Notes, " "), "1 of these was under a declared maintenance window") {
		t.Errorf("maintenance not marked: %+v %v", r, rs.Notes)
	}
	if !strings.Contains(Summarize(cat, &ast.AST{V: 1, Type: ast.SeasonalOutliers}, rs), "(during declared maintenance)") {
		t.Error("summary must say the judged hour was under maintenance")
	}
}

// The estate key labels are the planner's own templates for each rolled-up
// metric, so a stored entity key splits into the labels the answer names.
func TestEstateLabelsMatchTemplates(t *testing.T) {
	for m, ent := range seasonal.RolledMetrics {
		tp, ok := templates[m]
		if !ok {
			t.Errorf("%s has no template", m)
			continue
		}
		if !reflect.DeepEqual(tp.labels, estateLabels[ent]) {
			t.Errorf("%s: template labels %v, estate labels %v", m, tp.labels, estateLabels[ent])
		}
		if _, ok := cat.Metric(m); !ok {
			t.Errorf("%s is not a catalog metric", m)
		}
	}
}

// A workspace-scoped caller never reads the gated circuit metrics (N-B5), and
// is told so; a Scope that cannot say whether it is cross-tenant is treated as
// workspace-scoped.
func TestEstateGatesCircuitMetricsForAWorkspace(t *testing.T) {
	sc := &estateScope{fakeScope: &fakeScope{}, workspace: true, read: EstateRead{Hour: estateHour}}
	rs, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":""}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range sc.queries[0].Metrics {
		if seasonal.RolledMetrics[m.Name] == "circuit" {
			t.Errorf("a workspace caller read %s", m.Name)
		}
	}
	if !strings.Contains(strings.Join(rs.Notes, " "), "circuits are not included") {
		t.Errorf("the gate is not said: %v", rs.Notes)
	}
	// Only gated metrics asked for: nothing is read.
	sc = &estateScope{fakeScope: &fakeScope{}, workspace: true, read: EstateRead{Hour: estateHour}}
	if _, err := estateExec(t, sc, `{"v":1,"query_type":"seasonal_outliers","target":"circuit"}`); err != nil {
		t.Fatal(err)
	}
	if len(sc.queries) != 0 {
		t.Fatalf("a gated-only question read the roll-up: %+v", sc.queries)
	}
}
