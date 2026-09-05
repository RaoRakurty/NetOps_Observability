package dem

// stats_test.go — the metrics-query layer. Two things matter here: the tenant
// filter is ALWAYS applied for a scoped caller (and fails closed when it cannot
// be), and a backend failure surfaces as an error rather than as zeros.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeQuerier struct {
	rows    map[string][]Sample // expr substring → rows
	seen    []string
	filters [][]string
	err     error
}

func (f *fakeQuerier) Instant(_ context.Context, expr string, filters []string) ([]Sample, error) {
	f.seen = append(f.seen, expr)
	f.filters = append(f.filters, filters)
	if f.err != nil {
		return nil, f.err
	}
	for frag, rows := range f.rows {
		if strings.Contains(expr, frag) {
			return rows, nil
		}
	}
	return nil, nil
}

func TestTenantFilterAlwaysScopesANonCrossCaller(t *testing.T) {
	got := TenantFilter("Acme", false)
	if len(got) != 1 || got[0] != `{tenant="acme"}` {
		t.Fatalf("filter %v", got)
	}
	if f := TenantFilter("anything", true); f != nil {
		t.Fatalf("cross-tenant filter %v", f)
	}
	// Fail CLOSED: a scope we cannot express becomes a match-nothing selector,
	// never an unfiltered query.
	for _, bad := range []string{"", "*", `acme"} or up{`, strings.Repeat("a", 200)} {
		f := TenantFilter(bad, false)
		if len(f) != 1 || !strings.Contains(f[0], "__netops_no_visible_tenant__") {
			t.Fatalf("scope %q produced %v — a bad scope must never widen the query", bad, f)
		}
	}
}

func TestParseWindowRefusesAnythingElse(t *testing.T) {
	for _, ok := range []string{"", "1h", "24h"} {
		if _, _, err := ParseWindow(ok); err != nil {
			t.Fatalf("ParseWindow(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"7d", "5m", "1h;drop", "1h\\"} {
		if _, _, err := ParseWindow(bad); err == nil {
			t.Fatalf("ParseWindow(%q) was accepted", bad)
		}
	}
}

func TestFetchWindowFoldsByTargetAndScopes(t *testing.T) {
	q := &fakeQuerier{rows: map[string][]Sample{
		"count_over_time(dem_probe_success":    {{Labels: map[string]string{"target": "dem-1"}, Value: 60}},
		"sum_over_time(dem_probe_success":      {{Labels: map[string]string{"target": "dem-1"}, Value: 57}},
		"count_over_time(dem_probe_latency_ms": {{Labels: map[string]string{"target": "dem-1"}, Value: 57}},
		"quantile_over_time(0.95":              {{Labels: map[string]string{"target": "dem-1"}, Value: 310}},
		"changes(dem_path_fingerprint":         {{Labels: map[string]string{"target": "dem-1"}, Value: 2}},
		"count_over_time(dem_path_fingerprint": {{Labels: map[string]string{"target": "dem-1"}, Value: 12}},
		"timestamp(dem_probe_success":          {{Labels: map[string]string{"target": "dem-1"}, Value: 1_757_000_000}},
	}}
	out, err := FetchWindow(context.Background(), q, "acme", false, Window1h)
	if err != nil {
		t.Fatalf("FetchWindow: %v", err)
	}
	st := out["dem-1"]
	if st.Samples != 60 || st.Successes != 57 || st.LatencyP95Ms != 310 {
		t.Fatalf("stats: %+v", st)
	}
	if st.PathSamples != 12 || st.PathChanges != 2 {
		t.Fatalf("path stats: %+v", st)
	}
	if st.LastProbe.IsZero() {
		t.Fatal("last probe not folded")
	}
	// EVERY query carried the tenant filter — a single unscoped one is a leak.
	for i, f := range q.filters {
		if len(f) != 1 || f[0] != `{tenant="acme"}` {
			t.Fatalf("query %d ran with filters %v: %s", i, f, q.seen[i])
		}
	}
	// And no caller-supplied text ever reaches an expression.
	for _, e := range q.seen {
		if !strings.Contains(e, "dem_") {
			t.Fatalf("unexpected expression %q", e)
		}
	}
}

// A metrics failure must NOT read as "everything is zero".
func TestFetchWindowSurfacesBackendFailure(t *testing.T) {
	q := &fakeQuerier{err: errors.New("upstream refused")}
	if _, err := FetchWindow(context.Background(), q, "acme", false, Window1h); err == nil {
		t.Fatal("a failed metrics query was swallowed")
	}
	if _, err := FetchWindow(context.Background(), nil, "acme", false, Window1h); err == nil {
		t.Fatal("a missing metrics backend was swallowed")
	}
}

// Successes can never exceed samples; a backend that says otherwise is not one
// we render an availability from.
func TestFetchWindowClampsImpossibleSuccessCounts(t *testing.T) {
	q := &fakeQuerier{rows: map[string][]Sample{
		"count_over_time(dem_probe_success": {{Labels: map[string]string{"target": "dem-1"}, Value: 10}},
		"sum_over_time(dem_probe_success":   {{Labels: map[string]string{"target": "dem-1"}, Value: 99}},
	}}
	out, err := FetchWindow(context.Background(), q, "acme", false, Window1h)
	if err != nil {
		t.Fatalf("FetchWindow: %v", err)
	}
	if out["dem-1"].Successes != 10 {
		t.Fatalf("successes %d", out["dem-1"].Successes)
	}
}

// A response far larger than the catalogue can hold is evidence the filter did
// not apply. Refuse it rather than rendering another tenant's series.
func TestFetchWindowRefusesAnOversizedResponse(t *testing.T) {
	rows := make([]Sample, MaxScoredTargets*4+1)
	for i := range rows {
		rows[i] = Sample{Labels: map[string]string{"target": "dem-x"}, Value: 1}
	}
	q := &fakeQuerier{rows: map[string][]Sample{"count_over_time(dem_probe_success": rows}}
	if _, err := FetchWindow(context.Background(), q, "acme", false, Window1h); err == nil {
		t.Fatal("an oversized metrics response was accepted")
	}
}

func TestProberReporting(t *testing.T) {
	q := &fakeQuerier{rows: map[string][]Sample{"count_over_time(dem_probe_success": {{Value: 12}}}}
	up, err := ProberReporting(context.Background(), q, "acme", false, "15m")
	if err != nil || !up {
		t.Fatalf("ProberReporting: %v %v", up, err)
	}
	empty := &fakeQuerier{}
	up, err = ProberReporting(context.Background(), empty, "acme", false, "15m")
	if err != nil || up {
		t.Fatalf("absent series must read as not-reporting: %v %v", up, err)
	}
	if _, err := ProberReporting(context.Background(), q, "acme", false, "1y"); err == nil {
		t.Fatal("an arbitrary lookback reached a range selector")
	}
}
