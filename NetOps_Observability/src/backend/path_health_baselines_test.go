package main

// path_health_baselines_test.go — PBH V1 precompute: hour-of-week bucketing,
// exact quantiles, readiness gates, insert shape, and the tier-2 reader's
// degenerate-row guard.

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHourOfWeek(t *testing.T) {
	cases := []struct {
		ts   time.Time
		want int
	}{
		{time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC), 0},     // Monday 00:00
		{time.Date(2026, 7, 20, 12, 30, 0, 0, time.UTC), 12},  // Monday 12:xx
		{time.Date(2026, 7, 26, 23, 59, 0, 0, time.UTC), 167}, // Sunday 23:xx
	}
	for _, c := range cases {
		if got := hourOfWeek(c.ts); got != c.want {
			t.Errorf("hourOfWeek(%s) = %d, want %d", c.ts, got, c.want)
		}
	}
}

func TestQuantileAt(t *testing.T) {
	if q := quantileAt(nil, 0.5); q != 0 {
		t.Errorf("empty slice → 0, got %v", q)
	}
	sorted := []float64{10, 20, 30, 40, 50}
	if q := quantileAt(sorted, 0.5); q != 30 {
		t.Errorf("p50 = %v, want 30", q)
	}
	if q := quantileAt(sorted, 1.0); q != 50 {
		t.Errorf("p100 = %v, want 50", q)
	}
	if q := quantileAt(sorted, 0.99); q < 49 || q > 50 {
		t.Errorf("p99 = %v, want ≈49.6", q)
	}
}

// mondayNoonSeries builds n points inside the Monday-12h bucket across weeks.
func mondayNoonSeries(dst string, n int, val float64) vmRangeSeries {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) // a Monday
	pts := make([][2]float64, 0, n)
	for i := 0; i < n; i++ {
		week := i / 12
		ts := base.AddDate(0, 0, 7*week).Add(time.Duration(i%12) * 5 * time.Minute)
		pts = append(pts, [2]float64{float64(ts.Unix()), val})
	}
	return vmRangeSeries{Dst: dst, Points: pts}
}

func TestComputePathBaselinesReadinessAndDecoration(t *testing.T) {
	latency := []vmRangeSeries{
		mondayNoonSeries("edge.example:443", 48, 35), // enough → row
		mondayNoonSeries("sparse.example", 10, 99),   // < 24 samples → no row
	}
	jitter := []vmRangeSeries{mondayNoonSeries("edge.example:443", 48, 4)}
	loss := []vmRangeSeries{mondayNoonSeries("edge.example:443", 5, 0.2)}
	rows := computePathBaselines(latency, jitter, loss, 28)
	if len(rows) != 1 {
		t.Fatalf("want exactly 1 row (readiness gate), got %d", len(rows))
	}
	r := rows[0]
	if r.PathID != "edge.example" { // hostOnly key, matching the live endpoint
		t.Errorf("path key = %q, want host-only", r.PathID)
	}
	if r.HourOfWeek != 12 {
		t.Errorf("bucket = %d, want 12 (Monday noon)", r.HourOfWeek)
	}
	if r.Latency[0] != 35 || r.Jitter[0] != 4 || r.Loss[1] != 0.2 {
		t.Errorf("percentiles wrong: lat %v jit %v loss %v", r.Latency, r.Jitter, r.Loss)
	}
	if r.SampleCount != 48 || r.SamplesTotal != 48 || r.WindowDays != 28 {
		t.Errorf("counts wrong: %+v", r)
	}
}

func TestInsertPathBaselinesShape(t *testing.T) {
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	rows := computePathBaselines([]vmRangeSeries{mondayNoonSeries("edge.example", 48, 35)}, nil, nil, 28)
	if err := insertPathBaselines(t.Context(), rows); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if !strings.Contains(body, "INSERT INTO netops.path_baselines FORMAT JSONEachRow") {
		t.Errorf("unexpected insert body:\n%s", body)
	}
	if !strings.Contains(body, `"tenant_id":""`) {
		t.Error("precompute rows must be untagged (operator telemetry)")
	}
	if !strings.Contains(body, `"route_fingerprint":""`) {
		t.Error("tier-1 fingerprint must stay '' (honest subset)")
	}
}

// The tier-2 reader drops degenerate buckets (p99 ≤ p50) instead of letting the
// scorer divide by a baseline it cannot trust, and keys rows by path_id.
func TestFetchHourBaselinesGuardsDegenerate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[
		  {"path_id":"good.example","latency_p50":30,"latency_p99":90,"jitter_p50":3,"jitter_p99":20,"sample_count":48,"samples_total":8000,"window_days":28},
		  {"path_id":"flat.example","latency_p50":30,"latency_p99":30,"jitter_p50":0,"jitter_p99":0,"sample_count":48,"samples_total":8000,"window_days":28}
		]}`))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	s := &server{}
	got := s.fetchHourBaselines(req("GET", "/api/paths/health", "", superA()), time.Now().UTC())
	if len(got) != 1 {
		t.Fatalf("want only the non-degenerate row, got %d", len(got))
	}
	hb, ok := got["good.example"]
	if !ok {
		t.Fatal("good.example baseline missing")
	}
	if hb.Source != baselinePathHour {
		t.Errorf("source = %s, want %s (tier 2)", hb.Source, baselinePathHour)
	}
	if !baselineReady(hb) {
		t.Error("a 28-day hour baseline must pass the readiness gate")
	}
	// The cascade must prefer this tier over the per-path tier 3.
	base, ok := SelectBaseline([]BaselineCandidate{
		{Baseline: hb, Available: true},
		{Baseline: PathBaseline{Source: baselinePath, SampleCount: 9999, Days: 30, Latency: metricBaseline{P50: 10, P99: 20}}, Available: true},
	})
	if !ok || base.Source != baselinePathHour {
		t.Errorf("cascade picked %s, want path_hour first", base.Source)
	}
}

// CH unreachable → nil map → the cascade silently falls back to tiers 3–5.
func TestFetchHourBaselinesBestEffort(t *testing.T) {
	t.Setenv("CLICKHOUSE_URL", "http://127.0.0.1:9")
	s := &server{}
	if got := s.fetchHourBaselines(req("GET", "/x", "", superA()), time.Now()); got != nil {
		t.Fatalf("unreachable CH must yield nil, got %v", got)
	}
}
