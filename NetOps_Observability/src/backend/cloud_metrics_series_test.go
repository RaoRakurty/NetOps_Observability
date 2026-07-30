package backend

// cloud_metrics_series_test.go — unit tests for the Wave 5 #14 slice 1 chart
// feed: window/step bounding, closed metric vocabulary, resource-id hygiene,
// and the handler contract against a fake VictoriaMetrics (bounded parse,
// honest empty series, unreachable-store = explicit error).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"netops/backend/cloud"
)

func TestClampCloudSeriesWindow(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, cloud.SeriesDefaultWindow},
		{-10, cloud.SeriesDefaultWindow},
		{1, cloud.SeriesMinWindowMin},
		{5, 5},
		{180, 180},
		{10080, 10080},
		{99999, cloud.SeriesMaxWindowMin},
	}
	for _, c := range cases {
		if got := cloud.ClampSeriesWindow(c.in); got != c.want {
			t.Errorf("cloud.ClampSeriesWindow(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestCloudSeriesStepSecondsHoldsPointCap(t *testing.T) {
	for _, windowMin := range []int{5, 60, 180, 1440, 10080} {
		step := cloud.SeriesStepSeconds(windowMin)
		if step < 60 {
			t.Errorf("window %dm: step %ds below 60s floor", windowMin, step)
		}
		if step%60 != 0 {
			t.Errorf("window %dm: step %ds not whole minutes", windowMin, step)
		}
		points := windowMin * 60 / step
		if points > cloud.SeriesMaxPoints {
			t.Errorf("window %dm: %d points exceeds cap %d", windowMin, points, cloud.SeriesMaxPoints)
		}
	}
}

func TestCloudMetricInfoClosedVocabulary(t *testing.T) {
	if _, ok := cloud.MetricInfo("cloud_cpu_util"); !ok {
		t.Fatal("cloud_cpu_util must be in the catalog")
	}
	for _, bad := range []string{"", "up", "node_cpu_seconds_total", `cloud_cpu_util{x="y"}`, "cloud_cpu_util or on() vector(1)"} {
		if _, ok := cloud.MetricInfo(bad); ok {
			t.Errorf("metric %q must be refused", bad)
		}
	}
}

func TestValidCloudResourceID(t *testing.T) {
	ok := []string{"i-0abc123", "/subscriptions/1111/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm-1", "projects/p/zones/z/instances/i"}
	for _, id := range ok {
		if !cloud.ValidResourceID(id) {
			t.Errorf("id %q must be accepted", id)
		}
	}
	bad := []string{"", `i-"quote`, "i-back\\slash", "i-ctrl\x01", string(make([]byte, cloud.SeriesMaxResourceIDLen+1))}
	for _, id := range bad {
		if cloud.ValidResourceID(id) {
			t.Errorf("id %q must be refused", id)
		}
	}
}

// fakeVM serves a canned query_range response and records the queries it saw.
func fakeVM(t *testing.T, result string) (*httptest.Server, *[]string) {
	t.Helper()
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("query"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":%s}}`, result)
	}))
	t.Cleanup(srv.Close)
	return srv, &queries
}

func TestVMQueryRangeByParsesAndCaps(t *testing.T) {
	srv, _ := fakeVM(t, `[
		{"metric":{"resource_id":"i-a"},"values":[[1000,"1.5"],[1300,"2.5"],[1600,"not-a-number"]]},
		{"metric":{"other_label":"x"},"values":[[1000,"9"]]}
	]`)
	t.Setenv("VM_QUERY_URL", srv.URL)
	got, err := vmQueryRangeBy(context.Background(), `cloud_cpu_util{resource_id=~"i-a"}`, 900, 1700, 60, "resource_id")
	if err != nil {
		t.Fatal(err)
	}
	pts, ok := got["i-a"]
	if !ok || len(pts) != 2 {
		t.Fatalf("want 2 parsed points for i-a, got %v", got)
	}
	if pts[0] != (cloudSeriesPoint{1000, 1.5}) || pts[1] != (cloudSeriesPoint{1300, 2.5}) {
		t.Fatalf("wrong points: %v", pts)
	}
	if len(got) != 1 {
		t.Fatalf("series without the key label must be dropped, got %v", got)
	}
}

func TestVMQueryRangeByUnreachable(t *testing.T) {
	t.Setenv("VM_QUERY_URL", "http://127.0.0.1:1") // nothing listens here
	if _, err := vmQueryRangeBy(context.Background(), "cloud_cpu_util", 0, 1, 60, "resource_id"); err == nil {
		t.Fatal("unreachable store must be an error, not an empty result")
	}
}

func TestCloudMetricSeriesHandlerContract(t *testing.T) {
	srv, s := newTestServerState(t)
	s.cloud = newCloudStore()
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	st0, b0 := do(t, srv, "POST", "/api/onboard", admin, map[string]any{
		"org_name": "Chart Corp", "tenant_name": "Chart Prod", "tenant_slug": "chart-prod",
	})
	if st0 != 201 {
		t.Fatalf("onboard: %d %s", st0, b0)
	}
	var acme onboardResponse
	if err := json.Unmarshal(b0, &acme); err != nil {
		t.Fatal(err)
	}
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "chartop", "password": "Passw0rd!2345", "role": "operator", "tenant_id": acme.Tenant.ID,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	tok := login(t, srv, "chartop", "Passw0rd!2345").Token
	seedCloudResource(t, s, acme.Tenant.ID, "i-acme1", "acme-web-1")

	vm, queries := fakeVM(t, `[{"metric":{"resource_id":"i-acme1"},"values":[[1000,"42"]]}]`)
	t.Setenv("VM_QUERY_URL", vm.URL)

	// Bad metric → 400 (closed vocabulary).
	if st, _ := do(t, srv, "GET", "/api/cloud/metrics/series?metric=up&resource=i-acme1", tok, nil); st != 400 {
		t.Fatalf("unknown metric: want 400, got %d", st)
	}
	// Missing resource → 400.
	if st, _ := do(t, srv, "GET", "/api/cloud/metrics/series?metric=cloud_cpu_util", tok, nil); st != 400 {
		t.Fatalf("missing resource: want 400, got %d", st)
	}
	// Too many resources → 400.
	tooMany := "/api/cloud/metrics/series?metric=cloud_cpu_util"
	for i := 0; i <= cloudSeriesMaxResources; i++ {
		tooMany += fmt.Sprintf("&resource=i-acme%d", i)
	}
	if st, _ := do(t, srv, "GET", tooMany, tok, nil); st != 400 {
		t.Fatalf("resource cap: want 400, got %d", st)
	}
	// Unauthenticated → 401.
	if st, _ := do(t, srv, "GET", "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-acme1", "", nil); st != 401 {
		t.Fatal("unauthenticated must be refused")
	}

	// Happy path: own resource, data present.
	st, b := do(t, srv, "GET", "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-acme1&window_minutes=60", tok, nil)
	if st != 200 {
		t.Fatalf("own resource: want 200, got %d %s", st, b)
	}
	var resp struct {
		Metric        string `json:"metric"`
		Unit          string `json:"unit"`
		WindowMinutes int    `json:"window_minutes"`
		StepSeconds   int    `json:"step_seconds"`
		Series        []struct {
			ResourceID string             `json:"resource_id"`
			Points     []cloudSeriesPoint `json:"points"`
		} `json:"series"`
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Metric != "cloud_cpu_util" || resp.Unit != "percent" || resp.WindowMinutes != 60 {
		t.Fatalf("wrong envelope: %+v", resp)
	}
	if len(resp.Series) != 1 || resp.Series[0].ResourceID != "i-acme1" || len(resp.Series[0].Points) != 1 {
		t.Fatalf("wrong series: %+v", resp.Series)
	}
	if len(*queries) == 0 {
		t.Fatal("no query reached the metric store")
	}

	// Honest empty: VM knows nothing about this resource → empty points, 200.
	vm2, _ := fakeVM(t, `[]`)
	t.Setenv("VM_QUERY_URL", vm2.URL)
	st, b = do(t, srv, "GET", "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-acme1", tok, nil)
	if st != 200 {
		t.Fatalf("no-data: want 200, got %d", st)
	}
	if err := json.Unmarshal(b, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Series) != 1 || len(resp.Series[0].Points) != 0 {
		t.Fatalf("no-data must be an explicit empty series: %+v", resp.Series)
	}

	// Unreachable store → 502, never a fabricated empty chart.
	t.Setenv("VM_QUERY_URL", "http://127.0.0.1:1")
	if st, _ := do(t, srv, "GET", "/api/cloud/metrics/series?metric=cloud_cpu_util&resource=i-acme1", tok, nil); st != 502 {
		t.Fatalf("unreachable store: want 502, got %d", st)
	}
}
