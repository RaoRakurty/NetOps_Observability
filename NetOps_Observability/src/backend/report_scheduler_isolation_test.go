package main

// report_scheduler_isolation_test.go — §3a.5 isolation tests for the scheduled-
// report renderers. Reports are rendered server-side under the report's OWN
// tenant and delivered to that tenant's channels, so every telemetry-backed
// renderer must narrow its ClickHouse / VictoriaMetrics reads to the tenant's
// devices: a tenant-owned WAN/latency/security/utilization report must never
// describe another tenant's links, findings, or devices (the tunnels/findings
// row policies are hybrid — untagged rows are shared — so the app-layer clause
// is the isolation boundary, same contract as /api/tunnels and /api/flows).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/discovery"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/models"
)

// queryRecorder captures every SQL/PromQL request body or URL an isolated
// renderer issues, so tests can assert on the narrowing clause (or its absence).
type queryRecorder struct {
	mu      sync.Mutex
	queries []string
}

func (q *queryRecorder) add(s string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.queries = append(q.queries, s)
}

func (q *queryRecorder) all() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.queries...)
}

// isoReportScheduler builds a scheduler over a two-tenant inventory: tenant t-a
// owns leaf-a, tenant t-b owns leaf-b.
func isoReportScheduler(t *testing.T) *reportScheduler {
	t.Helper()
	agg := discovery.NewDiscoveryAggregator()
	agg.PollOnceForTest(context.Background(), &fakeSource{name: "static", devices: []models.Device{
		{ID: "dev-a", Name: "leaf-a", Address: "10.0.0.1", TenantID: "t-a"},
		{ID: "dev-b", Name: "leaf-b", Address: "10.0.0.2", TenantID: "t-b"},
	}})
	return &reportScheduler{
		discovery: agg,
		alerts:    alerts.NewEngine("", nil),
		runs:      map[string]reportRun{},
	}
}

// fakeClickHouse points chQuery at a recorder that returns an empty result set.
func fakeClickHouse(t *testing.T, rec *queryRecorder) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.add(string(body))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
}

func TestReportDeviceKeysScoping(t *testing.T) {
	rs := isoReportScheduler(t)

	// Global / unassigned reports stay platform-wide (pre-existing contract).
	for _, tenant := range []string{"", TenantGlobal} {
		if keys, platform := rs.reportDeviceKeys(tenant); !platform || keys != nil {
			t.Errorf("reportDeviceKeys(%q) = (%v, %v), want platform-wide", tenant, keys, platform)
		}
	}

	// A scoped tenant gets its own device keys only.
	keys, platform := rs.reportDeviceKeys("t-a")
	if platform {
		t.Fatal("tenant-owned report must not be platform-wide")
	}
	joined := strings.Join(keys, ",")
	if !strings.Contains(joined, "leaf-a") || !strings.Contains(joined, "dev-a") {
		t.Errorf("keys must carry the tenant's device name+id, got %v", keys)
	}
	if strings.Contains(joined, "leaf-b") || strings.Contains(joined, "dev-b") {
		t.Errorf("CROSS-TENANT LEAK: t-a report keys include t-b's device: %v", keys)
	}

	// Default-closed: a tenant with no devices gets an empty set, not platform.
	if keys, platform := rs.reportDeviceKeys("t-none"); platform || len(keys) != 0 {
		t.Errorf("deviceless tenant must be (empty, scoped), got (%v, %v)", keys, platform)
	}
}

// Every tunnels-backed renderer must send a device-bounded query for a
// tenant-owned report, and no clause for a platform report.
func TestTunnelReportQueriesAreDeviceScoped(t *testing.T) {
	rs := isoReportScheduler(t)
	rec := &queryRecorder{}
	fakeClickHouse(t, rec)

	rs.ds.DatasetWAN("t-a")
	rs.ds.DatasetLatency("t-a")
	rs.ds.RenderWANUtilization("t-a")
	rs.ds.RenderLatencyJitterSLA("t-a")
	scoped := rec.all()
	if len(scoped) != 4 {
		t.Fatalf("expected 4 tunnels queries, got %d", len(scoped))
	}
	for _, q := range scoped {
		if !strings.Contains(q, "local_device IN (") || !strings.Contains(q, "'leaf-a'") {
			t.Errorf("tenant-owned tunnels query missing device narrowing:\n%s", q)
		}
		if strings.Contains(q, "leaf-b") || strings.Contains(q, "dev-b") {
			t.Errorf("CROSS-TENANT LEAK: t-a tunnels query names t-b's device:\n%s", q)
		}
	}

	rec2 := &queryRecorder{}
	fakeClickHouse(t, rec2)
	rs.ds.DatasetWAN("")
	for _, q := range rec2.all() {
		if strings.Contains(q, "local_device IN (") {
			t.Errorf("platform report must stay unscoped, got:\n%s", q)
		}
	}
}

// Findings-backed security renderers must narrow on the device column and must
// not count other tenants' findings or alerts.
func TestSecurityReportQueriesAreDeviceScoped(t *testing.T) {
	rs := isoReportScheduler(t)
	rec := &queryRecorder{}
	fakeClickHouse(t, rec)

	rs.ds.DatasetSecurity("t-a")
	rs.ds.RenderSecurityThreats("t-a")
	qs := rec.all()
	if len(qs) < 4 {
		t.Fatalf("expected ≥4 findings queries, got %d", len(qs))
	}
	for _, q := range qs {
		if !strings.Contains(q, "device IN (") || !strings.Contains(q, "'leaf-a'") {
			t.Errorf("tenant-owned findings query missing device narrowing:\n%s", q)
		}
		if strings.Contains(q, "leaf-b") {
			t.Errorf("CROSS-TENANT LEAK: t-a findings query names t-b's device:\n%s", q)
		}
	}
}

// A scoped tenant with no visible devices must short-circuit to the "no data"
// note WITHOUT touching ClickHouse (default-closed — never fall back to the
// platform-wide view).
func TestDevicelessTenantReportsShortCircuit(t *testing.T) {
	rs := isoReportScheduler(t)
	rec := &queryRecorder{}
	fakeClickHouse(t, rec)

	if _, body := rs.ds.RenderWANUtilization("t-none"); !strings.Contains(body, "No tunnel/overlay telemetry") {
		t.Errorf("deviceless tenant WAN report should carry the no-data note, got %q", body)
	}
	rs.ds.DatasetWAN("t-none")
	rs.ds.DatasetLatency("t-none")
	rs.ds.RenderLatencyJitterSLA("t-none")
	rs.ds.DatasetSecurity("t-none")
	rs.ds.RenderSecurityThreats("t-none")
	if got := rec.all(); len(got) != 0 {
		t.Fatalf("deviceless tenant must issue NO telemetry queries, got %d:\n%s", len(got), strings.Join(got, "\n---\n"))
	}
}

// Device-utilization renderers rank over the tenant's devices only; the top-N
// is computed after filtering so a busy foreign device can't crowd out (or leak
// into) a tenant's report.
func TestDeviceUtilizationFilteredToTenant(t *testing.T) {
	rs := isoReportScheduler(t)
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"result":[
			{"metric":{"device":"leaf-a"},"value":[0,"41"]},
			{"metric":{"device":"leaf-b"},"value":[0,"93"]}
		]}}`))
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)

	_, body := rs.ds.RenderDeviceUtilization("t-a")
	if !strings.Contains(body, "leaf-a") {
		t.Errorf("tenant's own device missing from utilization report:\n%s", body)
	}
	if strings.Contains(body, "leaf-b") {
		t.Errorf("CROSS-TENANT LEAK: t-a utilization report lists t-b's device:\n%s", body)
	}

	_, sections := rs.ds.DatasetDeviceUtil("t-a")
	for _, sec := range sections {
		for _, row := range sec.Rows {
			for _, cell := range row {
				if strings.Contains(cell, "leaf-b") {
					t.Errorf("CROSS-TENANT LEAK: dataset lists t-b's device: %v", row)
				}
			}
		}
	}

	// Platform report keeps the full fleet.
	if _, body := rs.ds.RenderDeviceUtilization(""); !strings.Contains(body, "leaf-b") {
		t.Errorf("platform utilization report should list all devices:\n%s", body)
	}
}

// fakeSource duplicates the package-test fixture (test files cannot be
// imported across packages).
type fakeSource struct {
	name    string
	devices []models.Device
	err     error
}

func (f *fakeSource) Name() string                                  { return f.name }
func (f *fakeSource) Interval() time.Duration                       { return time.Minute }
func (f *fakeSource) Poll(context.Context) ([]models.Device, error) { return f.devices, f.err }
