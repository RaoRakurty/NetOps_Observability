// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"netops/backend/internal/discovery"
	"netops/backend/internal/saved"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/models"
	"netops/backend/notify"
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
	rs := &reportScheduler{
		discovery: agg,
		alerts:    alerts.NewEngine("", nil),
		runs:      map[string]reportRun{},
	}
	rs.ds = rs.dataSource()
	return rs
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

// ---- H7 / M15: HTTP + delivery isolation for the FILE backend --------------
//
// H7: /api/reports/runs on the file backend returned the WHOLE run-state map —
// no requirePerm, no tenant filter — leaking every tenant's report names,
// summaries and channel names through run.Detail. The handler must gate and
// filter exactly like the PG branch.
//
// M15: notify channels are platform-global resources. The file backend's
// deliver() used DispatchTo's nil fallback (empty list => broadcast to ALL
// channels), and /api/reports/run accepted arbitrary channel names from any
// reports:write principal. Empty must mean "contact points only", and only the
// cross-tenant platform owner may bind named channels.

// recordingChannel is a notify.Channel that counts what it was asked to send.
type recordingChannel struct {
	name string
	mu   sync.Mutex
	sent []models.Alert
}

func (c *recordingChannel) Name() string { return c.name }
func (c *recordingChannel) Send(a models.Alert) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sent = append(c.sent, a)
	return nil
}
func (c *recordingChannel) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sent)
}

// createReport creates a saved report through the real handler (so TenantID is
// stamped from the principal, as production does) and returns its id.
func createReport(t *testing.T, s *server, claims jwtClaims, name, body string) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleSaved(w, req("POST", "/api/saved", `{"type":"report","name":"`+name+`","body":`+body+`}`, claims))
	if w.Code != http.StatusCreated {
		t.Fatalf("create report %q: %d %s", name, w.Code, w.Body.String())
	}
	var obj saved.Object
	if err := json.NewDecoder(w.Body).Decode(&obj); err != nil {
		t.Fatalf("decode created report: %v", err)
	}
	return obj.ID
}

func TestHTTPReportRunsFileBackendTenantScoped(t *testing.T) {
	s := tenantServer(t)
	acmeID := createReport(t, s, acme(), "acme wan", `{"kind":"alerts_summary"}`)
	globexID := createReport(t, s, globex(), "globex wan", `{"kind":"alerts_summary"}`)
	s.reports = &reportScheduler{
		saved: s.saved,
		path:  t.TempDir() + "/runs.json",
		runs: map[string]reportRun{
			acmeID:   {Status: "ok", Detail: "Report: acme wan — sent to 1 channel(s)"},
			globexID: {Status: "ok", Detail: "Report: globex wan — sent to 1 channel(s)"},
		},
	}

	// Unauthenticated → 401 (the file branch previously had NO gate at all).
	w := httptest.NewRecorder()
	s.handleReportRuns(w, httptest.NewRequest("GET", "/api/reports/runs", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /api/reports/runs should be 401, got %d", w.Code)
	}

	// A read-only acme principal gets acme's run — and never globex's.
	w = httptest.NewRecorder()
	s.handleReportRuns(w, req("GET", "/api/reports/runs", "", jwtClaims{Sub: "ro@acme", Role: RoleReadOnly, Tenant: "acme"}))
	if w.Code != http.StatusOK {
		t.Fatalf("acme read-only /api/reports/runs: %d", w.Code)
	}
	var runs map[string]reportRun
	if err := json.NewDecoder(w.Body).Decode(&runs); err != nil {
		t.Fatalf("decode runs: %v", err)
	}
	if _, ok := runs[acmeID]; !ok {
		t.Error("acme should see its own report's run state")
	}
	if _, ok := runs[globexID]; ok {
		t.Fatal("TENANT LEAK: acme received globex's report run state from the file backend")
	}

	// The platform owner sees every tenant's runs.
	w = httptest.NewRecorder()
	s.handleReportRuns(w, req("GET", "/api/reports/runs", "", superA()))
	runs = nil
	if err := json.NewDecoder(w.Body).Decode(&runs); err != nil {
		t.Fatalf("decode platform runs: %v", err)
	}
	if len(runs) != 2 {
		t.Errorf("platform owner should see both runs, got %d", len(runs))
	}
}

func TestHTTPReportRunNowNamedChannelsArePlatformOnly(t *testing.T) {
	s := tenantServer(t)
	s.alerts = alerts.NewEngine("", nil)
	ch := &recordingChannel{name: "ops-slack"}
	d := notify.NewDispatcher()
	d.Register(ch)
	s.notifier = d
	rs := &reportScheduler{
		srv: s, saved: s.saved, notifier: d, discovery: s.discovery,
		alerts: s.alerts, runs: map[string]reportRun{}, path: t.TempDir() + "/runs.json",
	}
	rs.ds = rs.dataSource()
	s.reports = rs

	acmeAdmin := jwtClaims{Sub: "admin@acme", Role: RoleSuperAdmin, Tenant: "acme"}
	id := createReport(t, s, acmeAdmin, "acme rpt", `{"kind":"alerts_summary"}`)

	// A tenant principal naming a platform-global channel is refused outright.
	w := httptest.NewRecorder()
	s.handleReportRunNow(w, req("POST", "/api/reports/run", `{"id":"`+id+`","channels":["ops-slack"]}`, acmeAdmin))
	if w.Code != http.StatusForbidden {
		t.Errorf("tenant run-now naming a global channel should be 403, got %d", w.Code)
	}

	// The same run WITHOUT channels succeeds — and dispatches to NO global
	// channel (empty list means contact points only, never a broadcast).
	w = httptest.NewRecorder()
	s.handleReportRunNow(w, req("POST", "/api/reports/run", `{"id":"`+id+`"}`, acmeAdmin))
	if w.Code != http.StatusOK {
		t.Fatalf("tenant run-now without channels: %d %s", w.Code, w.Body.String())
	}
	var run reportRun
	if err := json.NewDecoder(w.Body).Decode(&run); err != nil {
		t.Fatalf("decode run: %v", err)
	}
	if !strings.Contains(run.Detail, "sent to 0 channel(s)") {
		t.Errorf("tenant report must not reach any global channel, detail: %q", run.Detail)
	}
	if got := ch.count(); got != 0 {
		t.Fatalf("CHANNEL LEAK: tenant report reached the platform channel %d time(s)", got)
	}

	// The platform owner running a PLATFORM-owned report may bind the channel.
	pid := createReport(t, s, superA(), "fleet rpt", `{"kind":"alerts_summary"}`)
	w = httptest.NewRecorder()
	s.handleReportRunNow(w, req("POST", "/api/reports/run", `{"id":"`+pid+`","channels":["ops-slack"]}`, superA()))
	if w.Code != http.StatusOK {
		t.Fatalf("platform run-now: %d %s", w.Code, w.Body.String())
	}
	run = reportRun{}
	if err := json.NewDecoder(w.Body).Decode(&run); err != nil {
		t.Fatalf("decode platform run: %v", err)
	}
	if !strings.Contains(run.Detail, "sent to 1 channel(s)") {
		t.Errorf("platform report should reach the named channel, detail: %q", run.Detail)
	}
}

// deliver-level guard: the scheduled path (tick → deliver) obeys the same
// semantics with no handler in front of it — a tenant-owned report's stored
// body cannot broadcast or bind platform channels.
func TestReportDeliverDoesNotBroadcastOrBindForeignChannels(t *testing.T) {
	rs := isoReportScheduler(t)
	ch := &recordingChannel{name: "ops-slack"}
	d := notify.NewDispatcher()
	d.Register(ch)
	rs.notifier = d
	rs.path = t.TempDir() + "/runs.json"
	now := time.Now().UTC()

	// Tenant report, empty channels: previously DispatchTo(nil) broadcast to
	// EVERY configured channel; now it must reach none.
	rs.deliver(saved.Object{ID: "r-a", Name: "t-a summary", Type: "report", TenantID: "t-a"},
		reportSpec{Kind: "alerts_summary"}, now)
	if det := rs.Run("r-a").Detail; !strings.Contains(det, "sent to 0 channel(s)") {
		t.Errorf("empty channels must not broadcast, detail: %q", det)
	}

	// Tenant report NAMING the platform channel: skipped, default-closed.
	rs.deliver(saved.Object{ID: "r-b", Name: "t-a summary", Type: "report", TenantID: "t-a"},
		reportSpec{Kind: "alerts_summary", Channels: []string{"ops-slack"}}, now)
	det := rs.Run("r-b").Detail
	if !strings.Contains(det, "sent to 0 channel(s)") || !strings.Contains(det, "named channels skipped") {
		t.Errorf("tenant report must not bind a platform channel, detail: %q", det)
	}
	if got := ch.count(); got != 0 {
		t.Fatalf("CHANNEL LEAK: tenant deliveries reached the platform channel %d time(s)", got)
	}

	// Platform-owned report naming the channel: still delivered (the operator's
	// own reports keep working).
	rs.deliver(saved.Object{ID: "r-p", Name: "fleet summary", Type: "report"},
		reportSpec{Kind: "alerts_summary", Channels: []string{"ops-slack"}}, now)
	if det := rs.Run("r-p").Detail; !strings.Contains(det, "sent to 1 channel(s)") {
		t.Errorf("platform report should reach its named channel, detail: %q", det)
	}
	deadline := time.Now().Add(5 * time.Second)
	for ch.count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := ch.count(); got != 1 {
		t.Errorf("platform report should have been sent exactly once, got %d", got)
	}
}

// TestReportChannelsRefusesTenantPrincipal pins the §3a.3/M15 gate on
// GET /api/reports/channels: notify channels are PLATFORM-GLOBAL resources, so a
// tenant admin must not enumerate the operator's channel names. Only the
// platform owner may — matching notify_config.go and RunNow's channel-binding
// cross gate. (Was under-gated at reports:read.)
func TestReportChannelsRefusesTenantPrincipal(t *testing.T) {
	s := tenantServer(t)
	s.notifier = notify.NewDispatcher()

	// Unauthenticated → 401.
	w := httptest.NewRecorder()
	s.handleReportChannels(w, httptest.NewRequest("GET", "/api/reports/channels", nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unauthenticated /api/reports/channels should be 401, got %d", w.Code)
	}

	// A tenant admin (super-admin scoped to its OWN tenant, non-owner) → 403:
	// it must not enumerate platform-global channel names.
	w = httptest.NewRecorder()
	s.handleReportChannels(w, req("GET", "/api/reports/channels", "", tAdmin("t-a")))
	if w.Code != http.StatusForbidden {
		t.Errorf("tenant admin GET /api/reports/channels should be 403 (platform-only), got %d", w.Code)
	}

	// The platform owner still lists channels — the operator's own UI keeps working.
	w = httptest.NewRecorder()
	s.handleReportChannels(w, req("GET", "/api/reports/channels", "", platformOwner()))
	if w.Code != http.StatusOK {
		t.Errorf("platform owner should list channels, got %d", w.Code)
	}
}
