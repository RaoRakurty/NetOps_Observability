// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_seasonal_rollup_isolation_test.go — CLAUDE.md §3a rule 5 for the
// seasonal roll-up (tracker 337 N-H6 PR 2).
//
// Proven:
//   - the read side (nlqScope.SeasonalHours) runs at the CALLER's ClickHouse
//     tenant scope, so the STRICT row policy returns only the caller's rows; a
//     malformed metric name reads nothing; every value reaches the SQL as a
//     literal (a quote in a key cannot break out);
//   - the write side stamps every row with its device's inventory owner: the
//     same device name in two tenants is AMBIGUOUS and owned by nobody (the
//     series is skipped, never guessed into either tenant), and no row is ever
//     written untagged;
//   - the worker's counters are on /metrics.

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/seriesroll"
	"netops/backend/models"
)

func TestSeasonalHoursReadAtTheCallersScope(t *testing.T) {
	var sqls, scopes []string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sqls, scopes = append(sqls, string(b)+r.URL.Query().Get("query")), append(scopes, r.URL.Query().Get("tenant_scope"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"meta":[],"data":[{"entity_key":"dev-a","h":1794549600,"p50":41.5}],"rows":1}`))
	}))
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	s, a, b := nlqFixture(t)
	hour := time.Unix(1794549600, 0)

	got, err := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", a), a).SeasonalHours(context.Background(), "cpu_util_pct", []string{"dev-a", "x'y"}, []time.Time{hour})
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 1 || scopes[0] != "t-a" {
		t.Fatalf("TENANT LEAK: the roll-up read ran at tenant_scope %v, want exactly [t-a]", scopes)
	}
	if got["dev-a"][1794549600] != 41.5 {
		t.Fatalf("parsed = %v", got)
	}
	q := sqls[0]
	for _, want := range []string{"FROM netops.series_hourly FINAL", "metric = 'cpu_util_pct'", "toDateTime(1794549600)", `'x\'y'`} {
		if !strings.Contains(q, want) {
			t.Fatalf("roll-up SQL missing %q:\n%s", want, q)
		}
	}
	// Another tenant reads at ITS scope, never t-a's.
	if _, err := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask?as_tenant=t-a", "", b), b).SeasonalHours(context.Background(), "cpu_util_pct", []string{"dev-a"}, []time.Time{hour}); err != nil {
		t.Fatal(err)
	}
	if scopes[len(scopes)-1] != "t-b" {
		t.Fatalf("as_tenant widened the roll-up read: tenant_scope %q", scopes[len(scopes)-1])
	}
	// A malformed metric name is not read at all.
	n := len(sqls)
	if out, err := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", a), a).SeasonalHours(context.Background(), "cpu'; DROP TABLE x --", []string{"dev-a"}, []time.Time{hour}); err != nil || out != nil || len(sqls) != n {
		t.Fatalf("malformed metric: out=%v err=%v reads=%d", out, err, len(sqls)-n)
	}
}

func TestSeasonalRollOwnerIndexRefusesAmbiguousNames(t *testing.T) {
	idx := seasonalRollOwnerIndex([]models.Device{
		{ID: "dev-a", Name: "edge-1", TenantID: "T-A"},
		{ID: "dev-b", Name: "edge-1", TenantID: "t-b"}, // the same name in another tenant
		{ID: "dev-c", Name: "core-1", TenantID: "t-a"},
		{ID: "dev-u", Name: "orphan"}, // no owner
	})
	if idx["dev-a"] != "t-a" || idx["dev-b"] != "t-b" || idx["core-1"] != "t-a" {
		t.Fatalf("ids and unique names map to their owner: %v", idx)
	}
	if idx["edge-1"] != "" {
		t.Fatalf("a name two tenants share must be ambiguous (no owner), got %q", idx["edge-1"])
	}
	o := &seasonalRollOwners{owner: idx, at: time.Now()}
	for _, d := range []string{"edge-1", "dev-u", "orphan", "missing"} {
		if t2, ok := o.Owner(d); ok {
			t.Errorf("%s: owned by %q — an ambiguous or unowned device must be skipped", d, t2)
		}
	}
	if t2, ok := o.Owner("dev-b"); !ok || t2 != "t-b" {
		t.Fatalf("dev-b owner = %q %v", t2, ok)
	}
}

func TestSeasonalRollStoreWritesOwnedRows(t *testing.T) {
	var body string
	ch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body += string(b) + r.URL.Query().Get("query")
		w.WriteHeader(http.StatusOK)
	}))
	defer ch.Close()
	t.Setenv("CLICKHOUSE_URL", ch.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	err := seasonalRollStore{}.Insert(context.Background(), []seriesroll.Row{{
		Tenant: "t-a", Metric: "cpu_util_pct", EntityKey: "dev-a", Hour: time.Unix(1794549600, 0), P10: 1, P50: 2, P90: 3, N: 60, Version: 7,
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"INSERT INTO netops.series_hourly FORMAT JSONEachRow", `"tenant_id":"t-a"`, `"hour":1794549600`, `"version":7`} {
		if !strings.Contains(body, want) {
			t.Fatalf("insert body missing %q:\n%s", want, body)
		}
	}
}

func TestSeasonalRollupCountersOnMetrics(t *testing.T) {
	_, s := newTestServerState(t)
	var buf bytes.Buffer
	s.writeSeasonalRollupMetrics(&buf)
	if buf.Len() != 0 {
		t.Fatalf("no roller → no lines, got %q", buf.String())
	}
	r, err := seriesroll.New(seriesroll.Config{Metrics: seasonalRollMetrics()}, seasonalRollVM{s}, seasonalRollStore{}, newSeasonalRollOwners(s))
	if err != nil {
		t.Fatal(err)
	}
	r.Stats.Unowned.Add(3)
	s.seasonalRoll.Store(r)
	s.writeSeasonalRollupMetrics(&buf)
	for _, want := range []string{"netops_seasonal_rollup_unowned_total 3", "netops_seasonal_rollup_store_errors_total 0", "# TYPE netops_seasonal_rollup_rows_total counter"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("metrics missing %q:\n%s", want, buf.String())
		}
	}
}
