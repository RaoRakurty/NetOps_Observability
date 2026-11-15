// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/mql"
)

// checkFake is a workspace's own Digital Experience checks (tracker 337 N-B5).
// Device-filter reads (MetricRange/MetricInstant on the embedded fakeScope)
// must NOT be used for a tenant-labeled metric: the series carry no device
// label, so that path would read nothing.
type checkFake struct {
	fakeScope
	checks       []ProbeTargetRef
	tenantExprs  []string
	tenantSeries []Series
	tenantRows   []Sample
	keysSeen     [][]string
}

func (c *checkFake) TenantMetricRange(_ context.Context, e mql.Expr, _, _ time.Time, _ time.Duration, _ int) ([]Series, bool, error) {
	c.tenantExprs = append(c.tenantExprs, e.String())
	return c.tenantSeries, false, nil
}

func (c *checkFake) TenantMetricInstant(_ context.Context, e mql.Expr, _ time.Time, _ int) ([]Sample, bool, error) {
	c.tenantExprs = append(c.tenantExprs, e.String())
	return c.tenantRows, false, nil
}

func (c *checkFake) ProbeTargets(_ context.Context, keys []string) ([]ProbeTargetRef, error) {
	c.keysSeen = append(c.keysSeen, keys)
	var out []ProbeTargetRef
	for _, t := range c.checks {
		if len(keys) == 0 {
			out = append(out, t)
			continue
		}
		for _, k := range keys {
			if strings.EqualFold(k, t.Host) || strings.EqualFold(k, t.Name) || k == t.ID {
				out = append(out, t)
				break
			}
		}
	}
	return out, nil
}

var ownChecks = []ProbeTargetRef{
	{ID: "chk-erp", Name: "ERP check", Host: "erp.example.com"},
	{ID: "chk-login", Name: "Login page", Host: "login.example.com"},
}

func execDirect(t *testing.T, sc Scope, js string) (*ResultSet, error) {
	t.Helper()
	a, err := ast.Decode([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return Planner{Cat: cat}.Execute(context.Background(), sc, a, nil)
}

func TestTenantLabeledMetricReadsThroughTheTenantSeamAndNamesTheCheck(t *testing.T) {
	sc := &checkFake{checks: ownChecks, tenantSeries: []Series{
		{Labels: map[string]string{"tenant": "t-a", "target": "chk-erp"}, Points: []Point{{T: 1, V: 2.5}}},
	}}
	rs, err := execDirect(t, sc, `{"v":1,"query_type":"metric_series","target":"probe_target","metric":"dem_probe_loss_pct","aggregation":"avg",`+
		`"entities":[{"type":"probe_target","id":"probe:erp.example.com"}],"time_range":{"kind":"relative","last":"1h"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if sc.ranges != 0 || len(sc.instants) != 0 {
		t.Fatal("a tenant-labeled metric was read through the device-filter path")
	}
	if len(sc.tenantExprs) != 1 || !strings.Contains(sc.tenantExprs[0], `dem_probe_loss_pct{target=~"chk-erp"}`) {
		t.Fatalf("expected one read narrowed to the named check, got %v", sc.tenantExprs)
	}
	if len(rs.Series) != 1 || rs.Series[0].Entity["probe_target"] != "ERP check" {
		t.Fatalf("the answer must name the check, got %+v", rs.Series)
	}
}

// No check named: every check the caller owns, with no target matcher — the
// scope's tenant filter is what bounds the read, not a list built here.
func TestTenantLabeledMetricWithNoTargetReadsEveryOwnCheck(t *testing.T) {
	sc := &checkFake{checks: ownChecks, tenantRows: []Sample{
		{Labels: map[string]string{"target": "chk-login"}, Value: 7},
		{Labels: map[string]string{"target": "chk-erp"}, Value: 1},
	}}
	rs, err := execDirect(t, sc, `{"v":1,"query_type":"metric_topk","target":"probe_target","metric":"dem_probe_loss_pct","aggregation":"avg","limit":5,`+
		`"time_range":{"kind":"relative","last":"1h"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.tenantExprs) != 1 || strings.Contains(sc.tenantExprs[0], "target=~") {
		t.Fatalf("expected one unnarrowed read, got %v", sc.tenantExprs)
	}
	if len(rs.Rows) != 2 || rs.Rows[0]["probe_target"] != "Login page" {
		t.Fatalf("rows must rank the caller's checks by name, got %+v", rs.Rows)
	}
}

// A named check the caller does not own resolves to nothing visible — never
// an unscoped read and never a silent "no loss".
func TestTenantLabeledMetricOnAForeignCheckIsNothingVisible(t *testing.T) {
	sc := &checkFake{checks: ownChecks}
	rs, err := execDirect(t, sc, `{"v":1,"query_type":"metric_series","target":"probe_target","metric":"dem_probe_latency_ms","aggregation":"p95",`+
		`"entities":[{"type":"probe_target","id":"probe:b-only.example.com"}],"time_range":{"kind":"relative","last":"1h"}}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.tenantExprs) != 0 {
		t.Fatalf("a foreign check was read: %v", sc.tenantExprs)
	}
	if len(rs.Notes) == 0 || !strings.Contains(rs.Notes[len(rs.Notes)-1], ErrEmptyScope.Error()) {
		t.Fatalf("want the nothing-visible note, got %v", rs.Notes)
	}
}

// A scope that cannot read tenant-labeled series says so instead of falling
// back to the device-filter path.
func TestTenantLabeledMetricWithoutTheSeamIsAnError(t *testing.T) {
	sc := &fakeScope{}
	_, err := execDirect(t, sc, `{"v":1,"query_type":"metric_series","target":"probe_target","metric":"dem_probe_loss_pct","aggregation":"avg",`+
		`"time_range":{"kind":"relative","last":"1h"}}`)
	if err == nil || errors.Is(err, ErrEmptyScope) {
		t.Fatalf("want an explicit error, got %v", err)
	}
	if sc.ranges != 0 {
		t.Fatal("fell back to the device-filter read")
	}
}

// The platform probe metric is unchanged: device-filter path, dst label.
func TestPlatformProbeMetricStillReadsTheDeviceFilterPath(t *testing.T) {
	sc := &checkFake{checks: ownChecks}
	if _, err := execDirect(t, sc, `{"v":1,"query_type":"metric_series","target":"probe_target","metric":"probe_rtt_ms","aggregation":"p95",`+
		`"entities":[{"type":"probe_target","id":"probe:8.8.8.8"}],"time_range":{"kind":"relative","last":"1h"}}`); err != nil {
		t.Fatal(err)
	}
	if sc.ranges != 1 || len(sc.tenantExprs) != 0 || !strings.Contains(sc.exprs[0], `probe_rtt_ms{dst=~"8\\.8\\.8\\.8"}`) {
		t.Fatalf("platform probe read went the wrong way: ranges=%d tenant=%v exprs=%v", sc.ranges, sc.tenantExprs, sc.exprs)
	}
}
