// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_seasonal_estate_isolation_test.go — CLAUDE.md §3a rule 5 for the
// estate-wide seasonal answer (tracker 337 N-H6 step 3), driven through the
// real validator, planner and nlqScope against a ClickHouse stub that holds
// BOTH tenants' roll-up rows and applies the STRICT row policy by tenant_scope
// the way the store does. Proven:
//   - every roll-up read runs at the CALLER's tenant_scope; ?as_tenant= and
//     X-Acting-Tenant never widen it;
//   - the answer names only the caller's own devices — and even if the row
//     policy failed and returned another tenant's row, that series is dropped
//     before it is ranked or counted;
//   - a foreign device named in the question is refused exactly like one that
//     does not exist (same code, same words);
//   - a malformed metric name reads nothing; device values reach the SQL as
//     literals; the read is bounded (FINAL, LIMIT maxSeries+1).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/plan"
	"netops/backend/internal/nlquery/seasonal"
	"netops/backend/internal/nlquery/validate"

	nlqast "netops/backend/internal/nlquery/ast"
)

type estateCH struct {
	mu     sync.Mutex
	scopes []string
	sqls   []string
	// leak makes the stub ignore tenant_scope (a failed row policy).
	leak bool
}

// startEstateCH serves netops.series_hourly for dev-a (t-a) and dev-b (t-b):
// cpu at 90 in the judged hour, 40 at every reference hour.
func startEstateCH(t *testing.T) *estateCH {
	t.Helper()
	rec := &estateCH{}
	hour := time.Now().UTC().Truncate(time.Hour).Add(-time.Hour)
	var hs, vs []any
	for i, h := range seasonal.RefHours(hour) {
		hs = append(hs, h.Unix())
		v := 40.0
		if i == 0 {
			v = 90
		}
		vs = append(vs, v)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		sql := string(b) + r.URL.Query().Get("query")
		scope := r.URL.Query().Get("tenant_scope")
		rec.mu.Lock()
		rec.scopes, rec.sqls = append(rec.scopes, scope), append(rec.sqls, sql)
		leak := rec.leak
		rec.mu.Unlock()
		owned := map[string]string{"dev-a": "t-a", "dev-b": "t-b"}
		var data []map[string]any
		visible := func(dev string) bool {
			return leak || scope == "" || scope == "*" || strings.Contains(","+scope+",", ","+owned[dev]+",")
		}
		if strings.Contains(sql, "count() AS n") {
			n := 0
			for d := range owned {
				if visible(d) {
					n++
				}
			}
			data = append(data, map[string]any{"n": n, "h": hour.Unix()})
		} else {
			for _, d := range []string{"dev-a", "dev-b"} {
				if visible(d) {
					data = append(data, map[string]any{"metric": "cpu_util_pct", "entity_key": d, "hs": hs, "vs": vs})
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"meta": []any{}, "data": data, "rows": len(data)})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")
	return rec
}

func estateAsk(t *testing.T, s *server, r *http.Request, claims jwtClaims, js string) (*plan.ResultSet, validate.Result) {
	t.Helper()
	a, err := nlqast.Decode([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if s.nlqCatalog == nil {
		s.nlqCatalog = catalog.MustLoad()
	}
	h := s.nlqScopeFor(r, claims)
	v, res := validate.Validate(context.Background(), s.nlqCatalog, h, a)
	if !res.Valid {
		return nil, res
	}
	rs, err := plan.Planner{Cat: s.nlqCatalog}.Execute(context.Background(), h, v, res.Constraints)
	if err != nil {
		t.Fatal(err)
	}
	return rs, res
}

const estateDevices = `{"v":1,"query_type":"seasonal_outliers","target":"device"}`

func estateDevicesNamed(rs *plan.ResultSet) []string {
	var out []string
	for _, r := range rs.Rows {
		d, _ := r["device"].(string)
		out = append(out, d)
	}
	return out
}

func TestSeasonalEstateIsTheCallersOwn(t *testing.T) {
	s, a, b := nlqFixture(t)
	ch := startEstateCH(t)

	rs, _ := estateAsk(t, s, req(http.MethodGet, "/api/ai/ask", "", a), a, estateDevices)
	if rs == nil {
		t.Fatal("query invalid")
	}
	if got := estateDevicesNamed(rs); len(got) != 1 || got[0] != "edge-a" {
		t.Fatalf("CROSS-TENANT LEAK or wrong verdict: devices %v", got)
	}
	if len(ch.scopes) != 2 {
		t.Fatalf("expected the latest-hour read and the series read, saw %d", len(ch.scopes))
	}
	for i, sc := range ch.scopes {
		if sc != "t-a" {
			t.Fatalf("TENANT LEAK: read %d ran at tenant_scope %q, want t-a", i, sc)
		}
	}
	if q := ch.sqls[1]; !strings.Contains(q, "FROM netops.series_hourly FINAL") || !strings.Contains(q, "LIMIT 10001") {
		t.Fatalf("series read unbounded or not FINAL:\n%s", q)
	}

	// B sees only B's.
	rs, _ = estateAsk(t, s, req(http.MethodGet, "/api/ai/ask", "", b), b, estateDevices)
	if got := estateDevicesNamed(rs); len(got) != 1 || got[0] != "edge-b" {
		t.Fatalf("tenant B devices %v", got)
	}

	// as_tenant / X-Acting-Tenant never widen a workspace user.
	ch.scopes = nil
	r := req(http.MethodGet, "/api/ai/ask?as_tenant=t-b", "", a)
	r.Header.Set("X-Acting-Tenant", "t-b")
	rs, _ = estateAsk(t, s, r, a, estateDevices)
	for i, sc := range ch.scopes {
		if sc != "t-a" {
			t.Fatalf("as_tenant widened read %d to tenant_scope %q", i, sc)
		}
	}
	if got := estateDevicesNamed(rs); len(got) != 1 || got[0] != "edge-a" {
		t.Fatalf("as_tenant reached another tenant: %v", got)
	}
}

// Defence in depth: a row policy that failed open still never puts another
// tenant's series in the answer or in its counts.
func TestSeasonalEstateDropsAForeignRowThePolicyLetThrough(t *testing.T) {
	s, a, _ := nlqFixture(t)
	ch := startEstateCH(t)
	ch.leak = true
	rs, _ := estateAsk(t, s, req(http.MethodGet, "/api/ai/ask", "", a), a, estateDevices)
	if got := estateDevicesNamed(rs); len(got) != 1 || got[0] != "edge-a" {
		t.Fatalf("CROSS-TENANT LEAK: a foreign roll-up row reached the answer: %v", got)
	}
	if notes := strings.Join(rs.Notes, " "); !strings.Contains(notes, ": 1 series checked") || strings.Contains(notes, "edge-b") || strings.Contains(notes, "dev-b") {
		t.Fatalf("a foreign series was counted or named: %s", notes)
	}
}

// A foreign device in the question is refused exactly like a missing one.
func TestSeasonalEstateForeignDeviceIsIndistinguishableFromMissing(t *testing.T) {
	s, a, _ := nlqFixture(t)
	ch := startEstateCH(t)
	ask := func(id string) validate.Result {
		_, res := estateAsk(t, s, req(http.MethodGet, "/api/ai/ask", "", a), a,
			`{"v":1,"query_type":"seasonal_outliers","target":"","entities":[{"type":"device","id":"`+id+`"}]}`)
		return res
	}
	foreign, missing := ask("device:dev-b"), ask("device:no-such")
	if foreign.Valid || missing.Valid || len(foreign.Errors) != 1 || len(missing.Errors) != 1 {
		t.Fatalf("foreign %+v missing %+v — both must be refused", foreign, missing)
	}
	f, m := foreign.Errors[0], missing.Errors[0]
	if f.Code != m.Code || f.Message != m.Message || f.Code != validate.CodeUnknownEntity {
		t.Fatalf("a foreign device reads differently from a missing one: %+v vs %+v", f, m)
	}
	if len(ch.sqls) != 0 {
		t.Fatalf("a refused question read the roll-up %d times", len(ch.sqls))
	}
	// Narrowed to the caller's own device: the read carries it as a literal.
	rs, _ := estateAsk(t, s, req(http.MethodGet, "/api/ai/ask", "", a), a,
		`{"v":1,"query_type":"seasonal_outliers","target":"","entities":[{"type":"device","id":"device:dev-a"}]}`)
	if rs == nil || len(ch.sqls) == 0 || !strings.Contains(ch.sqls[0], "splitByChar('\\x1F', entity_key)[1] IN ('dev-a', 'edge-a')") {
		t.Fatalf("narrowed read SQL:\n%v", ch.sqls)
	}
}

func TestSeasonalEstateReadRefusesBadInput(t *testing.T) {
	s, a, _ := nlqFixture(t)
	ch := startEstateCH(t)
	h := s.nlqScopeFor(req(http.MethodGet, "/api/ai/ask", "", a), a)
	ctx := context.Background()
	_, err := h.SeasonalEstate(ctx, plan.EstateQuery{Metrics: []plan.EstateMetric{{Name: "cpu'; DROP TABLE x --"}}, MaxSeries: 10, Since: time.Now().Add(-3 * time.Hour)})
	if err == nil || len(ch.sqls) != 0 {
		t.Fatalf("malformed metric: err=%v reads=%d", err, len(ch.sqls))
	}
	if out, err := h.SeasonalEstate(ctx, plan.EstateQuery{MaxSeries: 10}); err != nil || !out.Hour.IsZero() || len(ch.sqls) != 0 {
		t.Fatalf("no metrics: out=%+v err=%v reads=%d", out, err, len(ch.sqls))
	}
	// A quote in a device value stays inside its literal; MaxSeries is capped.
	out, err := h.SeasonalEstate(ctx, plan.EstateQuery{Metrics: []plan.EstateMetric{{Name: "circuit_qoe", DeviceAt: 1}},
		Devices: []string{"x'y"}, MaxSeries: 1 << 30, Since: time.Now().Add(-3 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ch.sqls[0], `splitByChar('\x1F', entity_key)[2] IN ('x\'y')`) || !strings.Contains(ch.sqls[1], "LIMIT 10001") {
		t.Fatalf("SQL:\n%s\n%s", ch.sqls[0], ch.sqls[1])
	}
	if out.Hour.IsZero() || len(out.Series) != 1 || out.Series[0].EntityKey != "dev-a" {
		t.Fatalf("parsed = %+v", out)
	}
}

// End to end through the Iris box's data arm: the question compiles on the
// deterministic path, runs in the caller's scope and is answered in the
// tier's own words — and another tenant's device never appears, even when the
// request asks to act as that tenant.
func TestSeasonalEstateThroughTheDataArm(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	s, a, b := nlqAPIFixture(t)
	startEstateCH(t)
	ask := func(c jwtClaims, path string) ai.DataAnswer {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, path, nil)
		r = r.WithContext(context.WithValue(r.Context(), userCtxKey, c))
		r.Header.Set("X-Acting-Tenant", "t-b")
		nlq := s.aiNLQuery(r, c)
		if nlq == nil {
			t.Fatal("the data arm is not wired for this caller")
		}
		d, err := nlq(context.Background(), ai.Principal{Tenant: c.Tenant}, "what is abnormal right now for this time of week?", ai.DataOpts{})
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	d := ask(a, "/api/ai/ask?as_tenant=t-b")
	if d.Status != ai.DataAnswered || d.Intent != "unusual_now" {
		t.Fatalf("status %q intent %q text %q", d.Status, d.Intent, d.Text)
	}
	for _, want := range []string{"1 series is unusual for the time right now", "edge-a", "its usual level for this time of week (4 of 4 weeks used)", "robust deviations above"} {
		if !strings.Contains(d.Text, want) {
			t.Fatalf("answer lacks %q:\n%s", want, d.Text)
		}
	}
	for _, foreign := range []string{"edge-b", "dev-b"} {
		if strings.Contains(d.Text, foreign) || strings.Contains(string(d.Payload), foreign) {
			t.Fatalf("CROSS-TENANT LEAK: %s reached tenant A:\n%s\n%s", foreign, d.Text, d.Payload)
		}
	}
	d = ask(b, "/api/ai/ask")
	if d.Status != ai.DataAnswered || !strings.Contains(d.Text, "edge-b") || strings.Contains(d.Text, "edge-a") || strings.Contains(string(d.Payload), "dev-a") {
		t.Fatalf("tenant B answer:\n%s\n%s", d.Text, d.Payload)
	}
}

// The estate answer covers exactly what the roll-up worker keeps, keyed by the
// same labels (seasonal.RolledMetrics ≡ seasonalRollMetrics).
func TestSeasonalEstateMetricsMatchTheRollup(t *testing.T) {
	labels := map[string][]string{"device": {"device"}, "interface": {"device", "ifName"}, "circuit": {"circuit", "local_device"}}
	rolled := seasonalRollMetrics()
	if len(rolled) != len(seasonal.RolledMetrics) {
		t.Fatalf("roll-up keeps %d metrics, the estate answer knows %d", len(rolled), len(seasonal.RolledMetrics))
	}
	for _, m := range rolled {
		ent, ok := seasonal.RolledMetrics[m.Name]
		if !ok {
			t.Errorf("%s is rolled up but the estate answer does not know it", m.Name)
			continue
		}
		if strings.Join(m.Labels, ",") != strings.Join(labels[ent], ",") {
			t.Errorf("%s: roll-up labels %v, estate %s labels %v", m.Name, m.Labels, ent, labels[ent])
		}
	}
}
