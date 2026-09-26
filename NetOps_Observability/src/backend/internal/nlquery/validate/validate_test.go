// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package validate

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
)

var fixedNow = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// fakeScope: tenant A sees site:dfw-hq, device:edge-1 and one incident; the
// ids of tenant B exist in the world but are NOT visible here.
type fakeScope struct {
	cross bool
	count int
}

var visibleToA = map[string]bool{
	"site:dfw-hq": true, "device:edge-1": true, "circuit:dfw-comcast": true,
	"incident:11111111-2222-3333-4444-555555555555": true, "provider:comcast": true,
}

func (f fakeScope) Visible(_ context.Context, r ast.EntityRef) (bool, error) {
	return visibleToA[r.ID], nil
}
func (f fakeScope) Count(_ context.Context, _ string, _ []ast.EntityRef) (int, error) {
	if f.count > 0 {
		return f.count, nil
	}
	return 10, nil
}
func (f fakeScope) CrossTenant() bool { return f.cross }
func (f fakeScope) Now() time.Time    { return fixedNow }

var cat = catalog.MustLoad()

func q(t *testing.T, js string) *ast.AST {
	t.Helper()
	a, err := ast.Decode([]byte(js))
	if err != nil {
		t.Fatalf("fixture does not decode: %v\n%s", err, js)
	}
	return a
}

func codes(r Result) string {
	var out []string
	for _, e := range r.Errors {
		out = append(out, e.Path+":"+e.Code)
	}
	return strings.Join(out, " ")
}

func mustFail(t *testing.T, sc Scope, js, wantCode string) Error {
	t.Helper()
	_, res := Validate(context.Background(), cat, sc, q(t, js))
	if res.Valid {
		t.Fatalf("accepted, want %s:\n%s", wantCode, js)
	}
	for _, e := range res.Errors {
		if e.Code == wantCode {
			return e
		}
	}
	t.Fatalf("want %s, got %s", wantCode, codes(res))
	return Error{}
}

const series = `{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"site","id":"site:dfw-hq"}],"time_range":{"kind":"relative","last":"2h"}}`

func TestValidQueryPassesAndDefaultsAgg(t *testing.T) {
	out, res := Validate(context.Background(), cat, fakeScope{}, q(t, series))
	if !res.Valid || out.Agg != "avg" {
		t.Fatalf("valid=%v agg=%q errors=%s", res.Valid, out.Agg, codes(res))
	}
}

func TestInputIsNeverMutated(t *testing.T) {
	in := q(t, `{"v":1,"query_type":"change_list","target":"change","limit":900}`)
	out, res := Validate(context.Background(), cat, fakeScope{}, in)
	if !res.Valid || out.Limit != MaxChangeRows || in.Limit != 900 || in.Time.Kind != "" {
		t.Fatalf("out=%d in=%d inTime=%q valid=%v", out.Limit, in.Limit, in.Time.Kind, res.Valid)
	}
	if len(res.Constraints) != 2 {
		t.Fatalf("both the default window and the row clamp must be reported: %+v", res.Constraints)
	}
}

// §3a: a foreign id and a nonexistent id produce the BYTE-IDENTICAL error.
func TestForeignAndMissingEntitiesAreIndistinguishable(t *testing.T) {
	mk := func(id string) string {
		return strings.Replace(series, "site:dfw-hq", id, 1)
	}
	foreign := mustFail(t, fakeScope{}, mk("site:tenant-b-hq"), CodeUnknownEntity)
	missing := mustFail(t, fakeScope{}, mk("site:no-such-site"), CodeUnknownEntity)
	foreign.Got, missing.Got = "", ""
	fj, _ := json.Marshal(foreign)
	mj, _ := json.Marshal(missing)
	if string(fj) != string(mj) {
		t.Fatalf("errors differ — the validator is an existence oracle:\n%s\n%s", fj, mj)
	}
	mustFail(t, fakeScope{}, `{"v":1,"query_type":"incident_explain","incident_id":"99999999-2222-3333-4444-555555555555"}`, CodeUnknownEntity)
}

func TestRules(t *testing.T) {
	cases := []struct{ name, js, code string }{
		{"version", strings.Replace(series, `"v":1`, `"v":2`, 1), CodeInvalidValue},
		{"unknown type", strings.Replace(series, "metric_series", "metric_seriez", 1), CodeUnknownQueryType},
		{"reserved type", `{"v":1,"query_type":"log_search","target":"device"}`, CodeUnsupportedQueryType},
		{"missing metric", strings.Replace(series, `"metric":"cpu_util_pct",`, "", 1), CodeMissingField},
		{"filters on metric", strings.Replace(series, `"time_range"`, `"filters":[{"field":"type","op":"eq","values":["x"]}],"time_range"`, 1), CodeForbiddenFieldForType},
		{"filter without predicate", strings.Replace(series, "metric_series", "metric_filter", 1), CodeMissingField},
		{"alias not canonical", strings.Replace(series, "cpu_util_pct", "cpu", 1), CodeUnknownMetric},
		{"typo metric", strings.Replace(series, "cpu_util_pct", "cpu_utl_pct", 1), CodeUnknownMetric},
		{"metric wrong target", strings.Replace(series, `"target":"device"`, `"target":"interface"`, 1), CodeMetricNotApplicable},
		{"bad aggregation", strings.Replace(series, `"metric":"cpu_util_pct",`, `"metric":"cpu_util_pct","aggregation":"median",`, 1), CodeAggregationNotAllowed},
		{"bad id form", strings.Replace(series, "site:dfw-hq", "site:DFW HQ", 1), CodeInvalidEntityID},
		{"unreachable ref", `{"v":1,"query_type":"metric_series","target":"probe_target","metric":"probe_rtt_ms","entities":[{"type":"change","id":"change:1"}]}`, CodeRelationshipNotAllowed},
		{"window too large", strings.Replace(series, `"last":"2h"`, `"last":"8d"`, 1), CodeWindowTooLarge},
		{"bad duration", strings.Replace(series, `"last":"2h"`, `"last":"2 hours"`, 1), CodeInvalidTime},
		{"unknown time kind", strings.Replace(series, `"kind":"relative"`, `"kind":"forever"`, 1), CodeInvalidTime},
		{"too many group-bys", strings.Replace(series, `"time_range"`, `"group_by":["site","device","interface"],"time_range"`, 1), CodeTooBroad},
		{"order by dimension on metric", strings.Replace(series, `"time_range"`, `"order_by":[{"field":"actor","dir":"asc"}],"time_range"`, 1), CodeUnknownDimension},
		{"bad order dir", strings.Replace(series, `"time_range"`, `"order_by":[{"field":"value","dir":"sideways"}],"time_range"`, 1), CodeInvalidValue},
		{"unknown dimension", `{"v":1,"query_type":"change_list","target":"change","filters":[{"field":"colour","op":"eq","values":["red"]}]}`, CodeUnknownDimension},
		{"restricted dimension", `{"v":1,"query_type":"change_list","target":"change","filters":[{"field":"before","op":"eq","values":["x"]}]}`, CodeUnknownDimension},
		{"operator not allowed", `{"v":1,"query_type":"change_list","target":"change","filters":[{"field":"type","op":"gt","values":["CONFIG_CHANGE"]}]}`, CodeOperatorNotAllowed},
		{"enum value", `{"v":1,"query_type":"change_list","target":"change","filters":[{"field":"type","op":"eq","values":["CONFIG_CHANGES"]}]}`, CodeInvalidValue},
		{"control chars", `{"v":1,"query_type":"change_list","target":"change","filters":[{"field":"actor","op":"eq","values":["jo\u0000hn"]}]}`, CodeInvalidValue},
		{"list with metric", `{"v":1,"query_type":"incident_list","target":"incident","metric":"cpu_util_pct"}`, CodeForbiddenFieldForType},
		{"future window", `{"v":1,"query_type":"change_list","target":"change","time_range":{"kind":"absolute","from":"2026-09-21T10:00:00Z","to":"2026-09-22T10:00:00Z"}}`, CodeInvalidTime},
		{"incidents anchor on metrics", strings.Replace(series, `{"kind":"relative","last":"2h"}`, `{"kind":"incidents","anchor":{"incidents":{"time_range":{"kind":"relative","last":"7d"}}}}`, 1), CodeInvalidTime},
		{"anchor span", `{"v":1,"query_type":"change_list","target":"change","time_range":{"kind":"incident","anchor":{"incident_id":"11111111-2222-3333-4444-555555555555","before":"2d"}}}`, CodeInvalidTime},
		{"too broad", strings.Replace(series, `"site","id":"site:dfw-hq"`, `"site","id":"site:dfw-hq"`, 1), ""},
	}
	for _, c := range cases {
		if c.code == "" {
			continue
		}
		t.Run(c.name, func(t *testing.T) { mustFail(t, fakeScope{}, c.js, c.code) })
	}
}

func TestPredicates(t *testing.T) {
	base := `{"v":1,"query_type":"metric_filter","target":"interface","metric":"if_util_max_pct","predicate":%s}`
	for name, c := range map[string]struct{ pred, code string }{
		"percent over 100":        {`{"op":"gt","value":150}`, CodeInvalidValue},
		"negative":                {`{"op":"gt","value":-1}`, CodeInvalidValue},
		"between backwards":       {`{"op":"between","value":80,"value2":20}`, CodeInvalidValue},
		"operator not for metric": {`{"op":"in","value":1}`, CodeOperatorNotAllowed},
	} {
		t.Run(name, func(t *testing.T) { mustFail(t, fakeScope{}, strings.Replace(base, "%s", c.pred, 1), c.code) })
	}
	mustFail(t, fakeScope{}, `{"v":1,"query_type":"metric_filter","target":"interface","metric":"if_flaps","predicate":{"op":"above_baseline"}}`, CodeOperatorNotAllowed)
	mustFail(t, fakeScope{}, `{"v":1,"query_type":"metric_filter","target":"bgp_peer","metric":"bgp_session_state","predicate":{"op":"eq","value":9}}`, CodeInvalidValue)
	if _, res := Validate(context.Background(), cat, fakeScope{}, q(t, `{"v":1,"query_type":"metric_filter","target":"bgp_peer","metric":"bgp_session_state","predicate":{"op":"ne","value":6}}`)); !res.Valid {
		t.Fatalf("\"not established\" must validate: %s", codes(res))
	}
}

// Circuit/probe series are invisible to scoped tenants until N-B5: the
// validator REFUSES rather than letting an empty result read as "no loss".
func TestGatedMetricIsRefusedForScopedButAllowedForCross(t *testing.T) {
	js := `{"v":1,"query_type":"metric_series","target":"circuit","metric":"circuit_loss_pct","entities":[{"type":"circuit","id":"circuit:dfw-comcast"}]}`
	mustFail(t, fakeScope{}, js, CodeScopeUnavailable)
	if _, res := Validate(context.Background(), cat, fakeScope{cross: true}, q(t, js)); !res.Valid {
		t.Fatalf("a cross-tenant operator may read it: %s", codes(res))
	}
}

func TestTooBroadIsRejected(t *testing.T) {
	mustFail(t, fakeScope{count: 1500}, strings.Replace(series, `"target":"device","metric":"cpu_util_pct"`, `"target":"interface","metric":"if_total_bps"`, 1), CodeTooBroad)
}

func TestCompareWindows(t *testing.T) {
	ok := `{"v":1,"query_type":"compare_windows","target":"device","metric":"cpu_util_pct","time_range":{"kind":"relative","last":"2h"},"compare_to":{"kind":"relative","last":"2h","offset":"1d"}}`
	out, res := Validate(context.Background(), cat, fakeScope{}, q(t, ok))
	if !res.Valid || out.Limit != DefaultTopK {
		t.Fatalf("valid=%v limit=%d %s", res.Valid, out.Limit, codes(res))
	}
	mustFail(t, fakeScope{}, strings.Replace(ok, `"last":"2h","offset"`, `"last":"3h","offset"`, 1), CodeInvalidTime)
	mustFail(t, fakeScope{}, strings.Replace(ok, `,"offset":"1d"`, "", 1), CodeMissingField)
	mustFail(t, fakeScope{}, strings.Replace(ok, `"offset":"1d"`, `"offset":"40d"`, 1), CodeInvalidTime)
}

func TestIncidentsAnchoredChangeList(t *testing.T) {
	js := `{"v":1,"query_type":"change_list","target":"change","time_range":{"kind":"incidents","anchor":{"before":"30m","incidents":{"filters":[{"field":"seam_class","op":"eq","values":["sdwan"]}],"time_range":{"kind":"relative","last":"7d"},"max":500}}}}`
	out, res := Validate(context.Background(), cat, fakeScope{}, q(t, js))
	if !res.Valid || out.Time.Anchor.Incidents.Max != MaxAnchorIncidents {
		t.Fatalf("valid=%v %s", res.Valid, codes(res))
	}
	mustFail(t, fakeScope{}, strings.Replace(js, `"sdwan"`, `"satellite"`, 1), CodeInvalidValue)
}

func TestSuggestionsAreDeterministicAndPreferTheTarget(t *testing.T) {
	e := mustFail(t, fakeScope{}, strings.Replace(series, "cpu_util_pct", "cpu", 1), CodeUnknownMetric)
	if len(e.Suggestions) == 0 || e.Suggestions[0] != "cpu_util_pct" {
		t.Fatalf("an alias must suggest its canonical name: %v", e.Suggestions)
	}
	for i := 0; i < 5; i++ {
		e2 := mustFail(t, fakeScope{}, strings.Replace(series, "cpu_util_pct", "cpu_utl_pct", 1), CodeUnknownMetric)
		if len(e2.Suggestions) == 0 || e2.Suggestions[0] != "cpu_util_pct" {
			t.Fatalf("typo suggestion = %v", e2.Suggestions)
		}
	}
}

func TestOSADistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{{"", "", 0}, {"abc", "abc", 0}, {"abc", "acb", 1}, {"kitten", "sitting", 3}, {"cpu", "cpu_util_pct", 9}} {
		if got := osaDistance(c.a, c.b); got != c.d {
			t.Errorf("osa(%q,%q)=%d want %d", c.a, c.b, got, c.d)
		}
	}
}

func TestCompoundIDsNeedTheirDeviceAndName(t *testing.T) {
	base := `{"v":1,"query_type":"metric_series","target":"interface","metric":"if_in_bps","entities":[{"type":"interface","id":"%s"}]}`
	for _, bad := range []string{"interface:edge-1", "interface:edge/1/Gi0/0x y", "interface:/Gi0/0"} {
		mustFail(t, fakeScope{}, strings.Replace(base, "%s", bad, 1), CodeInvalidEntityID)
	}
	mustFail(t, fakeScope{}, `{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"device","id":"device:a/b"}]}`, CodeInvalidEntityID)
	mustFail(t, fakeScope{}, `{"v":1,"query_type":"metric_series","target":"bgp_peer","metric":"bgp_flaps","entities":[{"type":"bgp_peer","id":"bgp_peer:d1/not-an-ip"}]}`, CodeInvalidEntityID)
}
