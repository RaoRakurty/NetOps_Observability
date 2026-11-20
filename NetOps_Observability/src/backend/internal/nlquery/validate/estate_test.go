// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package validate

// estate_test.go — the seasonal_outliers shape (tracker 337 N-H6 step 3):
// optional target among the rolled-up entity types, optional rolled-up metric
// or one metric filter, above_baseline as the only predicate, no window of its
// own (a plain "last N" is dropped and said), refs narrow to devices or sites,
// the K bound, the N-B5 gate, and foreign = missing.

import (
	"context"
	"encoding/json"
	"testing"
)

func TestEstateValidShapes(t *testing.T) {
	for _, js := range []string{
		`{"v":1,"query_type":"seasonal_outliers"}`,
		`{"v":1,"query_type":"seasonal_outliers","target":""}`,
		`{"v":1,"query_type":"seasonal_outliers","target":"interface"}`,
		`{"v":1,"query_type":"seasonal_outliers","target":"device","metric":"cpu_util_pct"}`,
		`{"v":1,"query_type":"seasonal_outliers","target":"interface","predicate":{"op":"above_baseline"},"filters":[{"field":"metric","op":"in","values":["if_in_bps","if_out_bps"]}]}`,
		`{"v":1,"query_type":"seasonal_outliers","entities":[{"type":"site","id":"site:dfw-hq"},{"type":"device","id":"device:edge-1"}]}`,
	} {
		out, res := Validate(context.Background(), cat, fakeScope{}, q(t, js))
		if !res.Valid {
			t.Errorf("%s: %s", js, codes(res))
			continue
		}
		if out.Limit != DefaultEstateRows || out.Time.Kind != "" {
			t.Errorf("%s: limit %d time %+v", js, out.Limit, out.Time)
		}
	}
	// A plain "last N" (a model's habit) is the present: dropped and said.
	out, res := Validate(context.Background(), cat, fakeScope{}, q(t, `{"v":1,"query_type":"seasonal_outliers","time_range":{"kind":"relative","last":"1h"},"limit":500}`))
	if !res.Valid || out.Time.Kind != "" || out.Limit != MaxEstateRows {
		t.Fatalf("valid=%v time=%+v limit=%d %s", res.Valid, out.Time, out.Limit, codes(res))
	}
	reasons := map[string]bool{}
	for _, c := range res.Constraints {
		reasons[c.Reason] = true
	}
	if !reasons["estate_hour"] || !reasons["max_topk"] {
		t.Fatalf("constraints %+v", res.Constraints)
	}
	// Circuits for a platform operator.
	if _, res := Validate(context.Background(), cat, fakeScope{cross: true}, q(t, `{"v":1,"query_type":"seasonal_outliers","target":"circuit","metric":"circuit_qoe"}`)); !res.Valid {
		t.Fatalf("operator circuit question: %s", codes(res))
	}
}

func TestEstateRules(t *testing.T) {
	for _, c := range []struct{ name, js, code string }{
		{"bgp target", `{"v":1,"query_type":"seasonal_outliers","target":"bgp_peer"}`, CodeInvalidValue},
		{"metric not rolled up", `{"v":1,"query_type":"seasonal_outliers","metric":"if_util_max_pct"}`, CodeInvalidValue},
		{"metric of another entity", `{"v":1,"query_type":"seasonal_outliers","target":"device","metric":"if_in_bps"}`, CodeInvalidValue},
		{"aggregation", `{"v":1,"query_type":"seasonal_outliers","aggregation":"max"}`, CodeForbiddenFieldForType},
		{"threshold predicate", `{"v":1,"query_type":"seasonal_outliers","predicate":{"op":"gt","value":5}}`, CodeOperatorNotAllowed},
		{"above_baseline with a value", `{"v":1,"query_type":"seasonal_outliers","predicate":{"op":"above_baseline","value":2}}`, CodeOperatorNotAllowed},
		{"compare", `{"v":1,"query_type":"seasonal_outliers","compare_to":{"kind":"relative","last":"1h","offset":"7d"}}`, CodeForbiddenFieldForType},
		{"group", `{"v":1,"query_type":"seasonal_outliers","group_by":["site"]}`, CodeForbiddenFieldForType},
		{"order", `{"v":1,"query_type":"seasonal_outliers","order_by":[{"field":"value","dir":"desc"}]}`, CodeForbiddenFieldForType},
		{"offset window", `{"v":1,"query_type":"seasonal_outliers","time_range":{"kind":"relative","last":"1h","offset":"1d"}}`, CodeForbiddenFieldForType},
		{"absolute window", `{"v":1,"query_type":"seasonal_outliers","time_range":{"kind":"absolute","from":"2026-09-01T00:00:00Z","to":"2026-09-01T01:00:00Z"}}`, CodeForbiddenFieldForType},
		{"interface ref", `{"v":1,"query_type":"seasonal_outliers","entities":[{"type":"interface","id":"interface:edge-1/Gi0/1"}]}`, CodeRelationshipNotAllowed},
		{"non-metric filter", `{"v":1,"query_type":"seasonal_outliers","filters":[{"field":"severity","op":"eq","values":["error"]}]}`, CodeUnknownDimension},
		{"two filters", `{"v":1,"query_type":"seasonal_outliers","filters":[{"field":"metric","op":"eq","values":["cpu_util_pct"]},{"field":"metric","op":"eq","values":["mem_util_pct"]}]}`, CodeTooBroad},
		{"metric and filter", `{"v":1,"query_type":"seasonal_outliers","metric":"cpu_util_pct","filters":[{"field":"metric","op":"eq","values":["mem_util_pct"]}]}`, CodeForbiddenFieldForType},
		{"filter op", `{"v":1,"query_type":"seasonal_outliers","filters":[{"field":"metric","op":"gt","values":["cpu_util_pct"]}]}`, CodeOperatorNotAllowed},
		{"filter value not rolled", `{"v":1,"query_type":"seasonal_outliers","filters":[{"field":"metric","op":"in","values":["cpu_util_pct","probe_loss_pct"]}]}`, CodeInvalidValue},
		{"filter value twice", `{"v":1,"query_type":"seasonal_outliers","filters":[{"field":"metric","op":"in","values":["cpu_util_pct","cpu_util_pct"]}]}`, CodeInvalidValue},
		// N-B5: never an empty answer that would read as "nothing unusual".
		{"workspace circuit target", `{"v":1,"query_type":"seasonal_outliers","target":"circuit"}`, CodeScopeUnavailable},
		{"workspace circuit metric", `{"v":1,"query_type":"seasonal_outliers","metric":"circuit_latency_ms"}`, CodeScopeUnavailable},
		{"workspace circuit filter", `{"v":1,"query_type":"seasonal_outliers","filters":[{"field":"metric","op":"in","values":["cpu_util_pct","circuit_qoe"]}]}`, CodeScopeUnavailable},
	} {
		t.Run(c.name, func(t *testing.T) { mustFail(t, fakeScope{}, c.js, c.code) })
	}
}

// §3a: a foreign device and a missing one read the same, byte for byte.
func TestEstateForeignAndMissingAreIndistinguishable(t *testing.T) {
	mk := func(id string) string {
		return `{"v":1,"query_type":"seasonal_outliers","entities":[{"type":"device","id":"` + id + `"}]}`
	}
	foreign := mustFail(t, fakeScope{}, mk("device:tenant-b-core"), CodeUnknownEntity)
	missing := mustFail(t, fakeScope{}, mk("device:no-such"), CodeUnknownEntity)
	foreign.Got, missing.Got = "", ""
	fj, _ := json.Marshal(foreign)
	mj, _ := json.Marshal(missing)
	if string(fj) != string(mj) {
		t.Fatalf("errors differ — the validator is an existence oracle:\n%s\n%s", fj, mj)
	}
}
