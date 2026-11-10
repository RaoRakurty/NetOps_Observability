// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package validate

import (
	"context"
	"testing"
)

// entity_count / entity_list (hybrid NLU plan A4): the caller's visible
// devices, sites or circuits — no window, no metric, no filters; a count may
// group by site; a list is clamped like every list.
func TestInventoryQueries(t *testing.T) {
	ctx := context.Background()
	for _, js := range []string{
		`{"v":1,"query_type":"entity_count","target":"device","time_range":{}}`,
		`{"v":1,"query_type":"entity_count","target":"device","entities":[{"type":"site","id":"site:dfw-hq"}],"time_range":{}}`,
		`{"v":1,"query_type":"entity_count","target":"circuit","group_by":["site"],"time_range":{}}`,
		`{"v":1,"query_type":"entity_count","target":"site","time_range":{}}`,
		`{"v":1,"query_type":"entity_list","target":"device","entities":[{"type":"device","id":"device:edge-1"}],"time_range":{}}`,
	} {
		checked, res := Validate(ctx, cat, fakeScope{}, q(t, js))
		if !res.Valid {
			t.Errorf("must validate: %s\n%s", codes(res), js)
			continue
		}
		if checked.Time.Kind != "" {
			t.Errorf("an inventory query gets no default window: %+v", checked.Time)
		}
	}
	for js, want := range map[string]string{
		`{"v":1,"query_type":"entity_count","target":"interface","time_range":{}}`:                                                     CodeInvalidValue,
		`{"v":1,"query_type":"entity_count","target":"device","time_range":{"kind":"relative","last":"1h"}}`:                           CodeForbiddenFieldForType,
		`{"v":1,"query_type":"entity_count","target":"device","metric":"cpu_util_pct","time_range":{}}`:                                CodeForbiddenFieldForType,
		`{"v":1,"query_type":"entity_count","target":"device","filters":[{"field":"state","op":"eq","values":["x"]}],"time_range":{}}`: CodeForbiddenFieldForType,
		`{"v":1,"query_type":"entity_count","target":"device","limit":5,"time_range":{}}`:                                              CodeForbiddenFieldForType,
		`{"v":1,"query_type":"entity_count","target":"site","group_by":["site"],"time_range":{}}`:                                      CodeUnknownDimension,
		`{"v":1,"query_type":"entity_count","target":"device","group_by":["vendor"],"time_range":{}}`:                                  CodeUnknownDimension,
		`{"v":1,"query_type":"entity_list","target":"device","group_by":["site"],"time_range":{}}`:                                     CodeUnknownDimension,
		`{"v":1,"query_type":"entity_list","target":"device","order_by":[{"field":"site","dir":"asc"}],"time_range":{}}`:               CodeForbiddenFieldForType,
		// §3a: a foreign site narrows nothing — refused exactly like a missing one.
		`{"v":1,"query_type":"entity_count","target":"device","entities":[{"type":"site","id":"site:gx-chi"}],"time_range":{}}`: CodeUnknownEntity,
	} {
		mustFail(t, fakeScope{}, js, want)
	}
	checked, res := Validate(ctx, cat, fakeScope{}, q(t, `{"v":1,"query_type":"entity_list","target":"device","limit":9999,"time_range":{}}`))
	if !res.Valid || checked.Limit != MaxEntityRows {
		t.Fatalf("a list is clamped to %d: %+v %s", MaxEntityRows, checked, codes(res))
	}
	checked, _ = Validate(ctx, cat, fakeScope{}, q(t, `{"v":1,"query_type":"entity_list","target":"device","time_range":{}}`))
	if checked.Limit != DefaultEntityRows {
		t.Fatalf("default list size %d, want %d", checked.Limit, DefaultEntityRows)
	}
}
