// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package validate

import (
	"context"
	"testing"
)

// A device count or list may filter by reachability and type — closed values,
// eq/in, each field once — and nothing else filters an inventory query.
func TestInventoryFilters(t *testing.T) {
	for _, js := range []string{
		`{"v":1,"query_type":"entity_list","target":"device","filters":[{"field":"reachability","op":"eq","values":["down"]}],"time_range":{}}`,
		`{"v":1,"query_type":"entity_count","target":"device","filters":[{"field":"reachability","op":"in","values":["down","partial"]},{"field":"type","op":"eq","values":["router"]}],"time_range":{}}`,
	} {
		if _, res := Validate(context.Background(), cat, fakeScope{}, q(t, js)); !res.Valid {
			t.Errorf("must validate: %s\n%s", codes(res), js)
		}
	}
	for js, want := range map[string]string{
		// Only devices carry liveness.
		`{"v":1,"query_type":"entity_list","target":"site","filters":[{"field":"reachability","op":"eq","values":["down"]}],"time_range":{}}`:                                                      CodeForbiddenFieldForType,
		`{"v":1,"query_type":"entity_list","target":"device","filters":[{"field":"owner","op":"eq","values":["x"]}],"time_range":{}}`:                                                              CodeForbiddenFieldForType,
		`{"v":1,"query_type":"entity_list","target":"device","filters":[{"field":"reachability","op":"eq","values":["sideways"]}],"time_range":{}}`:                                                CodeInvalidValue,
		`{"v":1,"query_type":"entity_list","target":"device","filters":[{"field":"type","op":"ne","values":["router"]}],"time_range":{}}`:                                                          CodeInvalidValue,
		`{"v":1,"query_type":"entity_list","target":"device","filters":[{"field":"type","op":"eq","values":["router","switch"]}],"time_range":{}}`:                                                 CodeInvalidValue,
		`{"v":1,"query_type":"entity_list","target":"device","filters":[{"field":"reachability","op":"eq","values":["up"]},{"field":"reachability","op":"eq","values":["down"]}],"time_range":{}}`: CodeInvalidValue,
		// Liveness is current: no window on an inventory query, filter or not.
		`{"v":1,"query_type":"entity_list","target":"device","filters":[{"field":"reachability","op":"eq","values":["down"]}],"time_range":{"kind":"relative","last":"1h"}}`: CodeForbiddenFieldForType,
	} {
		mustFail(t, fakeScope{}, js, want)
	}
}
