// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rbac

import (
	"encoding/json"
	"testing"
	"time"
)

// elevation_condition_test.go — the elevation CONDITION on a role binding.
//
// The predicate has to survive the kv round-trip: a binding is written as JSON
// and read back through map[string]any, so what went in as a Go bool comes back
// as a bool, but a record someone hand-edited (or a future store that stringifies)
// carries "true". Both must read as an elevation, and nothing else may.

func TestIsElevationSurvivesTheJSONRoundTrip(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	in := RoleBinding{
		ID: "x", PrincipalID: "u", RoleID: "operator", ScopeID: "tenant:t1", Effect: EffectAllow,
		ExpiresAt: &exp,
		Condition: map[string]any{
			ConditionElevation:         true,
			ConditionElevationProvider: "elev",
			ConditionElevationSID:      "sid-1",
			ConditionElevationTenant:   "t1",
		},
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out RoleBinding
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if !out.IsElevation() {
		t.Fatal("an elevation binding stopped being one after a store round-trip")
	}
	if out.ConditionString(ConditionElevationProvider) != "elev" ||
		out.ConditionString(ConditionElevationSID) != "sid-1" ||
		out.ConditionString(ConditionElevationTenant) != "t1" {
		t.Errorf("condition strings lost in the round-trip: %+v", out.Condition)
	}
	if out.IsBreakGlass() {
		t.Error("an elevation binding also claims to be break-glass")
	}
}

func TestIsElevationIsFailClosed(t *testing.T) {
	for name, cond := range map[string]map[string]any{
		"nil condition":  nil,
		"absent key":     {ConditionBreakGlass: true},
		"false":          {ConditionElevation: false},
		"string false":   {ConditionElevation: "false"},
		"number":         {ConditionElevation: 1},
		"object":         {ConditionElevation: map[string]any{"a": 1}},
		"empty string":   {ConditionElevation: ""},
		"unrelated word": {ConditionElevation: "yes"},
	} {
		if (RoleBinding{Condition: cond}).IsElevation() {
			t.Errorf("%s read as an elevation grant", name)
		}
	}
	if !(RoleBinding{Condition: map[string]any{ConditionElevation: "TRUE"}}).IsElevation() {
		t.Error(`a stored "TRUE" must still read as an elevation grant`)
	}
	if got := (RoleBinding{}).ConditionString(ConditionElevationProvider); got != "" {
		t.Errorf("ConditionString on a bare binding = %q", got)
	}
}
