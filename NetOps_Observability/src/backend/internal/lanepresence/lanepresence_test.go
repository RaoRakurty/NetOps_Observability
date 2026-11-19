// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package lanepresence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 19, 2, 0, 0, 0, time.UTC)

func TestLogQuery(t *testing.T) {
	tf := map[string]any{"term": map[string]any{"tenant_id": "acme"}}
	mn := []any{map[string]any{"terms": map[string]any{"tenant_id": []string{"x"}}}}
	body, ok := LogQuery(Device{ID: "edge-1", Name: "edge-1", Address: "10.0.0.1"}, now, Window, tf, mn)
	if !ok {
		t.Fatal("a device with identities must build a query")
	}
	b, _ := json.Marshal(body)
	s := string(b)
	for _, want := range []string{
		`"size":0`, `"terminate_after":1`, `"track_total_hits":1`,
		`"gte":"2026-11-18T02:00:00Z"`, `"lte":"2026-11-19T02:00:00Z"`,
		`"device_id":["edge-1","10.0.0.1"]`, // de-duplicated: id == name
		`"tenant_id":"acme"`, `"must_not"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("query missing %s\n%s", want, s)
		}
	}
	// A cross-tenant caller has no per-document filter: none is invented.
	body, _ = LogQuery(Device{ID: "edge-1"}, now, Window, nil, nil)
	b, _ = json.Marshal(body)
	if strings.Contains(string(b), "tenant_id") || strings.Contains(string(b), "must_not") {
		t.Errorf("no filter given, none expected: %s", b)
	}
	if _, ok := LogQuery(Device{}, now, Window, nil, nil); ok {
		t.Error("a device with no identity must not build a match-everything query")
	}
}

func TestFlowSQL(t *testing.T) {
	sql, ok := FlowSQL(Device{Address: " 10.0.0.1 "}, Window, " AND (tenant_id = 'acme')")
	if !ok {
		t.Fatal("a valid address must build")
	}
	for _, want := range []string{"INTERVAL 86400 SECOND", "sampler_address = '10.0.0.1'", " AND (tenant_id = 'acme')", "LIMIT 1"} {
		if !strings.Contains(sql, want) {
			t.Errorf("SQL missing %q:\n%s", want, sql)
		}
	}
	if sql, _ := FlowSQL(Device{Address: "::ffff:10.0.0.2"}, Window, ""); !strings.Contains(sql, "'10.0.0.2'") {
		t.Errorf("a v4-mapped address is rendered as v4:\n%s", sql)
	}
	for _, bad := range []string{"", "edge-1", "10.0.0.1' OR 1=1 --", "10.0.0.256"} {
		if _, ok := FlowSQL(Device{Address: bad}, Window, ""); ok {
			t.Errorf("address %q must not build SQL", bad)
		}
	}
	if _, ok := FlowSQL(Device{Address: "10.0.0.1"}, 0, ""); ok {
		t.Error("a zero window must not build")
	}
}
