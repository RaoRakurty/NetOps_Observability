// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestParseParam(t *testing.T) {
	for in, want := range map[string]bool{"": false, "false": false, "0": false, "true": true, "1": true, " TRUE ": true} {
		got, err := ParseParam(in)
		if err != nil || got != want {
			t.Errorf("ParseParam(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"yes", "all", "true;drop"} {
		if _, err := ParseParam(bad); !errors.Is(err, ErrBadParam) {
			t.Errorf("ParseParam(%q) err = %v, want ErrBadParam", bad, err)
		}
	}
}

func TestInjectAddsTheSummaryAndKeepsTheAnswer(t *testing.T) {
	raw := []byte(`{"took":3,"hits":{"total":{"value":12},"hits":[{"_id":"a","_source":{"message":"x"}}]},` +
		`"aggregations":{"` + AggName + `":{"doc_count":1234}}}`)
	out, err := Inject(raw, false)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Routine Summary `json:"routine_mgmt"`
		Took    int     `json:"took"`
		Hits    struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []map[string]any `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("injected answer is not JSON: %v\n%s", err, out)
	}
	if got.Routine != (Summary{Included: false, Count: 1234}) {
		t.Errorf("summary = %+v", got.Routine)
	}
	if got.Took != 3 || got.Hits.Total.Value != 12 || len(got.Hits.Hits) != 1 {
		t.Errorf("the answer changed: %s", out)
	}

	// No aggregation (an error answer, or a store that skipped it): count 0.
	out, err = Inject([]byte(`{"hits":{"hits":[]}}`), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &got); err != nil || got.Routine != (Summary{Included: true}) {
		t.Errorf("summary without aggregation = %+v (%v): %s", got.Routine, err, out)
	}

	// An empty object stays valid JSON.
	out, err = Inject([]byte(` {}`), false)
	if err != nil || string(out) != `{"routine_mgmt":{"included":false,"count":0}}` {
		t.Errorf("empty object: %s, %v", out, err)
	}

	// Not an object: untouched.
	if out, err := Inject([]byte(`[1]`), false); err != nil || string(out) != `[1]` {
		t.Errorf("non-object changed: %s, %v", out, err)
	}
	// An object that does not parse is refused, never relayed half-read.
	if _, err := Inject([]byte(`{"aggregations":`), false); err == nil {
		t.Error("a truncated answer must be refused")
	}
}
