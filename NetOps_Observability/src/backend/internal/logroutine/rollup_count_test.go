// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Tracker 410: the routine count is the originals from RollupCut onward plus
// the roll-ups before it, never the same session twice.

func TestAggSinceLeavesOldRoutineOriginalsToTheRollups(t *testing.T) {
	cut := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	b, _ := json.Marshal(AggSince(Sources{}, cut))
	s := string(b)
	for _, want := range []string{
		`"prefix":{"_index":"netops-syslogroutine-"}`,
		`"lt":"2026-11-18T10:00:00Z"`,
		`"must_not"`,
		RulePoll, RuleSessionDetail, // the read-time Clause is still the class
	} {
		if !strings.Contains(s, want) {
			t.Errorf("AggSince missing %s\n%s", want, s)
		}
	}
}

func TestSummarisedWindow(t *testing.T) {
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	cut := now.Add(-RollupCut)
	// A 7-day window: the roll-ups count [from, cut).
	from, to, ok := SummarisedWindow(now.Add(-7*24*time.Hour), now, now)
	if !ok || !from.Equal(now.Add(-7*24*time.Hour)) || !to.Equal(cut) {
		t.Errorf("7d window → [%v, %v) %v, want [.., %v)", from, to, ok, cut)
	}
	// A window wholly inside the last day: nothing for the roll-ups.
	if _, _, ok := SummarisedWindow(now.Add(-6*time.Hour), now, now); ok {
		t.Error("a window inside the originals' counted part needs no roll-up count")
	}
	// A window that ends before the cut: all of it.
	f2, t2, ok := SummarisedWindow(now.Add(-72*time.Hour), now.Add(-48*time.Hour), now)
	if !ok || !f2.Equal(now.Add(-72*time.Hour)) || !t2.Equal(now.Add(-48*time.Hour)) {
		t.Errorf("old window = [%v, %v) %v", f2, t2, ok)
	}
}

func TestRollupSumBodyAndParse(t *testing.T) {
	from := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	tenant := map[string]any{"term": map[string]any{"tenant_id": "acme"}}
	b, _ := json.Marshal(RollupSumBody(from, to, []any{tenant}, []any{map[string]any{"terms": map[string]any{"tenant_id": []string{"x"}}}}))
	s := string(b)
	for _, want := range []string{`"size":0`, `"sum":{"field":"occurrence_count"}`, `"gte":"2026-11-12T00:00:00Z"`, `"lt":"2026-11-13T00:00:00Z"`, `"tenant_id":"acme"`, `"must_not"`} {
		if !strings.Contains(s, want) {
			t.Errorf("RollupSumBody missing %s\n%s", want, s)
		}
	}
	n, err := ParseRollupSum([]byte(`{"aggregations":{"n":{"value":12345.0}}}`))
	if err != nil || n != 12345 {
		t.Errorf("ParseRollupSum = %d, %v", n, err)
	}
}

func TestInjectSummaryCarriesTheOlderPartAndInjectIsUnchanged(t *testing.T) {
	raw := []byte(`{"hits":{"total":{"value":3}},"aggregations":{"` + AggName + `":{"doc_count":42}}}`)
	out, err := InjectSummary(raw, Summary{Included: false, Summarised: 9000})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), `{"routine_mgmt":{"included":false,"count":42,"summarised":9000},`) {
		t.Errorf("InjectSummary = %s", out)
	}
	out, _ = InjectSummary(raw, Summary{SummarisedNote: NoteTextQuery})
	if !strings.Contains(string(out), `"summarised_note":"text_query"`) {
		t.Errorf("the note is missing: %s", out)
	}
	// Inject (no older part) renders exactly the pre-410 member.
	out, _ = Inject(raw, true)
	if !strings.HasPrefix(string(out), `{"routine_mgmt":{"included":true,"count":42},`) {
		t.Errorf("Inject changed shape: %s", out)
	}
}
