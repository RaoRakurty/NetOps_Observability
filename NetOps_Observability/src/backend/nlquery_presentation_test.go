// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_presentation_test.go — the server-side PresentationPlan (tracker 337
// N-E1) through the root wiring:
//
//   - every route that returns a ResultSet returns the plan beside it
//     (/api/ai/query/execute, a conversation turn, the /api/ai/ask data arm);
//   - the view is the server's, chosen from the query; a model suggestion is
//     honoured only as a closed-enum member that fits, and anything else is
//     ignored with a fixed disclosure — the model's words never reach it;
//   - §3a: the plan carries no data beyond the ResultSet it describes, and a
//     refused (foreign) read carries no plan at all.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/present"
)

func planOf(t *testing.T, v any) map[string]any {
	t.Helper()
	p, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("no presentation plan in the answer: %v", v)
	}
	return p
}

// The plan describes; it never repeats. No device id, entity or value from the
// result (or the query's entities) may appear in it.
func assertPlanCarriesNoData(t *testing.T, p map[string]any) {
	t.Helper()
	raw := nlqJSON(p)
	for _, leak := range []string{"dev-a", "dev-b", "edge-a", "t-a", "t-b", "12", "48", "<script", "onerror"} {
		if strings.Contains(raw, leak) {
			t.Fatalf("the presentation plan carries %q: %s", leak, raw)
		}
	}
}

func TestQueryExecuteReturnsTheServersPlan(t *testing.T) {
	t.Setenv("FEATURE_AI", "true")
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"values":[[1,"12"]]}]}}`)) // best-effort: a stub VictoriaMetrics reply
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	s, a, b := nlqAPIFixture(t)
	q := `{"ast":{"v":1,"query_type":"metric_series","target":"device","metric":"cpu_util_pct","entities":[{"type":"device","id":"device:dev-a"}],"time_range":{"kind":"relative","last":"1h"}}}`

	code, out := nlqAPI(t, s, a, "/api/ai/query/execute", q)
	if code != http.StatusOK || out["result"] == nil {
		t.Fatalf("tenant A execute: %d %v", code, out)
	}
	p := planOf(t, out["presentation"])
	if p["primary_view"] != string(present.TimeSeries) || p["secondary_view"] != string(present.Table) ||
		p["chosen_by"] != present.ChosenByServer || p["disclosure"] != nil {
		t.Fatalf("a metric series is drawn over time, by the server: %v", p)
	}
	if p["title"] != "CPU util pct over time" {
		t.Fatalf("title from the catalog name: %v", p["title"])
	}
	assertPlanCarriesNoData(t, p)

	// §3a: tenant B naming A's device is refused before anything runs — and a
	// refusal carries no plan describing A's data.
	code, out = nlqAPI(t, s, b, "/api/ai/query/execute", q)
	if code != http.StatusUnprocessableEntity || out["presentation"] != nil || out["result"] != nil {
		t.Fatalf("a foreign read must carry neither a result nor a plan: %d %v", code, out)
	}
}

func TestAConversationTurnCarriesThePlan(t *testing.T) {
	s, a, _ := convoFixture(t)
	id := startConvo(t, s, a)
	code, out := ask(t, s, a, id, "show cpu on edge-a for the last hour")
	if code != http.StatusOK || out["result"] == nil {
		t.Fatalf("turn: %d %v", code, out)
	}
	p := planOf(t, out["presentation"])
	if p["primary_view"] != string(present.TimeSeries) || p["chosen_by"] != present.ChosenByServer {
		t.Fatalf("turn plan: %v", p)
	}
	assertPlanCarriesNoData(t, p)
	// Not understood → nothing ran → no plan.
	if _, out := ask(t, s, a, id, "show cpu on that thing over there please"); out["result"] == nil && out["presentation"] != nil {
		t.Fatalf("an answer without a result must carry no plan: %v", out)
	}
}

func TestTheModelMayOnlySuggestAView(t *testing.T) {
	vm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"result":[{"metric":{"device":"dev-a"},"values":[[1,"12"],[2,"48"]]}]}}`)) // best-effort: a stub VictoriaMetrics reply
	}))
	defer vm.Close()
	t.Setenv("VICTORIA_URL", vm.URL)
	envelope := func(view string) string {
		return `{"ast":` + cpuOnDevA + `,"unmatched_names":[],"view":` + view + `}`
	}
	for _, c := range []struct {
		name, reply, primary, secondary, chosenBy, disclosure string
	}{
		{"no suggestion", modelEnvelope(cpuOnDevA), "TIME_SERIES", "TABLE", present.ChosenByServer, ""},
		{"fitting enum member", envelope(`"TABLE"`), "TABLE", "TIME_SERIES", present.ChosenByModel, ""},
		{"enum member that does not fit", envelope(`"DIFF"`), "TIME_SERIES", "TABLE", present.ChosenByServer, present.DisclosureNoFit},
		{"not in the enum", envelope(`"PIE_CHART"`), "TIME_SERIES", "TABLE", present.ChosenByServer, present.DisclosureNotAView},
		{"markup", envelope(`"<script>alert(1)</script>"`), "TIME_SERIES", "TABLE", present.ChosenByServer, present.DisclosureNotAView},
		{"wrong type", envelope(`{"primary_view":"TABLE"}`), "TIME_SERIES", "TABLE", present.ChosenByServer, present.DisclosureNotAView},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, a, _, _ := modelFallbackFixture(t, c.reply, "t-a")
			out := askIris(t, s, a, hotCPUQuestion)
			if out["mode"] != "data_query" {
				t.Fatalf("the model-compiled query must answer on the data arm: %v", out)
			}
			data, ok := out["data"].(map[string]any)
			if !ok || data["result"] == nil {
				t.Fatalf("no data answer: %v", out)
			}
			p := planOf(t, data["presentation"])
			got := func(k string) string { v, _ := p[k].(string); return v }
			if got("primary_view") != c.primary || got("secondary_view") != c.secondary || got("chosen_by") != c.chosenBy || got("disclosure") != c.disclosure {
				t.Fatalf("plan %v; want %s/%s by %s, disclosure %q", p, c.primary, c.secondary, c.chosenBy, c.disclosure)
			}
			assertPlanCarriesNoData(t, p)
			if strings.Contains(nlqJSON(out), "PIE_CHART") || strings.Contains(nlqJSON(out), "<script") {
				t.Fatalf("the model's suggestion text reached the answer: %s", nlqJSON(out))
			}
		})
	}
}

// The plan's JSON keys are the client contract; nothing else rides along.
func TestThePlanJSONIsTheClientContract(t *testing.T) {
	b, err := json.Marshal(present.Select(nil, nil, present.Suggestion{}))
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"primary_view":"SUMMARY","title":"Answer","chosen_by":"server"}` {
		t.Fatalf("plan JSON: %s", b)
	}
}
