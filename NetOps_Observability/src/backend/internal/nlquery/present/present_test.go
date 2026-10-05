// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package present

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/plan"
)

func q(t ast.QueryType, groupBy ...string) *ast.AST {
	return &ast.AST{V: ast.Version, Type: t, GroupBy: groupBy}
}

func changeRows(n int) []plan.Row {
	out := make([]plan.Row, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, plan.Row{"change_id": "c" + string(rune('a'+i)), "actor": "alice"})
	}
	return out
}

// Every result shape the engine returns gets exactly one deterministic plan.
func TestDefaultPlanForEveryShape(t *testing.T) {
	diffRow := plan.Row{"change_id": "c1", "before": map[string]any{"mtu": 1500}, "after": map[string]any{"mtu": 9000}}
	cases := []struct {
		name      string
		q         *ast.AST
		rs        *plan.ResultSet
		primary   View
		secondary View
		title     string
	}{
		{"metric_series", q(ast.MetricSeries), &plan.ResultSet{Metric: "circuit_loss_pct"}, TimeSeries, Table, "Circuit loss pct over time"},
		{"metric_series no metric", q(ast.MetricSeries), &plan.ResultSet{}, TimeSeries, Table, "Over time"},
		{"metric_topk", q(ast.MetricTopK), &plan.ResultSet{Metric: "cpu_util_pct"}, Bar, Table, "Highest CPU util pct"},
		{"metric_topk no metric", q(ast.MetricTopK), &plan.ResultSet{}, Bar, Table, "Highest values"},
		{"metric_filter", q(ast.MetricFilter), &plan.ResultSet{Metric: "if_errors"}, Table, "", "If errors matching the condition"},
		{"compare_windows", q(ast.CompareWindows), &plan.ResultSet{Metric: "probe_rtt_ms"}, Bar, Table, "Probe RTT ms: this window against the earlier one"},
		{"change_list", q(ast.ChangeList), &plan.ResultSet{Rows: changeRows(3)}, Timeline, Table, "Changes in this window"},
		{"change_list grouped", q(ast.ChangeList, "actor"), &plan.ResultSet{Rows: changeRows(3)}, Bar, Table, "Changes by Actor"},
		{"change_list grouped bad field", q(ast.ChangeList, "Actor<b>"), &plan.ResultSet{Rows: changeRows(3)}, Timeline, Table, "Changes in this window"},
		{"change_list one diffable", q(ast.ChangeList), &plan.ResultSet{Rows: []plan.Row{diffRow}}, Diff, ChangeCard, "What changed"},
		{"change_list one without diff", q(ast.ChangeList), &plan.ResultSet{Rows: changeRows(1)}, Timeline, Table, "Changes in this window"},
		{"change_list empty", q(ast.ChangeList), &plan.ResultSet{}, Timeline, Table, "Changes in this window"},
		{"incident_list", q(ast.IncidentList), &plan.ResultSet{}, Table, Timeline, "Incidents in this window"},
		{"incident_explain", q(ast.IncidentExplain), &plan.ResultSet{}, IncidentCard, EvidenceList, "Why this incident happened"},
		{"reserved flow_top", q(ast.FlowTop), &plan.ResultSet{}, Summary, "", "Answer"},
		{"nil query", nil, &plan.ResultSet{}, Summary, "", "Answer"},
		{"nil result", q(ast.MetricSeries), nil, Summary, "", "Answer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Select(c.q, c.rs, Suggestion{})
			if p.PrimaryView != c.primary || p.SecondaryView != c.secondary || p.Title != c.title {
				t.Fatalf("got %s/%s %q, want %s/%s %q", p.PrimaryView, p.SecondaryView, p.Title, c.primary, c.secondary, c.title)
			}
			if p.ChosenBy != ChosenByServer || p.Disclosure != "" {
				t.Fatalf("no suggestion: chosen_by=%q disclosure=%q", p.ChosenBy, p.Disclosure)
			}
			if !p.PrimaryView.Valid() || (p.SecondaryView != "" && !p.SecondaryView.Valid()) {
				t.Fatalf("plan left the enum: %+v", p)
			}
			if p.SecondaryView == p.PrimaryView {
				t.Fatalf("secondary repeats primary: %+v", p)
			}
			// Deterministic: the same inputs give the same plan.
			if again := Select(c.q, c.rs, Suggestion{}); !reflect.DeepEqual(p, again) {
				t.Fatalf("not deterministic: %+v vs %+v", p, again)
			}
			// The server's own choice always fits the shape it was chosen for.
			if !Fits(p.PrimaryView, c.q, c.rs) {
				t.Fatalf("default primary %s does not fit its own shape", p.PrimaryView)
			}
		})
	}
}

func raw(s string) Suggestion { return Suggestion{Raw: json.RawMessage(s)} }

// The model may only suggest — and only an enum member that fits the shape.
func TestModelSuggestion(t *testing.T) {
	changes := &plan.ResultSet{Rows: changeRows(3)}
	cases := []struct {
		name       string
		q          *ast.AST
		rs         *plan.ResultSet
		s          Suggestion
		primary    View
		secondary  View
		chosenBy   string
		disclosure string
	}{
		{"none", q(ast.ChangeList), changes, Suggestion{}, Timeline, Table, ChosenByServer, ""},
		{"json null is none", q(ast.ChangeList), changes, raw(`null`), Timeline, Table, ChosenByServer, ""},
		{"accepted different view", q(ast.ChangeList), changes, raw(`"BAR"`), Bar, Timeline, ChosenByModel, ""},
		{"accepted same as server", q(ast.ChangeList), changes, raw(`"TIMELINE"`), Timeline, Table, ChosenByModel, ""},
		{"accepted summary", q(ast.ChangeList), changes, raw(`"SUMMARY"`), Summary, Timeline, ChosenByModel, ""},
		{"accepted over summary default", q(ast.FlowTop), &plan.ResultSet{}, raw(`"SUMMARY"`), Summary, "", ChosenByModel, ""},
		{"lower case is not the enum", q(ast.ChangeList), changes, raw(`"bar"`), Timeline, Table, ChosenByServer, DisclosureNotAView},
		{"unknown name", q(ast.ChangeList), changes, raw(`"PIE"`), Timeline, Table, ChosenByServer, DisclosureNotAView},
		{"markup", q(ast.ChangeList), changes, raw(`"<script>alert(1)</script>"`), Timeline, Table, ChosenByServer, DisclosureNotAView},
		{"padded", q(ast.ChangeList), changes, raw(`" BAR"`), Timeline, Table, ChosenByServer, DisclosureNotAView},
		{"number", q(ast.ChangeList), changes, raw(`3`), Timeline, Table, ChosenByServer, DisclosureNotAView},
		{"object", q(ast.ChangeList), changes, raw(`{"view":"BAR"}`), Timeline, Table, ChosenByServer, DisclosureNotAView},
		{"array", q(ast.ChangeList), changes, raw(`["BAR"]`), Timeline, Table, ChosenByServer, DisclosureNotAView},
		{"oversized", q(ast.ChangeList), changes, raw(`"` + strings.Repeat("A", 200) + `"`), Timeline, Table, ChosenByServer, DisclosureNotAView},
		{"not json", q(ast.ChangeList), changes, raw(`BAR`), Timeline, Table, ChosenByServer, DisclosureNotAView},
		{"enum but wrong shape", q(ast.MetricSeries), &plan.ResultSet{}, raw(`"DIFF"`), TimeSeries, Table, ChosenByServer, DisclosureNoFit},
		{"topology fits nothing", q(ast.ChangeList), changes, raw(`"TOPOLOGY"`), Timeline, Table, ChosenByServer, DisclosureNoFit},
		{"change card needs one change", q(ast.ChangeList), changes, raw(`"CHANGE_CARD"`), Timeline, Table, ChosenByServer, DisclosureNoFit},
		{"change card for one change", q(ast.ChangeList), &plan.ResultSet{Rows: changeRows(1)}, raw(`"CHANGE_CARD"`), ChangeCard, Timeline, ChosenByModel, ""},
		{"diff needs a diff", q(ast.ChangeList), &plan.ResultSet{Rows: changeRows(1)}, raw(`"DIFF"`), Timeline, Table, ChosenByServer, DisclosureNoFit},
		{"diff with unified", q(ast.ChangeList), &plan.ResultSet{Rows: []plan.Row{{"change_id": "c", "unified": "-a\n+b"}}}, raw(`"DIFF"`), Diff, Timeline, ChosenByModel, ""},
		{"timeline for metrics refused", q(ast.MetricTopK), &plan.ResultSet{}, raw(`"TIMELINE"`), Bar, Table, ChosenByServer, DisclosureNoFit},
		{"incident card one incident", q(ast.IncidentList), &plan.ResultSet{Rows: []plan.Row{{"incident_id": "i"}}}, raw(`"INCIDENT_CARD"`), IncidentCard, Table, ChosenByModel, ""},
		{"recommendation never", q(ast.IncidentExplain), &plan.ResultSet{}, raw(`"RECOMMENDATION_CARD"`), IncidentCard, EvidenceList, ChosenByServer, DisclosureNoFit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := Select(c.q, c.rs, c.s)
			if p.PrimaryView != c.primary || p.SecondaryView != c.secondary || p.ChosenBy != c.chosenBy || p.Disclosure != c.disclosure {
				t.Fatalf("got %s/%s by=%q disclosure=%q; want %s/%s by=%q disclosure=%q",
					p.PrimaryView, p.SecondaryView, p.ChosenBy, p.Disclosure, c.primary, c.secondary, c.chosenBy, c.disclosure)
			}
			if !p.PrimaryView.Valid() || (p.SecondaryView != "" && !p.SecondaryView.Valid()) {
				t.Fatalf("a suggestion pushed the plan out of the enum: %+v", p)
			}
			// The model's words never reach the plan.
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), "script") || strings.Contains(string(b), "PIE") || strings.Contains(string(b), "AAAA") {
				t.Fatalf("suggestion text leaked into the plan: %s", b)
			}
		})
	}
}

// §3a: the plan is a description of the ResultSet, never a second copy of its
// data. Row values, entity ids and series labels never appear in it, and
// Select leaves the result untouched.
func TestPlanCarriesNoResultData(t *testing.T) {
	secret := "tenant-b-secret-device"
	rs := &plan.ResultSet{
		QueryID: "q-1", Metric: "cpu_util_pct",
		Rows:   []plan.Row{{"change_id": secret, "actor": secret, "before": secret, "after": secret, "summary": "<img src=x onerror=alert(1)>"}},
		Series: []plan.OutSeries{{Entity: map[string]string{"device": secret}, Points: []plan.Point{}}},
		Notes:  []string{secret},
		Provenance: plan.Provenance{Source: "victoriametrics", Entities: []ast.EntityRef{{Type: "device", ID: secret}},
			Physical: []string{secret}},
	}
	before, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []ast.QueryType{ast.MetricSeries, ast.MetricTopK, ast.MetricFilter, ast.CompareWindows,
		ast.ChangeList, ast.IncidentList, ast.IncidentExplain} {
		for _, s := range []Suggestion{{}, raw(`"TABLE"`), raw(`"` + secret + `"`)} {
			p := Select(&ast.AST{Type: typ, Refs: []ast.EntityRef{{Type: "device", ID: secret}}}, rs, s)
			b, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), secret) || strings.Contains(string(b), "onerror") {
				t.Fatalf("%s: plan carries result data: %s", typ, b)
			}
			if len(p.Highlight) != 0 || len(p.TableColumns) != 0 {
				t.Fatalf("%s: unexpected highlight/columns %+v", typ, p)
			}
		}
	}
	after, err := json.Marshal(rs)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("Select mutated the ResultSet")
	}
}

// The JSON field names are the client contract (presentation.ts PresentationPlan).
func TestPlanJSONShape(t *testing.T) {
	p := Select(q(ast.ChangeList), &plan.ResultSet{Rows: changeRows(2)}, raw(`"PIE"`))
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	want := []string{"chosen_by", "disclosure", "primary_view", "secondary_view", "title"}
	var got []string
	for k := range m {
		got = append(got, k)
	}
	if len(got) != len(want) {
		t.Fatalf("plan keys %v, want %v", got, want)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Fatalf("plan missing %q: %s", k, b)
		}
	}
}

func TestHumanizeMatchesClient(t *testing.T) {
	for in, want := range map[string]string{
		"object_kind": "Object kind", "wan_rtt": "WAN RTT", "id": "ID", "bgp_peer": "BGP peer",
		"cpu_util_pct": "CPU util pct", "a": "A", "": "", "Bad Name": "", "x<y": "", "__proto__": "",
	} {
		if got := Humanize(in); got != want {
			t.Errorf("Humanize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEnumsHaveNoDuplicates(t *testing.T) {
	seen := map[View]bool{}
	for _, v := range Views() {
		if seen[v] || !v.Valid() {
			t.Fatalf("view %q duplicated or invalid", v)
		}
		seen[v] = true
	}
	if View("").Valid() || View("summary").Valid() {
		t.Fatal("Valid accepts a non-member")
	}
}
