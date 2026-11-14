// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package compile

// causal_changes_test.go — N-S3: change questions asked in causal words, and
// the "did any of those changes cause incidents?" follow-up, compile to the
// incident-anchored change list. The grammar never decides cause: the planner
// labels each row correlated, or same kind as a step of the engine's chain.

import (
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
)

func anchored(t *testing.T, r Result) *ast.Anchor {
	t.Helper()
	if r.Unparsed || r.AST == nil {
		t.Fatalf("unparsed: %+v", r)
	}
	if r.AST.Type != ast.ChangeList || r.AST.Time.Kind != ast.TimeIncidents || r.AST.Time.Anchor == nil || r.AST.Time.Anchor.Incidents == nil {
		t.Fatalf("want an incident-anchored change list, got %+v", r.AST)
	}
	return r.AST.Time.Anchor
}

func TestCausalChangePhrasingsCompileToTheIncidentAnchoredList(t *testing.T) {
	cases := []struct {
		q        string
		seam     string // seam_class filter on the incident set, "" = none
		wantLast string // relative window of the incident set, "" = not relative
	}{
		{"which changes caused incidents this week", "", ""},
		{"what changes caused sdwan incidents in the last 7 days", "sdwan", "7d"},
		{"show changes that led to outages yesterday", "", ""},
		{"any changes linked to sd-wan incidents this week", "sdwan", ""},
		{"list the changes behind every incident", "", "7d"},
		{"which config changes preceded incidents today", "", ""},
		{"changes that triggered vpn outages", "vpn", "7d"},
	}
	for _, tc := range cases {
		t.Run(tc.q, func(t *testing.T) {
			r := run(t, tc.q, cx)
			a := anchored(t, r)
			if a.Before != "30m" || a.After != "1m" {
				t.Errorf("default window 30m before / 1m after, got %s / %s", a.Before, a.After)
			}
			set := a.Incidents
			gotSeam := ""
			for _, f := range set.Filters {
				if f.Field == "seam_class" && len(f.Values) == 1 {
					gotSeam = f.Values[0]
				}
			}
			if gotSeam != tc.seam {
				t.Errorf("seam filter = %q, want %q", gotSeam, tc.seam)
			}
			if tc.wantLast != "" && (set.Time.Kind != ast.TimeRelative || set.Time.Last != tc.wantLast) {
				t.Errorf("incident window = %+v, want relative %s", set.Time, tc.wantLast)
			}
			if set.Time.Kind == "" {
				t.Error("the incident set must carry a window")
			}
		})
	}
}

// The reviewed N-S3 phrasings in docs/ai/golden-examples/planner-paraphrases.json
// (data route) compile WITHOUT a model, each with its own window.
func TestEveryS3ParaphraseCompilesDeterministically(t *testing.T) {
	cases := map[string]string{ // question → window before each incident
		"show me what changed 30 minutes before every SD-WAN incident this week":   "30m",
		"what changed in the 30 min before each sdwan incident this week":          "30m",
		"changes 30m before every sd-wan outage since monday":                      "30m",
		"for each sdwan incident this week, what changed in the prior 30 minutes":  "30m",
		"which changes caused incidents this week":                                 "30m",
		"what changes caused sdwan incidents in the last 7 days":                   "30m",
		"show changes that led to outages yesterday":                               "30m",
		"any changes linked to sd-wan incidents this week":                         "30m",
		"list the changes behind every incident":                                   "30m",
		"which config changes preceded incidents today":                            "30m",
		"changes that triggered vpn outages":                                       "30m",
		"what was changed an hour before every outage this month":                  "1h",
		"chnages 30 mins before each incident this week":                           "30m", //nolint:misspell // deliberate typo: the typo repair is part of what is tested
		"were there config changes right before the sdwan incidents":               "30m",
		"which wan changes happened 15 minutes before every incident":              "15m",
		"show the changes that came before each outage last week":                  "30m",
		"who changed what in the half hour before every sd-wan incident":           "30m",
		"list changes 45 minutes before all cloud incidents this week":             "45m",
		"what changes preceded the incidents since monday":                         "30m",
		"pull up every change made 30 min before each incident in the last 3 days": "30m",
		"changes 2 hrs before every incident":                                      "2h",
	}
	for q, want := range cases {
		t.Run(q, func(t *testing.T) {
			if a := anchored(t, run(t, q, cx)); a.Before != want {
				t.Fatalf("window before = %s, want %s", a.Before, want)
			}
		})
	}
}

func TestExplicitMinutesStillWin(t *testing.T) {
	r := run(t, "show me what changed 45 minutes before every sdwan incident this week", cx)
	if a := anchored(t, r); a.Before != "45m" {
		t.Fatalf("explicit window lost: %+v", a)
	}
}

// A single incident is not this query: "what caused this incident" belongs to
// the incident explanation, "what changed before this incident" to the
// one-incident anchor.
func TestSingleIncidentIsNotTheCausalSet(t *testing.T) {
	x := cx
	x.IncidentID = "11111111-2222-3333-4444-555555555555"
	r := run(t, "what changed before this incident", x)
	if r.AST != nil && r.AST.Time.Kind == ast.TimeIncidents {
		t.Fatalf("one incident must not become the per-incident set: %+v", r.AST)
	}
	if causalChangesRe.MatchString("which change caused the incident") {
		t.Fatal("singular, unquantified incident must not match the set phrasing")
	}
}

func TestDidThoseChangesCauseIncidentsFollowUp(t *testing.T) {
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)
	prior := &ast.AST{V: 1, Type: ast.ChangeList, Target: "change",
		Filters: []ast.Filter{{Field: "actor", Op: "in", Values: []string{"John Smith"}}, {Field: "class", Op: "eq", Values: []string{"wan"}}},
		Time:    ast.TimeRange{Kind: ast.TimeAbsolute, From: &from, To: &to},
		OrderBy: []ast.OrderKey{{Field: "event_at", Dir: "desc"}}, Limit: 100}
	x := cx
	x.PriorAST = prior
	for _, q := range []string{
		"did any of those changes cause incidents",
		"did any of these changes cause outages",
		"did they cause any incidents",
		"were those changes behind any incidents",
		"could those changes have caused incidents",
	} {
		t.Run(q, func(t *testing.T) {
			r := run(t, q, x)
			a := anchored(t, r)
			if len(r.AST.Filters) != 2 || r.AST.Filters[0].Field != "actor" || r.AST.Filters[1].Field != "class" {
				t.Errorf("the prior change filters must carry over: %+v", r.AST.Filters)
			}
			set := a.Incidents
			if set.Time.Kind != ast.TimeAbsolute || set.Time.From == nil || set.Time.To == nil || !set.Time.From.Equal(from) || !set.Time.To.Equal(to.Add(30*time.Minute)) {
				t.Errorf("incident set window = %+v, want the prior window widened by 30m at the end", set.Time)
			}
			if a.Before != "30m" {
				t.Errorf("before = %s", a.Before)
			}
		})
	}
}

func TestCausedFollowUpOnlyOverAChangeList(t *testing.T) {
	x := cx
	x.PriorAST = &ast.AST{V: 1, Type: ast.IncidentList, Target: "incident", Time: ast.TimeRange{Kind: ast.TimeRelative, Last: "24h"}}
	r := run(t, "did any of those changes cause incidents", x)
	if r.AST != nil && r.AST.Time.Kind == ast.TimeIncidents && r.AST.Type == ast.ChangeList && len(r.AST.Filters) > 0 {
		t.Fatalf("an incident list prior must not be rewritten as a change follow-up: %+v", r.AST)
	}
}

func TestCausedFollowUpKeepsAnAlreadyAnchoredQuery(t *testing.T) {
	set := &ast.IncidentSet{Time: ast.TimeRange{Kind: ast.TimeRelative, Last: "7d"}}
	x := cx
	x.PriorAST = &ast.AST{V: 1, Type: ast.ChangeList, Target: "change",
		Time: ast.TimeRange{Kind: ast.TimeIncidents, Anchor: &ast.Anchor{Incidents: set, Before: "45m", After: "1m"}}}
	r := run(t, "did any of those cause incidents", x)
	if a := anchored(t, r); a.Before != "45m" || a.Incidents.Time.Last != "7d" {
		t.Fatalf("an anchored prior keeps its own window: %+v", a)
	}
}
