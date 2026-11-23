// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"strings"
	"testing"
)

func TestRewriteOperatorTextTouchesProseNotIdentifiers(t *testing.T) {
	up := func(s string) string { return strings.ReplaceAll(s, "dev-1-abcd", "Dev1") }
	a := Answer{
		Text: "dev-1-abcd down", Title: "dev-1-abcd", NextActions: []string{"reboot dev-1-abcd"},
		MissingEvidence: []string{"no SNMP from dev-1-abcd"},
		Recommendations: []Recommendation{{ID: "dev-1-abcd", Title: "Fix dev-1-abcd", Steps: []string{"ssh dev-1-abcd"}, Why: "dev-1-abcd flapped", Basis: []string{"c-dev-1-abcd"}}},
		Problem:         &ProblemExplanation{ProblemID: "dev-1-abcd", Title: "dev-1-abcd", Timeline: []string{"dev-1-abcd down"}, WhyFirst: []string{"dev-1-abcd"}},
		CurrentState:    &CurrentStateSummary{Summary: "dev-1-abcd", ImpactedEntities: []string{"dev-1-abcd:Gi1"}},
		Citations:       []Citation{{ID: "dev-1-abcd", Label: "syslog dev-1-abcd", Href: "#/devices/dev-1-abcd"}},
		Provider:        "dev-1-abcd",
	}
	a.RewriteOperatorText(up)
	for name, got := range map[string]string{
		"text": a.Text, "title": a.Title, "next": a.NextActions[0], "missing": a.MissingEvidence[0],
		"rec title": a.Recommendations[0].Title, "rec step": a.Recommendations[0].Steps[0], "rec why": a.Recommendations[0].Why,
		"problem title": a.Problem.Title, "timeline": a.Problem.Timeline[0], "why first": a.Problem.WhyFirst[0],
		"state": a.CurrentState.Summary, "impacted": a.CurrentState.ImpactedEntities[0],
		"citation label": a.Citations[0].Label,
	} {
		if !strings.Contains(got, "Dev1") || strings.Contains(got, "dev-1-abcd") {
			t.Errorf("%s not rewritten: %q", name, got)
		}
	}
	if a.Problem.ProblemID != "dev-1-abcd" || a.Citations[0].ID != "dev-1-abcd" || a.Citations[0].Href != "#/devices/dev-1-abcd" || a.Provider != "dev-1-abcd" ||
		a.Recommendations[0].ID != "dev-1-abcd" || a.Recommendations[0].Basis[0] != "c-dev-1-abcd" {
		t.Fatalf("identifiers must not change: %+v", a)
	}
	var nilAns *Answer
	nilAns.RewriteOperatorText(up) // must not panic
	b := Answer{Text: "x"}
	b.RewriteOperatorText(nil)
	if b.Text != "x" {
		t.Fatal("a nil rewrite must change nothing")
	}
}
