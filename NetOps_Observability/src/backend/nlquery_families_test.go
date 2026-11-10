// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/ai"
	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/chips"
	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/resolve"
)

// nlqAdmits is the server's half of the data arm's routing (hybrid NLU plan
// A4): what the router's options let the arm answer.
func TestNLQAdmits(t *testing.T) {
	withRef := &nlqast.AST{Type: nlqast.IncidentList, Refs: []nlqast.EntityRef{{Type: "device", ID: "device:a"}}}
	noRef := &nlqast.AST{Type: nlqast.IncidentList}
	metric := &nlqast.AST{Type: nlqast.MetricSeries, Refs: withRef.Refs}
	unparsed := nlqCompiled{res: compile.Result{Unparsed: true}}
	notFound := nlqCompiled{res: compile.Result{NotFound: &compile.NotFound{Name: "RETAIL"}}}
	cand := []resolve.Ref{{EntityID: "site:dfw-hq", EntityType: "site", NeedsConfirmation: true}}
	offered := nlqCompiled{res: compile.Result{Unparsed: true, NotUnderstood: []string{"dalas"},
		DidYouMean: []compile.Suggestion{{Word: "dalas", Refs: cand}}}, asks: []chips.Ask{{Word: "dalas", Label: "Dallas HQ", Question: "q"}}}
	partly := offered
	partly.res.NotUnderstood = []string{"dalas", "zork"}
	for name, c := range map[string]struct {
		c    nlqCompiled
		opts ai.DataOpts
		want bool
	}{
		"symptom + incidents of one entity":  {nlqCompiled{checked: withRef}, ai.DataOpts{IncidentRefOnly: true}, true},
		"symptom + incidents of nothing":     {nlqCompiled{checked: noRef}, ai.DataOpts{IncidentRefOnly: true}, false},
		"symptom + a metric":                 {nlqCompiled{checked: metric}, ai.DataOpts{IncidentRefOnly: true}, false},
		"symptom + not compiled":             {unparsed, ai.DataOpts{IncidentRefOnly: true}, false},
		"unparsed, router has an intent":     {unparsed, ai.DataOpts{ClassicIntent: "current_state"}, false},
		"unparsed, router is at a dead end":  {unparsed, ai.DataOpts{ClassicIntent: "capability"}, true},
		"not found, router has an intent":    {notFound, ai.DataOpts{ClassicIntent: "product_question"}, false},
		"not found, router is at a dead end": {notFound, ai.DataOpts{ClassicIntent: "capability"}, true},
		"compiled, any intent":               {nlqCompiled{checked: metric}, ai.DataOpts{ClassicIntent: "telemetry_summary"}, true},
		"unparsed but every word offered":    {offered, ai.DataOpts{ClassicIntent: "incident_list"}, true},
		"unparsed, one word not offered":     {partly, ai.DataOpts{ClassicIntent: "incident_list"}, false},
	} {
		if got := nlqAdmits(c.c, c.opts); got != c.want {
			t.Errorf("%s: admits = %v, want %v", name, got, c.want)
		}
	}
}
