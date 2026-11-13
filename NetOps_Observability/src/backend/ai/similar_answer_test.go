// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"strings"
	"testing"
	"time"
)

// recallSpy records which case the recall was asked about.
type recallSpy struct {
	asked []string
	res   SimilarIncidents
	err   error
}

func (r *recallSpy) fn(_ context.Context, p Principal, id, _ string) (SimilarIncidents, error) {
	r.asked = append(r.asked, p.Tenant+"/"+id)
	return r.res, r.err
}

func similarOrch(spy *recallSpy) *Orchestrator {
	o := &Orchestrator{DS: newMockDS(), Flags: func(string) bool { return true }}
	if spy != nil {
		o.Troubleshoot.SimilarIncidents = spy.fn
	}
	return o
}

func similarPlan(id string) Plan {
	pl, _ := planForRoute(PlanRouteSimilar, map[string]string{})
	if id != "" {
		pl.Entities["problem_id"] = id
	}
	return pl
}

func twoMatches() SimilarIncidents {
	return SimilarIncidents{Verdict: "similar_incidents", Examined: 9,
		Caveat: "Similar is not the same cause: past incidents are context, never confirmation of this one.",
		Matches: []SimilarMatch{
			{CorrelationID: "pa", Strength: "strong", MatchedOn: []string{"signature", "seam"},
				OccurredAt: time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)},
			{CorrelationID: "0f6e2a51-aaaa-bbbb-cccc-000000000001", Strength: "similar", MatchedOn: []string{"owner domain", "devices"},
				OccurredAt: time.Date(2026, 9, 14, 9, 0, 0, 0, time.UTC)},
		}}
}

// A named case: recall runs for THAT case, past cases are cited as HISTORICAL,
// the caveat is said, and no fix is ever claimed.
func TestSimilarAnswerForANamedCase(t *testing.T) {
	spy := &recallSpy{res: twoMatches()}
	o := similarOrch(spy)
	ans, err := o.answerSimilar(context.Background(), tenantA(), similarPlan("pa"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeSimilarIncidents || len(spy.asked) != 1 || spy.asked[0] != "t-a/pa" {
		t.Fatalf("mode %s, recall asked %v", ans.Mode, spy.asked)
	}
	for _, want := range []string{"2 earlier incidents look like", "strong match", "matched on signature, seam", "2026-10-02", noFixRecorded} {
		if !strings.Contains(ans.Text, want) {
			t.Errorf("answer lacks %q:\n%s", want, ans.Text)
		}
	}
	if len(ans.Citations) != 2 {
		t.Fatalf("citations: %+v", ans.Citations)
	}
	for _, c := range ans.Citations {
		if c.Class != ClassHistorical || c.Kind != "history" || !strings.HasPrefix(c.Href, "#/monitoring/correlations?id=") {
			t.Errorf("a past case must be HISTORICAL evidence with a deep link: %+v", c)
		}
	}
	if !strings.Contains(strings.Join(ans.Disclaimers, " "), "not the same cause") {
		t.Errorf("the caveat must be said: %v", ans.Disclaimers)
	}
	low := strings.ToLower(ans.Text)
	for _, claim := range []string{"was fixed by", "the fix was", "root cause is", "caused by"} {
		if strings.Contains(low, claim) {
			t.Errorf("history must never claim a fix or a cause (%q):\n%s", claim, ans.Text)
		}
	}
	// The past case readable in the caller's own scope is named by its handle.
	if !strings.Contains(ans.Text, "BGP peer down on edge-1") {
		t.Errorf("an own past case should carry its title:\n%s", ans.Text)
	}
}

// No case named: the top incident right now is compared, and the answer says so.
func TestSimilarAnswerDefaultsToTheTopIncidentAndSaysSo(t *testing.T) {
	spy := &recallSpy{res: SimilarIncidents{Verdict: "no_similar_incident", Examined: 4, Note: "Fingerprints build as cases close."}}
	o := similarOrch(spy)
	ans, err := o.answerSimilar(context.Background(), tenantA(), similarPlan(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.asked) != 1 || spy.asked[0] != "t-a/pa" {
		t.Fatalf("the top incident should be compared: %v", spy.asked)
	}
	if !strings.Contains(ans.Text, "You didn't name an incident, so I compared the top one right now") {
		t.Errorf("the choice must be disclosed:\n%s", ans.Text)
	}
	if !strings.Contains(ans.Text, "No earlier incident matches") || !strings.Contains(ans.Text, "4 closed incidents compared") {
		t.Errorf("the honest empty answer is missing:\n%s", ans.Text)
	}
	if len(ans.Citations) != 0 || len(ans.NextActions) != 0 {
		t.Errorf("no match must cite nothing and suggest nothing: %+v %v", ans.Citations, ans.NextActions)
	}
}

// Nothing open and nothing named: an honest answer, and recall never runs.
func TestSimilarAnswerWithNothingToCompare(t *testing.T) {
	spy := &recallSpy{res: twoMatches()}
	o := similarOrch(spy)
	ans, err := o.answerSimilar(context.Background(), Principal{Tenant: "t-empty", Perms: tenantA().Perms}, similarPlan(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.asked) != 0 || !strings.Contains(ans.Text, "nothing to compare") {
		t.Fatalf("recall asked %v, text %q", spy.asked, ans.Text)
	}
}

// §3a: another tenant's case is not found — no recall, no existence leak, in
// both directions (the data source's 404 and the recall's own ErrNotFound).
func TestSimilarAnswerNeverReachesAnotherTenantsCase(t *testing.T) {
	spy := &recallSpy{res: twoMatches()}
	o := similarOrch(spy)
	ans, err := o.answerSimilar(context.Background(), tenantA(), similarPlan("pb"), nil) // pb is t-b's
	if err != nil {
		t.Fatal(err)
	}
	if len(spy.asked) != 0 || !strings.Contains(ans.Text, "isn't available in your scope") || len(ans.Citations) != 0 {
		t.Fatalf("cross-tenant case: asked %v, answer %+v", spy.asked, ans)
	}
	spy2 := &recallSpy{err: ErrNotFound}
	ans, err = similarOrch(spy2).answerSimilar(context.Background(), tenantA(), similarPlan("pa"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ans.Text, "isn't available in your scope") || len(ans.Citations) != 0 {
		t.Fatalf("the recall's not-found must read as not found: %+v", ans)
	}
	// A match the recall returns that the caller cannot read by id is named by
	// a short token only — never another tenant's title.
	spy3 := &recallSpy{res: SimilarIncidents{Matches: []SimilarMatch{{CorrelationID: "pb", Strength: "similar",
		MatchedOn: []string{"seam"}, OccurredAt: time.Now()}}}}
	ans, _ = similarOrch(spy3).answerSimilar(context.Background(), tenantA(), similarPlan("pa"), nil)
	if strings.Contains(ans.Text, "High CPU on leaf-2") {
		t.Fatalf("another tenant's title leaked:\n%s", ans.Text)
	}
}

// Unwired recall: an honest unavailable answer, never a fabricated one.
func TestSimilarAnswerUnwired(t *testing.T) {
	ans, err := similarOrch(nil).answerSimilar(context.Background(), tenantA(), similarPlan("pa"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeUnavailable || !strings.Contains(ans.Text, "isn't available") {
		t.Fatalf("%+v", ans)
	}
}

// End to end through the model-first planner: any phrasing the model routes to
// similar_incidents reaches this arm, permission-gated like every RCA route.
func TestPlannerRoutesSimilarQuestionsToTheRecall(t *testing.T) {
	spy := &recallSpy{res: twoMatches()}
	llm := &plannerLLM{route: func(string) string { return "ROUTE: similar_incidents" }}
	o := plannerOrch(llm)
	o.Troubleshoot.SimilarIncidents = spy.fn
	// Asked from the Iris box with no problem in view (a problem in view keeps
	// its own one-call contextual path, and the RCA view shows the card).
	for _, q := range []string{"have we seen this before?", "what fixed it last time this happened", "is P-3E0400 a recurrence"} {
		ans, err := o.Ask(context.Background(), tenantA(), q, nil)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if ans.Mode != ModeSimilarIncidents || ans.Routing == nil || ans.Routing.Reason != RouteReasonPlanner {
			t.Errorf("%q: mode %s routing %+v", q, ans.Mode, ans.Routing)
		}
	}
	// No correlations permission: refused like any RCA answer, recall never runs.
	before := len(spy.asked)
	ans, err := o.Ask(context.Background(), Principal{Tenant: "t-a", Perms: map[string]bool{}}, "have we seen this before?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeUnavailable || len(spy.asked) != before {
		t.Fatalf("an unpermitted caller must be refused before recall: mode %s, asked %v", ans.Mode, spy.asked)
	}
}
