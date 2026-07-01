package ai

import (
	"context"
	"strings"
	"testing"
)

// The NOC-answer acceptance tests (spec §9). They reuse rankMockDS (one suspected
// CLASSIFIED "ISP / DIA egress latency" + two undetermined low-evidence items) so
// the ranking, separation, and reasoning are all exercised against realistic data.

func rankOrchProviderDown() *Orchestrator {
	ds := &rankMockDS{}
	return &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Err: context.DeadlineExceeded}, Flags: func(string) bool { return false }}
}

func rankP() Principal {
	return Principal{Tenant: "t", Perms: map[string]bool{"correlations:read": true, "infrastructure:read": true}}
}

// §9: "Explain the top incident" resolves the #1 item from the priority queue and
// explains it — it MUST NOT ask for a problem id when the queue has a top item.
func TestExplainTopIncidentResolvesFromQueue(t *testing.T) {
	o := rankOrchProviderDown()
	for _, q := range []string{"explain the top incident", "/top", "what is the highest priority incident"} {
		// Slash commands resolve to their canonical phrasing (as the route does).
		ask := q
		if question, _, ok := ResolveCommand(q); ok {
			ask = question
		}
		ans, err := o.Ask(context.Background(), rankP(), ask, nil)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if ans.Mode != ModeProblemExplanation || ans.Problem == nil {
			t.Fatalf("%q: expected a resolved problem_explanation, got mode=%s problem=%v", q, ans.Mode, ans.Problem)
		}
		// The suspected classified incident wins the queue (not an undetermined one).
		if !strings.Contains(ans.Problem.Title, "DIA egress latency") {
			t.Fatalf("%q: top incident should be the suspected classified one, got %q", q, ans.Problem.Title)
		}
		// It must NOT dead-end asking for an id.
		if strings.Contains(strings.ToLower(ans.Text), "which problem") {
			t.Fatalf("%q: must not ask for a problem id when the queue has a top item: %q", q, ans.Text)
		}
		if len(ans.Problem.WhyFirst) == 0 {
			t.Fatalf("%q: top-incident answer must explain WHY it is first", q)
		}
		if !containsStr(ans.ModeBadges, "Top incident") {
			t.Fatalf("%q: expected a Top incident badge, got %v", q, ans.ModeBadges)
		}
	}
}

// Empty queue is the ONLY case that may decline (spec §4 exception).
func TestExplainTopIncidentEmptyQueue(t *testing.T) {
	ds := newMockDS()
	// A tenant with no problems.
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{}, Flags: func(string) bool { return false }}
	ans, _ := o.Ask(context.Background(), Principal{Tenant: "t-empty", Perms: map[string]bool{"correlations:read": true}}, "explain the top incident", nil)
	if ans.Problem != nil {
		t.Fatalf("empty queue must not fabricate a top incident: %+v", ans.Problem)
	}
	if !strings.Contains(strings.ToLower(ans.Text), "no active correlations") {
		t.Fatalf("empty queue should say so, got %q", ans.Text)
	}
}

// §9: NOC-focus recommendation explains WHY the item is first (not just a list),
// and limits the "other" list.
func TestNocFocusRecommendation(t *testing.T) {
	o := rankOrchProviderDown()
	ans, err := o.Ask(context.Background(), rankP(), "which incident should the NOC focus on first and why?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeNocFocusRecommendation || ans.CurrentState == nil {
		t.Fatalf("expected noc_focus_recommendation, got mode=%s cs=%v", ans.Mode, ans.CurrentState)
	}
	cs := ans.CurrentState
	if len(cs.RecommendedFocus) == 0 || !strings.Contains(cs.RecommendedFocus[0], "DIA egress latency") {
		t.Fatalf("focus must be the suspected classified incident, got %v", cs.RecommendedFocus)
	}
	if len(cs.WhyFirst) == 0 {
		t.Fatalf("must include the reasoning (why first), got none")
	}
	if !strings.Contains(strings.ToLower(ans.Text), "focus first on") {
		t.Fatalf("narrative must lead with the recommendation, got %q", ans.Text)
	}
	// The undetermined items are a grouped watch note, never mixed into the focus.
	if cs.WatchNote == "" || !strings.Contains(strings.ToLower(cs.WatchNote), "watch") {
		t.Fatalf("undetermined must be grouped as a watch note, got %q", cs.WatchNote)
	}
}

// §9: suspected vs undetermined renders TWO separate sections and does not
// duplicate the suspected list.
func TestIncidentStatusBreakdown(t *testing.T) {
	o := rankOrchProviderDown()
	ans, err := o.Ask(context.Background(), rankP(), "show me active suspected incidents and separate them from undetermined watch items", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeIncidentStatusBreakdown || ans.CurrentState == nil {
		t.Fatalf("expected incident_status_breakdown, got mode=%s", ans.Mode)
	}
	cs := ans.CurrentState
	// Section 1: the suspected list (exactly the one suspected incident here).
	if len(cs.SuspectedIncidents) != 1 || !strings.Contains(cs.SuspectedIncidents[0], "DIA egress latency") {
		t.Fatalf("suspected section must list the suspected incident, got %v", cs.SuspectedIncidents)
	}
	// Section 2: the undetermined watch note (the two low-evidence items, grouped).
	if !strings.Contains(cs.WatchNote, "2 undetermined") {
		t.Fatalf("watch note must group the 2 undetermined items, got %q", cs.WatchNote)
	}
	// The suspected list must NOT be repeated inside ActiveIncidents (no dup).
	if len(cs.ActiveIncidents) != 0 {
		t.Fatalf("breakdown must not also fill the generic active list (duplication), got %v", cs.ActiveIncidents)
	}
}

// §9: counts are normalized and labeled; no conflicting numbers.
func TestCountsLabeled(t *testing.T) {
	o := rankOrchProviderDown()
	ans, err := o.Ask(context.Background(), rankP(), "what is going on right now?", nil)
	if err != nil {
		t.Fatal(err)
	}
	c := ans.Counts
	if c == nil {
		t.Fatal("counts must be attached to the answer")
	}
	if c.ActiveCorrelationGroups != 3 || c.SuspectedCount != 1 || c.UndeterminedCount != 2 {
		t.Fatalf("counts wrong: %+v", c)
	}
	if c.ActionableIncidentsCount != 1 || c.LowEvidenceWatchItemsCount != 2 {
		t.Fatalf("actionable/low-evidence counts wrong: %+v", c)
	}
	if len(ans.CurrentState.CountsLegend) == 0 {
		t.Fatal("a labeled legend must accompany the counts (no unexplained numbers)")
	}
}

// §9: the provider-fallback line appears ONCE as a small note, never as the main
// sentence, and is never repeated across text/disclaimers.
func TestProviderFallbackSingleNote(t *testing.T) {
	o := rankOrchProviderDown()
	for _, q := range []string{"what is going on right now?", "explain the top incident"} {
		ans, err := o.Ask(context.Background(), rankP(), q, nil)
		if err != nil {
			t.Fatalf("%q: %v", q, err)
		}
		if !ans.EvidenceOnly {
			t.Fatalf("%q: provider-down answer must be evidence-only", q)
		}
		if ans.ProviderNote == "" {
			t.Fatalf("%q: must carry a single provider note", q)
		}
		// The reason must not be a main answer sentence or a disclaimer line.
		low := strings.ToLower(ans.Text + " " + strings.Join(ans.Disclaimers, " "))
		if strings.Contains(low, "ai provider") || strings.Contains(low, "provider unavailable") || strings.Contains(low, "evidence-only summary") {
			t.Fatalf("%q: provider state leaked into text/disclaimers: text=%q disc=%v", q, ans.Text, ans.Disclaimers)
		}
		// The neutral chip is present; the loud "AI provider…" chip is not.
		for _, b := range ans.ModeBadges {
			if strings.Contains(strings.ToLower(b), "ai provider") {
				t.Fatalf("%q: loud provider badge must be gone, got %v", q, ans.ModeBadges)
			}
		}
	}
}

// §9: the /status card is not labeled with a single incident's status — the focus
// status lives inside the payload, not as the card-level Status.
func TestCurrentStateNoCardLevelStatus(t *testing.T) {
	o := rankOrchProviderDown()
	ans, err := o.Ask(context.Background(), rankP(), "what is going on right now?", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Status != "" {
		t.Fatalf("current-state must NOT set a card-level status (whole state isn't 'Suspected'): %q", ans.Status)
	}
	if ans.CurrentState.FocusStatus != "Suspected" {
		t.Fatalf("the focus status belongs in the payload, got %q", ans.CurrentState.FocusStatus)
	}
	if ans.Title != "Current Operations Summary" {
		t.Fatalf("card title should be the operations summary, got %q", ans.Title)
	}
}

// Classifier routes for the new intents.
func TestClassifyNocIntents(t *testing.T) {
	cases := []struct{ q, want string }{
		{"explain the top incident", "top_incident"},
		{"/top incidents", "top_incident"},
		{"explain the highest priority incident", "top_incident"},
		{"which incident should the NOC focus on first and why?", "noc_focus"},
		{"how should we prioritize?", "noc_focus"},
		{"show me active suspected incidents and separate them from undetermined watch items", "incident_breakdown"},
		{"suspected vs undetermined", "incident_breakdown"},
		// Guards: these must NOT be captured by the new routes.
		{"what's the biggest problem", "incident_list"},
		{"what should the NOC focus on", "current_state"},
		{"show me the critical incidents", "incident_list"},
	}
	for _, c := range cases {
		if got := Classify(c.q, nil).Intent; got != c.want {
			t.Errorf("Classify(%q) intent = %q, want %q", c.q, got, c.want)
		}
	}
}
