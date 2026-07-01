package ai

import (
	"context"
	"strings"
	"testing"
)

// New P3-P4 routes classify to the right module + tools, and natural language
// and the eventual slash command converge on the same intent.
func TestP3P4Routing(t *testing.T) {
	cases := []struct {
		q          string
		wantIntent string
		wantTool   string // a tool that must be present in the plan
	}{
		{"show me the busiest services right now", "flow_analytics_summary", "get_service_flow_summary"},
		{"are my integrations healthy?", "integration_health_summary", "get_integration_health"},
		{"is ServiceNow sync working", "integration_health_summary", "get_integration_health"},
		{"how do I troubleshoot a BGP adjacency flap", "network_kb", "search_playbooks"},
		{"what should I check for ISP latency", "network_kb", "search_playbooks"},
		// Regression: common words ("packet", "police") must NOT be mistaken for a
		// P-XXXX problem handle and hijack the query into an RCA lookup.
		{"how do I troubleshoot ISP latency and packet loss", "network_kb", "search_playbooks"},
		// Incident-list questions get the filtered actionable list, NOT the generic
		// current-state briefing that dumps every open correlation.
		{"show me the critical incidents", "incident_list", "get_actionable_incidents"},
		{"what needs attention right now", "incident_list", "get_actionable_incidents"},
		{"list the active incidents", "incident_list", "get_actionable_incidents"},
	}
	for _, c := range cases {
		plan := Classify(c.q, nil)
		if plan.Intent != c.wantIntent {
			t.Errorf("%q → intent %q, want %q", c.q, plan.Intent, c.wantIntent)
			continue
		}
		if c.wantTool != "" && !containsStr(plan.Tools, c.wantTool) {
			t.Errorf("%q → tools %v, want %q present", c.q, plan.Tools, c.wantTool)
		}
	}
}

// An RCA explanation now also pulls linked-ticket status (ITSM enrichment).
func TestProblemPlanEnrichesWithTicketStatus(t *testing.T) {
	plan := Classify("explain this problem", map[string]string{"problem_id": "5e65a2fa-0000-0000-0000-000000000000"})
	if plan.Intent != "problem_explanation" {
		t.Fatalf("intent = %q", plan.Intent)
	}
	if !containsStr(plan.Tools, "get_ticket_status") {
		t.Errorf("problem plan should enrich with get_ticket_status; tools=%v", plan.Tools)
	}
}

// The network_expert_kb module is registered and stable.
func TestKBModuleRegistered(t *testing.T) {
	m, ok := ModuleByID("network_expert_kb")
	if !ok {
		t.Fatal("network_expert_kb module must be registered")
	}
	if m.Availability != AvailabilityStable {
		t.Errorf("KB module should be stable, got %q", m.Availability)
	}
	if !IsModuleEnabled("network_expert_kb", func(string) bool { return false }) {
		t.Error("KB module should be enabled with no feature flag (curated public knowledge)")
	}
}

// incidentsDS is a DataSource with a fixed mixed-verdict active list.
type incidentsDS struct{ probs []Problem }

func (d incidentsDS) GetProblem(context.Context, Principal, string) (*Problem, error) {
	return nil, ErrNotFound
}
func (d incidentsDS) GetProblemEvidence(context.Context, Principal, string) ([]EvidenceItem, error) {
	return nil, ErrNotFound
}
func (d incidentsDS) ListActiveProblems(context.Context, Principal, int) ([]Problem, error) {
	return d.probs, nil
}

// The actionable-incidents tool returns only confirmed/suspected, ranked, and
// notes the undetermined count — instead of dumping every open correlation.
func TestActionableIncidentsFiltersAndRanks(t *testing.T) {
	ds := incidentsDS{probs: []Problem{
		{ID: "u1", Title: "Low-evidence blip", Verdict: "undetermined", Confidence: 0.1, SignalCount: 1, NodeCount: 1},
		{ID: "s1", Title: "ISP / DIA egress latency", Verdict: "suspected", Confidence: 1.0, SignalCount: 4, NodeCount: 3},
		{ID: "c1", Title: "BGP peer flapping", Verdict: "confirmed", Confidence: 0.9, SignalCount: 6, NodeCount: 2},
		{ID: "u2", Title: "Another blip", Verdict: "undetermined", Confidence: 0.2, SignalCount: 1, NodeCount: 1},
	}}
	tool := actionableIncidentsTool{ds: ds}
	res, err := tool.Run(context.Background(), Principal{Cross: true}, nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(res.Items) != 2 {
		t.Fatalf("expected 2 actionable (confirmed+suspected), got %d: %+v", len(res.Items), res.Items)
	}
	// Confirmed outranks suspected in the priority order.
	if !strings.Contains(res.Items[0].Text, "BGP peer flapping") {
		t.Errorf("confirmed should rank first, got %q", res.Items[0].Text)
	}
	// The undetermined count is disclosed as a note, not dumped as items.
	joined := strings.Join(res.Notes, " ")
	if !strings.Contains(joined, "2 correlations under investigation") {
		t.Errorf("expected an under-investigation note for the 2 undetermined, got %q", joined)
	}
}

func TestActionableIncidentsNoneActionable(t *testing.T) {
	ds := incidentsDS{probs: []Problem{
		{ID: "u1", Verdict: "undetermined", Title: "blip"},
		{ID: "u2", Verdict: "undetermined", Title: "blip"},
	}}
	res, _ := actionableIncidentsTool{ds: ds}.Run(context.Background(), Principal{Cross: true}, nil)
	if len(res.Items) != 0 {
		t.Fatalf("no confirmed/suspected → no items, got %d", len(res.Items))
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "No confirmed or suspected") {
		t.Errorf("expected honest 'none actionable' note, got %v", res.Notes)
	}
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}
