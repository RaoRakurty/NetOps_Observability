package ai

import (
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

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if strings.EqualFold(s, v) {
			return true
		}
	}
	return false
}
