package ai

import "testing"

// TestClassifyBroadPhrasings is the regression guard for the "every question
// gives the same 25-incident briefing" bug: current_state is now an EXPLICIT
// intent, natural incident phrasings route to the actionable list, and truly
// unrecognized questions get a capability clarification — NOT the briefing.
func TestClassifyBroadPhrasings(t *testing.T) {
	cases := []struct {
		q    string
		want string
	}{
		// Explicit status / overview → current_state (the briefing is appropriate here).
		{"what is going on right now", "current_state"},
		{"what's happening", "current_state"},
		{"give me a status update", "current_state"},
		{"how is the network", "current_state"},
		{"is everything ok", "current_state"},
		{"network health", "current_state"},
		{"what should the NOC focus on", "current_state"},
		{"summarize the network health", "current_state"},

		// Incident/problem/outage phrasings → the filtered actionable LIST.
		{"show me the critical incidents", "incident_list"},
		{"are there any issues", "incident_list"},
		{"is there any problem", "incident_list"},
		{"any outages", "incident_list"},
		{"what is broken", "incident_list"},
		{"whats wrong", "incident_list"},
		{"anything down", "incident_list"},
		{"what needs attention", "incident_list"},
		{"do we have any incidents", "incident_list"},
		{"what's the biggest problem", "incident_list"},

		// RCA / explain.
		{"explain this incident", "problem_explanation"},

		// Modules.
		{"show me top talkers", "flow_analytics_summary"},
		{"any metric anomalies", "telemetry_summary"},
		{"are my integrations healthy", "integration_health_summary"},

		// Playbook / history / shift.
		{"how do I troubleshoot a bgp flap", "network_kb"},
		{"what happened overnight", "time_range_summary"},
		{"give me the shift handoff", "shift_handoff"},

		// Navigation.
		{"where do I configure servicenow", "product_navigation"},

		// Product / how-to questions ABOUT Correlix → product_question (answered
		// from the product knowledge; degrades to a capability clarification if the
		// KB has no match — the KB lookup is the disambiguator).
		{"what is a seam", "product_question"},
		{"how do I set up SNMP discovery", "product_question"},
		{"what does suspected mean", "product_question"},

		// Truly unrecognized → capability clarification, NOT current_state.
		{"who should I call about the wan", "capability"},
		{"tell me a joke", "capability"},
	}
	for _, c := range cases {
		got := Classify(c.q, nil).Intent
		if got != c.want {
			t.Errorf("Classify(%q) intent = %q, want %q", c.q, got, c.want)
		}
	}
}
