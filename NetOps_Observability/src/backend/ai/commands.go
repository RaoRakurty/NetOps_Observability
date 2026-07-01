package ai

import "strings"

// commands.go — the Command Registry (HLD §5). Slash commands are a guided front
// door to the SAME intent system as natural language: "/status" and "what is
// going on right now?" must converge on the same answer. We implement that by
// mapping each command to a canonical natural-language phrasing that Classify
// already routes — so there is ONE intent path, not two. The registry is also
// served to the UI (the "/" menu) with labels, descriptions and risk levels.

// Command is one slash command entry.
type Command struct {
	Command     string   `json:"command"`           // canonical, e.g. "/status"
	Aliases     []string `json:"aliases,omitempty"` // e.g. ["/now","/current"]
	Label       string   `json:"label"`             // short menu label
	Description string   `json:"description"`       // one-line help
	Intent      string   `json:"intent"`            // the intent it resolves to (for display/audit)
	RiskLevel   string   `json:"risk_level"`        // read_only | draft (writes are draft-only in v1)
	RequiresCtx bool     `json:"requires_context"`  // needs an open problem id
	canonical   string   // the natural-language phrasing handed to Classify
}

// commands is the initial command set. Every entry resolves to an EXISTING intent
// via its canonical phrasing — no command invents a new answer path. Write-ish
// commands are draft-only in v1 (no send/close/assign).
var commands = []Command{
	{Command: "/status", Aliases: []string{"/now", "/current"}, Label: "Current NOC status",
		Description: "Summarize active incidents, priority focus, impact, and next actions.",
		Intent:      "current_state", RiskLevel: "read_only", canonical: "what is going on right now"},
	{Command: "/top", Aliases: []string{"/top-incidents", "/incidents"}, Label: "Top incidents",
		Description: "The highest-priority active incidents to focus on first.",
		Intent:      "current_state", RiskLevel: "read_only", canonical: "what are the top incidents right now"},
	{Command: "/explain", Aliases: []string{"/rca", "/problem", "/explain-problem"}, Label: "Explain problem",
		Description: "Explain an RCA: timeline, evidence, missing evidence, owner, next actions.",
		Intent:      "problem_explanation", RiskLevel: "read_only", RequiresCtx: true, canonical: "explain this problem"},
	{Command: "/missing", Aliases: []string{"/missing-evidence", "/gaps"}, Label: "Missing evidence",
		Description: "What evidence the engine still needs to confirm this problem.",
		Intent:      "problem_explanation", RiskLevel: "read_only", RequiresCtx: true, canonical: "what evidence is missing for this problem"},
	{Command: "/owner", Aliases: []string{"/who"}, Label: "Recommended owner",
		Description: "Who should own this problem (recommended domain).",
		Intent:      "problem_explanation", RiskLevel: "read_only", RequiresCtx: true, canonical: "who should own this problem"},
	{Command: "/handoff", Aliases: []string{"/shift", "/pass-down"}, Label: "Shift handoff",
		Description: "Draft a NOC shift pass-down summary.",
		Intent:      "shift_handoff", RiskLevel: "read_only", canonical: "shift handoff summary"},
	{Command: "/history", Aliases: []string{"/overnight", "/recap"}, Label: "What happened",
		Description: "Summarize what happened in a past window (overnight / last N hours).",
		Intent:      "time_range_summary", RiskLevel: "read_only", canonical: "what happened overnight"},
	{Command: "/itsm", Aliases: []string{"/itsm-update", "/ticket"}, Label: "ITSM update (draft)",
		Description: "Draft an ITSM update for this problem (draft only — never sent).",
		Intent:      "problem_explanation", RiskLevel: "draft", RequiresCtx: true, canonical: "draft an itsm update for this problem"},
	{Command: "/flows", Aliases: []string{"/talkers", "/traffic"}, Label: "Flow analytics",
		Description: "Top talkers and busiest services in the recent window.",
		Intent:      "flow_analytics_summary", RiskLevel: "read_only", canonical: "show me top talkers and busiest services"},
	{Command: "/telemetry", Aliases: []string{"/anomalies", "/metrics"}, Label: "Telemetry anomalies",
		Description: "Recent metric anomalies and device health.",
		Intent:      "telemetry_summary", RiskLevel: "read_only", canonical: "show me metric anomalies"},
	{Command: "/apps", Aliases: []string{"/app-id", "/applications"}, Label: "App identification",
		Description: "Identified applications and low-confidence matches.",
		Intent:      "app_identification_summary", RiskLevel: "read_only", canonical: "app identity summary"},
	{Command: "/integrations", Aliases: []string{"/connectors"}, Label: "Integration health",
		Description: "Connector configuration health (ServiceNow / Slack / …).",
		Intent:      "integration_health_summary", RiskLevel: "read_only", canonical: "integration health"},
	{Command: "/cloud", Aliases: []string{"/saas"}, Label: "Cloud app observability",
		Description: "SaaS / cloud application health (when enabled).",
		Intent:      "cloud_app_summary", RiskLevel: "read_only", canonical: "cloud app health"},
	{Command: "/topology", Aliases: []string{"/topo", "/path"}, Label: "Topology",
		Description: "Open the topology / path view for an incident.",
		Intent:      "product_navigation", RiskLevel: "read_only", canonical: "where is topology path"},
	{Command: "/playbook", Aliases: []string{"/runbook", "/kb"}, Label: "Troubleshooting playbook",
		Description: "Curated network-engineering guidance for a symptom or protocol.",
		Intent:      "network_kb", RiskLevel: "read_only", canonical: "how do I troubleshoot"},
	{Command: "/help", Aliases: []string{"/commands", "/?"}, Label: "Help",
		Description: "List the available Ask Correlix commands.",
		Intent:      "help", RiskLevel: "read_only", canonical: ""},
}

var commandIndex = func() map[string]Command {
	m := make(map[string]Command, len(commands)*2)
	for _, c := range commands {
		m[c.Command] = c
		for _, a := range c.Aliases {
			m[a] = c
		}
	}
	return m
}()

// Commands returns the command registry (for the UI "/" menu).
func Commands() []Command {
	out := make([]Command, len(commands))
	copy(out, commands)
	return out
}

// IsCommand reports whether the input is a slash command invocation.
func IsCommand(input string) bool {
	return strings.HasPrefix(strings.TrimSpace(input), "/")
}

// ResolveCommand maps a slash command (or alias) to the canonical question that
// Classify routes — so a command and its natural-language equivalent share ONE
// intent path. The trailing text after the command is appended (e.g.
// "/playbook bgp flap" → "how do I troubleshoot bgp flap"). Returns:
//   - question: the canonical phrasing to feed Classify ("" for /help)
//   - cmd: the matched command (for audit + the help path)
//   - ok: false if the input isn't a recognized command
func ResolveCommand(input string) (question string, cmd Command, ok bool) {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "/") {
		return "", Command{}, false
	}
	head := input
	rest := ""
	if i := strings.IndexAny(input, " \t"); i > 0 {
		head, rest = input[:i], strings.TrimSpace(input[i+1:])
	}
	c, found := commandIndex[strings.ToLower(head)]
	if !found {
		return "", Command{}, false
	}
	q := c.canonical
	if rest != "" {
		q = strings.TrimSpace(q + " " + rest)
	}
	return q, c, true
}

// SuggestCommands returns commands whose command/alias/label/description match a
// typed prefix or fragment, for the "/" suggestion menu. Empty query → all.
func SuggestCommands(q string) []Command {
	q = strings.ToLower(strings.TrimSpace(q))
	q = strings.TrimPrefix(q, "/")
	if q == "" {
		return Commands()
	}
	var out []Command
	for _, c := range commands {
		hay := strings.ToLower(c.Command + " " + strings.Join(c.Aliases, " ") + " " + c.Label + " " + c.Description)
		if strings.Contains(hay, q) {
			out = append(out, c)
		}
	}
	return out
}
