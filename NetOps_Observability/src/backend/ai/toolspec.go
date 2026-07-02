package ai

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// toolspec.go — the provider-agnostic tool-calling seam (intelligence plan P2,
// §3.d). The agent loop hands the model a MANIFEST of schema-described tools and
// receives back tool calls; both sides speak these neutral types, and thin
// per-provider adapters (in the server's copilot proxy) translate them to the
// OpenAI / Anthropic / Gemini wire formats. Pure stdlib.
//
// Security stance (CLAUDE.md §15, OWASP LLM06:2025 excessive agency):
//   - The manifest is filtered by the Policy Engine + the caller's Principal
//     BEFORE the model ever sees it — a tool the caller may not run is not
//     even visible to the model.
//   - A tool without declared meta here is NEVER in the manifest (fail closed):
//     the model can only call what we deliberately described.
//   - Args are validated against the declared schema (required fields, flat
//     string values) and then re-validated by the tool itself — defense in depth.

// ToolSpec describes one callable tool to the model: name, what it does, and a
// JSON-Schema for its arguments. InputSchema is always a flat object whose
// properties are strings (ToolArgs is map[string]string by contract — no nested
// payloads, no free-form SQL/shell, ever).
type ToolSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"input_schema"`
}

// ToolCall is one tool invocation the model requested. Args carries the raw
// JSON argument object exactly as the provider returned it; ParseToolArgs
// validates and flattens it before any tool runs.
type ToolCall struct {
	ID   string          // provider call id (echoed back in the reply)
	Name string          // tool name — must be in the manifest
	Args json.RawMessage // raw JSON argument object ("{}" when absent)
}

// ToolReply is the bounded, rendered result handed back to the model for one
// call. IsError marks a refusal/failure so the model knows the lookup yielded
// nothing (it must not invent data to fill the gap).
type ToolReply struct {
	ID      string // matches ToolCall.ID
	Name    string // matches ToolCall.Name (Gemini correlates by name)
	Content string
	IsError bool
}

// toolArgSpec declares one flat string argument.
type toolArgSpec struct {
	name, desc string
	required   bool
}

// toolMeta is what the model is told about a tool (description + args) plus the
// customer-facing label the UI shows for "investigated: N lookups". Only tools
// declared here can appear in a manifest — an undeclared tool is invisible to
// the model even if registered (fail closed).
type toolMeta struct {
	description string
	label       string // customer-facing wording — no schema jargon
	args        []toolArgSpec
}

var argProblemID = toolArgSpec{name: "problem_id", desc: "The problem's correlation UUID (take it from a problem:<uuid> citation id — not the P-XXXXXX display handle).", required: true}

// toolMetas describes every tool the agent loop may expose. Keep descriptions
// action-oriented and honest about scope/windows so the model picks well.
var toolMetas = map[string]toolMeta{
	"get_problem": {
		description: "Fetch one correlation problem: title, verdict (confirmed/suspected/undetermined), confidence, affected devices.",
		label:       "Problem lookup",
		args:        []toolArgSpec{argProblemID},
	},
	"get_problem_evidence": {
		description: "Fetch the cited evidence ledger for one correlation problem (candidate causes, impacted entities).",
		label:       "Evidence ledger",
		args:        []toolArgSpec{argProblemID},
	},
	"get_active_major_incidents": {
		description: "List the current open correlation problems (newest first, up to 25) with verdict and confidence.",
		label:       "Active incidents",
	},
	"get_actionable_incidents": {
		description: "List the prioritized ACTIONABLE incidents (confirmed + suspected only, ranked, top 8); low-evidence items are summarized as a count.",
		label:       "Actionable incidents",
	},
	"get_incident_history": {
		description: "Incidents whose onset fell in a past window — open AND resolved, with state. THE tool for \"what happened last night / today / this week\": it is the engine's merged view across logs, metrics, flows and paths.",
		label:       "Incident history",
		args: []toolArgSpec{
			{name: "window", desc: "Lookback window: 1h, 6h, 12h, 24h or 7d (default 24h). Resolve relative phrases yourself (\"last night\" → 12h or 24h) — never ask for exact timestamps.", required: false},
		},
	},
	"get_top_talkers": {
		description: "Top traffic conversations (heaviest source↔destination pairs) over the last 24 hours.",
		label:       "Top talkers",
	},
	"get_flow_summary": {
		description: "One-line network traffic totals (bytes, flows, sources) over the last 24 hours.",
		label:       "Traffic summary",
	},
	"get_service_flow_summary": {
		description: "Busiest destination services (HTTPS, DNS, databases, …) by traffic over the last 24 hours.",
		label:       "Service traffic",
	},
	"get_metric_anomalies": {
		description: "Recent detected metric anomalies (worst first) over the last 6 hours.",
		label:       "Metric anomalies",
	},
	"get_app_identity_summary": {
		description: "Identified applications on the network over the last 24 hours, with identification confidence.",
		label:       "Application identity",
	},
	"get_low_confidence_app_matches": {
		description: "Applications whose identification confidence is low (below 50%) over the last 24 hours.",
		label:       "Low-confidence apps",
	},
	"get_integration_health": {
		description: "Configured external integrations (ITSM, chat, paging) and whether each is enabled.",
		label:       "Integrations",
	},
	"get_ticket_status": {
		description: "The ITSM ticket linked to one correlation problem, with its latest action and state.",
		label:       "Ticket status",
		args:        []toolArgSpec{argProblemID},
	},
	"search_docs": {
		description: "Search the Correlix product documentation (setup guides, operator procedures, concepts). Returns the most relevant sections with citation ids. If it returns nothing, the docs do not cover the topic — say so; never invent steps.",
		label:       "Documentation",
		args: []toolArgSpec{
			{name: "query", desc: "What to look up, e.g. \"configure SNMP discovery scan scope\".", required: true},
		},
	},
	"search_logs": {
		description: "Search recent network device syslog (tenant-scoped, bounded to 50 redacted lines). Use for \"what is device X logging\" questions.",
		label:       "Log search",
		args: []toolArgSpec{
			{name: "query", desc: "Search text or Lucene query (e.g. \"BGP\" or \"severity:err\"). Empty matches everything in the window.", required: false},
			{name: "device", desc: "Restrict to one device by name.", required: false},
			{name: "window", desc: "Lookback window: 15m, 1h, 6h, 24h or 7d (default 1h). For longer ranges use 7d and say what you covered.", required: false},
		},
	},
	"get_device_health": {
		description: "Health snapshot for one inventory device: reachability, CPU/memory, and interfaces that are operationally down.",
		label:       "Device health",
		args: []toolArgSpec{
			{name: "device", desc: "The device name or id exactly as it appears in the inventory.", required: true},
		},
	},
}

// ToolLabel returns the customer-facing label for a tool ("Log search", not
// "search_logs"). Unknown tools fall back to the raw name.
func ToolLabel(name string) string {
	if m, ok := toolMetas[name]; ok && m.label != "" {
		return m.label
	}
	return name
}

// schemaFor renders a toolMeta's args as a flat JSON-Schema object. Marshaling a
// map is deterministic (sorted keys), so manifests are byte-stable per build.
func schemaFor(m toolMeta) json.RawMessage {
	props := map[string]any{}
	required := []string{}
	for _, a := range m.args {
		props[a.name] = map[string]any{"type": "string", "description": a.desc}
		if a.required {
			required = append(required, a.name)
		}
	}
	schema := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		schema["required"] = required
	}
	b, err := json.Marshal(schema)
	if err != nil { // cannot happen for this shape; keep the no-ignored-errors rule
		return json.RawMessage(`{"type":"object","properties":{}}`)
	}
	return b
}

// Manifest builds the tool list the model is allowed to SEE for this caller:
// every registered tool that (a) has declared meta and (b) passes the Policy
// Engine for this principal. Sorted by name for a stable prompt prefix.
func Manifest(reg *ToolRegistry, pol *PolicyEngine, p Principal) []ToolSpec {
	if reg == nil || pol == nil {
		return nil
	}
	names := reg.Names()
	sort.Strings(names)
	out := make([]ToolSpec, 0, len(names))
	for _, n := range names {
		m, ok := toolMetas[n]
		if !ok {
			continue // undeclared tool — invisible to the model (fail closed)
		}
		t, ok := reg.Get(n)
		if !ok {
			continue
		}
		if d := pol.EvaluateTool(t, p); !d.Allow {
			continue // the model never sees a tool this caller can't run
		}
		out = append(out, ToolSpec{Name: n, Description: m.description, InputSchema: schemaFor(m)})
	}
	return out
}

// ParseToolArgs validates a model-supplied raw JSON argument object against the
// tool's declared meta and flattens it to ToolArgs. Scalars are coerced to
// strings; nested objects/arrays are rejected (no structured payloads ride into
// tools); undeclared keys are dropped; missing required keys error.
func ParseToolArgs(name string, raw json.RawMessage) (ToolArgs, error) {
	m, ok := toolMetas[name]
	if !ok {
		return nil, fmt.Errorf("tool %q has no declared arguments schema", name)
	}
	var in map[string]any
	if len(raw) > 0 && strings.TrimSpace(string(raw)) != "" {
		if err := json.Unmarshal(raw, &in); err != nil {
			return nil, fmt.Errorf("arguments are not a JSON object: %w", err)
		}
	}
	declared := make(map[string]bool, len(m.args))
	for _, a := range m.args {
		declared[a.name] = true
	}
	out := ToolArgs{}
	for k, v := range in {
		if !declared[k] {
			continue // models add stray keys; drop them rather than fail the call
		}
		switch x := v.(type) {
		case string:
			out[k] = strings.TrimSpace(x)
		case float64:
			out[k] = strconv.FormatFloat(x, 'f', -1, 64)
		case bool:
			out[k] = strconv.FormatBool(x)
		case nil:
			// treat as absent
		default:
			return nil, fmt.Errorf("argument %q must be a flat string value", k)
		}
	}
	for _, a := range m.args {
		if a.required && strings.TrimSpace(out[a.name]) == "" {
			return nil, fmt.Errorf("argument %q is required", a.name)
		}
	}
	return out, nil
}
