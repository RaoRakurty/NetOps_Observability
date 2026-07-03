package ai

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Sentinel errors. Cross-tenant / unknown ids return ErrNotFound (never reveal
// another tenant's id — §3a). Stubbed future tools return ErrNotImplemented so
// the orchestrator answers with a clean "not available yet".
var (
	ErrNotFound       = errors.New("not found")
	ErrNotImplemented = errors.New("tool not implemented yet")
	ErrForbidden      = errors.New("forbidden")
)

// Principal is the minimal, already-resolved caller identity the tools need to
// scope data. The server builds it from the auth claims (tenant + cross-tenant
// flag + permission set) BEFORE calling the orchestrator, so the ai package
// never parses a token. Tenant scoping is enforced in the DataSource impl.
type Principal struct {
	Tenant string          // resolved tenant id ("" = global/platform)
	Cross  bool            // platform super-admin / cross-tenant
	Perms  map[string]bool // e.g. {"correlations:read": true}
}

// Can reports whether the principal holds a permission (cross-tenant holds all).
func (p Principal) Can(perm string) bool {
	if p.Cross {
		return true
	}
	return p.Perms[perm]
}

// HasAnyPerm is the any-of gate used for module/tool permission lists.
func (p Principal) HasAnyPerm(perms []string) bool {
	if len(perms) == 0 {
		return true
	}
	for _, perm := range perms {
		if p.Can(perm) {
			return true
		}
	}
	return false
}

// Problem is the RCA correlation object the assistant explains, in AI-package
// terms. The server maps its CorrObject → Problem (tenant-scoped fetch).
type Problem struct {
	ID              string // real correlation UUID — the key for routes/API/citation ids
	DisplayID       string // friendly NOC handle (P-5564D1) for narrative text; "" → falls back to ID
	Title           string
	Verdict         string // confirmed | suspected | undetermined
	Confidence      float64
	Devices         []string
	MissingEvidence []string
	Owner           string
	SignalCount     int
	NodeCount       int
	CreatedAt       string
	State           string   // open | closed | merged (window summaries: still-open vs resolved)
	Timeline        []string // optional human-readable timeline lines
	// Engine voice contract (v1 NOC catalog): when the matched signature carries
	// the owner-approved fault-family wording, the AI narrates THAT — it never
	// re-derives the cause statement (engine reasons, AI narrates).
	OperatorPhrase  string // signature operator_phrase ("" for pre-v1 signatures)
	ConfidenceLabel string // signature confidence_label: suspected|likely|confirmed
}

// Display returns the operator-facing problem handle for NARRATIVE text — the
// friendly P-XXXXXX id when set, else the raw id. Citation ids / deep links keep
// the real UUID (pr.ID); only human prose uses this.
func (pr *Problem) Display() string {
	if pr.DisplayID != "" {
		return pr.DisplayID
	}
	return pr.ID
}

// EvidenceItem is one grounded fact handed to the model, each with a stable
// citation id and a UI deep link so the answer is verifiable (anti-black-box).
type EvidenceItem struct {
	CitationID string `json:"citation_id"`
	Kind       string `json:"kind"` // finding | log | metric | ticket | topology | device
	Text       string `json:"text"`
	Href       string `json:"href"`
}

// ToolResult is a read-only tool's output. Truncated discloses a cap was hit.
type ToolResult struct {
	Items     []EvidenceItem
	Truncated bool
	Notes     []string
}

// ToolArgs are validated, simple string args (no free-form SQL/shell — ever).
type ToolArgs map[string]string

// plural renders "1 node" / "3 nodes" so AI narrative text reads naturally.
func plural(n int, singular string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %ss", n, singular)
}

// Capability classifies what a tool DOES — the axis the Policy Engine gates on.
// v1 permits only CapRead; CapWrite/CapExecute are hard-denied until the gated
// action subsystem exists (HLD P6).
type Capability string

const (
	CapRead    Capability = "read"    // returns data; no side effects (allowed in v1)
	CapWrite   Capability = "write"   // mutates app state (ITSM ticket, owner) — P6, gated
	CapExecute Capability = "execute" // touches a network device — P6+, fully gated
)

// AITool is the governed tool contract. v1 tools are tenant-scoped, bounded,
// read-only, and never touch a device. A future MCP server (HLD P7) is a thin
// adapter over this same interface. Capability() is what the Policy Engine reads
// to decide whether the AI may run the tool at all.
type AITool interface {
	Name() string
	Module() string
	Capability() Capability
	RequiredPerms() []string
	Freshness() Freshness
	Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error)
}

// ModuleDataSource is the P4 seam for module-specific reads (flow analytics,
// telemetry, app-identification, …). It is kept SEPARATE from DataSource so the
// stable P1/P2 RCA contract never churns as modules are added; the server's
// aiDataSource implements both. Each module tool calls ModuleQuery with a FIXED,
// allowlisted query name it owns (never model-supplied free text), and the
// trusted server maps that name to exactly ONE tenant-scoped store query. A
// query that has no data returns an empty ToolResult (not an error); an unknown
// query name returns ErrNotImplemented so the tool degrades honestly.
type ModuleDataSource interface {
	ModuleQuery(ctx context.Context, p Principal, query string, args ToolArgs) (ToolResult, error)
}

// DataSource is the seam the SERVER implements over the real, tenant-scoped
// stores (correlation store / rca-path-view, ClickHouse, OpenSearch, VM, PG).
// The ai package depends only on this interface — no import of the http server,
// no DB driver, no store query in the ai package.
type DataSource interface {
	// GetProblem returns the tenant-scoped problem, or ErrNotFound if it doesn't
	// exist OR belongs to another tenant (never reveal cross-tenant existence).
	GetProblem(ctx context.Context, p Principal, id string) (*Problem, error)
	// GetProblemEvidence returns the cited evidence items for the problem.
	GetProblemEvidence(ctx context.Context, p Principal, id string) ([]EvidenceItem, error)
	// ListActiveProblems returns the tenant-scoped recent/active correlation
	// problems (newest first), bounded by limit — for Command Center summaries (P2).
	ListActiveProblems(ctx context.Context, p Principal, limit int) ([]Problem, error)
}

// WindowDataSource is the OPTIONAL seam for PAST-window reads (the time-range
// outage summary — "what happened overnight"). Kept separate from DataSource so
// existing implementers don't churn; the real server implements it. A DataSource
// that doesn't implement it makes the time-range answer degrade to an honest
// "not available in this build" disclosure (never a live-state answer).
type WindowDataSource interface {
	// ListProblemsInWindow returns the tenant-scoped correlation problems whose
	// onset falls in [now-sinceSeconds, now], newest first — NOT filtered to open,
	// so a summary can distinguish still-open from resolved.
	ListProblemsInWindow(ctx context.Context, p Principal, sinceSeconds int) ([]Problem, error)
}

// ---- RCA read tools (HLD P1, module correlations_rca) -----------------------

type getProblemTool struct{ ds DataSource }

func (t getProblemTool) Name() string            { return "get_problem" }
func (t getProblemTool) Module() string          { return "correlations_rca" }
func (t getProblemTool) Capability() Capability  { return CapRead }
func (t getProblemTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t getProblemTool) Freshness() Freshness    { return FreshnessLive }
func (t getProblemTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	id := args["problem_id"]
	if id == "" {
		return ToolResult{}, fmt.Errorf("get_problem: problem_id required")
	}
	pr, err := t.ds.GetProblem(ctx, p, id)
	if err != nil {
		return ToolResult{}, err
	}
	text := fmt.Sprintf("%s — %s; verdict %s (%.0f%% confidence); %s across %s",
		pr.Display(), pr.Title, pr.Verdict, pr.Confidence*100, plural(pr.SignalCount, "signal"), plural(pr.NodeCount, "node"))
	if len(pr.Devices) > 0 { // omit a trailing "devices:" when there are none (paths-only incidents)
		text += "; devices: " + strings.Join(pr.Devices, ", ")
	}
	item := EvidenceItem{
		CitationID: "problem:" + pr.ID,
		Kind:       "finding",
		Text:       text,
		Href:       "#/monitoring/correlations?id=" + pr.ID,
	}
	return ToolResult{Items: []EvidenceItem{item}}, nil
}

type getProblemEvidenceTool struct{ ds DataSource }

func (t getProblemEvidenceTool) Name() string            { return "get_problem_evidence" }
func (t getProblemEvidenceTool) Module() string          { return "correlations_rca" }
func (t getProblemEvidenceTool) Capability() Capability  { return CapRead }
func (t getProblemEvidenceTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t getProblemEvidenceTool) Freshness() Freshness    { return FreshnessLive }
func (t getProblemEvidenceTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	id := args["problem_id"]
	if id == "" {
		return ToolResult{}, fmt.Errorf("get_problem_evidence: problem_id required")
	}
	items, err := t.ds.GetProblemEvidence(ctx, p, id)
	if err != nil {
		return ToolResult{}, err
	}
	const cap = 50
	tr := ToolResult{Items: items}
	if len(items) > cap {
		tr.Items = items[:cap]
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing first %d of %d evidence items", cap, len(items)))
	}
	return tr, nil
}

// ---- Command Center read tools (HLD P2, module command_center) --------------

type activeIncidentsTool struct{ ds DataSource }

func (t activeIncidentsTool) Name() string            { return "get_active_major_incidents" }
func (t activeIncidentsTool) Module() string          { return "command_center" }
func (t activeIncidentsTool) Capability() Capability  { return CapRead }
func (t activeIncidentsTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t activeIncidentsTool) Freshness() Freshness    { return FreshnessLive }
func (t activeIncidentsTool) Run(ctx context.Context, p Principal, _ ToolArgs) (ToolResult, error) {
	probs, err := t.ds.ListActiveProblems(ctx, p, 25)
	if err != nil {
		return ToolResult{}, err
	}
	items := make([]EvidenceItem, 0, len(probs))
	for _, pr := range probs {
		items = append(items, EvidenceItem{
			CitationID: "problem:" + pr.ID, Kind: "finding",
			Text: fmt.Sprintf("%s — %s (%s, %.0f%%)", pr.Display(), pr.Title, pr.Verdict, pr.Confidence*100),
			Href: "#/monitoring/correlations?id=" + pr.ID,
		})
	}
	return ToolResult{Items: items}, nil
}

// incidentHistoryTool answers "what happened last night / over the weekend":
// the correlation problems whose ONSET fell inside a past window — open and
// resolved alike, state included. This is the engine's already-merged view over
// logs, metrics, flows and paths, so a "summarize the past N hours" question is
// one lookup, not a source-by-source quiz. Window is a fixed allowlisted token
// (never a model-controlled duration — no unbounded scans).
type incidentHistoryTool struct{ ds WindowDataSource }

var incidentHistoryWindows = map[string]int{
	"1h": 3600, "6h": 6 * 3600, "12h": 12 * 3600, "24h": 24 * 3600, "7d": 7 * 24 * 3600,
}

func (t incidentHistoryTool) Name() string            { return "get_incident_history" }
func (t incidentHistoryTool) Module() string          { return "event_management" }
func (t incidentHistoryTool) Capability() Capability  { return CapRead }
func (t incidentHistoryTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t incidentHistoryTool) Freshness() Freshness    { return FreshnessLive }
func (t incidentHistoryTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	secs, ok := incidentHistoryWindows[strings.ToLower(strings.TrimSpace(args["window"]))]
	if !ok {
		secs = incidentHistoryWindows["24h"]
	}
	probs, err := t.ds.ListProblemsInWindow(ctx, p, secs)
	if err != nil {
		return ToolResult{}, err
	}
	if len(probs) > 25 {
		probs = probs[:25]
	}
	items := make([]EvidenceItem, 0, len(probs))
	for _, pr := range probs {
		state := pr.State
		if state == "" {
			state = "open"
		}
		items = append(items, EvidenceItem{
			CitationID: "problem:" + pr.ID, Kind: "finding",
			Text: fmt.Sprintf("%s — %s (%s, %.0f%%, %s)", pr.Display(), pr.Title, pr.Verdict, pr.Confidence*100, state),
			Href: "#/monitoring/correlations?id=" + pr.ID,
		})
	}
	return ToolResult{Items: items}, nil
}

// actionableIncidentsTool answers "show me the critical / actionable incidents"
// with the PRIORITIZED, FILTERED list — confirmed + suspected first, ranked by
// PriorityScore, capped — instead of dumping every open correlation. This is the
// event_management list answer (distinct from the command_center current-state
// briefing), so an incident question gets specific incidents, not the same 25.
type actionableIncidentsTool struct{ ds DataSource }

func (t actionableIncidentsTool) Name() string            { return "get_actionable_incidents" }
func (t actionableIncidentsTool) Module() string          { return "event_management" }
func (t actionableIncidentsTool) Capability() Capability  { return CapRead }
func (t actionableIncidentsTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t actionableIncidentsTool) Freshness() Freshness    { return FreshnessLive }
func (t actionableIncidentsTool) Run(ctx context.Context, p Principal, _ ToolArgs) (ToolResult, error) {
	probs, err := t.ds.ListActiveProblems(ctx, p, 100)
	if err != nil {
		return ToolResult{}, err
	}
	// Actionable = confirmed or suspected (needs a human). Undetermined are
	// low-evidence watch items, not action items — surfaced only as a count note.
	var actionable []Problem
	undetermined := 0
	for _, pr := range probs {
		switch strings.ToLower(pr.Verdict) {
		case "confirmed", "suspected":
			actionable = append(actionable, pr)
		default:
			undetermined++
		}
	}
	sort.SliceStable(actionable, func(i, j int) bool { return PriorityScore(actionable[i]) > PriorityScore(actionable[j]) })

	const cap = 8
	tr := ToolResult{}
	shown := actionable
	if len(shown) > cap {
		shown = shown[:cap]
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing the top %d of %d actionable incidents", cap, len(actionable)))
	}
	for _, pr := range shown {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: "problem:" + pr.ID, Kind: "finding",
			Text: fmt.Sprintf("%s — %s (%s, %.0f%%)", pr.Display(), pr.Title, StatusLabel(pr.Verdict), pr.Confidence*100),
			Href: "#/monitoring/correlations?id=" + pr.ID,
		})
	}
	if len(actionable) == 0 {
		note := "No confirmed or suspected incidents right now."
		if undetermined > 0 {
			note += fmt.Sprintf(" %s being investigated (low evidence).", plural(undetermined, "correlation"))
		}
		tr.Notes = append(tr.Notes, note)
	} else if undetermined > 0 {
		tr.Notes = append(tr.Notes, fmt.Sprintf("plus %s under investigation (low evidence).", plural(undetermined, "correlation")))
	}
	return tr, nil
}
// ---- Module read tools (HLD P4, generic governed wrapper) -------------------

// moduleReadTool is one governed, read-only tool over the ModuleDataSource seam.
// All P4 module tools are instances of this single type — the tool contract
// (name/module/perms/freshness) is data, the data fetch is the one ModuleQuery
// seam — so adding a module is a registry line, not a new type (HLD: P2–P4 add
// without rewrites). The query name is fixed by the tool, never the model, so it
// is injection-safe by construction.
type moduleReadTool struct {
	mds       ModuleDataSource
	name      string
	module    string
	perms     []string
	freshness Freshness
	query     string // the fixed ModuleQuery name this tool runs
}

func (t moduleReadTool) Name() string            { return t.name }
func (t moduleReadTool) Module() string          { return t.module }
func (t moduleReadTool) Capability() Capability  { return CapRead }
func (t moduleReadTool) RequiredPerms() []string { return t.perms }
func (t moduleReadTool) Freshness() Freshness    { return t.freshness }
func (t moduleReadTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	return t.mds.ModuleQuery(ctx, p, t.query, args)
}

// moduleTools is the catalog of P4 module read tools wired to real data. Each
// entry names the module it serves, the perm gate (any-of), how fresh its data
// is, and the allowlisted ModuleQuery it runs. Modules whose tools are not yet
// listed here route to an honest disclosure (the orchestrator skips unregistered
// tool names) — no faked data.
var moduleTools = []struct {
	name, module, query string
	perms               []string
	freshness           Freshness
}{
	// Flow Analytics (CH netops.flows, tenant_iso row policy).
	{"get_top_talkers", "flow_analytics", "top_talkers", []string{"flows:read"}, FreshnessRecent},
	{"get_flow_summary", "flow_analytics", "flow_summary", []string{"flows:read"}, FreshnessRecent},
	{"get_service_flow_summary", "flow_analytics", "service_flow_summary", []string{"flows:read"}, FreshnessRecent},
	// Telemetry (CH netops.findings, tenant_iso row policy — detected anomalies).
	{"get_metric_anomalies", "telemetry", "metric_anomalies", []string{"infrastructure:read"}, FreshnessRecent},
	// Telemetry — device syslog search (OpenSearch per-tenant index + doc-level
	// tenant filter; ≤50 redacted lines) and a per-device health snapshot
	// (inventory + VictoriaMetrics, device resolved tenant-scoped first). P2.
	{"search_logs", "telemetry", "search_logs", []string{"logs:read"}, FreshnessLive},
	{"get_device_health", "telemetry", "device_health", []string{"infrastructure:read"}, FreshnessLive},
	// App Identification (CH netops.app_identities, tenant_iso row policy).
	{"get_app_identity_summary", "app_identification", "app_identity_summary", []string{"applications:read"}, FreshnessRecent},
	{"get_low_confidence_app_matches", "app_identification", "low_confidence_apps", []string{"applications:read"}, FreshnessRecent},
	// Integrations (connector config store, tenant-scoped).
	{"get_integration_health", "integrations", "integration_health", []string{"administration:read"}, FreshnessConfig},
	// ITSM (ticketing store, tenant-scoped) — enriches an RCA with linked-ticket
	// state. Runs on the problem-explanation path (needs problem_id in args).
	{"get_ticket_status", "itsm", "ticket_status", []string{"incident:read"}, FreshnessLive},
}

// Tools builds the tool registry. P1 wires the RCA tools to the DataSource;
// when the DataSource also implements ModuleDataSource (the real server does),
// the P4 module read tools are wired too. Module tools whose names are NOT
// registered route to an honest disclosure, so routing always knows a module
// exists without faking data.
func Tools(ds DataSource) *ToolRegistry {
	reg := &ToolRegistry{byName: map[string]AITool{}}
	reg.add(getProblemTool{ds})
	reg.add(getProblemEvidenceTool{ds})
	reg.add(activeIncidentsTool{ds})
	reg.add(actionableIncidentsTool{ds})
	if wds, ok := ds.(WindowDataSource); ok {
		reg.add(incidentHistoryTool{wds})
	}
	if mds, ok := ds.(ModuleDataSource); ok {
		for _, mt := range moduleTools {
			reg.add(moduleReadTool{
				mds: mds, name: mt.name, module: mt.module,
				perms: mt.perms, freshness: mt.freshness, query: mt.query,
			})
		}
	}
	return reg
}

// ToolRegistry is the Module Tool Registry: name → governed tool.
type ToolRegistry struct{ byName map[string]AITool }

func (r *ToolRegistry) add(t AITool) { r.byName[t.Name()] = t }

// Get returns a tool by name (ok=false if not registered/implemented).
func (r *ToolRegistry) Get(name string) (AITool, bool) {
	t, ok := r.byName[name]
	return t, ok
}

// Names lists registered (implemented) tool names.
func (r *ToolRegistry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	return out
}
