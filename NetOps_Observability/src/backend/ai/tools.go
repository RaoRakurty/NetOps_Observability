package ai

import (
	"context"
	"errors"
	"fmt"
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
	ID              string
	Title           string
	Verdict         string // confirmed | suspected | undetermined
	Confidence      float64
	Devices         []string
	MissingEvidence []string
	Owner           string
	SignalCount     int
	NodeCount       int
	CreatedAt       string
	Timeline        []string // optional human-readable timeline lines
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
	item := EvidenceItem{
		CitationID: "problem:" + pr.ID,
		Kind:       "finding",
		Text: fmt.Sprintf("Problem %s — %s; verdict %s (%.0f%% confidence); %d signals across %d nodes; devices: %v",
			pr.ID, pr.Title, pr.Verdict, pr.Confidence*100, pr.SignalCount, pr.NodeCount, pr.Devices),
		Href: "#/monitoring/correlations?id=" + pr.ID,
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
			Text: fmt.Sprintf("%s — %s (%s, %.0f%%)", shortIDFor(pr.ID), pr.Title, pr.Verdict, pr.Confidence*100),
			Href: "#/monitoring/correlations?id=" + pr.ID,
		})
	}
	return ToolResult{Items: items}, nil
}

func shortIDFor(id string) string {
	if i := indexByte(id, '-'); i > 0 {
		return id[:i]
	}
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// Tools builds the tool registry. P1 wires the RCA tools to the DataSource;
// other modules' tools are catalog entries that return ErrNotImplemented until
// their phase lands (HLD P2–P4), so routing knows they exist without faking data.
func Tools(ds DataSource) *ToolRegistry {
	reg := &ToolRegistry{byName: map[string]AITool{}}
	reg.add(getProblemTool{ds})
	reg.add(getProblemEvidenceTool{ds})
	reg.add(activeIncidentsTool{ds})
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
