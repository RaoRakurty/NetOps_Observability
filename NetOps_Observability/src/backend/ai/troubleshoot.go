package ai

// troubleshoot.go — the IRIS Phase-A read-only tool set: the evidence the
// grounded loop was blind to (protocol diagnostics, security findings, topology
// context, case timeline, RCA verdict).
//
// Contract (roadmap Phase A, CLAUDE.md §3a/§4/§15):
//   - READ-ONLY. Every tool here is CapRead; none has a side effect, and
//     TestTroubleshootToolsAreReadOnly asserts it. The gated action subsystem
//     (HLD P6) stays a separate subsystem the model cannot reach.
//   - TENANT-SCOPED THROUGH THE SAME GATES the HTTP handlers use. The ai package
//     owns no store: each tool calls an injected TroubleshootDeps function that
//     the server implements with principalTenant + canSeeDevice + the same
//     row-policy/index scoping its handlers use. A foreign or unknown id returns
//     ErrNotFound — never "forbidden", never a leaked existence signal.
//   - BOUNDED. Every result is capped here as well as at the source, so a large
//     upstream answer can never become a large prompt.
//   - HONEST. A capability that is not wired on this deployment says so; it never
//     fabricates a capture, a finding, or a path.
//
// The seam shape (function fields on a Deps struct, filled at one wiring site)
// mirrors secapi/seclane: this package holds no ambient authority of its own.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Output caps. Each is applied here even when the source also caps, because the
// prompt budget is ours to defend, not the store's.
const (
	MaxDiagCommands       = 20
	MaxDiagFindings       = 10
	MaxSecurityFindings   = 50
	MaxTopologyNeighbors  = 25
	MaxTopologyPaths      = 10
	MaxTopologySeams      = 10
	MaxTimelineEvents     = 40
	maxToolTextChars      = 400 // per rendered evidence line
	maxDiagEvidenceChars  = 240 // per quoted device output line
	defaultFindingsLimit  = 25
	protocolDiagRouteHref = "#/infrastructure/protocol-diagnostics"
	// maxVerdictPhraseTokens bounds how many words of the ENGINE's own verdict
	// phrase become `verdict:phrase=` signals. The phrase is short by
	// construction; the cap is there so a pathological one cannot inflate the
	// signal list the chain evaluator walks (§9 bounded).
	maxVerdictPhraseTokens = 24
)

// ---- injected seams --------------------------------------------------------

// DeviceRef is one device the CALLER may see, already resolved by the server
// against the tenant-scoped inventory.
type DeviceRef struct {
	ID       string
	Name     string
	Platform string
	Vendor   string
}

// DiagnosticRequest is a validated protocol-diagnostic ask. Protocol is one of
// the closed vocabulary (bgp/ospf/isis); IssueID, when set, is a catalog issue id.
type DiagnosticRequest struct {
	DeviceID string
	Protocol string
	IssueID  string
}

// DiagnosticCommand is one curated READ-ONLY probe from the issue's bundle.
type DiagnosticCommand struct {
	SpecID  string
	Purpose string
	Command string
}

// DiagnosticFinding is one fired signature: the catalog's own verdict wording,
// never the model's.
type DiagnosticFinding struct {
	SignatureID  string
	Verdict      string
	Cause        string
	Remediation  string
	Confidence   string
	Command      string
	EvidenceLine string
}

// DiagnosticReport is the protocoldiag answer projected for the assistant.
// Collected=false with a non-empty NotWired is the honest "no capture transport
// on this deployment" case — the catalog bundle is still returned so the
// operator can paste outputs into the Protocol Diagnostics page.
type DiagnosticReport struct {
	DeviceID       string
	DeviceName     string
	Protocol       string
	IssueID        string
	IssueTitle     string
	IssueSummary   string
	RulesetVersion string
	Commands       []DiagnosticCommand
	Findings       []DiagnosticFinding
	Unmatched      string
	Collected      bool
	NotWired       string
}

// FindingsQuery is a validated security-findings ask.
type FindingsQuery struct {
	Device   string
	Seam     string
	Severity string
	Current  bool
	Limit    int
}

// SecurityFinding is one projected finding row (no raw evidence payload — §5c /
// LLM06: narrative and raw evidence stay off this path).
type SecurityFinding struct {
	ID       string
	Title    string
	Severity string
	Status   string
	SeamType string
	SeamID   string
	Entity   string
	Control  string
}

// TopologyNeighbor is one adjacency of the subject device.
type TopologyNeighbor struct {
	LocalPort string
	PeerName  string
	PeerPort  string
	Source    string // how the adjacency was observed (lldp, config, …)
}

// TopologySeam is one ownership handoff the device sits on.
type TopologySeam struct {
	ID    string
	Type  string
	Owner string
}

// TopologyPathRef is one measured path the device participates in.
type TopologyPathRef struct {
	ID     string
	Label  string
	Health string
	Hops   int
}

// TopologyContext is the read-only topology answer for one device.
type TopologyContext struct {
	DeviceID   string
	DeviceName string
	Site       string
	Role       string
	Neighbors  []TopologyNeighbor
	Seams      []TopologySeam
	Paths      []TopologyPathRef
	Notes      []string
}

// TimelineEvent is one entry of a correlation case's timeline.
type TimelineEvent struct {
	At     string
	Kind   string
	Entity string
	Text   string
}

// TroubleshootDeps are the injected, tenant-scoped reads behind the Phase-A
// tools. Every field is OPTIONAL: a nil field means that capability is not wired
// on this deployment, and the corresponding tool is simply NOT REGISTERED — the
// model never sees a tool that would answer with nothing.
//
// Implementations MUST scope by the principal exactly as the HTTP handlers do
// and MUST return ErrNotFound for an id the caller may not see.
type TroubleshootDeps struct {
	// ResolveDevice maps an operator-facing device reference (name or id) to one
	// of the CALLER'S OWN devices. ErrNotFound covers both "no such device" and
	// "another tenant's device" — the two must be indistinguishable (§3a rule 1).
	ResolveDevice func(ctx context.Context, p Principal, ref string) (DeviceRef, error)
	// ProtocolDiagnostic runs the protocoldiag catalog+analyze contract for one
	// device. It collects only when a CommandRunner is wired AND the caller holds
	// infrastructure:write; otherwise it returns the bundle with NotWired set.
	ProtocolDiagnostic func(ctx context.Context, p Principal, req DiagnosticRequest) (DiagnosticReport, error)
	// SecurityFindings lists the caller's own findings (secapi read path).
	SecurityFindings func(ctx context.Context, p Principal, q FindingsQuery) ([]SecurityFinding, error)
	// TopologyContext returns neighbours, seams and measured paths for a device.
	TopologyContext func(ctx context.Context, p Principal, deviceID string) (TopologyContext, error)
	// CaseTimeline returns one correlation case's ordered timeline.
	CaseTimeline func(ctx context.Context, p Principal, correlationID string) ([]TimelineEvent, error)

	// ── IRIS Phase A4 ──────────────────────────────────────────────────────

	// DeviceState runs the SHOW-FIRST state battery for one device and one area
	// and returns TYPED evidence rows (never raw CLI text the model must parse).
	// Like ProtocolDiagnostic it collects only when a battery runner is wired
	// AND the caller holds infrastructure:write; otherwise it returns the
	// read-only command list with NotWired set. Cross-tenant → ErrNotFound.
	DeviceState func(ctx context.Context, p Principal, req DeviceStateRequest) (DeviceStateReport, error)
	// BGPWatchlist lists the CALLER'S OWN watched prefixes and ASNs.
	BGPWatchlist func(ctx context.Context, p Principal) (BGPWatchlistReport, error)
	// BGPRPKI returns the RPKI validation state of the caller's own watched
	// prefixes (public routing facts, tenant-selected inputs).
	BGPRPKI func(ctx context.Context, p Principal) (BGPRPKIReport, error)
	// BGPFeedRecent returns recent BGP updates from the caller's OWN per-tenant
	// ring, optionally narrowed to one prefix.
	BGPFeedRecent func(ctx context.Context, p Principal, prefix string, limit int) (BGPFeedReport, error)

	// ── IRIS Phase B ───────────────────────────────────────────────────────

	// RecallInvestigations returns the CALLER'S OWN prior concluded
	// investigations for the entity in q (device / peer / prefix / case),
	// newest conclusion first. READ-ONLY memory: it never returns another
	// tenant's row, and an unkeyed query returns nothing (the store has no
	// unscoped list). nil = investigation memory is not wired on this
	// deployment, and `recall_investigations` is then not registered at all.
	RecallInvestigations func(ctx context.Context, p Principal, q InvestigationQuery) ([]InvestigationRow, error)
}

// ---- shared validation -----------------------------------------------------

// diagProtocols is the closed protocol vocabulary. A protocol outside it is
// rejected before any seam is touched (never passed through).
var diagProtocols = map[string]bool{"bgp": true, "ospf": true, "isis": true}

// severityTokens is the closed severity vocabulary for get_security_findings.
var severityTokens = map[string]bool{
	"critical": true, "high": true, "medium": true, "low": true, "info": true,
}

// reIDSafe bounds every id-ish argument that reaches a seam: printable,
// no whitespace, no wildcards, bounded length. Defence in depth — the seam
// re-validates, and the store scopes by tenant regardless.
func validIDArg(name, v string, max int) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", fmt.Errorf("%s is required", name)
	}
	if len(v) > max {
		return "", fmt.Errorf("%s is too long (max %d characters)", name, max)
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.' || r == ':' || r == '/':
		default:
			return "", fmt.Errorf("%s contains an unsupported character", name)
		}
	}
	return v, nil
}

func clampText(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + " …"
	}
	return s
}

// ---- run_protocol_diagnostic ----------------------------------------------

type protocolDiagnosticTool struct{ deps TroubleshootDeps }

func (t protocolDiagnosticTool) Name() string            { return "run_protocol_diagnostic" }
func (t protocolDiagnosticTool) Module() string          { return "protocol_diagnostics" }
func (t protocolDiagnosticTool) Capability() Capability  { return CapRead }
func (t protocolDiagnosticTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t protocolDiagnosticTool) Freshness() Freshness    { return FreshnessLive }

func (t protocolDiagnosticTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	dev, err := validIDArg("device_id", args["device_id"], 128)
	if err != nil {
		return ToolResult{}, err
	}
	proto := strings.ToLower(strings.TrimSpace(args["protocol"]))
	if !diagProtocols[proto] {
		return ToolResult{}, fmt.Errorf("protocol must be one of bgp, ospf, isis")
	}
	issue := strings.TrimSpace(args["issue_id"])
	if issue != "" {
		if issue, err = validIDArg("issue_id", issue, 64); err != nil {
			return ToolResult{}, err
		}
	}
	ref, err := t.deps.ResolveDevice(ctx, p, dev)
	if err != nil {
		return ToolResult{}, err // ErrNotFound for unknown OR another tenant's device
	}
	rep, err := t.deps.ProtocolDiagnostic(ctx, p, DiagnosticRequest{
		DeviceID: ref.ID, Protocol: proto, IssueID: issue,
	})
	if err != nil {
		return ToolResult{}, err
	}
	label := firstNonEmpty(rep.DeviceName, ref.Name, ref.ID)
	href := protocolDiagRouteHref
	tr := ToolResult{}
	head := fmt.Sprintf("%s — %s diagnostic %q (%s)", label, strings.ToUpper(rep.Protocol),
		firstNonEmpty(rep.IssueTitle, rep.IssueID), firstNonEmpty(rep.RulesetVersion, "catalog"))
	if rep.IssueSummary != "" {
		head += ": " + clampText(rep.IssueSummary, maxToolTextChars)
	}
	tr.Items = append(tr.Items, EvidenceItem{
		CitationID: "diag:" + rep.IssueID + ":" + ref.ID, Kind: "finding", Text: head, Href: href,
	})

	switch {
	case rep.Collected && len(rep.Findings) > 0:
		findings := rep.Findings
		if len(findings) > MaxDiagFindings {
			findings = findings[:MaxDiagFindings]
			tr.Truncated = true
			tr.Notes = append(tr.Notes, fmt.Sprintf("showing the top %d of %d matched signatures", MaxDiagFindings, len(rep.Findings)))
		}
		for _, f := range findings {
			// Machine fact for the investigation loop: THIS signature fired. The
			// id is the catalog's own (server-owned), and is shape-validated
			// before it can steer an authored next= rule.
			if reCondSignature.MatchString(f.SignatureID) {
				tr.Signals = append(tr.Signals, CondSignature+"="+f.SignatureID)
			}
			text := fmt.Sprintf("%s (%s confidence) — cause: %s; remediation: %s",
				f.Verdict, firstNonEmpty(f.Confidence, "unstated"), f.Cause, f.Remediation)
			if f.EvidenceLine != "" {
				text += fmt.Sprintf("; evidence from %q: %q", f.Command, clampText(f.EvidenceLine, maxDiagEvidenceChars))
			}
			tr.Items = append(tr.Items, EvidenceItem{
				CitationID: "diagsig:" + f.SignatureID, Kind: "finding",
				Text: clampText(text, maxToolTextChars+maxDiagEvidenceChars), Href: href,
			})
		}
	case rep.Collected:
		// Fail-closed: signatures ran and none fired. Say so; never invent a cause.
		tr.Notes = append(tr.Notes, firstNonEmpty(rep.Unmatched,
			"no known signature matched the captured output — report that plainly and show the raw output rather than naming a cause"))
	default:
		// Collection is not available on this deployment (or the caller lacks the
		// write level a device operation needs). Be honest and useful: hand back
		// the curated read-only bundle so a human can capture and paste it.
		tr.Notes = append(tr.Notes, firstNonEmpty(rep.NotWired,
			"live collection is not wired on this deployment — no output was captured"))
		tr.Notes = append(tr.Notes, "ask the operator to run the commands below and paste the output into Protocol Diagnostics; do NOT state a cause without output")
		cmds := rep.Commands
		if len(cmds) > MaxDiagCommands {
			cmds = cmds[:MaxDiagCommands]
			tr.Truncated = true
		}
		for _, c := range cmds {
			tr.Items = append(tr.Items, EvidenceItem{
				CitationID: "diagcmd:" + rep.IssueID + ":" + c.SpecID, Kind: "device",
				Text: clampText(fmt.Sprintf("suggested read-only check (%s): `%s`", c.Purpose, c.Command), maxToolTextChars),
				Href: href,
			})
		}
	}
	return tr, nil
}

// ---- get_security_findings -------------------------------------------------

type securityFindingsTool struct{ deps TroubleshootDeps }

func (t securityFindingsTool) Name() string            { return "get_security_findings" }
func (t securityFindingsTool) Module() string          { return "security_posture" }
func (t securityFindingsTool) Capability() Capability  { return CapRead }
func (t securityFindingsTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t securityFindingsTool) Freshness() Freshness    { return FreshnessRecent }

func (t securityFindingsTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	q := FindingsQuery{Current: true, Limit: defaultFindingsLimit}
	if raw := strings.TrimSpace(args["current"]); raw != "" {
		v, err := strconv.ParseBool(strings.ToLower(raw))
		if err != nil {
			return ToolResult{}, fmt.Errorf("current must be true or false")
		}
		q.Current = v
	}
	if raw := strings.TrimSpace(args["severity"]); raw != "" {
		sev := strings.ToLower(raw)
		if !severityTokens[sev] {
			return ToolResult{}, fmt.Errorf("severity must be one of critical, high, medium, low, info")
		}
		q.Severity = sev
	}
	if raw := strings.TrimSpace(args["seam"]); raw != "" {
		v, err := validIDArg("seam", raw, 128)
		if err != nil {
			return ToolResult{}, err
		}
		q.Seam = v
	}
	if raw := strings.TrimSpace(args["device"]); raw != "" {
		v, err := validIDArg("device", raw, 128)
		if err != nil {
			return ToolResult{}, err
		}
		// Resolve through the caller's OWN inventory first: a device the caller
		// cannot see must read as not-found, not as "no findings" (which would
		// silently confirm the device exists elsewhere).
		ref, rerr := t.deps.ResolveDevice(ctx, p, v)
		if rerr != nil {
			return ToolResult{}, rerr
		}
		q.Device = firstNonEmpty(ref.Name, ref.ID)
	}
	rows, err := t.deps.SecurityFindings(ctx, p, q)
	if err != nil {
		return ToolResult{}, err
	}
	tr := ToolResult{}
	if len(rows) > MaxSecurityFindings {
		rows = rows[:MaxSecurityFindings]
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("capped at %d findings", MaxSecurityFindings))
	}
	if len(rows) == 0 {
		// "No findings" and "not assessed" are different facts; say which we know.
		tr.Notes = append(tr.Notes, "no security findings matched this scope — say that no MATCHING finding was returned, not that the scope is clean (a device that was never assessed also returns nothing)")
		return tr, nil
	}
	for _, f := range rows {
		seam := f.SeamType
		if f.SeamID != "" {
			seam = strings.TrimSpace(seam + " " + f.SeamID)
		}
		text := fmt.Sprintf("%s — severity %s, status %s",
			firstNonEmpty(f.Title, f.Control, f.ID), firstNonEmpty(f.Severity, "unrated"), firstNonEmpty(f.Status, "unknown"))
		if f.Entity != "" {
			text += "; on " + f.Entity
		}
		if seam != "" {
			text += "; seam " + seam
		}
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: "secfinding:" + f.ID, Kind: "finding",
			Text: clampText(text, maxToolTextChars), Href: "#/security/findings",
		})
	}
	scope := "current state (latest verdict per finding)"
	if !q.Current {
		scope = "full retained verdict history"
	}
	tr.Notes = append(tr.Notes, "scope: "+scope)
	return tr, nil
}

// ---- get_topology_context --------------------------------------------------

type topologyContextTool struct{ deps TroubleshootDeps }

func (t topologyContextTool) Name() string            { return "get_topology_context" }
func (t topologyContextTool) Module() string          { return "topology" }
func (t topologyContextTool) Capability() Capability  { return CapRead }
func (t topologyContextTool) RequiredPerms() []string { return []string{"infrastructure:read"} }
func (t topologyContextTool) Freshness() Freshness    { return FreshnessLive }

func (t topologyContextTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	ref, err := validIDArg("device_id", args["device_id"], 128)
	if err != nil {
		return ToolResult{}, err
	}
	dev, err := t.deps.ResolveDevice(ctx, p, ref)
	if err != nil {
		return ToolResult{}, err
	}
	tc, err := t.deps.TopologyContext(ctx, p, dev.ID)
	if err != nil {
		return ToolResult{}, err
	}
	label := firstNonEmpty(tc.DeviceName, dev.Name, dev.ID)
	href := "#/infrastructure/topology-canvas"
	tr := ToolResult{}
	head := label
	if tc.Site != "" {
		head += ", site " + tc.Site
	}
	if tc.Role != "" {
		head += ", role " + tc.Role
	}
	head += fmt.Sprintf(" — %s, %s, %s",
		plural(len(tc.Neighbors), "neighbour"), plural(len(tc.Seams), "seam"), plural(len(tc.Paths), "measured path"))
	tr.Items = append(tr.Items, EvidenceItem{
		CitationID: "topo:" + dev.ID, Kind: "topology", Text: clampText(head, maxToolTextChars), Href: href,
	})

	ns := tc.Neighbors
	if len(ns) > MaxTopologyNeighbors {
		ns = ns[:MaxTopologyNeighbors]
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing %d of %d neighbours", MaxTopologyNeighbors, len(tc.Neighbors)))
	}
	for i, n := range ns {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: fmt.Sprintf("topo-nbr:%s:%d", dev.ID, i+1), Kind: "topology",
			Text: clampText(fmt.Sprintf("%s %s ↔ %s %s (%s)", label, n.LocalPort, n.PeerName, n.PeerPort,
				firstNonEmpty(n.Source, "observed")), maxToolTextChars),
			Href: href,
		})
	}
	seams := tc.Seams
	if len(seams) > MaxTopologySeams {
		seams = seams[:MaxTopologySeams]
		tr.Truncated = true
	}
	for i, s := range seams {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: fmt.Sprintf("topo-seam:%s:%d", dev.ID, i+1), Kind: "topology",
			Text: clampText(fmt.Sprintf("seam %s (%s) — owner %s", firstNonEmpty(s.ID, s.Type), s.Type,
				firstNonEmpty(s.Owner, "unassigned")), maxToolTextChars),
			Href: href,
		})
	}
	paths := tc.Paths
	if len(paths) > MaxTopologyPaths {
		paths = paths[:MaxTopologyPaths]
		tr.Truncated = true
	}
	for i, pth := range paths {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: fmt.Sprintf("topo-path:%s:%d", dev.ID, i+1), Kind: "topology",
			Text: clampText(fmt.Sprintf("path %s — %s, %s", firstNonEmpty(pth.Label, pth.ID),
				firstNonEmpty(pth.Health, "health unknown"), plural(pth.Hops, "hop")), maxToolTextChars),
			Href: "#/infrastructure/paths",
		})
	}
	if len(tc.Neighbors) == 0 && len(tc.Paths) == 0 {
		tr.Notes = append(tr.Notes, "no adjacency or measured path is recorded for this device — say the topology context is UNKNOWN here, not that the device is isolated")
	}
	tr.Notes = append(tr.Notes, tc.Notes...)
	return tr, nil
}

// ---- get_case_timeline -----------------------------------------------------

type caseTimelineTool struct{ deps TroubleshootDeps }

func (t caseTimelineTool) Name() string            { return "get_case_timeline" }
func (t caseTimelineTool) Module() string          { return "correlations_rca" }
func (t caseTimelineTool) Capability() Capability  { return CapRead }
func (t caseTimelineTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t caseTimelineTool) Freshness() Freshness    { return FreshnessLive }

func (t caseTimelineTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	id, err := validIDArg("correlation_id", args["correlation_id"], 64)
	if err != nil {
		return ToolResult{}, err
	}
	events, err := t.deps.CaseTimeline(ctx, p, id)
	if err != nil {
		return ToolResult{}, err
	}
	href := "#/monitoring/correlations?id=" + id
	tr := ToolResult{}
	if len(events) > MaxTimelineEvents {
		events = events[:MaxTimelineEvents]
		tr.Truncated = true
		tr.Notes = append(tr.Notes, fmt.Sprintf("showing the first %d timeline events", MaxTimelineEvents))
	}
	if len(events) == 0 {
		tr.Notes = append(tr.Notes, "this case has no timeline events in the retained window")
		return tr, nil
	}
	for i, e := range events {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: fmt.Sprintf("timeline:%s:%d", shortToken(id), i+1), Kind: "log",
			Text: clampText(strings.TrimSpace(fmt.Sprintf("%s %s %s — %s", e.At, e.Kind, e.Entity, e.Text)), maxToolTextChars),
			Href: href,
		})
	}
	return tr, nil
}

// ---- get_rca_verdict -------------------------------------------------------

// rcaVerdictTool answers the six-question RCA header from the SAME tenant-scoped
// DataSource the RCA page reads: what broke, the verdict tier + confidence, what
// is affected, what evidence is missing, and the recommended owner. It reads no
// new store — it is the engine's conclusion, projected for the assistant so a
// skill can start from the verdict instead of re-deriving it.
type rcaVerdictTool struct{ ds DataSource }

func (t rcaVerdictTool) Name() string            { return "get_rca_verdict" }
func (t rcaVerdictTool) Module() string          { return "correlations_rca" }
func (t rcaVerdictTool) Capability() Capability  { return CapRead }
func (t rcaVerdictTool) RequiredPerms() []string { return []string{"correlations:read"} }
func (t rcaVerdictTool) Freshness() Freshness    { return FreshnessLive }

func (t rcaVerdictTool) Run(ctx context.Context, p Principal, args ToolArgs) (ToolResult, error) {
	id, err := validIDArg("correlation_id", args["correlation_id"], 64)
	if err != nil {
		return ToolResult{}, err
	}
	pr, err := t.ds.GetProblem(ctx, p, id)
	if err != nil {
		return ToolResult{}, err // ErrNotFound for unknown OR another tenant's case
	}
	href := "#/monitoring/correlations?id=" + pr.ID
	tr := ToolResult{}
	// 1. What broke + 2. how sure we are.
	what := firstNonEmpty(pr.OperatorPhrase, pr.Title)
	// Machine facts for the investigation loop (skill_chain.go): the ENGINE's
	// verdict tier and the words of its own operator phrase. Both come from the
	// correlation engine, never from a model, and both are validated against the
	// closed condition vocabulary before they can steer an authored next= rule.
	if tier := strings.ToLower(strings.TrimSpace(pr.Verdict)); skillVerdictTiers[tier] {
		tr.Signals = append(tr.Signals, CondVerdictTier+"="+tier)
	}
	tr.Signals = append(tr.Signals, verdictPhraseSignals(what, maxVerdictPhraseTokens)...)
	conf := firstNonEmpty(pr.ConfidenceLabel, StatusLabel(pr.Verdict))
	tr.Items = append(tr.Items, EvidenceItem{
		CitationID: "verdict:" + pr.ID, Kind: "finding",
		Text: clampText(fmt.Sprintf("%s — %s; verdict %s (%s, %.0f%% model confidence); %s across %s",
			pr.Display(), what, pr.Verdict, conf, pr.Confidence*100,
			plural(pr.SignalCount, "signal"), plural(pr.NodeCount, "node")), maxToolTextChars),
		Href: href,
	})
	// 3. What is affected.
	if len(pr.Devices) > 0 {
		devs := pr.Devices
		if len(devs) > MaxTopologyNeighbors {
			devs = devs[:MaxTopologyNeighbors]
			tr.Truncated = true
		}
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: "verdict-affected:" + pr.ID, Kind: "topology",
			Text: clampText("affected: "+strings.Join(devs, ", "), maxToolTextChars), Href: href,
		})
	}
	// 4. What evidence is missing (the honesty half of the header).
	if len(pr.MissingEvidence) > 0 {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: "verdict-missing:" + pr.ID, Kind: "finding",
			Text: clampText("missing evidence: "+strings.Join(pr.MissingEvidence, "; "), maxToolTextChars), Href: href,
		})
	}
	// 5. Owner. 6. When it started.
	if pr.Owner != "" {
		tr.Items = append(tr.Items, EvidenceItem{
			CitationID: "verdict-owner:" + pr.ID, Kind: "finding",
			Text: "recommended owner: " + clampText(pr.Owner, 120), Href: href,
		})
	}
	if pr.CreatedAt != "" {
		tr.Notes = append(tr.Notes, "case opened "+clampText(pr.CreatedAt, 64))
	}
	tr.Notes = append(tr.Notes, "this is the ENGINE's conclusion — narrate it, do not re-derive a different cause")
	return tr, nil
}

// ---- registration ----------------------------------------------------------

// AddTroubleshootTools registers the Phase-A read-only tools for the seams that
// are actually wired. A nil Deps field means that capability is absent on this
// deployment: the tool is not registered, so it never appears in the model's
// manifest and never answers with fabricated data.
func (r *ToolRegistry) AddTroubleshootTools(ds DataSource, d TroubleshootDeps) {
	if r == nil {
		return
	}
	if ds != nil {
		r.add(rcaVerdictTool{ds: ds})
	}
	if d.CaseTimeline != nil {
		r.add(caseTimelineTool{deps: d})
	}
	// The BGP operations reads are RESOURCE-scoped, not device-scoped: they need
	// no inventory resolution, so they register independently of ResolveDevice.
	if d.BGPWatchlist != nil {
		r.add(bgpWatchlistTool{deps: d})
	}
	if d.BGPRPKI != nil {
		r.add(bgpRPKITool{deps: d})
	}
	if d.BGPFeedRecent != nil {
		r.add(bgpFeedTool{deps: d})
	}
	// Investigation memory is entity-keyed, not device-keyed: it answers for a
	// case, a peer or a prefix too, so it registers independently of the
	// inventory seam (a device ARGUMENT is still resolved through ResolveDevice
	// when one is wired).
	if d.RecallInvestigations != nil {
		r.add(recallInvestigationsTool{deps: d})
	}
	if d.ResolveDevice == nil {
		return // every remaining tool resolves a device under the caller's tenant first
	}
	if d.ProtocolDiagnostic != nil {
		r.add(protocolDiagnosticTool{deps: d})
	}
	if d.SecurityFindings != nil {
		r.add(securityFindingsTool{deps: d})
	}
	if d.TopologyContext != nil {
		r.add(topologyContextTool{deps: d})
	}
	if d.DeviceState != nil {
		r.add(deviceStateTool{deps: d})
	}
}

// verdictPhraseSignals turns the engine's own verdict phrase into bounded,
// deduplicated `verdict:phrase=<word>` signals. Only words that satisfy the
// condition-token shape become signals, so nothing outside the closed grammar
// can reach the chain evaluator.
func verdictPhraseSignals(phrase string, max int) []string {
	var out []string
	for _, w := range conditionTokens(phrase) {
		if len(out) >= max {
			break
		}
		out = append(out, CondVerdictPhrase+"="+w)
	}
	return out
}

// shortToken is a stable short form of an id for citation ids (no secret
// material — correlation ids are already operator-visible).
func shortToken(id string) string {
	if len(id) <= 8 {
		return id
	}
	return id[:8]
}

// TroubleshootToolNames lists the Phase-A tool names in a stable order (tests +
// documentation).
func TroubleshootToolNames() []string {
	out := []string{
		"run_protocol_diagnostic", "get_security_findings",
		"get_topology_context", "get_case_timeline", "get_rca_verdict",
		// Phase A4.
		"get_device_state", "get_bgp_watchlist", "get_bgp_rpki", "get_bgp_feed_recent",
		// Phase B.
		"recall_investigations",
	}
	sort.Strings(out)
	return out
}
