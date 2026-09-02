package backend

// ai_troubleshoot_deps.go — the SERVER half of ai.TroubleshootDeps (IRIS Phase
// A). The ai package owns no store and holds no ambient authority: it declares
// five read-only seams and this file fills them, for ONE request, with the same
// gates the corresponding HTTP handlers use.
//
// §3a is the whole point of the file. Every closure below scopes by the
// PRINCIPAL, not by an argument:
//
//	ResolveDevice      canSeeDevice over s.discovery, exactly as the collect
//	                   handler and moduleDeviceHealth do.
//	ProtocolDiagnostic the resolved device again + the same infrastructure:WRITE
//	                   gate the collect endpoint requires before a device is
//	                   touched; capture goes through the shared pdRunCollection
//	                   (redacted at capture, audited with the sensitive tag).
//	SecurityFindings   secapi.ListFindings — the same scope()/ListBody/decoder
//	                   path GET /api/security/findings takes.
//	TopologyContext    visibleDevices + gatherTopoLinks (the /api/topology/view
//	                   inputs), the tenant-scoped seam store, and the path graph's
//	                   tenant+cross-scoped reads.
//	CaseTimeline       loadCorrSlice under the caller's ClickHouse tenant scope,
//	                   PLUS the strict app-side check aiDataSource.corrRowVisible
//	                   applies (untagged correlation intel is platform-only).
//
// An unknown id and another tenant's id are both ai.ErrNotFound — never
// "forbidden", never a leaked existence signal. A capability that is not wired
// on this deployment leaves its field NIL, so the tool is not registered at all
// and the assistant cannot answer from it (honesty over coverage).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/protocoldiag"
	"netops/backend/models"
	"netops/backend/pathgraph"
	"netops/backend/secapi"
)

// Bounds for the assistant's reads. Each is deliberately tighter than the HTTP
// surface's: this data becomes prompt text, and the prompt budget is ours to
// defend (LLM04/LLM10).
const (
	aiTopoTimeout      = 6 * time.Second // adjacency/metric gather deadline (§9: all IO has a timeout)
	aiTopoMaxLinks     = 200             // links scanned for one device's adjacencies
	aiPathDefsScanned  = 200             // path definitions scanned before matching stops
	aiFindingsMaxLimit = 50              // hard cap on findings handed to a prompt
)

// aiTroubleshootDeps builds the Phase-A read seams for ONE request. Fields are
// left nil when the backing subsystem is absent on this deployment; the tool
// registry then simply does not expose that tool.
func (s *server) aiTroubleshootDeps(r *http.Request, claims jwtClaims) ai.TroubleshootDeps {
	deps := ai.TroubleshootDeps{}
	if s == nil {
		return deps
	}
	if s.discovery != nil {
		deps.ResolveDevice = s.aiResolveDevice(claims)
		deps.ProtocolDiagnostic = s.aiProtocolDiagnostic(r, claims)
		deps.TopologyContext = s.aiTopologyContext(claims)
	}
	if s.secAPI != nil {
		deps.SecurityFindings = s.aiSecurityFindings(claims)
	}
	deps.CaseTimeline = s.aiCaseTimeline(claims)
	return deps
}

// aiToolAudit records one skill gather-step execution. The ai package never
// sees a token, so the ACTOR is added here; the entry itself carries argument
// NAMES only (§8: no PII, no values, in a log line).
func (s *server) aiToolAudit(claims jwtClaims) func(ai.ToolAuditEntry) {
	tenant, cross := principalTenant(claims)
	return func(e ai.ToolAuditEntry) {
		logInfo("ai", "tool", map[string]any{
			"tenant": tenant, "cross": cross, "sub": claims.Sub,
			"skill": e.Skill, "tool": e.Tool, "args": e.Args,
			"allowed": e.Allowed, "reason": e.Reason,
			"items": e.Items, "duration_ms": e.Duration,
		})
	}
}

// ---- device resolution ------------------------------------------------------

// aiResolveDevice maps an operator-facing device reference (name OR id) to one
// of the CALLER'S OWN devices. It is the same scan moduleDeviceHealth and the
// topology handlers use: the tenant filter is applied per device, before the
// name is compared, so a name that exists only in another tenant is simply not
// found (§3a rule 1 — the two cases must be indistinguishable).
func (s *server) aiResolveDevice(claims jwtClaims) func(context.Context, ai.Principal, string) (ai.DeviceRef, error) {
	return func(_ context.Context, _ ai.Principal, ref string) (ai.DeviceRef, error) {
		dev, ok := s.aiLookupDevice(claims, ref)
		if !ok {
			return ai.DeviceRef{}, ai.ErrNotFound
		}
		return ai.DeviceRef{
			ID: dev.ID, Name: dev.Name,
			Platform: pdPlatformString(dev), Vendor: dev.Vendor,
		}, nil
	}
}

// aiLookupDevice is the shared, tenant-scoped inventory lookup. The tenant and
// cross flag come from the CLAIMS (the token is the authority), never from an
// argument the caller could shape.
func (s *server) aiLookupDevice(claims jwtClaims, ref string) (models.Device, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" || s.discovery == nil {
		return models.Device{}, false
	}
	tenant, cross := principalTenant(claims)
	for _, dev := range s.discovery.Devices() {
		if !canSeeDevice(dev, tenant, cross) {
			continue
		}
		if strings.EqualFold(dev.Name, ref) || strings.EqualFold(dev.ID, ref) {
			return dev, true
		}
	}
	return models.Device{}, false
}

// ---- protocol diagnostics ---------------------------------------------------

// aiProtocolDiagnostic runs the protocoldiag catalog → collect → analyze
// contract for one device, projected for the assistant.
//
// It collects ONLY when a CommandRunner is wired AND the caller holds
// infrastructure:WRITE — the exact gate handleProtocolDiagCollect requires,
// because a live capture is an operation against a device, not a read of stored
// state. Otherwise it returns the curated read-only command bundle with
// NotWired set: the assistant then hands the operator commands to run instead
// of inventing a capture that never happened.
func (s *server) aiProtocolDiagnostic(r *http.Request, claims jwtClaims) func(context.Context, ai.Principal, ai.DiagnosticRequest) (ai.DiagnosticReport, error) {
	return func(ctx context.Context, _ ai.Principal, req ai.DiagnosticRequest) (ai.DiagnosticReport, error) {
		dev, ok := s.aiLookupDevice(claims, req.DeviceID)
		if !ok {
			return ai.DiagnosticReport{}, ai.ErrNotFound
		}
		cat := s.pdCatalog()
		issue, ok := aiPickDiagIssue(cat, req.Protocol, req.IssueID)
		if !ok {
			return ai.DiagnosticReport{}, fmt.Errorf("no diagnostic scenario for protocol %q issue %q", req.Protocol, req.IssueID)
		}
		vendor := protocoldiag.VendorFromPlatform(pdPlatformString(dev))
		rep := ai.DiagnosticReport{
			DeviceID: dev.ID, DeviceName: dev.Name,
			Protocol: string(issue.Protocol), IssueID: issue.ID, IssueTitle: issue.Title,
			IssueSummary: issue.Description, RulesetVersion: protocoldiag.RulesetVersion,
		}
		for _, c := range pdBundleView(issue, vendor) {
			rep.Commands = append(rep.Commands, ai.DiagnosticCommand{
				SpecID: c.SpecID, Purpose: c.Purpose, Command: c.Command,
			})
		}

		switch {
		case s.protocolCollector == nil:
			rep.NotWired = "live collection is not wired on this deployment — no output was captured"
			return rep, nil
		case !s.roles.Allows(claims.Role, "infrastructure", LevelWrite):
			// A capture is a device operation. A read-only operator gets the
			// bundle to hand to someone who may run it — never a silent skip.
			rep.NotWired = "running a live capture needs infrastructure write access, which this account does not have — no output was captured"
			return rep, nil
		}

		col, err := s.pdRunCollection(ctx, dev, issue.ID, protocoldiag.Target{})
		if err != nil {
			// Never a silent failure (§10) and never a fabricated capture: the
			// operator gets the commands plus the honest reason.
			logWarn("ai", "protocol diagnostic collection failed", map[string]any{
				"device_id": dev.ID, "issue_id": issue.ID, "error": err.Error(),
			})
			rep.NotWired = "the live capture did not complete on this device — no output was analysed"
			return rep, nil
		}
		// §8: a live capture is the moment secrets could be read off a device —
		// audited with the sensitive tag, exactly as the HTTP collect path is.
		s.pdAudit(r, claims, deviceTenant(dev), "protocol_diagnostics.collect", map[string]any{
			"device_id": dev.ID, "issue_id": issue.ID,
			"commands": len(col.Commands), "via": "ai_assistant",
		})

		res := s.pdAnalyzer().Analyze(col)
		rep.Collected = true
		rep.Unmatched = res.Unmatched
		for _, f := range res.Findings {
			rep.Findings = append(rep.Findings, ai.DiagnosticFinding{
				SignatureID: f.SignatureID, Verdict: f.Verdict, Cause: f.Cause,
				Remediation: f.Remediation, Confidence: string(f.Confidence),
				Command: f.Evidence.Command, EvidenceLine: f.Evidence.Line,
			})
		}
		return rep, nil
	}
}

// aiPickDiagIssue resolves the catalog issue for a (protocol, optional issue id)
// pair. A named issue must EXIST and must belong to the requested protocol — a
// mismatch is refused rather than silently re-pointed, the same rule
// pdBuildCollection applies to the HTTP payload. With no issue named, the
// protocol's first authored scenario is the default.
func aiPickDiagIssue(cat *protocoldiag.Catalog, protocol, issueID string) (protocoldiag.Issue, bool) {
	proto := protocoldiag.Protocol(strings.ToLower(strings.TrimSpace(protocol)))
	if id := strings.TrimSpace(issueID); id != "" {
		issue, ok := cat.Issue(id)
		if !ok || issue.Protocol != proto {
			return protocoldiag.Issue{}, false
		}
		return issue, true
	}
	issues := cat.IssuesFor(proto)
	if len(issues) == 0 {
		return protocoldiag.Issue{}, false
	}
	return issues[0], true
}

// ---- security findings ------------------------------------------------------

// aiSecurityFindings lists the caller's OWN findings through secapi's non-HTTP
// read. The principal is built exactly as securityAuthz builds it (tenant,
// cross, and the visible device key/address sets that narrow untagged rows) —
// minus the HTTP gate, which is replaced by the same infrastructure:read check
// requirePerm would have applied.
func (s *server) aiSecurityFindings(claims jwtClaims) func(context.Context, ai.Principal, ai.FindingsQuery) ([]ai.SecurityFinding, error) {
	return func(_ context.Context, _ ai.Principal, q ai.FindingsQuery) ([]ai.SecurityFinding, error) {
		if !s.roles.Allows(claims.Role, "infrastructure", LevelRead) {
			return nil, ai.ErrForbidden
		}
		tenant, cross := principalTenant(claims)
		keys, _ := s.visibleDeviceKeys(claims)
		addrs, _ := s.visibleDeviceAddrs(claims)
		p := secapi.Principal{
			Tenant: tenant, Cross: cross, Subject: claims.Sub,
			DeviceKeys: keys, DeviceAddrs: addrs,
		}
		f := secapi.Filters{Current: q.Current}
		if q.Severity != "" {
			f.Severity = []string{q.Severity}
		}
		if q.Seam != "" {
			f.Seam = []string{q.Seam}
		}
		if q.Device != "" {
			f.Device = []string{q.Device}
		}
		limit := q.Limit
		if limit <= 0 || limit > aiFindingsMaxLimit {
			limit = aiFindingsMaxLimit
		}
		rows, err := s.secAPI.ListFindings(p, f, limit)
		if err != nil {
			if errors.Is(err, secapi.ErrNoSearch) {
				return nil, ai.ErrNotImplemented
			}
			return nil, err
		}
		out := make([]ai.SecurityFinding, 0, len(rows))
		for _, fn := range rows {
			row := ai.SecurityFinding{
				ID:      aiFirst(fn.DocID, fn.Native, fn.ID),
				Title:   aiFirst(fn.ControlTitle, fn.Detail, fn.ControlID),
				Status:  fn.Status,
				Control: fn.ControlID,
				Entity:  aiFirst(fn.Resource.DeviceName, fn.Resource.Hostname, fn.Resource.DeviceID),
			}
			row.Severity = strings.ToLower(fn.Severity)
			if fn.SeamContext != nil {
				row.SeamType = fn.SeamContext.SeamType
				row.SeamID = fn.SeamContext.SeamID
			}
			out = append(out, row)
		}
		return out, nil
	}
}

// ---- topology context -------------------------------------------------------

// aiTopologyContext answers "who is next to this device, which seam does it sit
// on, and which measured path does it carry" from the SAME tenant-scoped inputs
// /api/topology/view uses. The device slice handed to gatherTopoLinks IS the
// isolation boundary (a neighbour only ever resolves inside it), so it is always
// visibleDevices — never the platform-wide inventory.
func (s *server) aiTopologyContext(claims jwtClaims) func(context.Context, ai.Principal, string) (ai.TopologyContext, error) {
	return func(ctx context.Context, _ ai.Principal, deviceID string) (ai.TopologyContext, error) {
		dev, ok := s.aiLookupDevice(claims, deviceID)
		if !ok {
			return ai.TopologyContext{}, ai.ErrNotFound
		}
		tenant, cross := principalTenant(claims)
		out := ai.TopologyContext{
			DeviceID: dev.ID, DeviceName: dev.Name,
			Site: dev.Labels["site"], Role: aiFirst(dev.Labels["role"], dev.Type),
		}

		// §9: one bounded budget for the whole gather. Every read below rides it,
		// so a slow subsystem degrades this answer into an honest "unknown" note
		// rather than holding the assistant's turn open.
		tctx, cancel := context.WithTimeout(ctx, aiTopoTimeout)
		defer cancel()

		// Adjacencies: the deduped LLDP/CDP/BGP-LS link set, restricted to the
		// caller's own inventory, then to this device's own edges.
		devs := visibleDevices(s.discovery.Devices(), claims)
		links := s.gatherTopoLinks(tctx, devs)
		if len(links) > aiTopoMaxLinks {
			links = links[:aiTopoMaxLinks]
			out.Notes = append(out.Notes, "the adjacency set was capped before matching — some neighbours may not be listed")
		}
		for _, l := range links {
			switch {
			case l.Source == dev.ID:
				out.Neighbors = append(out.Neighbors, ai.TopologyNeighbor{
					LocalPort: l.LocalPort, PeerName: aiFirst(l.TargetName, l.Target),
					PeerPort: l.RemotePort, Source: l.SourceProto,
				})
			case l.Target == dev.ID:
				out.Neighbors = append(out.Neighbors, ai.TopologyNeighbor{
					LocalPort: l.RemotePort, PeerName: aiFirst(l.SourceName, l.Source),
					PeerPort: l.LocalPort, Source: l.SourceProto,
				})
			}
		}

		// Seams: the tenant-scoped seam register. A deployment without the store
		// says so rather than reporting "no seams", which would read as "this
		// device sits on no ownership handoff".
		if s.seams == nil {
			out.Notes = append(out.Notes, "the seam register is not enabled on this deployment — seam ownership is UNKNOWN here, not absent")
		} else if seams, err := s.seams.List(tctx, tenant, cross, "", ""); err != nil {
			logWarn("ai", "seam list failed for topology context", map[string]any{"device_id": dev.ID, "error": err.Error()})
			out.Notes = append(out.Notes, "the seam register could not be read — seam ownership is UNKNOWN for this answer")
		} else {
			for _, sm := range seams {
				if !aiSeamTouchesDevice(sm.Endpoints, dev) {
					continue
				}
				out.Seams = append(out.Seams, ai.TopologySeam{
					ID: aiFirst(sm.DisplayName, sm.SeamID), Type: sm.SeamType,
					Owner: sm.ControlPlaneOwner,
				})
			}
		}

		// Measured paths: the path graph's own tenant+cross scoped reads. Only
		// LIVE observations (pathgraph.LiveOnly) — synthetic/lab classes must
		// never be narrated as production measurements.
		if s.pathGraph == nil {
			out.Notes = append(out.Notes, "path measurement is not enabled on this deployment — no measured path is available")
		} else {
			out.Paths = append(out.Paths, s.aiDevicePaths(tctx, tenant, cross, dev)...)
		}
		return out, nil
	}
}

// aiSeamTouchesDevice reports whether any seam endpoint names this device. Seam
// endpoints are free-form (an address, a hostname, an interface), so all three
// device identities are compared, case-insensitively.
func aiSeamTouchesDevice(endpoints map[string]string, dev models.Device) bool {
	for _, v := range endpoints {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if strings.EqualFold(v, dev.ID) || strings.EqualFold(v, dev.Name) ||
			(dev.Address != "" && strings.EqualFold(v, dev.Address)) {
			return true
		}
	}
	return false
}

// aiDevicePaths returns the measured live paths this device is the vantage or
// source for, newest observation per path.
func (s *server) aiDevicePaths(ctx context.Context, tenant string, cross bool, dev models.Device) []ai.TopologyPathRef {
	defs, err := s.pathGraph.ListPathDefinitions(ctx, tenant, cross)
	if err != nil {
		logWarn("ai", "path definition list failed", map[string]any{"device_id": dev.ID, "error": err.Error()})
		return nil
	}
	if len(defs) > aiPathDefsScanned {
		defs = defs[:aiPathDefsScanned]
	}
	var out []ai.TopologyPathRef
	for _, d := range defs {
		if len(out) >= ai.MaxTopologyPaths {
			break
		}
		if !aiPathTouchesDevice(d, dev) {
			continue
		}
		ref := ai.TopologyPathRef{ID: d.PathID, Label: aiPathLabel(d, dev)}
		obs, _, _, found, oerr := s.pathGraph.LatestObservation(ctx, tenant, cross, pathgraph.ObservationFilter{
			PathID: d.PathID, DataClasses: pathgraph.LiveOnly(), Limit: 1,
		})
		switch {
		case oerr != nil:
			logWarn("ai", "path observation read failed", map[string]any{"path_id": d.PathID, "error": oerr.Error()})
			ref.Health = "not measured recently"
		case !found:
			ref.Health = "no live measurement"
		default:
			ref.Health = obs.Status
			ref.Hops = obs.HopCount
		}
		out = append(out, ref)
	}
	return out
}

// aiPathTouchesDevice reports whether a path definition is measured FROM this
// device (its vantage) or starts at one of its addresses.
func aiPathTouchesDevice(d pathgraph.PathDefinition, dev models.Device) bool {
	if d.VantageID != "" && (strings.EqualFold(d.VantageID, dev.ID) || strings.EqualFold(d.VantageID, dev.Name)) {
		return true
	}
	return dev.Address != "" && strings.EqualFold(d.SrcAddress, dev.Address)
}

func aiPathLabel(d pathgraph.PathDefinition, dev models.Device) string {
	src := aiFirst(dev.Name, dev.ID, d.SrcAddress)
	dst := aiFirst(d.DstAddress, d.DstEndpointRef, "destination")
	label := src + " → " + dst
	if d.Protocol != "" {
		label += " (" + d.Protocol + ")"
	}
	return label
}

// ---- case timeline ----------------------------------------------------------

// aiCaseTimeline returns one correlation case's ordered timeline, read through
// the SAME loadCorrSlice the /api/correlations/{id}/timeline endpoint uses.
//
// Isolation is the two layers ai_datasource.go documents: the ClickHouse
// tenant_scope row policy, PLUS the strict app-side check that a scoped
// principal never sees an untagged (platform) correlation object. Unknown,
// malformed and foreign ids all return ai.ErrNotFound.
func (s *server) aiCaseTimeline(claims jwtClaims) func(context.Context, ai.Principal, string) ([]ai.TimelineEvent, error) {
	return func(ctx context.Context, _ ai.Principal, correlationID string) ([]ai.TimelineEvent, error) {
		if !isUUIDToken(correlationID) {
			return nil, ai.ErrNotFound
		}
		meta, sigRows, _, _, status, err := s.loadCorrSlice(ctx, chTenantScopeFor(claims), correlationID, 0)
		if err != nil {
			if status == http.StatusNotFound {
				return nil, ai.ErrNotFound
			}
			return nil, err
		}
		tenant, cross := principalTenant(claims)
		if !cross && asStr(meta["tenant_id"]) != tenant {
			return nil, ai.ErrNotFound // another tenant's, or untagged platform intel
		}
		events := make([]ai.TimelineEvent, 0, len(sigRows))
		for _, row := range sigRows {
			events = append(events, ai.TimelineEvent{
				At:     asStr(row["ts"]),
				Kind:   aiFirst(asStr(row["kind"]), asStr(row["source"])),
				Entity: asStr(row["entity_id"]),
				Text:   aiTimelineText(row),
			})
		}
		// Oldest first: a timeline's whole value is the ORDER, and "what happened
		// first" is the question it answers.
		sort.SliceStable(events, func(i, j int) bool { return events[i].At < events[j].At })
		return events, nil
	}
}

// aiTimelineText renders one archived signal row as a single honest line: what
// was measured, and how far it deviated when the engine recorded a baseline.
func aiTimelineText(row map[string]any) string {
	var parts []string
	if m := asStr(row["metric_name"]); m != "" {
		parts = append(parts, m)
	}
	if sev := asStr(row["severity"]); sev != "" {
		parts = append(parts, "severity "+sev)
	}
	if v, ok := row["value"]; ok && asStr(v) != "" {
		line := "value " + asStr(v)
		if b := asStr(row["baseline"]); b != "" {
			line += " vs baseline " + b
		}
		parts = append(parts, line)
	}
	if ph := asStr(row["phase"]); ph != "" {
		parts = append(parts, "phase "+ph)
	}
	if len(parts) == 0 {
		return asStr(row["signal_id"])
	}
	return strings.Join(parts, ", ")
}
