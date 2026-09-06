// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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
	"strconv"
	"strings"
	"sync"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/bgpdepth"
	"netops/backend/internal/protocoldiag"
	"netops/backend/internal/showparse"
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

	// ── IRIS Phase A4 bounds ────────────────────────────────────────────────
	// The state battery's own defaults (60s per device, 5m per run) are sized
	// for a fleet sweep. An assistant turn has a 45s wall-clock budget for the
	// WHOLE investigation, so the battery is narrowed here — a state read that
	// outlived the turn would be paid for and thrown away.
	aiStateDeviceTimeout = 12 * time.Second
	aiStateTotalTimeout  = 15 * time.Second
	// aiStateGapLines bounds the raw (already redacted) lines one unreadable
	// capture contributes as honest fallback evidence.
	aiStateGapLines = 6
	// aiStateMaxRows bounds the TYPED rows one area may project, before the ai
	// package applies its own per-area prompt cap.
	aiStateMaxRows = 120
	// aiStateCPUHighPct / aiStateMemHighPct are the control-plane pressure
	// thresholds behind `state:platform=cpu_high` / `=mem_high`. They are the
	// design's own proactive-check numbers (model doc §3.4, "CPU >90 %").
	aiStateCPUHighPct = 90.0
	aiStateMemHighPct = 90.0

	// aiBGPTimeout bounds the whole outbound RPKI / announcement gather for one
	// assistant answer (§9: all IO has a timeout).
	aiBGPTimeout = 8 * time.Second
	// aiBGPStatusLookups bounds how many watched prefixes get a live
	// announced-origin lookup on a watchlist read. The rest are listed without a
	// status, which the tool renders as "no status", never as "not announced".
	aiBGPStatusLookups = 5
	// aiBGPFeedScan bounds how many ring entries are scanned to satisfy a
	// prefix-filtered feed read.
	aiBGPFeedScan = 200

	// aiMemoryTimeout bounds one investigation-memory recall (§9: all IO has a
	// timeout). Memory is a small, indexed, tenant-scoped read; if it cannot
	// answer inside this, the turn is better off without it than late.
	aiMemoryTimeout = 3 * time.Second
)

// aiStateBattery is the shipped show-first state battery, compiled ONCE. It is
// immutable after construction (its own package documents that), so sharing it
// across requests is safe and rebuilding it per request would re-validate 500+
// rendered command forms for nothing.
var aiStateBattery = sync.OnceValue(protocoldiag.DefaultStateBattery)

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
		// The state seam is ALWAYS wired when there is an inventory: with no
		// capture transport it answers with the read-only command list and an
		// honest NotWired, which is the useful answer — not silence.
		deps.DeviceState = s.aiDeviceState(r, claims)
	}
	// BGP operations reads. The watchlist needs the PG app-state store and the
	// feed needs its own feature flag; each seam is wired only when its source
	// exists, so a tool that could only answer "nothing" is never registered.
	if s.bgpWatch != nil {
		deps.BGPWatchlist = s.aiBGPWatchlist(claims)
		if s.bgpFetch != nil {
			deps.BGPRPKI = s.aiBGPRPKI(claims)
		}
	}
	if s.bgpFeed != nil {
		deps.BGPFeedRecent = s.aiBGPFeedRecent(claims)
	}
	if s.secAPI != nil {
		deps.SecurityFindings = s.aiSecurityFindings(claims)
	}
	deps.CaseTimeline = s.aiCaseTimeline(claims)
	// IRIS Phase B: investigation memory. Wired only when the store exists, so a
	// deployment without it never exposes a tool that could only answer nothing.
	if s.irisMemory != nil {
		deps.RecallInvestigations = s.aiRecallInvestigations(claims)
	}
	return deps
}

// ---- investigation memory (IRIS Phase B) ------------------------------------

// aiRecallInvestigations reads the CALLER'S OWN prior concluded investigations.
// The tenant and the cross flag come from the CLAIMS (the token is the
// authority), never from the query — so a recall can only ever see this
// tenant's memory, and the store refuses an unkeyed query outright (there is no
// tenant-wide dump to reach). A device argument was already resolved through the
// caller's own inventory by the tool, so another tenant's device name never gets
// this far.
func (s *server) aiRecallInvestigations(claims jwtClaims) func(context.Context, ai.Principal, ai.InvestigationQuery) ([]ai.InvestigationRow, error) {
	tenant, cross := principalTenant(claims)
	return func(ctx context.Context, _ ai.Principal, q ai.InvestigationQuery) ([]ai.InvestigationRow, error) {
		if s.irisMemory == nil {
			return nil, ai.ErrNotImplemented
		}
		if q.Limit <= 0 || q.Limit > ai.MaxRecallRows {
			q.Limit = ai.MaxRecallRows
		}
		ctx, cancel := context.WithTimeout(ctx, aiMemoryTimeout)
		defer cancel()
		return s.irisMemory.Recall(ctx, tenant, cross, q)
	}
}

// aiRecordInvestigation is the WRITE half: a finished skill chain hands its
// conclusion here, and it waits — in memory, bounded, per (tenant, subject) —
// for an operator to judge it on the feedback call. Nothing is persisted until
// then: an unjudged conclusion is forgotten, which is the correct outcome (a
// memory row's whole value is the outcome attached to it).
func (s *server) aiRecordInvestigation(claims jwtClaims) func(context.Context, ai.Principal, ai.ConcludedInvestigation) {
	tenant, _ := principalTenant(claims)
	return func(_ context.Context, _ ai.Principal, inv ai.ConcludedInvestigation) {
		s.irisPending.Stash(tenant, claims.Sub, inv)
	}
}

// aiToolAudit records one skill gather-step execution — or, when the tool is
// "next_skill", one chain SELECTION decision (IRIS Phase A2). The ai package
// never sees a token, so the ACTOR is added here; the entry itself carries
// argument NAMES only (§8: no PII, no values, in a log line), and `round` +
// `selected` make the whole investigation path reconstructible from the log.
func (s *server) aiToolAudit(claims jwtClaims) func(ai.ToolAuditEntry) {
	tenant, cross := principalTenant(claims)
	return func(e ai.ToolAuditEntry) {
		logInfo("ai", "tool", map[string]any{
			"tenant": tenant, "cross": cross, "sub": claims.Sub,
			"skill": e.Skill, "tool": e.Tool, "args": e.Args,
			"allowed": e.Allowed, "reason": e.Reason,
			"items": e.Items, "duration_ms": e.Duration,
			"round": e.Round, "selected": e.Selected,
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

		// D-4 — REPORT WHAT ACTUALLY HAPPENED. A collection can come back with
		// every command errored and zero bytes captured (proven live on the lab
		// spines: 20 of 20 read-only commands rejected). Setting Collected=true
		// unconditionally turned that into "the diagnostic ran and no known
		// signature matched", which an operator reads as "we looked, the
		// protocol is fine". The per-command outcome is carried onto the report
		// so a PARTIAL capture degrades honestly too (§10: no silent failures).
		rep.Commands = rep.Commands[:0]
		captured := 0
		for _, cc := range col.Commands {
			cmd := ai.DiagnosticCommand{
				SpecID:  cc.SpecID,
				Purpose: cc.Purpose,
				Command: cc.Command,
				Error:   clampString(cc.Err, pdMaxTargetField),
			}
			if strings.TrimSpace(cc.Output) != "" {
				captured++
			}
			rep.Commands = append(rep.Commands, cmd)
		}
		rep.Attempted = true
		rep.Total = len(col.Commands)
		rep.Failed = rep.Total - captured
		if captured == 0 {
			rep.CollectFailed = pdNothingCapturedReason(col)
			logWarn("ai", "protocol diagnostic captured no output", map[string]any{
				"device_id": dev.ID, "issue_id": issue.ID,
				"commands": rep.Total, "failed": rep.Failed,
			})
			return rep, nil
		}

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

// pdNothingCapturedReason is the honest sentence for a live capture in which no
// command produced output. It counts the failures and names the FIRST distinct
// device error, which is what tells an operator "the command set is wrong for
// this OS" apart from "the box is unreachable".
func pdNothingCapturedReason(col *protocoldiag.Collection) string {
	total, failed, first := len(col.Commands), 0, ""
	for _, cc := range col.Commands {
		if strings.TrimSpace(cc.Err) != "" {
			failed++
			if first == "" {
				first = strings.TrimSpace(cc.Err)
			}
		}
	}
	msg := fmt.Sprintf("the read-only commands were rejected by the device (%d of %d failed); no output was captured, so nothing was analysed",
		failed, total)
	if total > 0 && failed == 0 {
		msg = fmt.Sprintf("all %d read-only commands returned empty output; nothing was captured, so nothing was analysed", total)
	}
	if first != "" {
		msg += " — first error: " + clampString(first, pdMaxTargetField)
	}
	return msg
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

// ---- show-first device state (IRIS Phase A4) --------------------------------

// aiDeviceState runs ONE area of the show-first state battery against ONE
// device and projects the TYPED rows for the assistant.
//
// It is the same shape as aiProtocolDiagnostic and the same gates apply:
//
//   - the device is resolved through the CALLER'S OWN inventory first
//     (cross-tenant and unknown are both ai.ErrNotFound);
//   - the platform must resolve to a known CLI dialect — there is NO fallback,
//     because rendering a Cisco command at an unassessed platform is a guess;
//   - a live capture is a DEVICE OPERATION, so it needs infrastructure:WRITE,
//     exactly like the protocol-diagnostics collect endpoint. A read-only
//     operator gets the read-only command list to hand to someone who may run
//     it, never a fabricated reading;
//   - every capture is redacted and parsed inside protocoldiag/showparse before
//     it reaches this function; a capture no parser could read becomes an
//     explicit GAP, never a typed row.
//
// The battery collector is built ONCE PER REQUEST rather than once per process
// because the server struct (main.go) is owned elsewhere this wave. One-in-
// flight-per-device therefore holds within a turn (the chain runs its tools
// sequentially); promoting the collector to a server field is a follow-up.
func (s *server) aiDeviceState(r *http.Request, claims jwtClaims) func(context.Context, ai.Principal, ai.DeviceStateRequest) (ai.DeviceStateReport, error) {
	battery := aiStateBattery()
	collector := s.aiBatteryCollector(battery)
	return func(ctx context.Context, _ ai.Principal, req ai.DeviceStateRequest) (ai.DeviceStateReport, error) {
		dev, ok := s.aiLookupDevice(claims, req.DeviceID)
		if !ok {
			return ai.DeviceStateReport{}, ai.ErrNotFound
		}
		area := protocoldiag.Area(strings.ToLower(strings.TrimSpace(req.Area)))
		if !protocoldiag.ValidArea(area) {
			return ai.DeviceStateReport{}, fmt.Errorf("%w: %q", protocoldiag.ErrUnknownArea, req.Area)
		}
		platform := pdPlatformString(dev)
		rep := ai.DeviceStateReport{
			DeviceID: dev.ID, DeviceName: dev.Name, Platform: platform,
			Area: string(area), RulesetVersion: protocoldiag.RulesetVersion,
		}

		dialect, ok := showparse.DialectFromPlatform(platform)
		if !ok {
			rep.Status = string(protocoldiag.DeviceStatusUnsupported)
			rep.NotWired = fmt.Sprintf("platform %q does not resolve to a known CLI dialect — no read-only command is established for it, so its state is UNKNOWN rather than healthy", platform)
			return rep, nil
		}
		rep.Dialect = string(dialect)

		tgt := aiStateTarget(area, req.Target)
		cmds := battery.Battery(area, dialect, tgt)
		if len(cmds) == 0 {
			rep.Status = string(protocoldiag.DeviceStatusUnsupported)
			rep.NotWired = fmt.Sprintf("no %s command is established for dialect %s (or its required argument was not supplied) — nothing was run", area, dialect)
			return rep, nil
		}
		for _, c := range cmds {
			rep.Commands = append(rep.Commands, ai.DiagnosticCommand{
				SpecID: c.SpecID, Purpose: c.Purpose, Command: c.Command,
			})
		}

		switch {
		case collector == nil:
			rep.NotWired = "live device-state collection is not wired on this deployment — no command was run"
			return rep, nil
		case !s.roles.Allows(claims.Role, "infrastructure", LevelWrite):
			rep.NotWired = "reading live device state needs infrastructure write access, which this account does not have — no command was run"
			return rep, nil
		}

		run, err := collector.RunBattery(ctx, []protocoldiag.Device{pdDeviceFromDiscovery(dev)}, area, tgt)
		if err != nil || len(run.Devices) == 0 {
			if err != nil {
				logWarn("ai", "device state collection failed", map[string]any{
					"device_id": dev.ID, "area": string(area), "error": err.Error(),
				})
			}
			rep.NotWired = "the live state read did not complete on this device — no output was analysed"
			return rep, nil
		}
		// §8: a live capture is the moment secrets could be read off a device —
		// audited with the sensitive tag, exactly as the collect path is.
		s.pdAudit(r, claims, deviceTenant(dev), "protocol_diagnostics.device_state", map[string]any{
			"device_id": dev.ID, "area": string(area), "commands": len(cmds), "via": "ai_assistant",
		})
		aiProjectDeviceState(&rep, run.Devices[0], req.Target)
		return rep, nil
	}
}

// aiBatteryCollector builds the LIVE state-battery collector, or nil when the
// capture transport is not turned on. It reuses the SAME SSH gateway (host-key
// custody, sealed credentials, bounded dial) the protocol-diagnostics collector
// uses — there is exactly one device transport in this tree — but over the
// BATTERY's closed table, which is the only runner that will accept a battery
// command (protocoldiag.NewSSHBatteryRunner documents why the two tables must
// not be merged).
func (s *server) aiBatteryCollector(battery *protocoldiag.StateBattery) *protocoldiag.BatteryCollector {
	if s == nil || battery == nil || !protocolDiagCollectEnabled() || s.sshHosts == nil {
		return nil
	}
	runner, err := protocoldiag.NewSSHBatteryRunner(battery, s.protocolDiagGateway())
	if err != nil {
		logWarn("ai", "state battery runner not built", map[string]any{"error": err.Error()})
		return nil
	}
	col, err := protocoldiag.NewBatteryCollector(battery, runner,
		protocoldiag.WithConcurrency(1), // the assistant reads ONE device at a time
		protocoldiag.WithDeviceTimeout(aiStateDeviceTimeout),
		protocoldiag.WithTotalTimeout(aiStateTotalTimeout),
	)
	if err != nil {
		logWarn("ai", "state battery collector not built", map[string]any{"error": err.Error()})
		return nil
	}
	return col
}

// aiStateTarget maps the tool's single validated `target` onto the battery's
// typed Target for the area it belongs to. An area that takes no target gets an
// empty Target — the value is never smuggled into another placeholder.
func aiStateTarget(area protocoldiag.Area, target string) protocoldiag.Target {
	target = strings.TrimSpace(target)
	if target == "" {
		return protocoldiag.Target{}
	}
	switch area {
	case protocoldiag.AreaInterfaces:
		return protocoldiag.Target{Interface: target}
	case protocoldiag.AreaRoutes:
		return protocoldiag.Target{Prefix: target}
	case protocoldiag.AreaL2:
		return protocoldiag.Target{Address: target}
	case protocoldiag.AreaIGP, protocoldiag.AreaBGP:
		// Neither adjacency table is rendered per-neighbour by the battery, so
		// the target NARROWS the projected rows rather than the command.
		return protocoldiag.Target{Peer: target}
	default:
		return protocoldiag.Target{}
	}
}

// ---- typed-row projection ---------------------------------------------------

// aiStateSignal is one candidate `state:` machine fact plus the row it was
// derived from and how BAD it is. Only the worst candidate per facet becomes a
// signal, so an area that read twenty healthy interfaces and one dead one
// asserts `state:if_oper=down` — one fact, the decisive one — instead of
// asserting "up" and "down" at the same time.
type aiStateSignal struct {
	facet string
	value string
	rank  int
	row   int
}

// aiProjectDeviceState turns one battery DeviceState into the assistant's typed
// evidence: rendered rows, decisive machine facts, and explicit gaps.
//
// Three honesty rules are structural here:
//   - a FAILED or TIMED-OUT read is reported as not-collected, so the caller
//     hands back the read-only commands instead of narrating a partial silence;
//   - a SKIPPED parse becomes a Gap carrying the (already redacted) raw lines,
//     never a typed row;
//   - a command that never ran becomes a Gap with its reason and NO lines.
func aiProjectDeviceState(rep *ai.DeviceStateReport, st protocoldiag.DeviceState, filter string) {
	rep.Status = string(st.Status)
	rep.Note = st.Note
	rep.Collected = st.Status == protocoldiag.DeviceStatusOK || st.Status == protocoldiag.DeviceStatusPartial
	if !rep.Collected {
		rep.NotWired = aiFirst(st.Note, "the live state read did not produce any output on this device")
		return
	}

	outputs := make(map[string]string, len(st.Commands))
	commandOf := make(map[string]string, len(st.Commands))
	for _, c := range st.Commands {
		if c.Err != "" {
			rep.Gaps = append(rep.Gaps, ai.StateGap{
				Command: c.Command,
				Reason:  "the command did not run: " + aiClampLine(c.Err, 160),
			})
			continue
		}
		outputs[c.SpecID] = c.Output
		commandOf[c.SpecID] = c.Command
	}

	var cands []aiStateSignal
	add := func(facet, value string, rank int) {
		cands = append(cands, aiStateSignal{facet: facet, value: value, rank: rank, row: len(rep.Rows) - 1})
	}
	push := func(kind, text string) bool {
		if strings.TrimSpace(text) == "" || len(rep.Rows) >= aiStateMaxRows {
			return false
		}
		rep.Rows = append(rep.Rows, ai.StateRow{Text: text, Kind: kind})
		return true
	}

	for _, res := range st.Parsed {
		if res.Skipped {
			rep.Gaps = append(rep.Gaps, ai.StateGap{
				Command: aiFirst(commandOf[res.CmdID], res.CmdID),
				Reason:  aiFirst(res.Reason, "no parser is established for this output"),
				Lines:   aiStateRawLines(outputs[res.CmdID], aiStateGapLines),
			})
			continue
		}
		aiProjectParsed(res, commandOf[res.CmdID], strings.TrimSpace(filter), push, add)
	}

	// One signal per facet: the worst candidate wins, ties go to the first row.
	best := map[string]aiStateSignal{}
	for _, c := range cands {
		if cur, seen := best[c.facet]; !seen || c.rank > cur.rank {
			best[c.facet] = c
		}
	}
	for _, facet := range aiSortedFacets(best) {
		c := best[facet]
		if c.row >= 0 && c.row < len(rep.Rows) {
			rep.Rows[c.row].Signals = append(rep.Rows[c.row].Signals, "state:"+c.facet+"="+c.value)
		}
	}
}

// aiSortedFacets orders the winning facets so a row's signal list is stable
// across runs (a map iteration must never leak into output).
func aiSortedFacets(best map[string]aiStateSignal) []string {
	out := make([]string, 0, len(best))
	for k := range best {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// aiProjectParsed renders ONE parse result. push appends a row (reporting
// whether it was accepted) and add records a signal candidate for the row just
// pushed — so a fact is only ever asserted alongside the evidence that carries
// it.
func aiProjectParsed(res showparse.Result, command, filter string, push func(kind, text string) bool, add func(facet, value string, rank int)) {
	switch {
	case len(res.Interfaces) > 0:
		for _, x := range res.Interfaces {
			if !push("device", aiIfaceLine(x)) {
				continue
			}
			if v, rank := aiIfaceOper(x); v != "" {
				add("if_oper", v, rank)
			}
			if aiIfaceHasErrors(x) {
				add("if_errors", "present", 2)
			} else if aiIfaceReportsCounters(x) {
				add("if_errors", "none", 1)
			}
		}
	case len(res.IGPNeighbors) > 0:
		matched := 0
		for _, n := range res.IGPNeighbors {
			if !aiStateMatches(filter, n.ID, aiStr(n.Address), n.Iface) {
				continue
			}
			matched++
			if !push("device", aiIGPLine(n)) {
				continue
			}
			if aiIGPHealthy(n) {
				add("igp_nbr", "full", 1)
			} else {
				add("igp_nbr", "not_full", 3)
			}
		}
		aiNoteFilterMiss(push, filter, matched, len(res.IGPNeighbors), "IGP adjacency")
	case len(res.BGPPeers) > 0:
		matched := 0
		for _, pr := range res.BGPPeers {
			if !aiStateMatches(filter, pr.Peer) {
				continue
			}
			matched++
			if !push("device", aiBGPPeerLine(pr)) {
				continue
			}
			v, rank := aiBGPPeerState(pr)
			add("bgp_peer", v, rank)
		}
		aiNoteFilterMiss(push, filter, matched, len(res.BGPPeers), "BGP neighbour")
	case len(res.Routes) > 0:
		for _, rt := range res.Routes {
			if push("device", aiRouteLine(rt)) {
				add("route", "present", 1)
			}
		}
	case len(res.ARP) > 0 || len(res.MAC) > 0:
		for _, a := range res.ARP {
			if push("device", aiARPLine(a)) {
				add("l2_entry", "present", 1)
			}
		}
		for _, m := range res.MAC {
			if push("device", aiMACLine(m)) {
				add("l2_entry", "present", 1)
			}
		}
	case res.Platform != nil:
		if !push("device", aiPlatformLine(*res.Platform)) {
			return
		}
		switch v, rank := aiPlatformPressure(*res.Platform); v {
		case "":
		default:
			add("platform", v, rank)
		}
	case len(res.Logs) > 0:
		// Log lines are the device's own words: quoted, never mined for a
		// machine fact (a `state:` signal must come from a TYPED field).
		for _, l := range res.Logs {
			push("log", aiClampLine(l.Raw, 300))
		}
	default:
		// A recognized-but-EMPTY result: the device answered definitively that
		// there is nothing here. That is a different fact from "we could not
		// read it", and the two must never collapse.
		reason := aiFirst(res.Reason, "the device reported no entry")
		switch res.CmdID {
		case showparse.CmdRoutePrefix:
			if push("device", "the device reports NO matching route — "+aiClampLine(reason, 200)) {
				add("route", "absent", 2)
			}
		case showparse.CmdARP, showparse.CmdMAC:
			if push("device", "the device reports NO ARP/MAC entry for the subject address — "+aiClampLine(reason, 200)) {
				add("l2_entry", "absent", 2)
			}
		case showparse.CmdOSPFNeighbor, showparse.CmdISISNeighbor:
			if push("device", "the device reports NO IGP adjacency in this table — "+aiClampLine(reason, 200)) {
				add("igp_nbr", "none", 2)
			}
		case showparse.CmdBGPSummary:
			if push("device", "the device reports NO BGP neighbour — "+aiClampLine(reason, 200)) {
				add("bgp_peer", "none", 2)
			}
		default:
			push("device", "`"+aiFirst(command, res.CmdID)+"` returned no rows — "+aiClampLine(reason, 200))
		}
	}
}

// aiStateMatches applies the caller's optional row filter. An EMPTY filter
// matches everything; otherwise a row is kept when any of its identity fields
// contains the filter (case-insensitive), which is how an operator naming a
// peer address or a system id finds the row they mean.
func aiStateMatches(filter string, fields ...string) bool {
	if filter == "" {
		return true
	}
	needle := strings.ToLower(filter)
	for _, f := range fields {
		if f != "" && strings.Contains(strings.ToLower(f), needle) {
			return true
		}
	}
	return false
}

// aiNoteFilterMiss states, as its own evidence row, that the table WAS read and
// the named subject is not in it. "The peer is not configured here" is a
// finding; an empty answer would read as "we found nothing", which is not the
// same thing.
func aiNoteFilterMiss(push func(kind, text string) bool, filter string, matched, total int, what string) {
	if filter == "" || matched > 0 || total == 0 {
		return
	}
	push("device", fmt.Sprintf("the device's %s table has %d entries and NONE matches %q — the subject is not present in this table",
		what, total, aiClampLine(filter, 64)))
}

// aiStateRawLines returns up to n non-empty lines of an already-redacted
// capture, each clamped. This is the ONLY path by which raw device text reaches
// the assistant, and it is used exclusively for output no parser could read.
func aiStateRawLines(raw string, n int) []string {
	if strings.TrimSpace(raw) == "" || n <= 0 {
		return nil
	}
	out := make([]string, 0, n)
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, aiClampLine(line, 200))
		if len(out) >= n {
			break
		}
	}
	return out
}

func aiClampLine(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " "))
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// aiStr renders an optional string field: "" when the device did not report it.
func aiStr(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

func aiInt64(p *int64) (int64, bool) {
	if p == nil {
		return 0, false
	}
	return *p, true
}

func aiFloat(p *float64) (float64, bool) {
	if p == nil {
		return 0, false
	}
	return *p, true
}

// aiJoinParts assembles a row from the parts the device ACTUALLY reported.
func aiJoinParts(head string, parts []string) string {
	if len(parts) == 0 {
		return head
	}
	return head + " — " + strings.Join(parts, ", ")
}

func aiIfaceLine(x showparse.InterfaceState) string {
	var parts []string
	if v := aiStr(x.Admin); v != "" {
		parts = append(parts, "admin "+v)
	}
	if v := aiStr(x.Oper); v != "" {
		parts = append(parts, "oper "+v)
	}
	if v := aiStr(x.Description); v != "" {
		parts = append(parts, "description "+strconv.Quote(aiClampLine(v, 80)))
	}
	if v := aiStr(x.IPv4); v != "" {
		parts = append(parts, "ipv4 "+v)
	}
	if v, ok := aiInt64(x.SpeedMbps); ok {
		parts = append(parts, fmt.Sprintf("speed %d Mbps", v))
	}
	if v := aiStr(x.Duplex); v != "" {
		parts = append(parts, "duplex "+v)
	}
	if x.MTU != nil {
		parts = append(parts, fmt.Sprintf("mtu %d", *x.MTU))
	}
	for _, c := range []struct {
		label string
		v     *int64
	}{
		{"input errors", x.InErrors}, {"CRC", x.CRC}, {"input drops", x.InDrops},
		{"output errors", x.OutErrors}, {"output drops", x.OutDrops},
		{"carrier transitions", x.CarrierTransitions},
	} {
		if v, ok := aiInt64(c.v); ok {
			parts = append(parts, fmt.Sprintf("%s %d", c.label, v))
		}
	}
	if v := aiStr(x.LastFlap); v != "" {
		parts = append(parts, "last flap "+v)
	}
	for _, o := range []struct {
		label, unit string
		v           *float64
	}{
		{"rx power", " dBm", x.RxPowerDbm}, {"tx power", " dBm", x.TxPowerDbm},
		{"bias", " mA", x.BiasCurrentMa}, {"voltage", " V", x.VoltageV}, {"temperature", " C", x.TempC},
	} {
		if v, ok := aiFloat(o.v); ok {
			parts = append(parts, fmt.Sprintf("%s %.2f%s", o.label, v, o.unit))
		}
	}
	return aiJoinParts("interface "+aiFirst(x.Name, "(unnamed)"), parts)
}

// aiIfaceOper derives `state:if_oper` from the TYPED admin/oper fields. An
// interface that reported neither yields no fact at all.
func aiIfaceOper(x showparse.InterfaceState) (string, int) {
	admin, oper := strings.ToLower(aiStr(x.Admin)), strings.ToLower(aiStr(x.Oper))
	adminDown := strings.Contains(admin, "down") || strings.Contains(admin, "disabled") || admin == "adm"
	switch {
	case adminDown:
		return "admin_down", 2
	case oper == "":
		return "", 0
	case strings.Contains(oper, "down") || strings.Contains(oper, "notpresent") || strings.Contains(oper, "not present"):
		return "down", 3
	case strings.Contains(oper, "up") || strings.Contains(oper, "enabled"):
		return "up", 1
	default:
		return "", 0
	}
}

// aiIfaceReportsCounters reports whether the capture carried ANY error counter,
// so "no errors" is only asserted when the device actually said so.
func aiIfaceReportsCounters(x showparse.InterfaceState) bool {
	return x.InErrors != nil || x.CRC != nil || x.InDrops != nil || x.OutErrors != nil || x.OutDrops != nil
}

func aiIfaceHasErrors(x showparse.InterfaceState) bool {
	for _, c := range []*int64{x.InErrors, x.CRC, x.InDrops, x.OutErrors, x.OutDrops} {
		if v, ok := aiInt64(c); ok && v > 0 {
			return true
		}
	}
	return false
}

func aiIGPLine(n showparse.IGPNeighbor) string {
	var parts []string
	parts = append(parts, "state "+aiFirst(n.State, "unreported"))
	if n.Iface != "" {
		parts = append(parts, "on "+n.Iface)
	}
	if v := aiStr(n.Address); v != "" {
		parts = append(parts, "address "+v)
	}
	if v := aiStr(n.Level); v != "" {
		parts = append(parts, "level "+v)
	}
	if v := aiStr(n.Area); v != "" {
		parts = append(parts, "area "+v)
	}
	if n.Priority != nil {
		parts = append(parts, fmt.Sprintf("priority %d", *n.Priority))
	}
	if v := aiStr(n.DeadTime); v != "" {
		parts = append(parts, "dead time "+v)
	}
	if v := aiStr(n.Holdtime); v != "" {
		parts = append(parts, "holdtime "+v)
	}
	if v := aiStr(n.Uptime); v != "" {
		parts = append(parts, "up "+v)
	}
	return aiJoinParts(strings.ToUpper(aiFirst(n.Proto, "igp"))+" neighbour "+aiFirst(n.ID, "(unnamed)"), parts)
}

// aiIGPHealthy reads the adjacency state VERBATIM: OSPF's only healthy state is
// FULL, IS-IS's is Up. Anything else — including a state we do not recognize —
// is NOT healthy, which is the fail-closed direction.
func aiIGPHealthy(n showparse.IGPNeighbor) bool {
	st := strings.ToLower(n.State)
	if strings.EqualFold(n.Proto, "isis") {
		return strings.HasPrefix(st, "up")
	}
	return strings.Contains(st, "full")
}

func aiBGPPeerLine(pr showparse.BGPPeer) string {
	var parts []string
	if v, ok := aiInt64(pr.AS); ok {
		parts = append(parts, fmt.Sprintf("AS%d", v))
	}
	parts = append(parts, "state "+aiFirst(pr.State, "unreported"))
	if v, ok := aiInt64(pr.PrefixesRx); ok {
		parts = append(parts, fmt.Sprintf("%d prefixes received", v))
	}
	if v := aiStr(pr.UpDown); v != "" {
		parts = append(parts, "up/down "+v)
	}
	if v, ok := aiInt64(pr.MsgRcvd); ok {
		parts = append(parts, fmt.Sprintf("msgs rcvd %d", v))
	}
	if v, ok := aiInt64(pr.MsgSent); ok {
		parts = append(parts, fmt.Sprintf("msgs sent %d", v))
	}
	if v := aiStr(pr.VRF); v != "" {
		parts = append(parts, "vrf "+v)
	}
	return aiJoinParts("BGP peer "+aiFirst(pr.Peer, "(unnamed)"), parts)
}

// aiBGPPeerState maps the peer's VERBATIM FSM state onto the closed
// `state:bgp_peer` vocabulary. Established is read from the parser's derived
// flag (which also covers the dialects that print a prefix count instead of a
// state word); everything else is matched on the state text.
func aiBGPPeerState(pr showparse.BGPPeer) (string, int) {
	if pr.Established {
		return "established", 1
	}
	switch st := strings.ToLower(pr.State); {
	case strings.HasPrefix(st, "idle"):
		return "idle", 5
	case strings.HasPrefix(st, "active"):
		return "active", 4
	case strings.HasPrefix(st, "connect"):
		return "connect", 3
	default:
		return "other", 2
	}
}

func aiRouteLine(rt showparse.RouteEntry) string {
	var parts []string
	if v := aiStr(rt.Protocol); v != "" {
		parts = append(parts, "via "+v)
	}
	if v := aiStr(rt.NextHop); v != "" {
		parts = append(parts, "next hop "+v)
	}
	if v := aiStr(rt.Iface); v != "" {
		parts = append(parts, "out "+v)
	}
	if v, ok := aiInt64(rt.Preference); ok {
		parts = append(parts, fmt.Sprintf("preference %d", v))
	}
	if v, ok := aiInt64(rt.Metric); ok {
		parts = append(parts, fmt.Sprintf("metric %d", v))
	}
	if v := aiStr(rt.Age); v != "" {
		parts = append(parts, "age "+v)
	}
	if rt.Active != nil {
		if *rt.Active {
			parts = append(parts, "active")
		} else {
			parts = append(parts, "not active")
		}
	}
	return aiJoinParts("route "+aiFirst(rt.Prefix, "(unnamed)"), parts)
}

func aiARPLine(a showparse.ARPEntry) string {
	var parts []string
	if v := aiStr(a.MAC); v != "" {
		parts = append(parts, "mac "+v)
	}
	if v := aiStr(a.Iface); v != "" {
		parts = append(parts, "on "+v)
	}
	if v := aiStr(a.Age); v != "" {
		parts = append(parts, "age "+v)
	}
	if v := aiStr(a.Type); v != "" {
		parts = append(parts, "type "+v)
	}
	return aiJoinParts("arp "+aiFirst(a.Address, "(unnamed)"), parts)
}

func aiMACLine(m showparse.MACEntry) string {
	var parts []string
	if m.VLAN != nil {
		parts = append(parts, fmt.Sprintf("vlan %d", *m.VLAN))
	}
	if v := aiStr(m.Iface); v != "" {
		parts = append(parts, "on "+v)
	}
	if v := aiStr(m.Type); v != "" {
		parts = append(parts, "type "+v)
	}
	return aiJoinParts("mac "+aiFirst(m.MAC, "(unnamed)"), parts)
}

func aiPlatformLine(h showparse.PlatformHealth) string {
	var parts []string
	if v, ok := aiFloat(h.CPUPercent); ok {
		parts = append(parts, fmt.Sprintf("cpu %.1f%%", v))
	}
	for _, w := range []struct {
		label string
		v     *float64
	}{{"cpu 5s", h.CPU5Sec}, {"cpu 1m", h.CPU1Min}, {"cpu 5m", h.CPU5Min}} {
		if v, ok := aiFloat(w.v); ok {
			parts = append(parts, fmt.Sprintf("%s %.1f%%", w.label, v))
		}
	}
	if v, ok := aiFloat(h.MemUsedPercent); ok {
		parts = append(parts, fmt.Sprintf("memory %.1f%% used", v))
	}
	if v, ok := aiInt64(h.MemUsedKB); ok {
		parts = append(parts, fmt.Sprintf("memory used %d KiB", v))
	}
	if v, ok := aiInt64(h.MemTotalKB); ok {
		parts = append(parts, fmt.Sprintf("memory total %d KiB", v))
	}
	if v := aiStr(h.Uptime); v != "" {
		parts = append(parts, "uptime "+v)
	}
	if v := aiStr(h.LastReload); v != "" {
		parts = append(parts, "last reload "+aiClampLine(v, 80))
	}
	if v := aiStr(h.Version); v != "" {
		parts = append(parts, "version "+aiClampLine(v, 60))
	}
	for _, group := range []struct {
		label string
		s     []showparse.SensorReading
	}{{"temperature", h.Temps}, {"fan", h.Fans}, {"psu", h.PSUs}} {
		for _, r := range group.s {
			line := group.label + " " + r.Name
			if v, ok := aiFloat(r.ValueC); ok {
				line += fmt.Sprintf(" %.1f C", v)
			}
			if v := aiStr(r.Status); v != "" {
				line += " " + v
			}
			parts = append(parts, line)
		}
	}
	if len(parts) == 0 {
		return "platform health: the device reported no CPU, memory, environment or uptime field"
	}
	return aiJoinParts("platform health", parts)
}

// aiPlatformCPU picks the most headline CPU figure the capture carried.
func aiPlatformCPU(h showparse.PlatformHealth) (float64, bool) {
	for _, p := range []*float64{h.CPUPercent, h.CPU1Min, h.CPU5Sec, h.CPU5Min} {
		if v, ok := aiFloat(p); ok {
			return v, true
		}
	}
	return 0, false
}

// aiPlatformMem returns memory utilization as a percentage, using the absolute
// figures only when the device did not report a percentage itself.
func aiPlatformMem(h showparse.PlatformHealth) (float64, bool) {
	if v, ok := aiFloat(h.MemUsedPercent); ok {
		return v, true
	}
	used, uok := aiInt64(h.MemUsedKB)
	total, tok := aiInt64(h.MemTotalKB)
	if uok && tok && total > 0 {
		return float64(used) / float64(total) * 100, true
	}
	return 0, false
}

// aiPlatformPressure derives `state:platform` from the typed CPU/memory fields.
// A device that reported neither yields no fact — an unread CPU is not a calm
// one (model doc §3.4: the "CPU >90 %" proactive flag).
func aiPlatformPressure(h showparse.PlatformHealth) (string, int) {
	cpu, cok := aiPlatformCPU(h)
	mem, mok := aiPlatformMem(h)
	switch {
	case cok && cpu >= aiStateCPUHighPct:
		return "cpu_high", 3
	case mok && mem >= aiStateMemHighPct:
		return "mem_high", 2
	case cok || mok:
		return "ok", 1
	default:
		return "", 0
	}
}

// ---- BGP operations reads (IRIS Phase A4) -----------------------------------

// aiBGPWatchlist lists the CALLER'S OWN watched prefixes and ASNs through the
// same FORCE-RLS store /api/bgp/watchlist reads (§3a.4). The tenant and the
// cross flag come from the CLAIMS; nothing in the tool call can widen them, and
// the WRITE path (add/delete) is deliberately not reachable from here at all.
//
// A small, bounded number of prefixes also get their currently-announced origin
// resolved through the fetcher's TTL cache, so the answer says "announced by
// AS64500" rather than only naming the prefix. The rest are listed WITHOUT a
// status, which the tool renders as no status — never as "not announced".
func (s *server) aiBGPWatchlist(claims jwtClaims) func(context.Context, ai.Principal) (ai.BGPWatchlistReport, error) {
	return func(ctx context.Context, _ ai.Principal) (ai.BGPWatchlistReport, error) {
		if !s.roles.Allows(claims.Role, "infrastructure", LevelRead) {
			return ai.BGPWatchlistReport{}, ai.ErrForbidden
		}
		tenant, cross := principalTenant(claims)
		rep := ai.BGPWatchlistReport{Scope: aiBGPScopeLabel(tenant, cross)}
		if s.bgpWatch == nil {
			rep.NotWired = "the BGP watchlist is not enabled on this deployment — say the watched-resource list is UNKNOWN here"
			return rep, nil
		}
		rows, err := s.bgpWatch.List(ctx, tenant, cross)
		if err != nil {
			return ai.BGPWatchlistReport{}, err
		}
		bctx, cancel := context.WithTimeout(ctx, aiBGPTimeout)
		defer cancel()
		looked := 0
		for _, e := range rows {
			item := ai.BGPWatchItem{
				Resource: e.Resource, Kind: e.Kind,
				Note: aiClampLine(e.Note, 160), AddedBy: e.AddedBy,
			}
			if !e.CreatedAt.IsZero() {
				item.Added = e.CreatedAt.UTC().Format(time.RFC3339)
			}
			if e.Kind == "prefix" && s.bgpFetch != nil && looked < aiBGPStatusLookups && bctx.Err() == nil {
				looked++
				if origin := bgpAnnouncedOrigin(bctx, s.bgpFetch, e.Resource); origin != "" {
					item.Status = "announced by AS" + origin
				} else {
					item.Status = "not currently announced in the global table (or the lookup did not answer)"
				}
			}
			rep.Items = append(rep.Items, item)
		}
		return rep, nil
	}
}

// aiBGPRPKI validates the CALLER'S OWN watched prefixes. The prefix set is the
// tenant's (per-tenant data, read through the same store the handler uses); the
// verdict itself is a public routing fact from the same validator
// /api/bgp/rpki uses, so no cross-tenant information can enter or leave.
func (s *server) aiBGPRPKI(claims jwtClaims) func(context.Context, ai.Principal) (ai.BGPRPKIReport, error) {
	return func(ctx context.Context, _ ai.Principal) (ai.BGPRPKIReport, error) {
		if !s.roles.Allows(claims.Role, "infrastructure", LevelRead) {
			return ai.BGPRPKIReport{}, ai.ErrForbidden
		}
		tenant, cross := principalTenant(claims)
		rep := ai.BGPRPKIReport{Scope: aiBGPScopeLabel(tenant, cross)}
		if s.bgpFetch == nil {
			rep.NotWired = "the BGP resource fetcher is not initialised on this deployment — RPKI state is UNKNOWN here"
			return rep, nil
		}
		var prefixes []string
		for _, res := range s.bgpTenantResources(ctx, tenant, cross, "prefix") {
			if p, kind := bgpNormalizeResource(res); kind == "prefix" {
				prefixes = append(prefixes, p)
			}
		}
		if len(prefixes) == 0 {
			return rep, nil // no watched prefix; the tool says so honestly
		}
		bctx, cancel := context.WithTimeout(ctx, aiBGPTimeout)
		defer cancel()
		results, truncated, err := bgpdepth.ValidateRPKISet(bctx, s.bgpFetch, time.Now, s.bgpFetch.bgpOrigin, prefixes)
		if err != nil {
			return ai.BGPRPKIReport{}, err
		}
		bgpdepth.SortRPKIWorstFirst(results)
		rep.Truncated = truncated
		for _, r := range results {
			rep.Items = append(rep.Items, ai.BGPRPKIItem{
				Prefix: r.Prefix, Origin: r.Origin, State: string(r.State),
				Reason: aiClampLine(r.Reason, 200), Validator: r.Validator,
				ROAs: len(r.ROAs), Error: aiClampLine(r.Error, 160),
			})
		}
		return rep, nil
	}
}

// aiBGPFeedRecent reads the NEWEST page of the caller's own per-tenant update
// ring. The buffer is per-tenant data, so — exactly like /api/bgp/feed — a
// cross-tenant principal with no tenant selected is refused with an honest
// "select a tenant", never served another tenant's updates.
//
// The ring's own cursor pages OLDEST-first, so the head is located from the
// status counter (a second in-memory read, no network) and the tail of the ring
// is what the assistant sees: "recent" must mean recent.
func (s *server) aiBGPFeedRecent(claims jwtClaims) func(context.Context, ai.Principal, string, int) (ai.BGPFeedReport, error) {
	return func(ctx context.Context, _ ai.Principal, prefix string, limit int) (ai.BGPFeedReport, error) {
		if !s.roles.Allows(claims.Role, "infrastructure", LevelRead) {
			return ai.BGPFeedReport{}, ai.ErrForbidden
		}
		tenant, cross := principalTenant(claims)
		rep := ai.BGPFeedReport{Scope: aiBGPScopeLabel(tenant, cross)}
		switch {
		case s.bgpFeed == nil:
			rep.NotWired = "the near-live BGP update feed is not enabled on this deployment (" + bgpdepth.EnvFeatureFlag + ")"
			return rep, nil
		case cross || tenant == "" || tenant == TenantGlobal:
			rep.NotWired = "the BGP update buffer is per-tenant — select a tenant before asking for its recent updates"
			return rep, nil
		}
		if limit <= 0 || limit > ai.MaxBGPFeedUpdates {
			limit = ai.MaxBGPFeedUpdates
		}
		resources := s.bgpTenantResources(ctx, tenant, false, "")

		// Probe for the ring head, then read the window that ends at it.
		probe, err := s.bgpFeed.Page(ctx, tenant, resources, 0, 1)
		if err != nil && !errors.Is(err, bgpdepth.ErrFeedDisabled) {
			return ai.BGPFeedReport{}, err
		}
		rep.Resources = probe.Status.Resources
		if !probe.Status.Enabled {
			rep.NotWired = aiFirst(probe.Status.Note, "the near-live BGP update feed is off on this deployment")
			return rep, nil
		}
		window := limit
		if prefix != "" {
			window = aiBGPFeedScan // a filtered read needs a wider window to fill
		}
		var since uint64
		if probe.Status.Written > uint64(window) {
			since = probe.Status.Written - uint64(window)
		}
		page, err := s.bgpFeed.Page(ctx, tenant, resources, since, window)
		if err != nil && !errors.Is(err, bgpdepth.ErrFeedDisabled) {
			return ai.BGPFeedReport{}, err
		}
		rep.Gap = page.Gap
		for _, u := range page.Updates {
			if prefix != "" && !aiStateMatches(prefix, u.Prefix, u.Resource) {
				continue
			}
			item := ai.BGPFeedUpdate{
				Seq: u.Seq, At: u.Time.UTC().Format(time.RFC3339), Type: u.Type,
				Resource: u.Resource, Prefix: u.Prefix, Peer: u.Peer, PathLen: len(u.Path),
			}
			if u.Origin != 0 {
				item.Origin = "AS" + strconv.FormatUint(uint64(u.Origin), 10)
			}
			rep.Updates = append(rep.Updates, item)
		}
		// Newest first: "what happened most recently" is the question asked.
		sort.SliceStable(rep.Updates, func(i, j int) bool { return rep.Updates[i].Seq > rep.Updates[j].Seq })
		if len(rep.Updates) > limit {
			rep.Updates = rep.Updates[:limit]
		}
		return rep, nil
	}
}

// aiBGPScopeLabel names the scope a BGP answer belongs to, for narration and
// audit. It never widens anything — it only describes what was read.
func aiBGPScopeLabel(tenant string, cross bool) string {
	if cross {
		return "platform (cross-tenant)"
	}
	if tenant == "" {
		return "unscoped"
	}
	return tenant
}
