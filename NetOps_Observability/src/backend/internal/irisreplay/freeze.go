// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package irisreplay is Iris Incident Replay, offline leg (tracker 337 N-H2).
//
// It runs one frozen incident through the real answer path and reports what
// came out: RCA, evidence, tools, cost, latency and unsupported claims. Two
// runs over a change (a prompt, a skill, a tool contract, a model) are compared
// so that the change is named, and judged on cases rather than on opinion.
//
// WHAT IT NEVER DOES. It never re-runs the correlation engine: it consumes the
// STORED snapshot in the case (the `hypotheses` blob and RCAResult) and compares
// the version pins, the same honesty rule as src/correlation/replay.py. It never
// reaches a store or a provider: this package imports neither
// (TestReplayImportsNoStore), every seam it builds reads the case and nothing
// else, and a tool the case does not list is not registered at all.
//
// THE MODEL LEG IS A SEAM. Only ScriptedLeg exists. A live leg would implement
// ModelLeg; it is deliberately not built here (docs/audit/INVARIANTS.md).
//
// The case format and its loader live in package ai, because the corpus test is
// an in-package test of ai and cannot import a package that imports ai. See
// ai/replay_case.go.
//
// Stdlib, plus ai, evalsplit, irisgate and aidecision's types.
package irisreplay

import (
	"context"
	"fmt"
	"sort"

	"netops/backend/ai"
)

// Case is one frozen incident.
type Case = ai.ReplayCase

// LoadCases loads a corpus directory through the one strict loader.
func LoadCases(dir string) ([]Case, error) { return ai.LoadReplayCases(dir) }

// Frozen is what a case freezes into. Every field reads the case and nothing
// else; there is no way to reach a live read through it.
type Frozen struct {
	DS       ai.DataSource
	Deps     ai.TroubleshootDeps
	Registry *ai.ToolRegistry
	// Allowed is the sorted set of tools this replay may run.
	Allowed []string
}

// frozenDS adds a module seam that answers nothing, so the module tools can be
// registered (their metadata is what the Policy Engine reads) and then wrapped.
type frozenDS struct{ ai.ReplayDS }

// ModuleQuery has no frozen data behind it: a module tool answers from its
// fixture or not at all.
func (frozenDS) ModuleQuery(context.Context, ai.Principal, string, ai.ToolArgs) (ai.ToolResult, error) {
	return ai.ToolResult{}, ai.ErrNotImplemented
}

// frozenTool is a registered tool answering from the case's fixture. It embeds
// the REAL tool, so everything the Policy Engine reads is the production value.
type frozenTool struct {
	ai.AITool
	fx ai.ReplayToolFixture
	c  *Case
}

// Run answers from the case.
func (t frozenTool) Run(ctx context.Context, p ai.Principal, args ai.ToolArgs) (ai.ToolResult, error) {
	return t.c.FrozenToolResult(ctx, p, t.fx, args)
}

// rcaTools read the one RCAResult seam.
var rcaTools = []string{"get_causal_chain", "get_blast_radius", "get_owner", "get_confidence_breakdown", "get_affected_entities"}

// allowedSet is the case's closed tool set. A fixture that says not_wired wins:
// that deployment does not have the tool.
func allowedSet(c *Case) map[string]bool {
	out := make(map[string]bool, len(c.AllowedTools))
	for _, name := range c.AllowedTools {
		if c.Tools[name].Outcome != "not_wired" {
			out[name] = true
		}
	}
	return out
}

// bindSeams builds the TroubleshootDeps from the case. A seam whose tool is not
// allowed stays NIL, so the real registry does not register that tool; asking
// for it is OutcomeNotRegistered, a finding, never a live call.
//
// Device resolution is not a tool: it is the case's own inventory, scoped to the
// caller.
func bindSeams(c *Case, allowed map[string]bool) ai.TroubleshootDeps {
	d := ai.TroubleshootDeps{ResolveDevice: c.ResolveDevice}
	if allowed["get_case_timeline"] {
		d.CaseTimeline = func(context.Context, ai.Principal, string) ([]ai.TimelineEvent, error) {
			return nil, ai.ErrNotImplemented
		}
	}
	if allowed["run_protocol_diagnostic"] {
		d.ProtocolDiagnostic = func(context.Context, ai.Principal, ai.DiagnosticRequest) (ai.DiagnosticReport, error) {
			return ai.DiagnosticReport{}, ai.ErrNotImplemented
		}
	}
	if allowed["get_security_findings"] {
		d.SecurityFindings = func(context.Context, ai.Principal, ai.FindingsQuery) ([]ai.SecurityFinding, error) {
			return nil, ai.ErrNotImplemented
		}
	}
	if allowed["get_device_state"] {
		d.DeviceState = func(context.Context, ai.Principal, ai.DeviceStateRequest) (ai.DeviceStateReport, error) {
			return ai.DeviceStateReport{}, ai.ErrNotImplemented
		}
	}
	if allowed["get_bgp_watchlist"] {
		d.BGPWatchlist = func(context.Context, ai.Principal) (ai.BGPWatchlistReport, error) {
			return ai.BGPWatchlistReport{}, ai.ErrNotImplemented
		}
	}
	if allowed["get_bgp_rpki"] {
		d.BGPRPKI = func(context.Context, ai.Principal) (ai.BGPRPKIReport, error) {
			return ai.BGPRPKIReport{}, ai.ErrNotImplemented
		}
	}
	if allowed["get_bgp_feed_recent"] {
		d.BGPFeedRecent = func(context.Context, ai.Principal, string, int) (ai.BGPFeedReport, error) {
			return ai.BGPFeedReport{}, ai.ErrNotImplemented
		}
	}
	if allowed["recall_investigations"] {
		d.RecallInvestigations = func(context.Context, ai.Principal, ai.InvestigationQuery) ([]ai.InvestigationRow, error) {
			return nil, ai.ErrNotImplemented
		}
	}
	if allowed["find_similar_incidents"] {
		d.SimilarIncidents = func(context.Context, ai.Principal, string, string) (ai.SimilarIncidents, error) {
			return ai.SimilarIncidents{}, ai.ErrNotImplemented
		}
	}
	if allowed["compile_query"] {
		d.CompileQuery = func(context.Context, ai.Principal, string) (ai.QueryInterpretation, error) {
			return ai.QueryInterpretation{}, ai.ErrNotImplemented
		}
	}
	if allowed["get_topology_context"] {
		d.TopologyContext = func(_ context.Context, p ai.Principal, deviceID string) (ai.TopologyContext, error) {
			tc, ok := c.Topology[deviceID]
			if !ok || p.Tenant != c.Principal.Tenant {
				return ai.TopologyContext{}, ai.ErrNotFound
			}
			return tc, nil
		}
	}
	if allowed["get_network_topology"] {
		// No frozen whole-network read exists in a case yet: a case that allows
		// the tool answers from its scripted fixture (frozenTool), never live.
		d.NetworkTopology = func(context.Context, ai.Principal) (ai.NetworkTopology, error) {
			return ai.NetworkTopology{}, ai.ErrNotImplemented
		}
	}
	// The WAN reads (NetClaw ingestion Batch 2) have no frozen slice in a case
	// yet: a case that allows one answers from its scripted fixture, never live.
	if allowed["get_overlay_state"] {
		d.OverlayState = func(context.Context, ai.Principal, string) (ai.OverlayState, error) {
			return ai.OverlayState{}, ai.ErrNotImplemented
		}
	}
	if allowed["get_tunnel_state"] {
		d.TunnelState = func(context.Context, ai.Principal, string) (ai.TunnelState, error) {
			return ai.TunnelState{}, ai.ErrNotImplemented
		}
	}
	if allowed["get_path_evidence"] {
		d.PathEvidence = func(context.Context, ai.Principal, string) (ai.PathEvidence, error) {
			return ai.PathEvidence{}, ai.ErrNotImplemented
		}
	}
	// The synthetic-probe read (NetClaw ingestion Batch 3) has no frozen slice
	// in a case yet either: a case that allows it answers from its fixture.
	if allowed["get_probe_results"] {
		d.ProbeResults = func(context.Context, ai.Principal, ai.ProbeQuery) (ai.ProbeResults, error) {
			return ai.ProbeResults{}, ai.ErrNotImplemented
		}
	}
	if allowed["get_recent_changes"] {
		d.RecentChanges = func(_ context.Context, p ai.Principal, q ai.ChangeQuery) (ai.ChangeReport, error) {
			return frozenChanges(c, p, q)
		}
	}
	if allowed["get_config_diff"] {
		d.ConfigDiff = func(_ context.Context, p ai.Principal, req ai.ConfigDiffRequest) (ai.ConfigDiffReport, error) {
			return frozenDiff(c, p, req)
		}
	}
	for _, name := range rcaTools {
		if allowed[name] {
			d.RCAResult = func(_ context.Context, p ai.Principal, id string) (ai.RCAResult, error) {
				if r, ok := c.Tenants[p.Tenant].RCA[id]; ok {
					return r, nil
				}
				return ai.RCAResult{}, ai.ErrNotFound
			}
			break
		}
	}
	return d
}

func frozenChanges(c *Case, p ai.Principal, q ai.ChangeQuery) (ai.ChangeReport, error) {
	if c.Config == nil || c.Config.Changes == nil || p.Tenant != c.Principal.Tenant {
		return ai.ChangeReport{}, ai.ErrNotFound
	}
	rep := *c.Config.Changes
	if q.DeviceID != "" {
		rep.Changes = nil
		for _, ch := range c.Config.Changes.Changes {
			if ch.DeviceID == q.DeviceID {
				rep.Changes = append(rep.Changes, ch)
			}
		}
	}
	return rep, nil
}

func frozenDiff(c *Case, p ai.Principal, req ai.ConfigDiffRequest) (ai.ConfigDiffReport, error) {
	if c.Config != nil && p.Tenant == c.Principal.Tenant {
		for _, d := range c.Config.Diffs {
			if d.DeviceID == req.DeviceID {
				return d, nil
			}
		}
	}
	return ai.ConfigDiffReport{}, ai.ErrNotFound
}

// projectsFromSeam reports a tool that runs for real over the case's frozen
// data: the tool's own projection is part of what is being replayed. A tool
// with a scripted fixture answers from the fixture. On the skill path a tool
// with neither reads as empty, so that a method's plan is judged on what the
// case froze, not on a zero value rendered as a finding.
func projectsFromSeam(c *Case, name string) bool {
	if _, scripted := c.Tools[name]; scripted {
		return false
	}
	switch name {
	case "get_topology_context":
		return c.Topology != nil
	case "get_recent_changes", "get_config_diff":
		return c.Config != nil
	}
	return c.Path != ai.ReplayPathSkill
}

// Freeze builds the seams and the closed tool registry from the case ONLY.
func Freeze(c *Case) (*Frozen, error) {
	allowed := allowedSet(c)
	ds := frozenDS{ai.ReplayDS{Case: c}}
	deps := bindSeams(c, allowed)
	reg := ai.BuildToolRegistry(ds, deps, nil).Restricted(
		func(name string) bool { return allowed[name] },
		func(t ai.AITool) ai.AITool {
			if projectsFromSeam(c, t.Name()) {
				return t
			}
			return frozenTool{AITool: t, fx: c.Tools[t.Name()], c: c}
		})
	if errs := reg.Rejected(); len(errs) > 0 {
		return nil, fmt.Errorf("freeze %s: %v", c.ID, errs)
	}
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		if _, ok := reg.Get(name); !ok {
			return nil, fmt.Errorf("freeze %s: allowed tool %q has no frozen seam", c.ID, name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return &Frozen{DS: ds, Deps: deps, Registry: reg, Allowed: names}, nil
}
