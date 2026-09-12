// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// troubleshoot_test.go — the Phase-A tool contract. Three properties are load-
// bearing and pinned here: every tool is READ-ONLY, every argument is validated
// before a seam is touched, and an unavailable capability is DISCLOSED rather
// than fabricated (a "not wired" diagnostic hands back the read-only command
// bundle and refuses to name a cause).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// tsMemoryDay is the fixed conclusion date the memory fixture reports, so the
// rendered evidence line is byte-stable across runs.
var tsMemoryDay = time.Date(2026, 8, 30, 9, 0, 0, 0, time.UTC)

// ---- fixture deps ----------------------------------------------------------

// tsDeps is a fully wired TroubleshootDeps whose behaviour each test overrides.
// ResolveDevice knows one device per tenant, so cross-tenant reads take the same
// ErrNotFound path an unknown name does.
func tsDeps() TroubleshootDeps {
	return TroubleshootDeps{
		ResolveDevice: func(_ context.Context, p Principal, ref string) (DeviceRef, error) {
			switch {
			case p.Tenant == "t-a" && (ref == "edge-1" || ref == "dev-a"):
				return DeviceRef{ID: "dev-a", Name: "edge-1", Vendor: "cisco", Platform: "ios-xe"}, nil
			case p.Tenant == "t-b" && (ref == "leaf-2" || ref == "dev-b"):
				return DeviceRef{ID: "dev-b", Name: "leaf-2"}, nil
			}
			return DeviceRef{}, ErrNotFound
		},
		ProtocolDiagnostic: func(_ context.Context, _ Principal, req DiagnosticRequest) (DiagnosticReport, error) {
			return DiagnosticReport{
				DeviceID: req.DeviceID, DeviceName: "edge-1", Protocol: req.Protocol,
				IssueID: firstNonEmpty(req.IssueID, "bgp-session-down"), IssueTitle: "BGP session down",
				RulesetVersion: "v1", Collected: true,
				Findings: []DiagnosticFinding{{
					SignatureID: "sig-1", Verdict: "peer is Idle (admin down)", Cause: "neighbor shutdown",
					Remediation: "no shutdown the neighbor", Confidence: "high",
					Command: "show bgp summary", EvidenceLine: "10.0.0.1 4 65001 Idle (Admin)",
				}},
			}, nil
		},
		SecurityFindings: func(_ context.Context, _ Principal, q FindingsQuery) ([]SecurityFinding, error) {
			return []SecurityFinding{{
				ID: "f-1", Title: "Telnet enabled", Severity: firstNonEmpty(q.Severity, "high"),
				Status: "open", SeamType: "dia", SeamID: "seam-1", Entity: "edge-1", Control: "CIS-1.1",
			}}, nil
		},
		TopologyContext: func(_ context.Context, _ Principal, deviceID string) (TopologyContext, error) {
			return TopologyContext{
				DeviceID: deviceID, DeviceName: "edge-1", Site: "dc1", Role: "border",
				Neighbors: []TopologyNeighbor{{LocalPort: "Gi0/1", PeerName: "core-1", PeerPort: "Gi1/1", Source: "lldp"}},
				Seams:     []TopologySeam{{ID: "seam-1", Type: "dia", Owner: "ISP"}},
				Paths:     []TopologyPathRef{{ID: "p-1", Label: "edge-1 → 8.8.8.8", Health: "degraded", Hops: 7}},
			}, nil
		},
		CaseTimeline: func(_ context.Context, _ Principal, correlationID string) ([]TimelineEvent, error) {
			if correlationID != "pa" {
				return nil, ErrNotFound
			}
			return []TimelineEvent{{At: "2026-09-01T10:00:00Z", Kind: "log", Entity: "edge-1", Text: "%BGP-5-ADJCHANGE Down"}}, nil
		},
		DeviceState: func(_ context.Context, _ Principal, req DeviceStateRequest) (DeviceStateReport, error) {
			return DeviceStateReport{
				DeviceID: req.DeviceID, DeviceName: "edge-1", Platform: "ios-xe",
				Dialect: "cisco/ios_xe", Area: req.Area, Status: "ok", Collected: true,
				RulesetVersion: "v1",
				Rows: []StateRow{
					{Text: "BGP peer 10.0.0.1 — AS65001, state Idle", Kind: "device", Signals: []string{"state:bgp_peer=idle"}},
				},
			}, nil
		},
		BGPWatchlist: func(_ context.Context, _ Principal) (BGPWatchlistReport, error) {
			return BGPWatchlistReport{Scope: "t-a", Items: []BGPWatchItem{
				{Resource: "203.0.113.0/24", Kind: "prefix", Note: "customer block", Status: "announced by AS64500"},
			}}, nil
		},
		BGPRPKI: func(_ context.Context, _ Principal) (BGPRPKIReport, error) {
			return BGPRPKIReport{Scope: "t-a", Items: []BGPRPKIItem{
				{Prefix: "203.0.113.0/24", Origin: "AS64500", State: "valid", ROAs: 1},
			}}, nil
		},
		RecallInvestigations: func(_ context.Context, p Principal, q InvestigationQuery) ([]InvestigationRow, error) {
			if p.Tenant != "t-a" {
				return nil, nil // another tenant's memory is simply not there
			}
			return []InvestigationRow{{
				ID: "mem-1", DeviceID: "dev-a", DeviceName: "edge-1", Peer: "10.0.0.1",
				Skills:    []string{"bgp-session-down", "interface-down"},
				Verdict:   "the session dropped because the uplink optic was failing",
				Citations: []string{"diagsig:sig-1"}, Outcome: OutcomeConfirmed,
				ResolvedAt: tsMemoryDay,
			}}, nil
		},
		BGPFeedRecent: func(_ context.Context, _ Principal, prefix string, limit int) (BGPFeedReport, error) {
			return BGPFeedReport{
				Scope: "t-a", Resources: []string{"203.0.113.0/24"},
				Updates: []BGPFeedUpdate{
					{Seq: 7, At: "2026-09-02T10:00:00Z", Type: "W", Prefix: "203.0.113.0/24", Peer: "192.0.2.1"},
				},
			}, nil
		},
	}
}

func tsPrincipal() Principal {
	return Principal{Tenant: "t-a", Perms: map[string]bool{"correlations:read": true, "infrastructure:read": true}}
}

func tsRegistry(t *testing.T, d TroubleshootDeps) *ToolRegistry {
	t.Helper()
	ds := newMockDS()
	reg := Tools(ds)
	reg.AddTroubleshootTools(ds, d)
	return reg
}

func mustRun(t *testing.T, reg *ToolRegistry, name string, args ToolArgs) ToolResult {
	t.Helper()
	tool, ok := reg.Get(name)
	if !ok {
		t.Fatalf("tool %q is not registered", name)
	}
	res, err := tool.Run(context.Background(), tsPrincipal(), args)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

// ---- read-only + registration ---------------------------------------------

func TestTroubleshootToolsAreReadOnly(t *testing.T) {
	reg := tsRegistry(t, tsDeps())
	names := TroubleshootToolNames()
	if len(names) != 10 {
		t.Fatalf("expected 10 Phase-A/A4/B tools, got %v", names)
	}
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("TroubleshootToolNames must be sorted and unique: %v", names)
		}
	}
	for _, n := range names {
		tool, ok := reg.Get(n)
		if !ok {
			t.Fatalf("tool %q is not registered with fully wired deps", n)
		}
		if tool.Capability() != CapRead {
			t.Errorf("%s has capability %q — every Phase-A tool must be read-only (the model can never reach a write)", n, tool.Capability())
		}
		if len(tool.RequiredPerms()) == 0 {
			t.Errorf("%s declares no required permission", n)
		}
		if _, ok := toolMetas[n]; !ok {
			t.Errorf("%s has no toolMetas entry — it would be invisible to the agent loop", n)
		}
		if _, ok := ModuleByID(tool.Module()); !ok {
			t.Errorf("%s claims unknown module %q", n, tool.Module())
		}
		// The Policy Engine must actually permit it for a properly permissioned
		// caller (a read tool that the gate rejects is dead weight).
		pe := NewPolicyEngine(PolicyConfig{}, func(string) bool { return true })
		if d := pe.EvaluateTool(tool, Principal{Cross: true}); !d.Allow {
			t.Errorf("%s is denied by the default read-only policy: %s", n, d.Reason)
		}
	}
}

func TestAddTroubleshootToolsRegistersOnlyWiredSeams(t *testing.T) {
	full := tsDeps()
	cases := []struct {
		name    string
		ds      DataSource
		deps    TroubleshootDeps
		want    []string
		notWant []string
	}{
		{
			name: "nothing wired", ds: nil, deps: TroubleshootDeps{},
			notWant: TroubleshootToolNames(),
		},
		{
			name: "only the DataSource", ds: newMockDS(), deps: TroubleshootDeps{},
			want:    []string{"get_rca_verdict"},
			notWant: []string{"get_case_timeline", "run_protocol_diagnostic", "get_security_findings", "get_topology_context", "get_device_state", "get_bgp_watchlist", "get_bgp_rpki", "get_bgp_feed_recent", "recall_investigations"},
		},
		{
			name: "timeline without device resolution",
			ds:   newMockDS(), deps: TroubleshootDeps{CaseTimeline: full.CaseTimeline},
			want:    []string{"get_rca_verdict", "get_case_timeline"},
			notWant: []string{"run_protocol_diagnostic", "get_security_findings", "get_topology_context"},
		},
		{
			name: "device resolution but no findings seam",
			ds:   newMockDS(),
			deps: TroubleshootDeps{ResolveDevice: full.ResolveDevice, TopologyContext: full.TopologyContext},
			want: []string{"get_topology_context"}, notWant: []string{"get_security_findings", "run_protocol_diagnostic", "get_device_state"},
		},
		{
			name: "everything wired", ds: newMockDS(), deps: full,
			want: TroubleshootToolNames(),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := &ToolRegistry{byName: map[string]AITool{}}
			reg.AddTroubleshootTools(tc.ds, tc.deps)
			for _, n := range tc.want {
				if _, ok := reg.Get(n); !ok {
					t.Errorf("%q should be registered", n)
				}
			}
			for _, n := range tc.notWant {
				if _, ok := reg.Get(n); ok {
					t.Errorf("%q must NOT be registered — its seam is not wired, and it would answer with nothing", n)
				}
			}
		})
	}
	// A nil registry must be a no-op, not a panic.
	var nilReg *ToolRegistry
	nilReg.AddTroubleshootTools(newMockDS(), full)
}

// ---- argument validation ---------------------------------------------------

func TestTroubleshootToolArgValidation(t *testing.T) {
	reg := tsRegistry(t, tsDeps())
	cases := []struct {
		name string
		tool string
		args ToolArgs
		want string
	}{
		{"diag: missing device", "run_protocol_diagnostic", ToolArgs{"protocol": "bgp"}, "device_id is required"},
		{"diag: bad protocol", "run_protocol_diagnostic", ToolArgs{"device_id": "edge-1", "protocol": "rip"}, "protocol must be one of"},
		{"diag: empty protocol", "run_protocol_diagnostic", ToolArgs{"device_id": "edge-1"}, "protocol must be one of"},
		{"diag: device id with a wildcard", "run_protocol_diagnostic", ToolArgs{"device_id": "edge-*", "protocol": "bgp"}, "unsupported character"},
		{"diag: device id with whitespace", "run_protocol_diagnostic", ToolArgs{"device_id": "edge 1", "protocol": "bgp"}, "unsupported character"},
		{"diag: device id too long", "run_protocol_diagnostic", ToolArgs{"device_id": strings.Repeat("a", 129), "protocol": "bgp"}, "too long"},
		{"diag: issue id too long", "run_protocol_diagnostic", ToolArgs{"device_id": "edge-1", "protocol": "bgp", "issue_id": strings.Repeat("b", 65)}, "too long"},
		{"diag: issue id with a quote", "run_protocol_diagnostic", ToolArgs{"device_id": "edge-1", "protocol": "bgp", "issue_id": "bgp\"; drop"}, "unsupported character"},
		{"findings: bad severity", "get_security_findings", ToolArgs{"severity": "catastrophic"}, "severity must be one of"},
		{"findings: bad current flag", "get_security_findings", ToolArgs{"current": "maybe"}, "current must be true or false"},
		{"findings: seam with a wildcard", "get_security_findings", ToolArgs{"seam": "seam-*"}, "unsupported character"},
		{"topology: missing device", "get_topology_context", ToolArgs{}, "device_id is required"},
		{"topology: device id too long", "get_topology_context", ToolArgs{"device_id": strings.Repeat("a", 200)}, "too long"},
		{"timeline: missing id", "get_case_timeline", ToolArgs{}, "correlation_id is required"},
		{"timeline: id too long", "get_case_timeline", ToolArgs{"correlation_id": strings.Repeat("9", 65)}, "too long"},
		{"timeline: id with a slash-escape attempt", "get_case_timeline", ToolArgs{"correlation_id": "pa\n\rX"}, "unsupported character"},
		{"verdict: missing id", "get_rca_verdict", ToolArgs{}, "correlation_id is required"},
		{"verdict: id with a wildcard", "get_rca_verdict", ToolArgs{"correlation_id": "*"}, "unsupported character"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool, ok := reg.Get(tc.tool)
			if !ok {
				t.Fatalf("%s not registered", tc.tool)
			}
			_, err := tool.Run(context.Background(), tsPrincipal(), tc.args)
			if err == nil {
				t.Fatalf("expected a validation error mentioning %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// An invalid argument must be refused BEFORE any seam is touched.
func TestTroubleshootValidationRunsBeforeTheSeam(t *testing.T) {
	var touched bool
	d := tsDeps()
	d.ResolveDevice = func(_ context.Context, _ Principal, _ string) (DeviceRef, error) {
		touched = true
		return DeviceRef{ID: "x"}, nil
	}
	reg := tsRegistry(t, d)
	tool, _ := reg.Get("run_protocol_diagnostic")
	if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"device_id": "edge-1", "protocol": "rip"}); err == nil {
		t.Fatal("expected a protocol validation error")
	}
	if touched {
		t.Fatal("the device seam was touched despite an invalid protocol")
	}
}

// ---- ErrNotFound passthrough (§3a: unknown == another tenant's) ------------

func TestTroubleshootErrNotFoundPassthrough(t *testing.T) {
	reg := tsRegistry(t, tsDeps())
	cases := []struct {
		name string
		tool string
		args ToolArgs
	}{
		{"diagnostic on an unknown device", "run_protocol_diagnostic", ToolArgs{"device_id": "nope-1", "protocol": "bgp"}},
		{"diagnostic on another tenant's device", "run_protocol_diagnostic", ToolArgs{"device_id": "leaf-2", "protocol": "bgp"}},
		{"topology on another tenant's device", "get_topology_context", ToolArgs{"device_id": "leaf-2"}},
		{"findings scoped to another tenant's device", "get_security_findings", ToolArgs{"device": "leaf-2"}},
		{"timeline for another tenant's case", "get_case_timeline", ToolArgs{"correlation_id": "pb"}},
		{"verdict for another tenant's case", "get_rca_verdict", ToolArgs{"correlation_id": "pb"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tool, ok := reg.Get(tc.tool)
			if !ok {
				t.Fatalf("%s not registered", tc.tool)
			}
			res, err := tool.Run(context.Background(), tsPrincipal(), tc.args)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("err = %v, want ErrNotFound (unknown and cross-tenant must be indistinguishable)", err)
			}
			if len(res.Items) != 0 {
				t.Errorf("a not-found lookup must return no evidence, got %d items", len(res.Items))
			}
		})
	}
}

// ---- honest "not wired" branch --------------------------------------------

func TestProtocolDiagnosticNotWiredReturnsCommandsNotACause(t *testing.T) {
	d := tsDeps()
	d.ProtocolDiagnostic = func(_ context.Context, _ Principal, req DiagnosticRequest) (DiagnosticReport, error) {
		var cmds []DiagnosticCommand
		for i := 0; i < MaxDiagCommands+3; i++ {
			cmds = append(cmds, DiagnosticCommand{
				SpecID:  fmt.Sprintf("cmd-%d", i),
				Purpose: "peer state", Command: "show bgp summary",
			})
		}
		return DiagnosticReport{
			DeviceID: req.DeviceID, DeviceName: "edge-1", Protocol: req.Protocol,
			IssueID: "bgp-session-down", IssueTitle: "BGP session down", RulesetVersion: "v1",
			Commands: cmds, Collected: false,
			NotWired: "live collection is not wired on this deployment",
		}, nil
	}
	res := mustRun(t, tsRegistry(t, d), "run_protocol_diagnostic", ToolArgs{"device_id": "edge-1", "protocol": "bgp"})
	if !res.Truncated {
		t.Error("the command bundle exceeded its cap; Truncated must be set")
	}
	// 1 heading + the capped command list.
	if got := len(res.Items) - 1; got != MaxDiagCommands {
		t.Fatalf("returned %d commands, want the %d cap", got, MaxDiagCommands)
	}
	notes := strings.ToLower(strings.Join(res.Notes, " | "))
	for _, want := range []string{"not wired", "paste the output", "do not state a cause"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes must say %q; got %q", want, notes)
		}
	}
	for _, it := range res.Items[1:] {
		if it.Kind != "device" || !strings.Contains(it.Text, "suggested read-only check") {
			t.Errorf("a not-wired item must be a suggested READ-ONLY check, got %+v", it)
		}
		if strings.Contains(strings.ToLower(it.Text), "cause") {
			t.Errorf("a not-wired item must never name a cause: %q", it.Text)
		}
	}
}

func TestProtocolDiagnosticCollectedButUnmatchedNamesNoCause(t *testing.T) {
	d := tsDeps()
	d.ProtocolDiagnostic = func(_ context.Context, _ Principal, req DiagnosticRequest) (DiagnosticReport, error) {
		return DiagnosticReport{
			DeviceID: req.DeviceID, Protocol: req.Protocol, IssueID: "bgp-session-down",
			Collected: true, Unmatched: "no known signature matched the captured output",
		}, nil
	}
	res := mustRun(t, tsRegistry(t, d), "run_protocol_diagnostic", ToolArgs{"device_id": "edge-1", "protocol": "bgp"})
	if len(res.Items) != 1 {
		t.Fatalf("expected only the heading when nothing matched, got %d items", len(res.Items))
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "no known signature matched") {
		t.Errorf("an unmatched capture must say so plainly, notes = %v", res.Notes)
	}
}

func TestProtocolDiagnosticFindingsAreCapped(t *testing.T) {
	d := tsDeps()
	d.ProtocolDiagnostic = func(_ context.Context, _ Principal, req DiagnosticRequest) (DiagnosticReport, error) {
		var fs []DiagnosticFinding
		for i := 0; i < MaxDiagFindings+4; i++ {
			fs = append(fs, DiagnosticFinding{
				SignatureID: fmt.Sprintf("sig-%d", i), Verdict: "peer is Idle", Cause: "shutdown",
				Remediation: "no shutdown", Confidence: "high", Command: "show bgp summary",
				EvidenceLine: strings.Repeat("x", maxDiagEvidenceChars*2),
			})
		}
		return DiagnosticReport{DeviceID: req.DeviceID, Protocol: req.Protocol,
			IssueID: "bgp-session-down", Collected: true, Findings: fs}, nil
	}
	res := mustRun(t, tsRegistry(t, d), "run_protocol_diagnostic", ToolArgs{"device_id": "edge-1", "protocol": "bgp"})
	if !res.Truncated {
		t.Error("Truncated must disclose the finding cap")
	}
	if got := len(res.Items) - 1; got != MaxDiagFindings {
		t.Fatalf("returned %d findings, want the %d cap", got, MaxDiagFindings)
	}
	for _, it := range res.Items[1:] {
		if len(it.Text) > maxToolTextChars+maxDiagEvidenceChars+4 {
			t.Errorf("evidence line was not clamped: %d chars", len(it.Text))
		}
	}
}

func TestProtocolDiagnosticHappyPath(t *testing.T) {
	res := mustRun(t, tsRegistry(t, tsDeps()), "run_protocol_diagnostic",
		ToolArgs{"device_id": "edge-1", "protocol": "BGP", "issue_id": "bgp-session-down"})
	if len(res.Items) != 2 {
		t.Fatalf("want a heading + one finding, got %d", len(res.Items))
	}
	if !strings.Contains(res.Items[0].Text, "BGP") || !strings.Contains(res.Items[0].Text, "edge-1") {
		t.Errorf("heading = %q", res.Items[0].Text)
	}
	if res.Items[1].CitationID != "diagsig:sig-1" {
		t.Errorf("finding citation = %q", res.Items[1].CitationID)
	}
	if !strings.Contains(res.Items[1].Text, "no shutdown the neighbor") {
		t.Errorf("the catalog's own remediation must be carried through: %q", res.Items[1].Text)
	}
	for _, it := range res.Items {
		if it.Href != protocolDiagRouteHref {
			t.Errorf("every diagnostic item must deep-link to the page, got %q", it.Href)
		}
	}
}

// ---- caps + honesty on the other tools ------------------------------------

func TestSecurityFindingsCapsAndScopeNote(t *testing.T) {
	d := tsDeps()
	d.SecurityFindings = func(_ context.Context, _ Principal, _ FindingsQuery) ([]SecurityFinding, error) {
		var out []SecurityFinding
		for i := 0; i < MaxSecurityFindings+7; i++ {
			out = append(out, SecurityFinding{ID: fmt.Sprintf("f-%d", i), Title: "Telnet enabled", Severity: "high", Status: "open"})
		}
		return out, nil
	}
	res := mustRun(t, tsRegistry(t, d), "get_security_findings", ToolArgs{})
	if !res.Truncated || len(res.Items) != MaxSecurityFindings {
		t.Fatalf("items = %d (truncated=%v), want the %d cap", len(res.Items), res.Truncated, MaxSecurityFindings)
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "current state") {
		t.Errorf("the tool must state which scope it read, notes = %v", res.Notes)
	}
}

func TestSecurityFindingsEmptyIsNotClean(t *testing.T) {
	d := tsDeps()
	d.SecurityFindings = func(_ context.Context, _ Principal, _ FindingsQuery) ([]SecurityFinding, error) {
		return nil, nil
	}
	res := mustRun(t, tsRegistry(t, d), "get_security_findings", ToolArgs{"severity": "critical", "current": "false"})
	if len(res.Items) != 0 {
		t.Fatalf("expected no evidence rows, got %d", len(res.Items))
	}
	note := strings.Join(res.Notes, " ")
	if !strings.Contains(note, "not that the scope is clean") {
		t.Errorf("an empty result must NOT read as a clean bill of health: %q", note)
	}
}

func TestTopologyContextCapsAndUnknownDisclosure(t *testing.T) {
	d := tsDeps()
	d.TopologyContext = func(_ context.Context, _ Principal, deviceID string) (TopologyContext, error) {
		tc := TopologyContext{DeviceID: deviceID, DeviceName: "edge-1"}
		for i := 0; i < MaxTopologyNeighbors+5; i++ {
			tc.Neighbors = append(tc.Neighbors, TopologyNeighbor{LocalPort: "Gi0/1", PeerName: "core", PeerPort: "Gi1/1"})
		}
		for i := 0; i < MaxTopologySeams+2; i++ {
			tc.Seams = append(tc.Seams, TopologySeam{ID: "seam", Type: "dia"})
		}
		for i := 0; i < MaxTopologyPaths+2; i++ {
			tc.Paths = append(tc.Paths, TopologyPathRef{ID: "p", Label: "l", Hops: 3})
		}
		return tc, nil
	}
	res := mustRun(t, tsRegistry(t, d), "get_topology_context", ToolArgs{"device_id": "edge-1"})
	if !res.Truncated {
		t.Error("Truncated must disclose the topology caps")
	}
	want := 1 + MaxTopologyNeighbors + MaxTopologySeams + MaxTopologyPaths
	if len(res.Items) != want {
		t.Fatalf("items = %d, want %d (heading + capped neighbours/seams/paths)", len(res.Items), want)
	}

	d.TopologyContext = func(_ context.Context, _ Principal, deviceID string) (TopologyContext, error) {
		return TopologyContext{DeviceID: deviceID, Notes: []string{"lldp is not collected here"}}, nil
	}
	res = mustRun(t, tsRegistry(t, d), "get_topology_context", ToolArgs{"device_id": "edge-1"})
	note := strings.Join(res.Notes, " ")
	if !strings.Contains(note, "UNKNOWN") || !strings.Contains(note, "not that the device is isolated") {
		t.Errorf("an empty topology must read as UNKNOWN, not isolated: %q", note)
	}
	if !strings.Contains(note, "lldp is not collected here") {
		t.Errorf("the seam's own notes must be carried through: %q", note)
	}
}

func TestCaseTimelineCapsAndEmptyWindow(t *testing.T) {
	d := tsDeps()
	d.CaseTimeline = func(_ context.Context, _ Principal, _ string) ([]TimelineEvent, error) {
		var out []TimelineEvent
		for i := 0; i < MaxTimelineEvents+6; i++ {
			out = append(out, TimelineEvent{At: "2026-09-01T10:00:00Z", Kind: "log", Entity: "edge-1", Text: "line"})
		}
		return out, nil
	}
	res := mustRun(t, tsRegistry(t, d), "get_case_timeline", ToolArgs{"correlation_id": "pa"})
	if !res.Truncated || len(res.Items) != MaxTimelineEvents {
		t.Fatalf("items = %d (truncated=%v), want the %d cap", len(res.Items), res.Truncated, MaxTimelineEvents)
	}
	seen := map[string]bool{}
	for _, it := range res.Items {
		if seen[it.CitationID] {
			t.Fatalf("duplicate timeline citation id %q — citations must be unique", it.CitationID)
		}
		seen[it.CitationID] = true
	}

	d.CaseTimeline = func(_ context.Context, _ Principal, _ string) ([]TimelineEvent, error) { return nil, nil }
	res = mustRun(t, tsRegistry(t, d), "get_case_timeline", ToolArgs{"correlation_id": "pa"})
	if len(res.Items) != 0 || len(res.Notes) == 0 {
		t.Fatalf("an empty timeline must return a note and no rows: %+v", res)
	}
}

func TestRCAVerdictProjectsTheEngineConclusion(t *testing.T) {
	res := mustRun(t, tsRegistry(t, tsDeps()), "get_rca_verdict", ToolArgs{"correlation_id": "pa"})
	if len(res.Items) == 0 {
		t.Fatal("expected the verdict header")
	}
	if res.Items[0].CitationID != "verdict:pa" {
		t.Errorf("verdict citation = %q", res.Items[0].CitationID)
	}
	joined := ""
	for _, it := range res.Items {
		joined += it.Text + " | "
	}
	for _, want := range []string{"confirmed", "edge-1", "missing evidence", "neteng"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the RCA header must carry %q; got %q", want, joined)
		}
	}
	if !strings.Contains(strings.Join(res.Notes, " "), "ENGINE's conclusion") {
		t.Errorf("the tool must tell the model not to re-derive a cause, notes = %v", res.Notes)
	}
}

// ---- shared validators -----------------------------------------------------

func TestValidIDArg(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		ok   bool
		want string
	}{
		{"edge-1", 32, true, "edge-1"},
		{"  edge-1  ", 32, true, "edge-1"},
		{"a/b:c_d.e-1", 32, true, "a/b:c_d.e-1"},
		{"", 32, false, ""},
		{"   ", 32, false, ""},
		{"edge 1", 32, false, ""},
		{"edge*", 32, false, ""},
		{"edge'--", 32, false, ""},
		{"edge\n1", 32, false, ""},
		{"edge;rm -rf /", 32, false, ""},
		{strings.Repeat("a", 33), 32, false, ""},
	}
	for _, tc := range cases {
		got, err := validIDArg("device_id", tc.in, tc.max)
		if tc.ok {
			if err != nil || got != tc.want {
				t.Errorf("validIDArg(%q) = (%q, %v), want (%q, nil)", tc.in, got, err, tc.want)
			}
			continue
		}
		if err == nil {
			t.Errorf("validIDArg(%q) should have failed", tc.in)
		}
	}
}

func TestClampTextAndShortToken(t *testing.T) {
	if got := clampText("a\nb  ", 10); got != "a b" {
		t.Errorf("clampText should flatten newlines and trim, got %q", got)
	}
	if got := clampText(strings.Repeat("x", 20), 5); got != "xxxxx …" {
		t.Errorf("clampText = %q", got)
	}
	if got := shortToken("abc"); got != "abc" {
		t.Errorf("shortToken(short) = %q", got)
	}
	if got := shortToken("0123456789abcdef"); got != "01234567" {
		t.Errorf("shortToken(long) = %q", got)
	}
}
