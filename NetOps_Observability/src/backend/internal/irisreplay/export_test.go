// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irisreplay

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/evalsplit"
)

const captureID = "aa01ffff-0000-4000-8000-000000000071"

// fakeProbe is a device probe that must never run during a capture.
type captureFake struct {
	seams     CaptureSeams
	probeRuns *int
}

func captureFixture(t *testing.T, entries []aidecision.Entry) captureFake {
	t.Helper()
	blob := `{"ranking":{"hypotheses":[{"id":"optic-los","title":"Optical loss on edge-1","confidence":0.6}]}}`
	c := &ai.ReplayCase{Principal: ai.ReplayPrincipal{Tenant: "t-a"}, Tenants: map[string]ai.ReplayTenant{"t-a": {
		Problems: []ai.ReplayProblem{{ID: captureID, Title: "Optical loss on edge-1", Verdict: "suspected", Confidence: 0.6, Devices: []string{"edge-1"}, Hypotheses: []byte(blob),
			Evidence: []ai.EvidenceItem{{CitationID: "log:os:7", Kind: "log", Text: "login failed password=hunter2 user=alice aa:bb:cc:dd:ee:ff", Href: "#/logs"}}}},
		Devices: []ai.ReplayDevice{{ID: "dev-a", Name: "edge-1"}},
	}}}
	ds := ai.ReplayDS{Case: c}
	probes := 0
	deps := ai.TroubleshootDeps{
		ResolveDevice: c.ResolveDevice,
		TopologyContext: func(context.Context, ai.Principal, string) (ai.TopologyContext, error) {
			return ai.TopologyContext{DeviceID: "dev-a", DeviceName: "edge-1", Notes: []string{"snmp-server community public RO"}}, nil
		},
		RecentChanges: func(context.Context, ai.Principal, ai.ChangeQuery) (ai.ChangeReport, error) {
			return ai.ChangeReport{Window: "24h"}, nil
		},
		RCAResult: func(context.Context, ai.Principal, string) (ai.RCAResult, error) {
			return ai.RCAResult{IncidentID: captureID, Title: "Optical loss"}, nil
		},
		DeviceState: func(context.Context, ai.Principal, ai.DeviceStateRequest) (ai.DeviceStateReport, error) {
			probes++
			return ai.DeviceStateReport{}, nil
		},
	}
	reg := ai.BuildToolRegistry(ds, deps, nil)
	perms := map[string]bool{"correlations:read": true, "infrastructure:read": true}
	return captureFake{probeRuns: &probes, seams: CaptureSeams{
		Principal: ai.Principal{Tenant: "t-a", Perms: perms},
		DS:        ds,
		Deps:      deps,
		Toolbox:   ai.Toolbox{Registry: reg, Policy: ai.NewPolicyEngine(ai.PolicyConfig{}, func(string) bool { return true }), Gateway: ai.NewToolGateway()},
		Snapshot: func(_ context.Context, id string) (Snapshot, error) {
			if id != captureID {
				return Snapshot{}, ai.ErrNotFound
			}
			return Snapshot{TenantID: "t-a", Hypotheses: blob, EngineVersion: "3.2.0+cfg.abc", CatalogVersion: "cat-1"}, nil
		},
		Decision: func(context.Context, string, string) ([]aidecision.Entry, error) { return entries, nil },
		ContextFacts: func(context.Context) (string, []string) {
			return "v1", []string{"the core is in Dallas; password=hunter2"}
		},
		Now: func() time.Time { return time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC) },
	}}
}

// Every text field goes through the outbound filter, and the result still loads.
func TestExportRedactsEveryTextField(t *testing.T) {
	f := captureFixture(t, nil)
	body, err := Export(context.Background(), f.seams, captureID)
	if err != nil {
		t.Fatal(err)
	}
	s := string(body)
	for _, leak := range []string{"hunter2", "alice", "dd:ee:ff", "community public"} {
		if strings.Contains(s, leak) {
			t.Errorf("LEAK: %q in the export:\n%s", leak, s)
		}
	}
	for _, keep := range []string{"Optical loss on edge-1", "optic-los", ai.Mask} {
		if !strings.Contains(s, keep) {
			t.Errorf("%q must survive: \n%s", keep, s)
		}
	}
	cases, err := ai.ParseReplayCases("export", body)
	if err != nil || len(cases) != 1 {
		t.Fatalf("%v %d", err, len(cases))
	}
	c := cases[0]
	if c.ContextVersion != "v1" || len(c.ContextFacts) != 1 || c.Config == nil || c.Topology["dev-a"].DeviceID != "dev-a" || len(c.Tenants["t-a"].RCA) != 1 {
		t.Fatalf("frozen data: %+v", c)
	}
	if c.Expected.LeadingHypothesis != "optic-los" || c.EngineVersion == "" {
		t.Fatalf("expected %+v, pin %q", c.Expected, c.EngineVersion)
	}
	for i, it := range c.Tenants["t-a"].Problems[0].Evidence {
		if it.CitationID != "log:os:7" {
			t.Errorf("evidence[%d] duplicates what the frozen reader derives: %s", i, it.CitationID)
		}
	}
	// The whole chain: the export runs offline, and reports say what it holds.
	rep, err := Run(context.Background(), cases, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Cases[0].Result != ResultPass || !hasLine(rep.Cases[0].Provenance, "re-read at capture") || !hasLine(rep.Cases[0].Provenance, "not as-of state") {
		t.Fatalf("%s %v %v", rep.Cases[0].Result, rep.Cases[0].Failures, rep.Cases[0].Provenance)
	}
}

func TestCaptureUnknownIsNotFound(t *testing.T) {
	f := captureFixture(t, nil)
	if _, err := Capture(context.Background(), f.seams, "aa01ffff-0000-4000-8000-000000000000"); !errors.Is(err, ai.ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

// administration:read does not by itself read incidents.
func TestCaptureNeedsCorrelationRead(t *testing.T) {
	f := captureFixture(t, nil)
	f.seams.Principal.Perms = map[string]bool{"administration:read": true}
	if _, err := Capture(context.Background(), f.seams, captureID); !errors.Is(err, ai.ErrForbidden) {
		t.Fatalf("%v", err)
	}
}

// source is forced to field unless the incident is a synthetic or twin fixture.
func TestCaptureSourceIsFieldUnlessSynthetic(t *testing.T) {
	f := captureFixture(t, nil)
	c, err := Capture(context.Background(), f.seams, captureID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Source != string(evalsplit.SourceField) || c.Split() != evalsplit.HeldOut {
		t.Fatalf("%q %s", c.Source, c.Split())
	}
	inner := f.seams.Snapshot
	f.seams.Snapshot = func(ctx context.Context, id string) (Snapshot, error) {
		s, err := inner(ctx, id)
		s.Synthetic = true
		return s, err
	}
	c, err = Capture(context.Background(), f.seams, captureID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Source != string(evalsplit.SourceSynthetic) {
		t.Fatalf("%q", c.Source)
	}
}

// A capture never opens a device session or spends a model call, and a ledgered
// step it cannot reproduce is named, not guessed.
func TestCaptureRereadsOnlyReads(t *testing.T) {
	probeArgs := ai.HashToolArgs(ai.ToolArgs{"problem_id": captureID})
	f := captureFixture(t, []aidecision.Entry{
		{DecisionID: "d", EventType: aidecision.QuestionReceived},
		{DecisionID: "d", EventType: aidecision.ToolExecuted, Tool: "get_device_state", ArgsSHA256: probeArgs, ResultSHA256: "x"},
		{DecisionID: "d", EventType: aidecision.ToolExecuted, Tool: "compile_query", ArgsSHA256: probeArgs, ResultSHA256: "x"},
		{DecisionID: "d", EventType: aidecision.ToolExecuted, Tool: "get_problem_evidence", ArgsSHA256: "no-such-hash", ResultSHA256: "x"},
		{DecisionID: "d", EventType: aidecision.AnswerReturned, ModelProvider: "p", ModelName: "m"},
	})
	c, err := Capture(context.Background(), f.seams, captureID)
	if err != nil {
		t.Fatal(err)
	}
	if *f.probeRuns != 0 {
		t.Fatalf("a capture opened %d device sessions", *f.probeRuns)
	}
	got := map[string]string{}
	for _, chk := range c.Capture.ToolChecks {
		got[chk.Tool] = chk.Status
	}
	if got["get_device_state"] != CaptureNotReRead || got["compile_query"] != CaptureNotReRead || got["get_problem_evidence"] != CaptureArgsUnknown {
		t.Fatalf("%v", got)
	}
	if c.Capture.DecisionID != "d" || c.Model == nil || c.Model.Name != "m" {
		t.Fatalf("%+v %+v", c.Capture, c.Model)
	}
}

// matches and moved are told apart by the ledger's own hash.
func TestCaptureComparesTheHash(t *testing.T) {
	args := ai.ToolArgs{"problem_id": captureID}
	f := captureFixture(t, nil)
	iv := f.seams.Toolbox.Invoke(context.Background(), f.seams.Principal, "get_problem_evidence", args)
	if !iv.OK() {
		t.Fatalf("%s %v", iv.Outcome, iv.Err)
	}
	same := ai.HashToolResult(iv.Result)
	f = captureFixture(t, []aidecision.Entry{
		{DecisionID: "d", EventType: aidecision.ToolExecuted, Tool: "get_problem_evidence", ArgsSHA256: ai.HashToolArgs(args), ResultSHA256: same},
		{DecisionID: "d", EventType: aidecision.ToolExecuted, Tool: "get_problem", ArgsSHA256: ai.HashToolArgs(args), ResultSHA256: strings.Repeat("0", 64)},
	})
	c, err := Capture(context.Background(), f.seams, captureID)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, chk := range c.Capture.ToolChecks {
		got[chk.Tool] = chk.Status
	}
	if got["get_problem_evidence"] != CaptureMatches || got["get_problem"] != CaptureMoved {
		t.Fatalf("%v", got)
	}
}

func TestFindDecision(t *testing.T) {
	ref := "aa01ffff-0000-4000-8000-000000000071"
	all := []aidecision.Entry{
		{TenantID: "t-b", DecisionID: "foreign", EventType: aidecision.QuestionReceived, IncidentRef: ref},
		{TenantID: "t-a", DecisionID: "newest", EventType: aidecision.QuestionReceived, IncidentRef: ref},
		{TenantID: "t-a", DecisionID: "older", EventType: aidecision.QuestionReceived, IncidentRef: ref},
		{TenantID: "t-a", DecisionID: "other", EventType: aidecision.QuestionReceived, IncidentRef: "aa01ffff-0000-4000-8000-000000000072"},
	}
	list := func(_ context.Context, f aidecision.ListFilter) ([]aidecision.Entry, error) {
		if f.DecisionID == "" {
			return all, nil
		}
		return []aidecision.Entry{{DecisionID: f.DecisionID}}, nil
	}
	got, err := FindDecision(context.Background(), true, "t-a", ref, list)
	if err != nil || len(got) != 1 || got[0].DecisionID != "newest" {
		t.Fatalf("a platform reader keeps to the incident's tenant: %+v %v", got, err)
	}
	if got, err := FindDecision(context.Background(), false, "t-b", "aa01ffff-0000-4000-8000-000000000099", list); err != nil || got != nil {
		t.Fatalf("no decision: %+v %v", got, err)
	}
	boom := errors.New("ledger down")
	if _, err := FindDecision(context.Background(), false, "t-a", ref, func(context.Context, aidecision.ListFilter) ([]aidecision.Entry, error) { return nil, boom }); !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
}

// Nothing is written on the server: the capture's code cannot touch a file.
func TestExportWritesNoFile(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "export.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		if path == "os" || path == "io/ioutil" || path == "io/fs" {
			t.Errorf("export.go imports %s: an export writes nothing on the server", path)
		}
	}
}
