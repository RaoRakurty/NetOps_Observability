// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aidecision

// steps_test.go — the seam mapping: a tool step becomes the right events with
// its hashes, evidence is hashed independently of citation order, and the
// query-log id is taken from a data payload only as a token.

import (
	"errors"
	"testing"
	"time"
)

func TestAddToolStepMapsEveryOutcome(t *testing.T) {
	rec, err := NewRecorder("alice", SurfaceAsk)
	if err != nil {
		t.Fatal(err)
	}
	rec.AddToolStep(ToolStep{Skill: "bgp-peer-down", Tool: "bgp_peers", Selected: "entry", Reason: "ok", Items: 2,
		ArgsSHA256: testHash, ResultSHA256: testHash}, "v1+abc")
	rec.AddToolStep(ToolStep{Skill: "bgp-peer-down", Tool: "device_ssh", Reason: "policy_denied", ArgsSHA256: testHash}, "v1+abc")
	rec.AddToolStep(ToolStep{Skill: "bgp-peer-down", Tool: "gone", Reason: "not_registered"}, "v1+abc")
	rec.AddToolStep(ToolStep{Skill: "bgp-peer-down", Tool: NextSkillTool, Reason: "model_selected_invalid"}, "v1+abc")
	rec.AddToolStep(ToolStep{Tool: "get_problem", Reason: "tool_error", ArgsSHA256: testHash}, "v1+abc")
	var nilRec *Recorder
	nilRec.AddToolStep(ToolStep{Tool: "x"}, "v")

	want := []struct{ typ, tool, outcome string }{
		{InvestigationStarted, "", "entry"},
		{PolicyEvaluated, "bgp_peers", "allow"},
		{ToolExecuted, "bgp_peers", "ok"},
		{PolicyEvaluated, "device_ssh", "deny"},
		{ToolSelected, "gone", "not_registered"},
		{PlanCreated, "", "model_selected_invalid"},
		{PolicyEvaluated, "get_problem", "allow"},
		{ToolExecuted, "get_problem", "tool_error"},
	}
	got := rec.Entries()
	if len(got) != len(want) {
		t.Fatalf("entries: %+v", got)
	}
	for i, w := range want {
		if got[i].EventType != w.typ || got[i].Tool != w.tool || got[i].Outcome != w.outcome {
			t.Errorf("entry %d = %+v, want %+v", i, got[i], w)
		}
	}
	if e := got[2]; e.ArgsSHA256 != testHash || e.ResultSHA256 != testHash || e.ItemCount != 2 || e.ToolVersion != "v1+abc" {
		t.Errorf("TOOL_EXECUTED must carry the hashes, count and version: %+v", e)
	}
	if e := got[7]; e.ResultSHA256 != "" {
		t.Errorf("a tool that did not return has no result hash: %+v", e)
	}
}

func TestEvidenceAndRecommendationHashes(t *testing.T) {
	a, _ := NewRecorder("u", SurfaceAsk) // NewRecorder fails only if crypto/rand does; ValidID below catches it
	b, _ := NewRecorder("u", SurfaceAsk) // same
	if !ValidID(a.DecisionID()) || !ValidID(b.DecisionID()) {
		t.Fatal("recorders")
	}
	a.AddEvidence([]string{"c2", "c1"})
	b.AddEvidence([]string{"c1", "c2"})
	a.AddEvidence(nil)
	a.AddRecommendation(nil, 3)
	a.AddRecommendation([]byte(`["x"]`), 0)
	a.AddRecommendation([]byte(`["x"]`), 1)
	ea, eb := a.Entries(), b.Entries()
	if len(ea) != 2 || ea[0].EventType != EvidenceAdded || ea[0].ItemCount != 2 || ea[0].ResultSHA256 != eb[0].ResultSHA256 {
		t.Fatalf("evidence: %+v vs %+v", ea, eb)
	}
	if ea[1].EventType != RecommendationCreated || ea[1].ResultSHA256 != SHA256Hex([]byte(`["x"]`)) || ea[1].ItemCount != 1 {
		t.Fatalf("recommendation: %+v", ea[1])
	}
}

func TestQueryLogID(t *testing.T) {
	for in, want := range map[string]string{
		`{"query_log_id":"0e1eb585-c9cf-4dcb-9fa4-d34b44c3d823"}`: "0e1eb585-c9cf-4dcb-9fa4-d34b44c3d823",
		`{"query_log_id":"two words"}`:                            "",
		`{"rows":[]}`:                                             "",
		`not json`:                                                "",
		``:                                                        "",
	} {
		if got := QueryLogID([]byte(in)); got != want {
			t.Errorf("QueryLogID(%s) = %q, want %q", in, got, want)
		}
	}
}

// Tool contract v2 (N-A8): the gateway's outcomes. A rate-limited call never
// ran, so it is a policy decision only; timeout / schema_rejected / bad_args /
// cancelled ran (or tried to) and carry the latency; truncation is kept.
func TestAddToolStepGatewayOutcomes(t *testing.T) {
	rec, err := NewRecorder("alice", SurfaceCopilot)
	if err != nil {
		t.Fatal(err)
	}
	rec.AddToolStep(ToolStep{Tool: "get_top_talkers", Reason: OutcomeRateLimited, ArgsSHA256: testHash}, "1@v1")
	rec.AddToolStep(ToolStep{Tool: "search_logs", Reason: OutcomeTimeout, Latency: 15 * time.Second}, "1@v1")
	rec.AddToolStep(ToolStep{Tool: "get_problem", Reason: OutcomeSchemaRejected, ResultSHA256: testHash, Latency: 40 * time.Millisecond}, "1@v1")
	rec.AddToolStep(ToolStep{Tool: "search_docs", Reason: "ok", Items: 3, Truncated: true, Latency: -time.Second}, "1@v1")
	got := rec.Entries()
	want := []struct {
		typ, tool, outcome string
		ms                 int64
		trunc              bool
	}{
		{PolicyEvaluated, "get_top_talkers", OutcomeRateLimited, 0, false},
		{PolicyEvaluated, "search_logs", "allow", 0, false},
		{ToolExecuted, "search_logs", OutcomeTimeout, 15000, false},
		{PolicyEvaluated, "get_problem", "allow", 0, false},
		{ToolExecuted, "get_problem", OutcomeSchemaRejected, 40, false},
		{PolicyEvaluated, "search_docs", "allow", 0, false},
		{ToolExecuted, "search_docs", "ok", 0, true}, // a negative duration is clamped, never stored
	}
	if len(got) != len(want) {
		t.Fatalf("entries: %+v", got)
	}
	for i, w := range want {
		g := got[i]
		if g.EventType != w.typ || g.Tool != w.tool || g.Outcome != w.outcome || g.LatencyMS != w.ms || g.Truncated != w.trunc {
			t.Errorf("entry %d = %+v, want %+v", i, g, w)
		}
	}
}

func TestNormalizeBoundsLatencyAndKnowsTheCopilotSurface(t *testing.T) {
	base := func() Entry {
		id, _ := NewID() // NewID fails only if crypto/rand does; ValidID in Normalize catches it
		return Entry{EventType: ToolExecuted, Principal: "alice", Surface: SurfaceCopilot, DecisionID: id}
	}
	if _, err := Normalize("t1", base(), time.Now()); err != nil {
		t.Fatalf("copilot surface must be accepted: %v", err)
	}
	for _, ms := range []int64{-1, MaxLatencyMS + 1} {
		e := base()
		e.LatencyMS = ms
		if _, err := Normalize("t1", e, time.Now()); !errors.Is(err, ErrInvalid) {
			t.Errorf("latency %d: want ErrInvalid, got %v", ms, err)
		}
	}
}
