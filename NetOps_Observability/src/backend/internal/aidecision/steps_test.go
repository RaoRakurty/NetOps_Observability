// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aidecision

// steps_test.go — the seam mapping: a tool step becomes the right events with
// its hashes, evidence is hashed independently of citation order, and the
// query-log id is taken from a data payload only as a token.

import "testing"

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
