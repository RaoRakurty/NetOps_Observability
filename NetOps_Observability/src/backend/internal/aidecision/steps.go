// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package aidecision

// steps.go — how the seams of one Iris decision become ledger entries. The
// mapping lives here, beside the vocabulary, so the HTTP layer only converts
// its own types into these plain inputs: a tool step (the orchestrator's audit
// hook), the citations an answer rests on, the next actions it recommends.

import (
	"encoding/json"
	"sort"
	"strings"
)

// ToolStep is one audited tool step, as the orchestrator's audit hook reports
// it: which method (Skill) ran which Tool, how it ended (Reason: ok,
// policy_denied, not_registered, not_found, tool_error … — or, for Tool
// "next_skill", the selection reason), and the HASHES of its arguments and
// result. Selected is how the method was chosen (entry, rule_selected …).
type ToolStep struct {
	Skill        string
	Tool         string
	Selected     string
	Reason       string
	Items        int
	ArgsSHA256   string
	ResultSHA256 string
}

// NextSkillTool is the audit hook's name for a SELECTION — the investigation
// moved to its next method — rather than a tool run.
const NextSkillTool = "next_skill"

// AddToolStep records one tool step. A step inside a method first opens the
// investigation (once per decision). Then:
//
//	next_skill       → PLAN_CREATED (the plan moved on; Outcome = the reason)
//	not_registered   → TOOL_SELECTED (named by the plan, not wired here)
//	policy_denied    → POLICY_EVALUATED deny
//	anything else    → POLICY_EVALUATED allow + TOOL_EXECUTED with both hashes
//
// toolVersion names the build the tool ran in. Nil-safe.
func (r *Recorder) AddToolStep(s ToolStep, toolVersion string) {
	if r == nil {
		return
	}
	if s.Skill != "" {
		r.StartInvestigation(s.Skill, s.Selected)
	}
	switch {
	case s.Tool == NextSkillTool:
		r.Add(Entry{EventType: PlanCreated, Skill: s.Skill, Outcome: s.Reason})
		return
	case s.Reason == "not_registered":
		r.Add(Entry{EventType: ToolSelected, Skill: s.Skill, Tool: s.Tool,
			ToolVersion: toolVersion, ArgsSHA256: s.ArgsSHA256, Outcome: "not_registered"})
		return
	case s.Reason == "policy_denied":
		r.Add(Entry{EventType: PolicyEvaluated, Skill: s.Skill, Tool: s.Tool,
			ToolVersion: toolVersion, ArgsSHA256: s.ArgsSHA256, Outcome: "deny"})
		return
	}
	r.Add(Entry{EventType: PolicyEvaluated, Skill: s.Skill, Tool: s.Tool,
		ToolVersion: toolVersion, ArgsSHA256: s.ArgsSHA256, Outcome: "allow"})
	r.Add(Entry{EventType: ToolExecuted, Skill: s.Skill, Tool: s.Tool,
		ToolVersion: toolVersion, ArgsSHA256: s.ArgsSHA256, ResultSHA256: s.ResultSHA256,
		ItemCount: s.Items, Outcome: s.Reason})
}

// AddEvidence records EVIDENCE_ADDED for the citation ids an answer rests on:
// the hash of the sorted ids, and how many. Nothing when there are none.
func (r *Recorder) AddEvidence(citationIDs []string) {
	if r == nil || len(citationIDs) == 0 {
		return
	}
	ids := append([]string(nil), citationIDs...)
	sort.Strings(ids)
	r.Add(Entry{EventType: EvidenceAdded, ResultSHA256: SHA256Hex([]byte(strings.Join(ids, "\n"))), ItemCount: len(ids)})
}

// AddRecommendation records RECOMMENDATION_CREATED: the hash of the
// recommendations' canonical encoding and how many there are.
func (r *Recorder) AddRecommendation(encoded []byte, n int) {
	if r == nil || n <= 0 || len(encoded) == 0 {
		return
	}
	r.Add(Entry{EventType: RecommendationCreated, ResultSHA256: SHA256Hex(encoded), ItemCount: n})
}

// QueryLogID is the query-log record id (N-C8) a data answer's payload
// carries, as a token — "" when there is none or it is not one.
func QueryLogID(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	var obj struct {
		ID string `json:"query_log_id"`
	}
	if json.Unmarshal(data, &obj) != nil {
		return ""
	}
	return Token(obj.ID)
}
