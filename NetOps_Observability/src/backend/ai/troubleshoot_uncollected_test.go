// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// troubleshoot_uncollected_test.go — D-4 (QA run 2026-09-03).
//
// A live capture in which the device REJECTED every read-only command produced
// zero bytes, and the assistant reported "the diagnostic ran and no known
// signature matched". An operator reads that as "we looked, the protocol is
// fine". Nothing was looked at. These tests pin the three outcomes apart:
//
//	not attempted        → the read-only bundle to hand to a human
//	attempted, 0 bytes   → UNKNOWN state + the per-command rejection reasons
//	attempted, collected → the original scored contract, unchanged

import (
	"context"
	"strings"
	"testing"
)

func uncollectedDeps(total int, reason string) TroubleshootDeps {
	d := tsDeps()
	d.ProtocolDiagnostic = func(_ context.Context, _ Principal, req DiagnosticRequest) (DiagnosticReport, error) {
		rep := DiagnosticReport{
			DeviceID: req.DeviceID, DeviceName: "edge-1", Protocol: req.Protocol,
			IssueID: "bgp-session-down", IssueTitle: "BGP session down", RulesetVersion: "v1",
			Attempted: true, Collected: false, Total: total, Failed: total,
			CollectFailed: reason,
		}
		for i := 0; i < total; i++ {
			rep.Commands = append(rep.Commands, DiagnosticCommand{
				SpecID:  "spec-" + string(rune('a'+i)),
				Purpose: "read the session table",
				Command: "show router bgp summary",
				Error:   "command failed: Process exited with status 1",
			})
		}
		return rep, nil
	}
	return d
}

func TestProtocolDiagnosticNothingCapturedIsNotNothingMatched(t *testing.T) {
	const reason = "the read-only commands were rejected by the device (7 of 7 failed); no output was captured"
	res := mustRun(t, tsRegistry(t, uncollectedDeps(7, reason)), "run_protocol_diagnostic",
		ToolArgs{"device_id": "edge-1", "protocol": "bgp"})

	notes := strings.ToLower(strings.Join(res.Notes, " | "))
	if strings.Contains(notes, "no known signature matched") {
		t.Fatalf("a capture that produced NOTHING still claims the signatures were scored: %q", notes)
	}
	if !strings.Contains(notes, "rejected by the device") {
		t.Errorf("the notes must say what actually happened: %q", notes)
	}
	if !strings.Contains(notes, "unknown") || !strings.Contains(notes, "not healthy") {
		t.Errorf("the notes must mark the protocol state UNKNOWN, not healthy: %q", notes)
	}
	if !strings.Contains(notes, "7 of 7") {
		t.Errorf("the notes must count the failures: %q", notes)
	}

	// The machine fact the chain routes on.
	want := CondSignature + "=" + CondSignatureUncollected
	found := false
	for _, sig := range res.Signals {
		if sig == want {
			found = true
		}
		if sig == CondSignature+"="+CondSignatureNone {
			t.Errorf("the tool asserted %q for a capture that produced nothing", sig)
		}
	}
	if !found {
		t.Fatalf("signal %q was not emitted (signals: %v)", want, res.Signals)
	}

	// Every rejection reason reaches the operator as its own evidence row, and
	// none of them may read as a suggestion to run something.
	rejections := 0
	for _, it := range res.Items[1:] {
		if !strings.HasPrefix(it.CitationID, "diagerr:") {
			continue
		}
		rejections++
		if !strings.Contains(it.Text, "rejected") || !strings.Contains(it.Text, "status 1") {
			t.Errorf("a rejection row must carry the device's own reason: %q", it.Text)
		}
		if strings.Contains(strings.ToLower(it.Text), "cause") {
			t.Errorf("a rejection row must never name a cause: %q", it.Text)
		}
	}
	if rejections != 7 {
		t.Errorf("%d rejection rows, want one per failed command", rejections)
	}
}

// The three outcomes must never collapse into each other.
func TestProtocolDiagnosticOutcomesAreDistinct(t *testing.T) {
	notWired := tsDeps()
	notWired.ProtocolDiagnostic = func(_ context.Context, _ Principal, req DiagnosticRequest) (DiagnosticReport, error) {
		return DiagnosticReport{
			DeviceID: req.DeviceID, Protocol: req.Protocol, IssueID: "bgp-session-down",
			Commands: []DiagnosticCommand{{SpecID: "bgp-summary", Purpose: "session table", Command: "show bgp summary"}},
			NotWired: "live collection is not wired on this deployment",
		}, nil
	}
	scored := tsDeps()
	scored.ProtocolDiagnostic = func(_ context.Context, _ Principal, req DiagnosticRequest) (DiagnosticReport, error) {
		return DiagnosticReport{
			DeviceID: req.DeviceID, Protocol: req.Protocol, IssueID: "bgp-session-down",
			Attempted: true, Collected: true, Total: 3, Failed: 0,
			Unmatched: "no known signature matched the captured output",
		}, nil
	}

	cases := []struct {
		name         string
		deps         TroubleshootDeps
		mustSay      []string
		mustNotSay   []string
		wantSignal   string
		unwantSignal string
	}{
		{
			name: "no transport", deps: notWired,
			mustSay:      []string{"not wired", "paste the output"},
			mustNotSay:   []string{"rejected by the device", "no known signature matched"},
			unwantSignal: CondSignature + "=" + CondSignatureUncollected,
		},
		{
			name: "attempted, nothing captured", deps: uncollectedDeps(3, ""),
			mustSay:      []string{"rejected by the device", "unknown"},
			mustNotSay:   []string{"no known signature matched", "not wired"},
			wantSignal:   CondSignature + "=" + CondSignatureUncollected,
			unwantSignal: "",
		},
		{
			name: "captured and scored", deps: scored,
			mustSay:      []string{"no known signature matched"},
			mustNotSay:   []string{"rejected by the device", "not wired", "partial"},
			unwantSignal: CondSignature + "=" + CondSignatureUncollected,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := mustRun(t, tsRegistry(t, tc.deps), "run_protocol_diagnostic",
				ToolArgs{"device_id": "edge-1", "protocol": "bgp"})
			notes := strings.ToLower(strings.Join(res.Notes, " | "))
			for _, want := range tc.mustSay {
				if !strings.Contains(notes, want) {
					t.Errorf("notes must say %q: %q", want, notes)
				}
			}
			for _, no := range tc.mustNotSay {
				if strings.Contains(notes, no) {
					t.Errorf("notes must NOT say %q: %q", no, notes)
				}
			}
			has := func(s string) bool {
				for _, v := range res.Signals {
					if v == s {
						return true
					}
				}
				return false
			}
			if tc.wantSignal != "" && !has(tc.wantSignal) {
				t.Errorf("missing signal %q (got %v)", tc.wantSignal, res.Signals)
			}
			if tc.unwantSignal != "" && has(tc.unwantSignal) {
				t.Errorf("unexpected signal %q (got %v)", tc.unwantSignal, res.Signals)
			}
		})
	}
}

// A PARTIAL capture is scored, but the operator is told the verdict rests on
// less than the bundle.
func TestProtocolDiagnosticPartialCaptureIsDisclosed(t *testing.T) {
	d := tsDeps()
	d.ProtocolDiagnostic = func(_ context.Context, _ Principal, req DiagnosticRequest) (DiagnosticReport, error) {
		return DiagnosticReport{
			DeviceID: req.DeviceID, Protocol: req.Protocol, IssueID: "bgp-session-down",
			Attempted: true, Collected: true, Total: 7, Failed: 5,
			Findings: []DiagnosticFinding{{
				SignatureID: "bgp-peer-idle", Verdict: "peer is Idle", Cause: "shutdown",
				Remediation: "no shutdown", Confidence: "high", Command: "show bgp summary",
			}},
		}, nil
	}
	res := mustRun(t, tsRegistry(t, d), "run_protocol_diagnostic", ToolArgs{"device_id": "edge-1", "protocol": "bgp"})
	notes := strings.ToLower(strings.Join(res.Notes, " | "))
	if !strings.Contains(notes, "partial") || !strings.Contains(notes, "5 of 7") {
		t.Fatalf("a partial capture must be disclosed with its counts: %q", notes)
	}
}

// The chain-level half of D-4: `signature=none` ("we scored it and nothing
// matched") must NOT hold when the capture produced nothing.
func TestSignatureNoneDoesNotHoldForAnUncollectedCapture(t *testing.T) {
	none := SkillCondition{Key: CondSignature, Value: CondSignatureNone}
	uncollected := SkillCondition{Key: CondSignature, Value: CondSignatureUncollected}

	scored := newChainFacts()
	scored.recordTool("run_protocol_diagnostic", "ok")
	if !scored.holds(none) {
		t.Error("a scored capture with no matches must still satisfy signature=none")
	}
	if scored.holds(uncollected) {
		t.Error("signature=uncollected must not hold for a scored capture")
	}

	empty := newChainFacts()
	empty.recordTool("run_protocol_diagnostic", "ok")
	empty.addSignals([]string{CondSignature + "=" + CondSignatureUncollected})
	if empty.holds(none) {
		t.Fatal("signature=none held for a capture that produced NOTHING — this is D-4 at the chain level")
	}
	if !empty.holds(uncollected) {
		t.Error("signature=uncollected must hold once the tool asserted it")
	}
	// The reserved value must never be mistaken for a real signature id.
	if len(empty.signatures) != 0 {
		t.Errorf("the reserved value leaked into the signature set: %v", empty.signatures)
	}
	if empty.holds(SkillCondition{Key: CondSignature, Value: CondSignatureUncollected + "x"}) {
		t.Error("a near-miss value must not fire")
	}

	// A turn that never ran a diagnostic satisfies neither.
	never := newChainFacts()
	if never.holds(none) || never.holds(uncollected) {
		t.Error("neither condition may hold on a turn with no diagnostic")
	}

	// Both render an operator-facing reason, and they must differ.
	if none.Human() == uncollected.Human() {
		t.Fatal("the two outcomes must not share a sentence")
	}
	if strings.Contains(strings.ToLower(uncollected.Human()), "no known signature matched") {
		t.Errorf("the uncollected reason claims a scored analysis: %q", uncollected.Human())
	}
}
