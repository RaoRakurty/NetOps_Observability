// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_copy_denylist_test.go — a COPY guard over the DETERMINISTIC action list.
//
// skillNextActions pastes an author's words into a template. D-9 was what that
// costs when the template assumes a shape the author did not write:
// log-confirmation authors `escalate=only with the quoted lines and their
// timestamps attached`, and the old "Escalate to "+reason+"." rendered
//
//	"Escalate to only with the quoted lines and their timestamps attached."
//
// which reads to an operator like a substitution that came back empty. The guard
// runs the REAL skill corpus through the real renderer and asserts every line is
// a readable sentence — so a new skill authored in a new shape fails the build
// rather than shipping broken copy.

import (
	"regexp"
	"strings"
	"testing"
)

// danglingAction matches the ways a template can betray an empty or misfitting
// substitution: a preposition or dash with nothing after it, and the specific
// "to <qualifier>" shape D-9 shipped.
var danglingActionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`Escalate to\s*\.`),           // "Escalate to ."
	regexp.MustCompile(`Escalate to\s*$`),            // "Escalate to"
	regexp.MustCompile(`(?i)\bto only\b`),            // "Escalate to only with …" (D-9)
	regexp.MustCompile(`(?i)\bto with\b`),            //
	regexp.MustCompile(`(?i)\bto when\b`),            //
	regexp.MustCompile(`—\s*\.`),                     // "Check x — ."
	regexp.MustCompile(`when\s*\.`),                  // "… — when ."
	regexp.MustCompile(`\s{2,}`),                     // a collapsed substitution leaves a double space
	regexp.MustCompile(`\.\.`),                       // doubled terminator
	regexp.MustCompile(`(?i)\b(to|with|for|when)\.`), // a sentence that ends on a preposition
}

// checkAction is the shape of the DecisionNext branch.
var checkActionRe = regexp.MustCompile(`^Check [a-z0-9 ]+( — when .+)?\.$`)

// escalateActionRe is the shape of the DecisionEscalate branch: an owner phrase
// addressed with "to", a qualifier attached with a dash, or the bare word.
var escalateActionRe = regexp.MustCompile(`^Escalate( to | — )?.*\.$`)

// assertReadableAction is the whole denylist, applied to one rendered line.
func assertReadableAction(t *testing.T, where, action string) {
	t.Helper()
	if strings.TrimSpace(action) == "" {
		t.Errorf("%s: rendered an empty action", where)
		return
	}
	if action != strings.TrimSpace(action) {
		t.Errorf("%s: action has leading/trailing space: %q", where, action)
	}
	if !strings.HasSuffix(action, ".") {
		t.Errorf("%s: action is not a sentence (no terminator): %q", where, action)
	}
	for _, re := range danglingActionPatterns {
		if re.MatchString(action) {
			t.Errorf("%s: action matches the dangling-substitution pattern %s: %q", where, re, action)
		}
	}
	switch {
	case strings.HasPrefix(action, "Check "):
		if !checkActionRe.MatchString(action) {
			t.Errorf("%s: Check action is malformed: %q", where, action)
		}
	case strings.HasPrefix(action, "Escalate"):
		if !escalateActionRe.MatchString(action) {
			t.Errorf("%s: Escalate action is malformed: %q", where, action)
		}
		// The word after "Escalate to " must open a party, never a qualifier:
		// that is the exact D-9 failure, stated positively.
		if rest, ok := strings.CutPrefix(action, "Escalate to "); ok {
			if !startsWithOwnerPhrase(rest) {
				t.Errorf("%s: \"Escalate to\" is followed by a qualifier, not an owner: %q", where, action)
			}
		}
	default:
		t.Errorf("%s: action is neither a Check nor an Escalate line: %q", where, action)
	}
}

// TestSkillNextActionsReadAsEnglish runs EVERY embedded skill through the real
// renderer. It is the regression guard for D-9 and for the Check branch beside it.
func TestSkillNextActionsReadAsEnglish(t *testing.T) {
	set, err := LoadSkills()
	if err != nil {
		t.Fatalf("LoadSkills: %v", err)
	}
	if set.Len() == 0 {
		t.Fatal("no skills loaded — the guard would pass vacuously")
	}
	escalations, checks := 0, 0
	for _, name := range set.Names() {
		sk, ok := set.Get(name)
		if !ok {
			t.Fatalf("skill %q vanished between Names and Get", name)
		}
		actions := skillNextActions(sk)
		for _, a := range actions {
			assertReadableAction(t, name, a)
			switch {
			case strings.HasPrefix(a, "Escalate"):
				escalations++
			case strings.HasPrefix(a, "Check "):
				checks++
			}
		}
	}
	// The corpus really did exercise both branches.
	if escalations == 0 {
		t.Error("no skill rendered an Escalate action — the guard is not aimed at the D-9 branch")
	}
	if checks == 0 {
		t.Error("no skill rendered a Check action — the guard is not aimed at the handoff branch")
	}
}

// TestEscalateActionShapes pins the renderer's rule directly, including the
// shapes the corpus does not currently contain: an empty reason must never
// produce "Escalate to .".
func TestEscalateActionShapes(t *testing.T) {
	cases := []struct{ reason, want string }{
		// owner phrases keep "to" — the wording operators already read.
		{"the peer's owner", "Escalate to the peer's owner."},
		{"the routing owner with both ends' level and area named when the mismatch is on the far end",
			"Escalate to the routing owner with both ends' level and area named when the mismatch is on the far end."},
		{"field engineering for a clean-and-reseat", "Escalate to field engineering for a clean-and-reseat."},
		{"a partner NOC", "Escalate to a partner NOC."},
		{"Level3 with the circuit id quoted", "Escalate to Level3 with the circuit id quoted."},
		// qualifiers attach with a dash instead of a dangling "to".
		{"only with the quoted lines and their timestamps attached",
			"Escalate — only with the quoted lines and their timestamps attached."},
		{"say plainly which evidence is missing and which check would close the gap",
			"Escalate — say plainly which evidence is missing and which check would close the gap."},
		{"immediately when the seam is a paid circuit", "Escalate — immediately when the seam is a paid circuit."},
		// nothing authored is "Escalate." — never a dangling preposition.
		{"", "Escalate."},
		{"   ", "Escalate."},
		{"\t\n", "Escalate."},
		// an authored terminator is not doubled.
		{"the LAN owner.", "Escalate to the LAN owner."},
	}
	for _, c := range cases {
		if got := escalateAction(c.reason); got != c.want {
			t.Errorf("escalateAction(%q) = %q, want %q", c.reason, got, c.want)
		}
	}
	for _, c := range cases {
		assertReadableAction(t, "escalateAction("+c.reason+")", escalateAction(c.reason))
	}
}

// TestSkillNextActionsHandleEmptyReasons — a decision with no authored reason
// still renders a sentence on both branches.
func TestSkillNextActionsHandleEmptyReasons(t *testing.T) {
	sk := &Skill{
		Name:  "unit",
		Layer: SkillLayer("transport"),
		Decisions: []SkillDecision{
			{Kind: DecisionNext, Target: "interface-down"},
			{Kind: DecisionNext, Target: "log-confirmation", Reason: "   "},
			{Kind: DecisionEscalate},
			{Kind: DecisionEscalate, Reason: " "},
		},
	}
	got := skillNextActions(sk)
	want := []string{"Check interface down.", "Check log confirmation.", "Escalate.", "Escalate."}
	if len(got) != len(want) {
		t.Fatalf("actions = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("action %d = %q, want %q", i, got[i], want[i])
		}
		assertReadableAction(t, "empty-reason skill", got[i])
	}
}
