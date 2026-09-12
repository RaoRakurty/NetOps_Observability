// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeNarrator struct {
	out  string
	err  error
	seen NarrationRequest
}

func (f *fakeNarrator) Narrate(_ context.Context, req NarrationRequest) (string, error) {
	f.seen = req
	return f.out, f.err
}

func problemFixture(t *testing.T) ProblemInput {
	t.Helper()
	in := fixtureBundleInput(t)
	ev := buildEvidenceIndex(in)
	return ProblemInput{
		TenantID: in.TenantID, IncidentID: in.IncidentID, IncidentRef: in.IncidentRef,
		Title: in.Title, WindowStart: in.WindowStart, WindowEnd: in.WindowEnd,
		Hostname: in.Capture.Hostname, Platform: in.Capture.Platform,
		DialectLabel: in.Capture.Display, Class: in.Class, Plan: in.Plan,
		Capture: in.Capture, Evidence: ev,
	}
}

// TestTemplateStatementCitesEverything is the evidence-only rule applied to
// Correlix's own writing: every claim line in the deterministic statement must
// carry an evidence id.
func TestTemplateStatementCitesEverything(t *testing.T) {
	in := problemFixture(t)
	st := WriteProblemStatement(context.Background(), in, nil)
	if st.WrittenBy != "template" {
		t.Fatalf("WrittenBy = %q", st.WrittenBy)
	}
	known := map[string]struct{}{}
	for _, e := range in.Evidence {
		known[e.ID] = struct{}{}
	}
	if reason := validateStatement(st.Text, known); reason != "" {
		t.Fatalf("Correlix's own statement fails the evidence-only rule: %s\n---\n%s", reason, st.Text)
	}
	for _, h := range []string{"## What happened", "## When", "## What Correlix checked",
		"## What was NOT established", "## Where TAC should look first"} {
		if !strings.Contains(st.Text, h) {
			t.Errorf("statement is missing the %q section", h)
		}
	}
	if len(st.CitedIDs) == 0 {
		t.Fatal("the statement cites nothing")
	}
}

// TestUnclassifiedStatementSaysSo — an unclassified incident must not read as
// though a cause was found.
func TestUnclassifiedStatementSaysSo(t *testing.T) {
	cat := mustCatalog(t)
	in := problemFixture(t)
	in.Class = cat.Classify(Evidence{})
	st := WriteProblemStatement(context.Background(), in, nil)
	if !strings.Contains(st.Text, "did NOT classify") {
		t.Fatalf("the statement must state the classification gap:\n%s", st.Text)
	}
}

// TestNarratorOutputMustCiteRealEvidence — the §15 gate on untrusted output.
func TestNarratorOutputMustCiteRealEvidence(t *testing.T) {
	in := problemFixture(t)
	id := in.Evidence[0].ID
	for _, tc := range []struct {
		name, out, wantReason string
		accept                bool
	}{
		{
			name:   "well-cited prose is accepted",
			out:    "# Problem statement\n\n## What happened\n\nThe BGP session dropped [" + id + "].\n",
			accept: true,
		},
		{
			name:       "an uncited claim is refused",
			out:        "# Problem statement\n\nThe optics are failing and should be replaced.\n",
			wantReason: "cited no evidence",
			accept:     false,
		},
		{
			name:       "a fabricated citation is refused",
			out:        "# Problem statement\n\nThe session dropped [Z999].\n",
			wantReason: "not in the bundle",
			accept:     false,
		},
		{
			name:       "a link is refused",
			out:        "# Problem statement\n\nSee [here](http://evil.invalid) [" + id + "].\n",
			wantReason: "markup or a link",
			accept:     false,
		},
		{
			name:       "an empty answer is refused",
			out:        "   ",
			wantReason: "empty",
			accept:     false,
		},
		{
			name:       "an oversized answer is refused",
			out:        "x [" + id + "]\n" + strings.Repeat("padding [", 4000),
			wantReason: "size cap",
			accept:     false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := &fakeNarrator{out: tc.out}
			st := WriteProblemStatement(context.Background(), in, n)
			if tc.accept {
				if st.WrittenBy != "iris" {
					t.Fatalf("a valid draft was refused: %s", st.Rejected)
				}
				return
			}
			if st.WrittenBy != "template" {
				t.Fatal("an invalid draft was accepted")
			}
			if !strings.Contains(st.Rejected, tc.wantReason) {
				t.Fatalf("rejection %q does not mention %q", st.Rejected, tc.wantReason)
			}
		})
	}
}

// TestNarratorFailureFallsBackHonestly.
func TestNarratorFailureFallsBackHonestly(t *testing.T) {
	in := problemFixture(t)
	st := WriteProblemStatement(context.Background(), in, &fakeNarrator{err: errors.New("provider down")})
	if st.WrittenBy != "template" {
		t.Fatal("a failed narrator must fall back to the template")
	}
	if !strings.Contains(st.Rejected, "not available") {
		t.Fatalf("the fallback must be stated, got %q", st.Rejected)
	}
	if strings.TrimSpace(st.Text) == "" {
		t.Fatal("the fallback statement is empty")
	}
}

// TestNarratorGetsTheServerControlledInstructionOnly — LLM01: nothing from a
// request can reach the instruction, and the evidence set is closed.
func TestNarratorGetsTheServerControlledInstructionOnly(t *testing.T) {
	in := problemFixture(t)
	n := &fakeNarrator{out: "# Problem statement\n\nfine [" + in.Evidence[0].ID + "]\n"}
	_ = WriteProblemStatement(context.Background(), in, n)
	if n.seen.Instruction != NarrationInstruction {
		t.Fatal("the narrator was handed an instruction other than the server's own")
	}
	if len(n.seen.Evidence) != len(in.Evidence) {
		t.Fatal("the narrator's evidence set is not the bundle's closed set")
	}
	if n.seen.Draft == "" {
		t.Fatal("the narrator must be handed the deterministic draft to rewrite, not a blank page")
	}
	if !strings.Contains(NarrationInstruction, "MUST cite at least one evidence id") {
		t.Fatal("the instruction no longer states the evidence-only rule")
	}
}
