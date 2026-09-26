// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// rca_result_test.go — the Iris RCA contract tools (tracker 337 N-B1/B2).
//
// Pinned: the tools exist only with a wired seam; a foreign incident is
// ErrNotFound; an inferred link can never be labelled observed; the evidence
// AGAINST a candidate is always rendered; an unmeasured impact is "not
// measured", never zero; an absent owner/chain is disclosed, never invented.

import (
	"context"
	"errors"
	"strings"
	"testing"
)

const rcaTestID = "11111111-2222-3333-4444-555555555555"

func rcaFixture() RCAResult {
	users := 214.0
	return RCAResult{
		IncidentID: rcaTestID, Verdict: "probable", RootCauseState: "under_investigation",
		Confidence: 0.91, ConfidenceLabel: "likely",
		CausalChain: []RCACausalLink{
			{Number: 1, Claim: "DIA packet loss on the Comcast underlay", Relation: RelationObserved, EpistemicState: "observed", Interval: "10:17 → 10:40 UTC"},
			{Number: 2, Claim: "SD-WAN tunnel SLA degraded", Relation: RelationInferred, EpistemicState: "inferred", Link: "followed by",
				Contradictions: []string{"one Comcast site remains healthy"}},
		},
		Hypotheses: []RCAHypothesis{{Rank: 1, Title: "Comcast DIA degradation", CausalRole: "probable_origin", Confidence: 0.91, Label: "likely",
			Supporting: []string{"loss starts after provider handoff"}, Contradicting: []string{"one Comcast site remains healthy"},
			Missing: []string{"remote probe data"}}},
		Affected: RCAAffected{Sites: []string{"Dallas HQ"}, Services: []string{"Salesforce"}, Paths: 3},
		Impact: []RCAImpact{
			{Measure: "active_users", Label: "Active users affected", Status: "measured", Value: &users, Unit: "users", Basis: "DEM sessions"},
			{Measure: "transactions", Label: "Transactions affected", Status: "not_measured", Basis: "no transaction mapping"},
		},
		Owner:   RCAOwner{Triage: "NOC", TriageReason: "default", ExternalCandidate: "Comcast", Demarcation: "local_checks_pending"},
		Missing: []string{"remote probe data"},
	}
}

func rcaDeps(res RCAResult) TroubleshootDeps {
	d := tsDeps()
	d.RCAResult = func(_ context.Context, p Principal, id string) (RCAResult, error) {
		if p.Tenant != "t-a" || id != rcaTestID {
			return RCAResult{}, ErrNotFound
		}
		return res, nil
	}
	return d
}

func runRCATool(t *testing.T, res RCAResult, name string) ToolResult {
	t.Helper()
	out, err := bgpTool(t, rcaDeps(res), name).Run(context.Background(), tsPrincipal(), ToolArgs{"correlation_id": rcaTestID})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func joinTexts(tr ToolResult) string {
	var b strings.Builder
	for _, it := range tr.Items {
		b.WriteString(it.Text + "\n")
	}
	return b.String() + strings.Join(tr.Notes, "\n")
}

func TestRCAToolsRegisterOnlyWhenWired(t *testing.T) {
	names := []string{"get_causal_chain", "get_blast_radius", "get_owner", "get_confidence_breakdown"}
	reg := tsRegistry(t, tsDeps())
	for _, n := range names {
		if _, ok := reg.Get(n); ok {
			t.Errorf("%s registered without a seam", n)
		}
	}
	reg = tsRegistry(t, rcaDeps(rcaFixture()))
	for _, n := range names {
		tool, ok := reg.Get(n)
		if !ok || tool.Capability() != CapRead {
			t.Errorf("%s must register as CapRead with a wired seam", n)
		}
	}
}

func TestRCAToolsForeignIncidentIsNotFound(t *testing.T) {
	tool := bgpTool(t, rcaDeps(rcaFixture()), "get_causal_chain")
	other := Principal{Tenant: "t-b", Perms: map[string]bool{"correlations:read": true}}
	if _, err := tool.Run(context.Background(), other, ToolArgs{"correlation_id": rcaTestID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another tenant's incident must be ErrNotFound, got %v", err)
	}
	if _, err := tool.Run(context.Background(), tsPrincipal(), ToolArgs{"correlation_id": "x'; DROP"}); err == nil {
		t.Fatal("a malformed id must be refused before the seam")
	}
}

func TestRelationForNeverPromotesToObserved(t *testing.T) {
	cases := map[string]string{"observed": RelationObserved, "corroborated": RelationObserved, "inferred": RelationInferred,
		"contradicted": RelationInferred, "unknown": RelationInferred, "": RelationInferred, "reported": RelationUserDefined,
		"made-up": RelationInferred}
	for in, want := range cases {
		if got := RelationFor(in); got != want {
			t.Errorf("RelationFor(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestCausalChainLabelsRelationAndContradictions(t *testing.T) {
	out := joinTexts(runRCATool(t, rcaFixture(), "get_causal_chain"))
	for _, want := range []string{"step 1 [OBSERVED", "step 2 [INFERRED", "(followed by)", "CONTRADICTED BY: one Comcast site remains healthy", "never \"caused\""} {
		if !strings.Contains(out, want) {
			t.Errorf("causal chain output missing %q:\n%s", want, out)
		}
	}
	empty := rcaFixture()
	empty.CausalChain, empty.ChainNote = nil, "No causal sequence is proposed for this case"
	if out := joinTexts(runRCATool(t, empty, "get_causal_chain")); !strings.Contains(out, "do not invent one") {
		t.Fatalf("an absent chain must be disclosed: %s", out)
	}
}

func TestConfidenceBreakdownAlwaysShowsEvidenceAgainst(t *testing.T) {
	out := joinTexts(runRCATool(t, rcaFixture(), "get_confidence_breakdown"))
	for _, want := range []string{"91% engine confidence", "FOR: loss starts after provider handoff", "AGAINST: one Comcast site remains healthy", "MISSING: remote probe data", "never raise it"} {
		if !strings.Contains(out, want) {
			t.Errorf("confidence output missing %q:\n%s", want, out)
		}
	}
}

func TestBlastRadiusNeverTurnsUnmeasuredIntoZero(t *testing.T) {
	out := joinTexts(runRCATool(t, rcaFixture(), "get_blast_radius"))
	for _, want := range []string{"affected sites: Dallas HQ", "affected services: Salesforce", "affected paths: 3",
		"Active users affected: 214 users", "Transactions affected: not measured — no transaction mapping"} {
		if !strings.Contains(out, want) {
			t.Errorf("blast radius output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Transactions affected: 0") {
		t.Fatal("an unmeasured impact must never render as zero")
	}
	none := RCAResult{IncidentID: rcaTestID}
	if out := joinTexts(runRCATool(t, none, "get_blast_radius")); !strings.Contains(out, "unknown, not empty") {
		t.Fatalf("an empty scope must be disclosed as unknown: %s", out)
	}
}

func TestOwnerIsNeverGuessed(t *testing.T) {
	out := joinTexts(runRCATool(t, rcaFixture(), "get_owner"))
	if !strings.Contains(out, "external candidate: Comcast (demarcation: local_checks_pending)") {
		t.Fatalf("owner output: %s", out)
	}
	if out := joinTexts(runRCATool(t, RCAResult{IncidentID: rcaTestID}, "get_owner")); !strings.Contains(out, "never guess an owner") {
		t.Fatalf("an absent owner must be disclosed: %s", out)
	}
}
