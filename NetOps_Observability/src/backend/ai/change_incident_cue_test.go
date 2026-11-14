// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import "testing"

// N-S3: a change LISTING asked in causal words reaches the data arm (which
// answers with the per-incident change list, correlated and causal kept
// apart); a real diagnosis question still does not.
func TestAsksDiagnosisLetsCausalChangeListingsThrough(t *testing.T) {
	listing := []string{
		"which changes caused incidents this week",
		"what changes caused sdwan incidents in the last 7 days",
		"show changes that led to outages yesterday",
		"any changes linked to sd-wan incidents this week",
		"list the changes behind every incident",
		"did any of those changes cause incidents?",
		"did they cause any incidents",
		"were those changes behind any outages",
		"show me what changed 30 minutes before every SD-WAN incident this week",
	}
	for _, q := range listing {
		if asksDiagnosis(q) {
			t.Errorf("%q is a change listing, not a diagnosis", q)
		}
	}
	diagnosis := []string{
		"what caused the outage at dallas",
		"why did the change cause an outage",
		"did the bgp flap cause an outage",
		"explain which change caused the incident",
		"what caused this incident",
		"root cause of the sdwan incidents",
		"how do i fix the incidents caused by changes",
		"troubleshoot the changes that caused incidents",
	}
	for _, q := range diagnosis {
		if !asksDiagnosis(q) {
			t.Errorf("%q must stay a diagnosis", q)
		}
	}
}

// The planner's ledger-type → engine-kind map and the engine's own change
// kinds are one list (plan/chain.go keeps a copy; this pins it).
func TestChangeChainPlacementCollectsEveryChangeKind(t *testing.T) {
	res := RCAResult{Verdict: "confirmed", RootCause: RCARootCause{Identified: true},
		CausalChain: []RCACausalLink{
			{Number: 1, Kinds: []string{"bfd_session_down"}, Relation: RelationObserved},
			{Number: 2, Kinds: []string{"Device_Config_Change", "config_change"}, Relation: RelationObserved},
			{Number: 3, Kinds: []string{"deploy_event", "config_change"}, Relation: RelationInferred},
		}}
	kinds, step, established, contradicted := ChangeChainPlacement(res)
	if len(kinds) != 3 || kinds[0] != "device_config_change" || kinds[1] != "config_change" || kinds[2] != "deploy_event" {
		t.Fatalf("kinds = %v", kinds)
	}
	if step != 2 || !established || contradicted {
		t.Fatalf("step=%d established=%v contradicted=%v", step, established, contradicted)
	}
	res.PrimaryContradicted = true
	if _, _, est, con := ChangeChainPlacement(res); est || !con {
		t.Fatalf("a contradicted sequence establishes nothing: est=%v con=%v", est, con)
	}
	if k, s, _, _ := ChangeChainPlacement(RCAResult{}); len(k) != 0 || s != 0 {
		t.Fatalf("no chain → no kinds: %v %d", k, s)
	}
	if !IsEngineChangeKind(" CLOUD_AUDIT ") || IsEngineChangeKind("bgp_flap") {
		t.Fatal("IsEngineChangeKind")
	}
}
