// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_step_kinds_test.go — the RCA page's JSON contract for the causal-chain
// step's `kinds` field (tracker 337 N-B4). The field is ADDITIVE: every key the
// page already reads is still there with the same value, and `kinds` lists only
// the observation kinds that actually carried evidence for the step.

import (
	"encoding/json"
	"testing"
)

func TestCausalStepJSONCarriesObservedKindsOnly(t *testing.T) {
	rep := buildRichFixtureReport(t)
	raw, err := json.Marshal(rep.CausalChain)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Steps []map[string]json.RawMessage `json:"steps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Steps) != 4 {
		t.Fatalf("steps = %d, want the fixture's 4", len(doc.Steps))
	}
	// The contract the RCA page already reads is unchanged.
	for i, st := range doc.Steps {
		for _, key := range []string{"number", "claim", "causal_role", "epistemic_state", "epistemic_basis", "interval"} {
			if _, ok := st[key]; !ok {
				t.Errorf("step %d lost the %q key the RCA page reads", i+1, key)
			}
		}
	}
	kinds := func(i int) []string {
		var out []string
		if raw, ok := doc.Steps[i]["kinds"]; ok {
			if err := json.Unmarshal(raw, &out); err != nil {
				t.Fatalf("step %d kinds: %v", i+1, err)
			}
		}
		return out
	}
	// Step 1 (IPsec tunnel down) was witnessed with ipsec_tunnel_status rows.
	if k := kinds(0); len(k) != 1 || k[0] != "ipsec_tunnel_status" {
		t.Errorf("step 1 kinds = %v, want [ipsec_tunnel_status]", k)
	}
	// Step 2 declares bgp_adjacency_change but saw none in the window: a
	// declared kind with no observation is NOT listed, and the key is omitted.
	if _, present := doc.Steps[1]["kinds"]; present {
		t.Errorf("an unwitnessed step must omit kinds, got %s", doc.Steps[1]["kinds"])
	}
	if k := kinds(2); len(k) != 1 || k[0] != "probe_loss" {
		t.Errorf("step 3 kinds = %v, want [probe_loss]", k)
	}
	// Step 4 declares no kinds at all.
	if _, present := doc.Steps[3]["kinds"]; present {
		t.Errorf("a step with no declared kinds must omit kinds")
	}
	// The in-memory form agrees with the wire form.
	if len(rep.CausalChain.Steps[0].Kinds) != 1 || len(rep.CausalChain.Steps[1].Kinds) != 0 {
		t.Errorf("struct kinds = %v / %v", rep.CausalChain.Steps[0].Kinds, rep.CausalChain.Steps[1].Kinds)
	}
}
