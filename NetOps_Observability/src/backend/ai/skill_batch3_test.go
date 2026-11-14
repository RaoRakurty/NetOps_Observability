// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_batch3_test.go — NetClaw ingestion Batch 3 (dns-resolution,
// scope-contrast, network-design-read, evpn-vxlan-overlay,
// fhrp-lag-redundancy): applicability on the lab's real shape, the analysis
// layer, and that the golden questions select their method.

import (
	"context"
	"strings"
	"testing"
)

// batch3Turn builds a turn for skill `name` on the device `device`, with the
// given discovered facts for that device.
func batch3Turn(t *testing.T, name, question, device string, facts DeviceFacts) (*Orchestrator, *harnessProvider, *[]ToolAuditEntry, *Skill, map[string]string) {
	t.Helper()
	set := loadTestSkills(t)
	sk, ok := set.Get(name)
	if !ok {
		t.Fatalf("%s must load", name)
	}
	ui := map[string]string{"device": device}
	c := SkillCase{Name: "batch3", Question: question, UI: ui, Evidence: []string{"device"}}
	o, llm, audit, err := newHarnessTurn(set, c, harnessEnv{})
	if err != nil {
		t.Fatal(err)
	}
	o.Troubleshoot.DeviceFacts = func(_ context.Context, _ Principal, id string) (DeviceFacts, error) {
		if id != device {
			return DeviceFacts{}, ErrNotFound
		}
		return facts, nil
	}
	return o, llm, audit, sk, ui
}

// The applicability case from the ingestion plan, on the lab's real shape: an
// SD-WAN edge with no OSPF adjacency discovered. The OSPF method is rerouted,
// says why, and NO OSPF read is ever issued.
func TestOSPFOnAnSDWANEdgeWithNoOSPFIsRerouted(t *testing.T) {
	var f DeviceFacts
	f.SetValue(FactRole, "wan_edge")
	f.SetValue(FactWANFlavor, "sdwan")
	f.Observe(FactAdjacency, "ospf", false)
	f.Observe(FactAdjacency, "overlay", true)
	q := "why is ospf down on vedge-51"
	o, llm, audit, sk, ui := batch3Turn(t, "ospf-adjacency", q, "vedge-51", f)
	ans, handled := o.answerSkill(context.Background(), harnessPrincipal(), q,
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk, Reason: "matched ospf"}, ui, nil)
	if !handled {
		t.Fatal("the rerouted turn must still be handled")
	}
	for _, e := range *audit {
		if e.Tool == "run_protocol_diagnostic" {
			t.Fatalf("an OSPF read was issued on a device with no OSPF: %+v", e)
		}
		if e.Skill == "ospf-adjacency" && e.Tool != "next_skill" {
			t.Fatalf("the ruled-out method gathered: %+v", e)
		}
	}
	if len(ans.Chain) == 0 || ans.Chain[0].Name == "ospf-adjacency" {
		t.Fatalf("chain must not start at the ruled-out method: %+v", ans.Chain)
	}
	if p := lastPrompt(llm); !strings.Contains(p, "no OSPF adjacency is discovered on vedge-51") {
		t.Fatalf("the operator was never told why; prompt:\n%s", p)
	}
}

// EVPN applies only to a data-centre fabric switch: on the lab's SD-WAN edge
// the method does not run and says so.
func TestEVPNIsRuledOutOnAWANEdge(t *testing.T) {
	var f DeviceFacts
	f.SetValue(FactRole, "wan_edge")
	q := "vtep down on cedge-80"
	o, llm, audit, sk, ui := batch3Turn(t, "evpn-vxlan-overlay", q, "cedge-80", f)
	ans, handled := o.answerSkill(context.Background(), harnessPrincipal(), q,
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk, Reason: "matched vtep"}, ui, nil)
	if !handled {
		t.Fatal("the rerouted turn must still be handled")
	}
	for _, e := range *audit {
		if e.Skill == "evpn-vxlan-overlay" && e.Tool != "next_skill" {
			t.Fatalf("the ruled-out EVPN method gathered: %+v", e)
		}
	}
	if len(ans.Chain) == 0 || ans.Chain[0].Name == "evpn-vxlan-overlay" {
		t.Fatalf("chain must not start at the ruled-out method: %+v", ans.Chain)
	}
	if p := lastPrompt(llm); !strings.Contains(p, "does not apply") {
		t.Fatalf("the reroute must be said; prompt:\n%s", p)
	}
}

// On a leaf the EVPN method runs, and its first read is the fabric state.
func TestEVPNRunsOnALeafAndReadsTheFabricFirst(t *testing.T) {
	var f DeviceFacts
	f.SetValue(FactRole, "dc_leaf")
	q := "vtep down on leaf-3"
	o, _, audit, sk, ui := batch3Turn(t, "evpn-vxlan-overlay", q, "leaf-3", f)
	ans, handled := o.answerSkill(context.Background(), harnessPrincipal(), q,
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk, Reason: "matched vtep"}, ui, nil)
	if !handled || len(ans.Chain) == 0 || ans.Chain[0].Name != "evpn-vxlan-overlay" {
		t.Fatalf("the method must run on a leaf: %+v", ans.Chain)
	}
	first := ""
	for _, e := range *audit {
		if e.Skill == "evpn-vxlan-overlay" && e.Allowed && e.Tool != "next_skill" {
			first = e.Tool
			break
		}
	}
	if first != "get_device_state" {
		t.Fatalf("the first read must be the live fabric state, got %q", first)
	}
}

// The two reasoning methods sit in the analysis layer; there is still exactly
// one entry method, and the analysis layer ranks below every fault layer.
func TestAnalysisLayerKeepsOneEntryMethod(t *testing.T) {
	set := loadTestSkills(t)
	for _, n := range []string{"scope-contrast", "network-design-read"} {
		sk, ok := set.Get(n)
		if !ok || sk.Layer != LayerAnalysis {
			t.Fatalf("%s must load in the analysis layer: %+v", n, sk)
		}
		if !plannerOffers(sk) {
			t.Fatalf("%s must be offered to the model planner like any non-entry method", n)
		}
	}
	methods := 0
	for _, n := range set.Names() {
		if sk, _ := set.Get(n); sk.Layer == LayerMethod {
			methods++
		}
	}
	if methods != 1 {
		t.Fatalf("exactly one entry method, found %d", methods)
	}
	for _, l := range []SkillLayer{LayerPhysical, LayerServices, LayerLogs} {
		if LayerRank(LayerAnalysis) <= LayerRank(l) {
			t.Fatalf("analysis must rank below %s", l)
		}
	}
}

// The golden selection questions of the ingestion plan pick their method.
func TestBatch3GoldenQuestionsSelectTheirMethod(t *testing.T) {
	set := loadTestSkills(t)
	cases := map[string]string{
		"the site is down but ping by ip works":              "dns-resolution",
		"some users at HQ cannot reach ERP, others can":      "scope-contrast",
		"explain our network design":                         "network-design-read",
		"where are the single points of failure":             "network-design-read",
		"vtep down on leaf-3":                                "evpn-vxlan-overlay",
		"hsrp flapping on core-1":                            "fhrp-lag-redundancy",
		"lacp bundle member down on core-1":                  "fhrp-lag-redundancy",
		"nxdomain for the payroll site":                      "dns-resolution",
		"only one building has the problem, others are fine": "scope-contrast",
	}
	for q, want := range cases {
		m, ok := SelectSkill(set, q, Plan{Intent: "troubleshoot"})
		if !ok || m.Skill.Name != want {
			got := "<none>"
			if ok {
				got = m.Skill.Name
			}
			t.Errorf("%q selected %s, want %s", q, got, want)
		}
	}
}

// The five Batch 3 methods cite NetClaw at the pin, and none of them names a
// third-party method in its text (attribution lives in source: and NOTICE).
func TestBatch3MethodsAreOurOwnWords(t *testing.T) {
	set := loadTestSkills(t)
	for _, n := range []string{"dns-resolution", "scope-contrast", "network-design-read", "evpn-vxlan-overlay", "fhrp-lag-redundancy"} {
		sk, ok := set.Get(n)
		if !ok {
			t.Fatalf("%s must load", n)
		}
		if !strings.Contains(sk.Source, "/blob/"+netclawBatch1Pin+"/") {
			t.Errorf("%s source %q is not at the pin", n, sk.Source)
		}
		body := strings.ToLower(strings.Join(sk.LookFor, " ") + " " + sk.Body)
		for _, banned := range []string{"kepner", "tregoe", "k-t "} {
			if strings.Contains(body, banned) {
				t.Errorf("%s names a third-party method (%q) in its text", n, banned)
			}
		}
	}
}
