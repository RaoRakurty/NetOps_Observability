package ai

// skill_select_health_test.go — D-3 regression suite (QA run 2026-09-03,
// docs/qa/scenarios/troubleshooting-2026-09-03.md).
//
// The defect: the neutral NOC enquiry — "is spine1 healthy right now", "check
// spine1 status", "what's the status of leaf-3", "how is BGP on spine1" —
// reached NO skill, no tool and no citation, and was answered with the
// capability clarification ("I didn't quite catch that"), because
// reTroubleshootCue only recognised COMPLAINT words. Worse, "what is the health
// of spine1" classified as product_question and was answered out of the product
// knowledge base: the operator was told what "health" means in Correlix instead
// of being told about spine1.
//
// These tests pin the routing for the phrasings an operator actually types, in
// BOTH directions: the device-scoped enquiry must reach a skill, and the
// generic/fleet/product question must still reach its own better answer.

import (
	"strings"
	"testing"
)

// TestHealthStatusPhrasingsRouteToASkill is the ≥15-phrasing table: every one of
// these was typed at, or is the direct neighbour of, a question the live run
// showed dead-ending. `want` is the skill the phrasing must resolve to.
func TestHealthStatusPhrasingsRouteToASkill(t *testing.T) {
	set := loadTestSkills(t)
	cases := []struct {
		question string
		want     string
	}{
		// The two phrasings that FAILED live.
		{"is spine1 healthy right now", "osi-bisection"},
		{"check spine1 status", "osi-bisection"},
		// The one that was answered from the product KB instead of the device.
		{"what is the health of spine1", "osi-bisection"},
		{"what is the state of spine1", "osi-bisection"},
		// "what's the status of …" — classified as the FLEET briefing until a
		// hostname makes it device-scoped.
		{"what's the status of spine1", "osi-bisection"},
		{"what is the status of leaf-3", "osi-bisection"},
		{"status of leaf-3", "osi-bisection"},
		{"spine1 status", "osi-bisection"},
		{"health check on core2", "osi-bisection"},
		{"how is spine1 doing", "osi-bisection"},
		{"how is rtr01 looking", "osi-bisection"},
		{"is spine1 ok", "osi-bisection"},
		{"is spine1 up", "osi-bisection"},
		{"are the uplinks on dist-3 healthy", "osi-bisection"},
		// A protocol named in a health question must still win over the entry
		// method — the specific skill is the better investigation.
		{"how is bgp on spine1", "bgp-session-down"},
		{"is bgp healthy on spine1", "bgp-session-down"},
		{"what is the status of bgp on spine1", "bgp-session-down"},
		{"how is isis on spine1", "isis-adjacency"},
		{"isis status on spine1", "isis-adjacency"},
		{"ospf status on core-2", "ospf-adjacency"},
		// "interface" on its own is not a fault signature (the interface-down
		// skill claims "interface down" / "no link"), so the neutral enquiry
		// correctly starts at the entry method, which bisects from there.
		{"how is the interface on leaf2 doing", "osi-bisection"},
	}
	if len(cases) < 15 {
		t.Fatalf("this table is the D-3 guard; it must carry at least 15 phrasings, has %d", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.question, func(t *testing.T) {
			plan := Classify(tc.question, nil)
			m, ok := SelectSkill(set, tc.question, plan)
			if !ok {
				t.Fatalf("no skill selected for %q (intent %q) — this is the D-3 dead end", tc.question, plan.Intent)
			}
			if m.Skill.Name != tc.want {
				t.Fatalf("%q (intent %q) selected %q, want %q", tc.question, plan.Intent, m.Skill.Name, tc.want)
			}
			if strings.TrimSpace(m.Reason) == "" {
				t.Error("selection must always state a reason (it is shown and audited)")
			}
			// Determinism: an operator must be able to reproduce the routing.
			for i := 0; i < 5; i++ {
				again, ok2 := SelectSkill(set, tc.question, Classify(tc.question, nil))
				if !ok2 || again.Skill.Name != m.Skill.Name {
					t.Fatalf("selection is not deterministic for %q", tc.question)
				}
			}
		})
	}
}

// TestHealthStatusWithUIDeviceContext — the Troubleshooting page passes the open
// device, so a pronoun question ("is it healthy") is still device-scoped even
// though the text names no host.
func TestHealthStatusWithUIDeviceContext(t *testing.T) {
	set := loadTestSkills(t)
	ui := map[string]string{"device": "spine1"}
	for _, q := range []string{"is it healthy", "what is the health of this device", "how is it doing", "what's the status"} {
		t.Run(q, func(t *testing.T) {
			plan := Classify(q, ui)
			if plan.Entities["device"] != "spine1" {
				t.Fatalf("the UI device must reach the plan as a routing hint, got %q", plan.Entities["device"])
			}
			m, ok := SelectSkill(set, q, plan)
			if !ok {
				t.Fatalf("no skill selected for %q with an open device", q)
			}
			if m.Skill.Name != "osi-bisection" {
				t.Fatalf("%q selected %q, want the entry method", q, m.Skill.Name)
			}
		})
	}
	// Without the UI device and without a hostname, the SAME words keep their
	// existing answer: the bypass is device-scoped, not a blanket override.
	for _, q := range []string{"what is the health of this device", "what's the status"} {
		if m, ok := SelectSkill(set, q, Classify(q, nil)); ok {
			t.Errorf("%q with no device in scope took skill %q; it must keep its deterministic answer", q, m.Skill.Name)
		}
	}
}

// TestHealthCueDoesNotHijackGenericAnswers is the other half of the contract: a
// fleet, product or list question must NOT be pulled into an investigation just
// because it contains the word "health" or "status".
func TestHealthCueDoesNotHijackGenericAnswers(t *testing.T) {
	set := loadTestSkills(t)
	for _, q := range []string{
		"how is the network",
		"is everything ok",
		"network health",
		"what is the current status",
		"give me a status update",
		"what is a seam",
		"what does suspected mean",
		"how do i set up snmp discovery",
		"show me the critical incidents",
		"what happened last night",
		"who is on call next tuesday",
		"thanks, that was helpful",
		// hostname-SHAPED, but never a device: the enquiry stays a product one.
		"what is the health of ipv4 routing",
		"what is the status of ospfv2 support",
	} {
		t.Run(q, func(t *testing.T) {
			if m, ok := SelectSkill(set, q, Classify(q, nil)); ok {
				t.Fatalf("%q was hijacked into skill %q", q, m.Skill.Name)
			}
		})
	}
}

// TestDeviceHealthBypassIsNarrow pins WHICH excluded intents a device-scoped
// health question may take a skill from. Widening this set is a product
// decision, not an accident of a regex edit.
func TestDeviceHealthBypassIsNarrow(t *testing.T) {
	set := loadTestSkills(t)
	const q = "what is the health of spine1"
	if !deviceScopedHealthQuestion(q, Plan{}) {
		t.Fatal("precondition: this must read as a device-scoped health question")
	}
	for intent := range skillExcludedIntents {
		_, ok := SelectSkill(set, q, planWithIntent(intent))
		if ok != skillDeviceHealthBypass[intent] {
			t.Errorf("intent %q: selected=%v, bypass-allowed=%v", intent, ok, skillDeviceHealthBypass[intent])
		}
	}
	for intent := range skillDeviceHealthBypass {
		if !skillExcludedIntents[intent] {
			t.Errorf("bypass intent %q is not an excluded intent — the entry is dead code", intent)
		}
	}
	// A question with no health cue never bypasses, whatever else it carries.
	const complaint = "bgp neighbor down on edge-1, packet loss on the isp handoff"
	for intent := range skillDeviceHealthBypass {
		if m, ok := SelectSkill(set, complaint, planWithIntent(intent)); ok {
			t.Errorf("intent %q was pre-empted by %q without a health cue", intent, m.Skill.Name)
		}
	}
}

// TestNonDeviceTokensAreNotHostnames guards the small stop-list that keeps
// "IPv4" from reading as a box called ipv4.
func TestNonDeviceTokensAreNotHostnames(t *testing.T) {
	for tok := range nonDeviceTokens {
		if !reHostnameToken.MatchString(tok) {
			t.Errorf("%q is in the stop-list but is not hostname-shaped — the entry is dead weight", tok)
		}
		if deviceScopedHealthQuestion("what is the health of "+tok, Plan{}) {
			t.Errorf("%q was treated as a device", tok)
		}
	}
	// Ordinary hyphenated English must never read as a hostname.
	for _, q := range []string{
		"what is the health of a read-only account",
		"what is the status of end-to-end encryption",
		"what is the status of the round-trip measurement",
	} {
		if deviceScopedHealthQuestion(q, Plan{}) {
			t.Errorf("%q was treated as device-scoped", q)
		}
	}
}
