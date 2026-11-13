// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_batch1_test.go — NetClaw ingestion Batch 1 (platform-health, ntp-clock,
// qos-congestion): the `source:` attribution line, the `interface` entity, and
// the new `state:` facets at the loader boundary.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const netclawBatch1Pin = "cfafa46c3227356ca6ef38261fa9c1f4ba4711cb"

// TestNetClawSourcedSkillsCiteThePinInNOTICE: every embedded skill that names a
// NetClaw source pins it to the commit the NOTICE records, so attribution can
// never point at a moving branch or at a commit nobody reviewed.
func TestNetClawSourcedSkillsCiteThePinInNOTICE(t *testing.T) {
	set := loadTestSkills(t)
	notice, err := os.ReadFile(filepath.Join("..", "..", "..", "NOTICE"))
	if err != nil {
		t.Fatalf("NOTICE is unreadable: %v", err)
	}
	cited := 0
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		if !strings.Contains(sk.Source, "automateyournetwork/netclaw") {
			continue
		}
		cited++
		if !strings.Contains(sk.Source, "/blob/"+netclawBatch1Pin+"/") {
			t.Errorf("%s cites NetClaw at %q, not at the pinned commit %s", name, sk.Source, netclawBatch1Pin)
		}
		if !strings.Contains(string(notice), "-> "+name) && !strings.Contains(string(notice), ", "+name) {
			t.Errorf("%s is NetClaw-derived but NOTICE does not list it", name)
		}
	}
	if !strings.Contains(string(notice), netclawBatch1Pin) {
		t.Errorf("NOTICE does not record the NetClaw pin %s", netclawBatch1Pin)
	}
	if cited < 3 {
		t.Errorf("only %d skills cite NetClaw; Batch 1 ships platform-health, ntp-clock and qos-congestion", cited)
	}
}

// TestSkillSourceIsValidated: `source:` is attribution, so a malformed one fails
// the build instead of being silently dropped.
func TestSkillSourceIsValidated(t *testing.T) {
	ok := strings.Replace(goodSkill, "version: 1\n", "version: 1\nsource: https://example.org/method.md\n", 1)
	sk, err := parseSkill("unit-probe", ok)
	if err != nil {
		t.Fatalf("a well-formed source was refused: %v", err)
	}
	if sk.Source != "https://example.org/method.md" {
		t.Errorf("Source = %q", sk.Source)
	}
	for _, bad := range []string{
		"http://example.org/plain-http.md",
		"javascript:alert(1)",
		"https://example.org/" + strings.Repeat("a", maxSkillSourceLen),
	} {
		raw := strings.Replace(goodSkill, "version: 1\n", "version: 1\nsource: "+bad+"\n", 1)
		if _, err := parseSkill("unit-probe", raw); err == nil || !strings.Contains(err.Error(), "source") {
			t.Errorf("source %q was accepted (err=%v)", bad, err)
		}
	}
}

// TestIfaceEntityResolution: the `interface` entity binds only a strict
// interface-name shape, from the UI or the question, and never steals a
// hostname that merely starts like one.
func TestIfaceEntityResolution(t *testing.T) {
	cases := []struct {
		ui, question, want string
	}{
		{"", "output drops on GigabitEthernet1 at edge-1", "GigabitEthernet1"},
		{"", "drops on Gi0/0/1 at core-2", "Gi0/0/1"},
		{"", "queue drops on xe-0/0/2.0 at mx-1", "xe-0/0/2.0"},
		{"", "is Ethernet1/12 congested on leaf-3", "Ethernet1/12"},
		{"", "check Port-channel10 on dist-1", "Port-channel10"},
		{"", "errors on HundredGigE0/0/0/3", "HundredGigE0/0/0/3"},
		{"", "drops on ae0 at mx-1", "ae0"},
		{"TenGigabitEthernet1/0/1", "is it congested", "TenGigabitEthernet1/0/1"},
		// A hostname that starts like an interface is not one.
		{"", "is Eth1-core congested", ""},
		{"", "slow at Lo1_dc today", ""},
		// Free text and injection-shaped UI values are dropped.
		{"Gi1; show running-config", "the wan is slow", ""},
		{"interface please", "the wan is slow", ""},
		{"", "the wan is slow at the branch", ""},
	}
	for _, tc := range cases {
		out := skillEntitySet{values: map[string]string{}}
		resolveIfaceEntity(&out, tc.ui, tc.question)
		if got := out.values["interface"]; got != tc.want {
			t.Errorf("ui=%q q=%q: interface=%q, want %q", tc.ui, tc.question, got, tc.want)
		}
	}
}

// TestIfaceTokensAreNotOfferedAsHostnames: an interface name is bound as the
// interface, so it is blanked before the question is scanned for device names.
func TestIfaceTokensAreNotOfferedAsHostnames(t *testing.T) {
	got := blankIfaceTokens("drops on GigabitEthernet1 at edge-1 and Eth1-core")
	if strings.Contains(got, "GigabitEthernet1") {
		t.Errorf("interface token survived: %q", got)
	}
	for _, keep := range []string{"edge-1", "Eth1-core"} {
		if !strings.Contains(got, keep) {
			t.Errorf("hostname %q was blanked: %q", keep, got)
		}
	}
}

// TestBatch1StateFactsAreClosed: the new facets parse, and values outside them
// are refused at the loader — a typo can never become a rule that never fires.
func TestBatch1StateFactsAreClosed(t *testing.T) {
	declared := map[string]bool{"get_device_state": true}
	for _, good := range []string{
		"state:if_faults=present", "state:if_drops=none", "state:reload=recent",
		"state:reload=earlier", "state:clock=unsynced", "state:clock=offset_high",
	} {
		if _, err := parseSkillCondition(good, declared); err != nil {
			t.Errorf("%s refused: %v", good, err)
		}
	}
	for _, bad := range []string{
		"state:clock=drifting", "state:reload=yesterday", "state:if_drops=some", "state:ntp=synced",
	} {
		if _, err := parseSkillCondition(bad, declared); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	// And every new facet value has a human reason that is not the raw key.
	for facet, vals := range map[string][]string{
		"if_faults": {"none", "present"}, "if_drops": {"none", "present"},
		"reload": {"recent", "earlier"}, "clock": {"synced", "unsynced", "offset_high"},
	} {
		for _, v := range vals {
			if h := stateConditionHuman(facet, v); strings.HasPrefix(h, CondStatePrefix) {
				t.Errorf("state:%s=%s has no human reason (%q)", facet, v, h)
			}
		}
	}
}
