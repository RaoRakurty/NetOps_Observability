// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_memory_test.go — how INVESTIGATION MEMORY plugs into the skill layer
// (IRIS Phase B). Three structural rules are pinned here, because each one is a
// design invariant the prose of a SKILL.md cannot be trusted to keep:
//
//  1. a skill may gather memory only AFTER live state, and never first — the
//     loader refuses anything else (NetClaw: never guess device state, and never
//     carry an assumption between sessions);
//  2. the SHIPPED skills that gather memory actually obey that ordering;
//  3. a concluded chain is handed to the memory seam with the entity keys, the
//     chain and the citations the operator was shown — and nothing is recorded
//     when there is no entity to key it on.

import (
	"context"
	"os"
	"strings"
	"testing"
)

func memGather(tools ...string) []GatherStep {
	out := make([]GatherStep, 0, len(tools))
	for _, tool := range tools {
		out = append(out, GatherStep{Tool: tool, Bind: map[string]string{}, Args: map[string]string{}})
	}
	return out
}

func TestValidateMemoryOrderRefusesMemoryBeforeLiveState(t *testing.T) {
	cases := []struct {
		name    string
		gather  []GatherStep
		wantErr string
	}{
		{"memory first", memGather("recall_investigations", "get_device_state"),
			"may never be the first evidence gathered"},
		{"memory before a device-state read", memGather("get_rca_verdict", "recall_investigations", "get_device_state"),
			"never before"},
		{"memory before a protocol diagnostic", memGather("get_rca_verdict", "recall_investigations", "run_protocol_diagnostic"),
			"never before"},
		{"memory after live state", memGather("get_device_state", "recall_investigations"), ""},
		{"memory last, several live reads", memGather("get_device_state", "run_protocol_diagnostic", "search_logs", "recall_investigations"), ""},
		{"no memory at all", memGather("get_device_state", "search_logs"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateMemoryOrder(tc.gather)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("expected a loader error containing %q", tc.wantErr)
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestShippedSkillsGatherMemoryAfterLiveState(t *testing.T) {
	set, err := LoadSkills()
	if err != nil {
		t.Fatalf("skills failed to load: %v", err)
	}
	gathering := 0
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		if err := validateMemoryOrder(sk.Gather); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		for _, g := range sk.Gather {
			if g.Tool == memoryToolName {
				gathering++
				break
			}
		}
	}
	if gathering == 0 {
		t.Fatal("no shipped skill gathers investigation memory — Phase B would be dead code")
	}
	// The entry method must be one of them: it is the skill that runs when the
	// operator has not named a fault, and prior context is most valuable there.
	entry, ok := set.Get("osi-bisection")
	if !ok {
		t.Fatal("the entry method is missing")
	}
	found := false
	for _, g := range entry.Gather {
		if g.Tool == memoryToolName {
			found = true
		}
	}
	if !found {
		t.Error("osi-bisection should gather investigation memory")
	}
}

func TestSkillEntitiesIncludeMemoryKeys(t *testing.T) {
	for _, name := range []string{"peer", "prefix"} {
		if !skillEntities[name] {
			t.Errorf("%q must be a bindable entity — memory is keyed by it", name)
		}
	}
}

func TestResolveSkillEntitiesBindsPeerAndPrefix(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{})
	ctx := context.Background()
	cases := []struct {
		name           string
		question       string
		ui             map[string]string
		wantPeer       string
		wantPrefix     string
		wantNoPeer     bool
		wantNoPrefixOK bool
	}{
		{name: "prefix in the question", question: "why is 203.0.113.0/24 not advertised?", wantPrefix: "203.0.113.0/24", wantNoPeer: true},
		{name: "peer in the question", question: "bgp peer 10.0.0.1 is idle", wantPeer: "10.0.0.1"},
		{name: "both, prefix wins its own slot", question: "10.0.0.1 stopped announcing 203.0.113.0/24", wantPeer: "10.0.0.1", wantPrefix: "203.0.113.0/24"},
		{name: "from ui context", question: "what happened?", ui: map[string]string{"peer": "192.0.2.9"}, wantPeer: "192.0.2.9", wantNoPrefixOK: true},
		{name: "garbage is not an entity", question: "the peer is flapping badly", wantNoPeer: true, wantNoPrefixOK: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ent := o.resolveSkillEntities(ctx, runPrincipal(), tc.question, tc.ui)
			peer, hasPeer := ent.get("peer")
			prefix, hasPrefix := ent.get("prefix")
			if tc.wantPeer != "" && peer != tc.wantPeer {
				t.Errorf("peer = %q (bound=%v), want %q", peer, hasPeer, tc.wantPeer)
			}
			if tc.wantNoPeer && hasPeer {
				t.Errorf("peer should not have bound, got %q", peer)
			}
			if tc.wantPrefix != "" && prefix != tc.wantPrefix {
				t.Errorf("prefix = %q (bound=%v), want %q", prefix, hasPrefix, tc.wantPrefix)
			}
			if tc.wantNoPrefixOK && hasPrefix {
				t.Errorf("prefix should not have bound, got %q", prefix)
			}
		})
	}
}

func TestAnswerSkillRecordsTheConcludedInvestigation(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{})
	var got []ConcludedInvestigation
	o.RecordInvestigation = func(_ context.Context, _ Principal, inv ConcludedInvestigation) {
		got = append(got, inv)
	}
	sk := runSkill()
	ans, ok := o.answerSkill(context.Background(), runPrincipal(),
		"why is bgp down on edge-1 for peer 10.0.0.1?",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk, Reason: "bgp"},
		map[string]string{"correlation_id": "pa"}, nil)
	if !ok {
		t.Fatal("the skill turn did not produce an answer")
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one concluded investigation, got %d", len(got))
	}
	inv := got[0]
	if inv.AnswerID == "" || inv.AnswerID != ans.AnswerID {
		t.Fatalf("the answer and the memory must share an id: answer %q, memory %q", ans.AnswerID, inv.AnswerID)
	}
	if inv.DeviceID != "dev-a" || inv.DeviceName != "edge-1" {
		t.Errorf("device keys were not carried: %+v", inv)
	}
	if inv.Peer != "10.0.0.1" {
		t.Errorf("peer key was not carried: %q", inv.Peer)
	}
	if inv.CorrelationID != "pa" {
		t.Errorf("case key was not carried: %q", inv.CorrelationID)
	}
	if len(inv.Skills) == 0 || inv.Skills[0] != sk.Name {
		t.Errorf("the chain was not recorded: %v", inv.Skills)
	}
	if strings.TrimSpace(inv.Verdict) == "" {
		t.Error("a conclusion with no verdict is not worth remembering")
	}
	if len(inv.Citations) == 0 {
		t.Error("the citations the conclusion rested on were not recorded")
	}
}

func TestAnswerSkillRecordsNothingWithoutAnEntity(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{})
	recorded := 0
	o.RecordInvestigation = func(context.Context, Principal, ConcludedInvestigation) { recorded++ }
	// No device, no case, no address anywhere: nothing a future recall could
	// key on, so nothing is remembered (and the answer is unaffected).
	ans, ok := o.answerSkill(context.Background(), runPrincipal(),
		"is anything wrong", Plan{Intent: "troubleshoot"},
		SkillMatch{Skill: runSkill(), Reason: "bgp"}, nil, nil)
	if ok && ans.AnswerID != "" {
		t.Errorf("an unkeyed answer must not be stamped for memory: %q", ans.AnswerID)
	}
	if recorded != 0 {
		t.Fatalf("recorded %d unkeyed conclusions", recorded)
	}
}

// TestInvestigationMemoryMigrationShape pins the Postgres store against its
// migration: a column the store reads but the table does not have (or a missing
// FORCE-RLS policy) is a runtime failure in an environment tests rarely cover,
// so the drift is caught here at build time.
func TestInvestigationMemoryMigrationShape(t *testing.T) {
	raw, err := os.ReadFile("../internal/platformdb/migrations/0040_iris_investigations.sql")
	if err != nil {
		t.Fatalf("the Phase-B migration is missing: %v", err)
	}
	sql := string(raw)
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS iris_investigations",
		"PRIMARY KEY (tenant_id, id)",
		"ALTER TABLE iris_investigations ENABLE ROW LEVEL SECURITY",
		"ALTER TABLE iris_investigations FORCE ROW LEVEL SECURITY",
		"CREATE POLICY tenant_iso ON iris_investigations",
		"current_setting('app.tenant_id', true)",
		"CHECK (outcome IN ('confirmed','wrong','unknown'))",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("migration 0040 is missing %q", want)
		}
	}
	// Every column the store selects and inserts must exist in the table.
	for _, col := range strings.Split(pgInvestigationCols, ",") {
		col = strings.TrimSpace(strings.ReplaceAll(col, "\n", ""))
		col = strings.TrimSpace(strings.ReplaceAll(col, "\t", ""))
		if col == "" {
			continue
		}
		if !strings.Contains(sql, "    "+col+" ") && !strings.Contains(sql, "    "+col+"\t") {
			t.Errorf("column %q is read by the pg store but not declared in migration 0040", col)
		}
	}
	// The closed outcome vocabulary must match on both sides.
	for _, o := range []InvestigationOutcome{OutcomeConfirmed, OutcomeWrong, OutcomeUnknown} {
		if !strings.Contains(sql, "'"+string(o)+"'") {
			t.Errorf("outcome %q is not accepted by the migration's CHECK", o)
		}
	}
}
