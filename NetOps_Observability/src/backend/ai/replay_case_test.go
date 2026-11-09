// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"context"
	"sort"
	"strings"
	"testing"

	"netops/backend/internal/evalsplit"
)

type wrongRiskTool struct{ AITool }

func (wrongRiskTool) Capability() Capability { return CapWrite }

// Restricted closes a tool set, and a wrapper cannot launder a tool's risk past
// its contract.
func TestRestrictedRegistry(t *testing.T) {
	ds := newMockDS()
	reg := Tools(ds)
	only := reg.Restricted(func(n string) bool { return n == "get_problem" || n == "get_problem_evidence" }, nil)
	names := only.Names()
	sort.Strings(names)
	if strings.Join(names, ",") != "get_problem,get_problem_evidence" {
		t.Fatalf("kept %v", names)
	}
	if _, ok := reg.Get("get_active_major_incidents"); !ok {
		t.Fatal("the source registry must be untouched")
	}
	tb := Toolbox{Registry: only, Policy: NewPolicyEngine(PolicyConfig{}, func(string) bool { return true })}
	iv := tb.Invoke(context.Background(), Principal{Tenant: "t-a"}, "get_active_major_incidents", nil)
	if iv.Outcome != OutcomeNotRegistered {
		t.Fatalf("a dropped tool: %s", iv.Outcome)
	}
	bad := reg.Restricted(func(n string) bool { return n == "get_problem" }, func(a AITool) AITool { return wrongRiskTool{a} })
	if _, ok := bad.Get("get_problem"); ok || len(bad.Rejected()) != 1 {
		t.Fatalf("a wrapper that changes the risk must be refused: %v", bad.Rejected())
	}
	var nilReg *ToolRegistry
	if got := nilReg.Restricted(nil, nil); len(got.Names()) != 0 {
		t.Fatal("a nil registry restricts to nothing")
	}
}

func TestAnswerNamedSkillRefusesWhatItCannotRun(t *testing.T) {
	o := &Orchestrator{}
	if _, _, err := o.AnswerNamedSkill(context.Background(), Principal{}, "q", "log-confirmation", nil); err == nil {
		t.Fatal("no skill set is an error, not an empty answer")
	}
	o.Skills = loadTestSkills(t)
	if _, _, err := o.AnswerNamedSkill(context.Background(), Principal{}, "q", "no-such-skill", nil); err == nil {
		t.Fatal("an unknown skill is an error")
	}
}

func TestOverclaimingSentences(t *testing.T) {
	got := OverclaimingSentences("The root cause is the optic. It might be the optic [hypothesis:x:0]. Nothing else.")
	if len(got) != 1 || !strings.Contains(got[0], "root cause is") {
		t.Fatalf("%v", got)
	}
}

func TestReplayFingerprintSources(t *testing.T) {
	files, err := ReplaySkillFiles()
	if err != nil || len(files) != loadTestSkills(t).Len() {
		t.Fatalf("%d files, %d skills, %v", len(files), loadTestSkills(t).Len(), err)
	}
	for name, b := range files {
		if !strings.HasSuffix(name, "/SKILL.md") || len(b) == 0 {
			t.Errorf("%s: %d bytes", name, len(b))
		}
	}
	a, err := ReplayPromptProbes()
	if err != nil {
		t.Fatal(err)
	}
	b, err := ReplayPromptProbes()
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range a {
		if strings.TrimSpace(s) == "" || b[name] != s {
			t.Errorf("probe %s is empty or not stable", name)
		}
	}
	if !strings.Contains(a["problem"], "probe evidence line") {
		t.Errorf("the problem probe must render its evidence: %s", a["problem"])
	}
}

// The corpus loader refuses a field capture: it is customer data.
func TestCommittedCorpusHasNoFieldCapture(t *testing.T) {
	for _, c := range loadGoldenIncidents(t) {
		if c.Source == string(evalsplit.SourceField) || c.Category == ReplayCategoryField {
			t.Errorf("%s: a committed case must be synthetic", c.ID)
		}
	}
	raw := []byte(`[{"id":"a-capture","category":"field_capture","source":"field","description":"d","path":"ask","principal":{"tenant":"t"},"question":"q","provider_down":true,"expect":{"status":"x"}}]`)
	cases, err := ParseReplayCases("capture", raw)
	if err != nil || len(cases) != 1 {
		t.Fatalf("the shared loader reads a capture: %v", err)
	}
	if cases[0].Split() != evalsplit.HeldOut {
		t.Fatal("a capture is held out")
	}
}
