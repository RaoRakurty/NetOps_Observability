package ai

// skill_test.go — the loader is the CI gate for the skills layer: a method that
// names a tool we do not have, hands off to a skill that does not exist, or
// declares an argument nothing can bind must FAIL THE BUILD, not degrade
// silently at runtime into a confidently-wrong answer.

import (
	"strings"
	"testing"
)

func TestLoadSkillsEmbeddedSet(t *testing.T) {
	set, err := LoadSkills()
	if err != nil {
		t.Fatalf("LoadSkills: %v", err)
	}
	if set.Len() < 10 {
		t.Fatalf("expected the full embedded method set, got %d skills", set.Len())
	}
	names := set.Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] >= names[i] {
			t.Fatalf("Names() must be sorted and unique: %v", names)
		}
	}
	if _, ok := set.Get("osi-bisection"); !ok {
		t.Fatal("the entry method osi-bisection must load")
	}
	if _, ok := set.Get("no-such-skill"); ok {
		t.Fatal("Get must report a miss for an unknown skill")
	}
}

// TestSkillInvariants is the whole-set contract every embedded skill must hold.
// It is deliberately table-free: the table IS the embedded corpus.
func TestSkillInvariants(t *testing.T) {
	set, err := LoadSkills()
	if err != nil {
		t.Fatalf("LoadSkills: %v", err)
	}
	methods := 0
	for _, name := range set.Names() {
		sk, ok := set.Get(name)
		if !ok {
			t.Fatalf("%s: Names() listed a skill Get cannot return", name)
		}
		if sk.Layer == LayerMethod {
			methods++
		}
		declared := map[string]bool{}
		for _, tool := range sk.Tools {
			if !skillToolAllowlist[tool] {
				t.Errorf("%s: tool %q is off the read-only allowlist", name, tool)
			}
			declared[tool] = true
		}
		// Every gather tool must be in the skill's own tools: list (the loader
		// enforces it; this proves the corpus actually satisfies it).
		for _, g := range sk.Gather {
			if !declared[g.Tool] {
				t.Errorf("%s: gather calls %q which is not in its tools list", name, g.Tool)
			}
			meta, ok := toolMetas[g.Tool]
			if !ok {
				t.Fatalf("%s: gather calls %q with no toolMetas entry", name, g.Tool)
			}
			argOK := map[string]bool{}
			for _, a := range meta.args {
				argOK[a.name] = true
			}
			for _, b := range g.BindOrder() {
				if !argOK[b] {
					t.Errorf("%s: gather %s binds unknown argument %q", name, g.Tool, b)
				}
				if !skillEntities[g.Bind[b]] {
					t.Errorf("%s: gather %s binds from non-entity %q", name, g.Tool, g.Bind[b])
				}
			}
			for k := range g.Args {
				if !argOK[k] {
					t.Errorf("%s: gather %s passes unknown literal %q", name, g.Tool, k)
				}
			}
		}
		if len(sk.Gather) > MaxSkillToolCalls {
			t.Errorf("%s: %d gather steps exceeds the %d-call budget", name, len(sk.Gather), MaxSkillToolCalls)
		}
		// Every handoff target must exist (no dead ends in the method graph).
		for _, next := range sk.NextSkills() {
			if _, ok := set.Get(next); !ok {
				t.Errorf("%s: next=%q names a skill that does not exist", name, next)
			}
			if next == name {
				t.Errorf("%s: hands off to itself", name)
			}
		}
		verdicts := 0
		for _, d := range sk.Decisions {
			if d.Kind == DecisionVerdict {
				verdicts++
			}
		}
		if verdicts == 0 {
			t.Errorf("%s: no verdict= decision", name)
		}
		if !validSkillLayer(sk.Layer) {
			t.Errorf("%s: invalid layer %q", name, sk.Layer)
		}
		if sk.Version < 1 {
			t.Errorf("%s: version %d must be >= 1", name, sk.Version)
		}
		if strings.TrimSpace(sk.Body) == "" {
			t.Errorf("%s: empty body", name)
		}
		if len(sk.WhenToUse) == 0 || len(sk.SymptomKinds) == 0 || len(sk.LookFor) == 0 {
			t.Errorf("%s: when_to_use / symptom_kinds / look_for must all be present", name)
		}
		if got := sk.Ref(); got.Name != sk.Name || got.Layer != string(sk.Layer) || got.Version != sk.Version {
			t.Errorf("%s: Ref() %+v does not stamp the skill", name, got)
		}
	}
	if methods != 1 {
		t.Fatalf("expected exactly 1 method-layer entry skill, got %d", methods)
	}
}

// goodSkill is the minimal VALID skill the negative cases mutate, so every
// failure below is attributable to the one thing that was broken.
const goodSkill = `---
name: unit-probe
layer: bgp
version: 1
when_to_use: unit probe, probe fault
symptom_kinds: bgp
tools: get_rca_verdict, run_protocol_diagnostic
gather:
  - get_rca_verdict(correlation_id)
  - run_protocol_diagnostic(device_id, protocol=bgp)
look_for:
  - the peer state
decisions:
  - verdict=name the peer and its state
---

Body prose.
`

func TestParseSkillAcceptsAValidSkill(t *testing.T) {
	sk, err := parseSkill("unit-probe", goodSkill)
	if err != nil {
		t.Fatalf("parseSkill: %v", err)
	}
	if sk.Name != "unit-probe" || sk.Layer != LayerBGP || sk.Version != 1 {
		t.Fatalf("unexpected header: %+v", sk)
	}
	if len(sk.Gather) != 2 {
		t.Fatalf("want 2 gather steps, got %d", len(sk.Gather))
	}
	if got := sk.Gather[0].Bind["correlation_id"]; got != "correlation_id" {
		t.Errorf("bare identifier must bind from the same entity, got %q", got)
	}
	if got := sk.Gather[1].Args["protocol"]; got != "bgp" {
		t.Errorf("k=v must be a literal, got %q", got)
	}
	if got := sk.Gather[1].BindOrder(); len(got) != 1 || got[0] != "device_id" {
		t.Errorf("BindOrder = %v, want [device_id]", got)
	}
	if sk.Body != "Body prose." {
		t.Errorf("body = %q", sk.Body)
	}
}

func TestParseSkillRejects(t *testing.T) {
	cases := []struct {
		name string
		dir  string
		raw  string
		want string // substring of the expected error
	}{
		{
			name: "no verdict decision",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - verdict=name the peer and its state", "  - escalate=the peer owner", 1),
			want: "verdict=",
		},
		{
			name: "unknown tool",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "tools: get_rca_verdict, run_protocol_diagnostic", "tools: get_rca_verdict, reboot_device", 1),
			want: "allowlist",
		},
		{
			name: "gather names an undeclared tool",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - get_rca_verdict(correlation_id)", "  - search_logs(device)", 1),
			want: "not in this skill's tools",
		},
		{
			name: "required arg neither bound nor literal",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - run_protocol_diagnostic(device_id, protocol=bgp)", "  - run_protocol_diagnostic(device_id)", 1),
			want: "required argument",
		},
		{
			name: "unknown entity binding",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - run_protocol_diagnostic(device_id, protocol=bgp)", "  - run_protocol_diagnostic(device_id, protocol)", 1),
			want: "not a resolvable entity",
		},
		{
			name: "argument not on the tool",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - get_rca_verdict(correlation_id)", "  - get_rca_verdict(device_id)", 1),
			want: "not a declared argument",
		},
		{
			name: "bad layer",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "layer: bgp", "layer: transport", 1),
			want: "layer",
		},
		{
			name: "name does not equal its directory",
			dir:  "other-dir",
			raw:  goodSkill,
			want: "must equal its directory",
		},
		{
			name: "duplicate key",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "version: 1", "version: 1\nversion: 2", 1),
			want: "duplicate key",
		},
		{
			name: "bad indentation",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - the peer state", "    the peer state", 1),
			want: "unexpected indentation",
		},
		{
			name: "no frontmatter fence",
			dir:  "unit-probe",
			raw:  strings.TrimPrefix(goodSkill, "---\n"),
			want: "frontmatter fence",
		},
		{
			name: "unclosed frontmatter",
			dir:  "unit-probe",
			raw:  "---\nname: unit-probe\n",
			want: "not closed",
		},
		{
			name: "empty body",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "\nBody prose.\n", "\n   \n", 1),
			want: "body is empty",
		},
		{
			name: "bad version",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "version: 1", "version: zero", 1),
			want: "version",
		},
		{
			name: "missing when_to_use",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "when_to_use: unit probe, probe fault\n", "", 1),
			want: "when_to_use",
		},
		{
			name: "missing symptom_kinds",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "symptom_kinds: bgp\n", "", 1),
			want: "symptom_kinds",
		},
		{
			name: "missing tools",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "tools: get_rca_verdict, run_protocol_diagnostic\n", "", 1),
			want: "tools is required",
		},
		{
			name: "missing look_for",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "look_for:\n  - the peer state\n", "", 1),
			want: "look_for",
		},
		{
			name: "missing gather",
			dir:  "unit-probe",
			raw: strings.Replace(goodSkill,
				"gather:\n  - get_rca_verdict(correlation_id)\n  - run_protocol_diagnostic(device_id, protocol=bgp)\n", "", 1),
			want: "gather is required",
		},
		{
			name: "missing decisions",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "decisions:\n  - verdict=name the peer and its state\n", "", 1),
			want: "decisions is required",
		},
		{
			name: "malformed gather call",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - get_rca_verdict(correlation_id)", "  - get_rca_verdict correlation_id", 1),
			want: "expected tool(arg, key=value)",
		},
		{
			name: "unknown decision kind",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - verdict=name the peer and its state", "  - reboot=the box\n  - verdict=x", 1),
			want: "must be next, verdict or escalate",
		},
		{
			name: "next= target is not a skill name",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - verdict=name the peer and its state", "  - next=Not A Name\n  - verdict=x", 1),
			want: "next= must name a skill",
		},
		{
			name: "bad skill name",
			dir:  "Unit_Probe",
			raw:  strings.Replace(goodSkill, "name: unit-probe", "name: Unit_Probe", 1),
			want: "must match",
		},
		{
			name: "empty literal value",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "protocol=bgp", "protocol=", 1),
			want: "empty value",
		},
		{
			name: "argument given twice",
			dir:  "unit-probe",
			raw:  strings.Replace(goodSkill, "  - get_rca_verdict(correlation_id)", "  - get_rca_verdict(correlation_id, correlation_id)", 1),
			want: "given twice",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSkill(tc.dir, tc.raw)
			if err == nil {
				t.Fatalf("expected a parse error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestLayerRankOrdersBisection(t *testing.T) {
	if LayerRank(LayerMethod) != 0 {
		t.Fatal("the entry method must rank first")
	}
	if LayerRank(LayerPhysical) >= LayerRank(LayerBGP) {
		t.Fatal("bisection runs bottom-up: physical before bgp")
	}
	if LayerRank(SkillLayer("nonsense")) != len(skillLayerOrder) {
		t.Fatal("an unknown layer must sort last so it can never pre-empt a real one")
	}
}

func TestSkillSetNilIsSafe(t *testing.T) {
	var set *SkillSet
	if set.Len() != 0 || set.Names() != nil {
		t.Fatal("a nil SkillSet must read as empty, not panic")
	}
	if _, ok := set.Get("anything"); ok {
		t.Fatal("a nil SkillSet must never return a skill")
	}
}
