// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_run_test.go — the skill-guided turn. What is pinned here is the AGENCY
// contract, not prose quality: the server plans the gather, the audit records
// argument NAMES only, an unavailable capability is DISCLOSED rather than
// imagined, next actions come from the authored decisions (never the model), and
// a turn that gathered nothing falls back instead of narrating air.

import (
	"context"
	"strings"
	"testing"
)

// ---- fixtures --------------------------------------------------------------

// runSkill is a hand-built method used instead of an embedded one so each test
// controls exactly which tools the gather names.
func runSkill() *Skill {
	return &Skill{
		Name: "bgp-session-down", Layer: LayerBGP, Version: 3,
		WhenToUse: []string{"bgp down"}, SymptomKinds: []string{"bgp"},
		Tools: []string{"get_rca_verdict", "get_device_health"},
		Gather: []GatherStep{
			{Tool: "get_rca_verdict", Bind: map[string]string{"correlation_id": "correlation_id"}, Args: map[string]string{}},
			{Tool: "get_device_health", Bind: map[string]string{"device": "device"}, Args: map[string]string{}},
		},
		LookFor: []string{"the peer FSM state"},
		Decisions: []SkillDecision{
			{Kind: DecisionNext, Target: "interface-down", Reason: "the link beneath it is down"},
			{Kind: DecisionVerdict, Reason: "name the peer and the reset reason"},
			{Kind: DecisionEscalate, Reason: "the peer's owner"},
		},
		Body: "Work the FSM state first.",
	}
}

func runPrincipal() Principal {
	return Principal{Tenant: "t-a", Perms: map[string]bool{
		"correlations:read": true, "infrastructure:read": true, "logs:read": true,
	}}
}

// stubDeps resolves exactly one device for tenant t-a; everything else is
// ErrNotFound (unknown and cross-tenant are indistinguishable, by design).
func stubDeps() TroubleshootDeps {
	return TroubleshootDeps{
		ResolveDevice: func(_ context.Context, p Principal, ref string) (DeviceRef, error) {
			if p.Tenant == "t-a" && (ref == "edge-1" || ref == "dev-a") {
				return DeviceRef{ID: "dev-a", Name: "edge-1"}, nil
			}
			return DeviceRef{}, ErrNotFound
		},
	}
}

func runOrchestrator(t *testing.T, llm LLMClient) (*Orchestrator, *[]ToolAuditEntry) {
	t.Helper()
	ds := newMockDS()
	var audit []ToolAuditEntry
	o := &Orchestrator{
		DS: ds, Tools: Tools(ds), LLM: llm,
		Flags:        func(string) bool { return true },
		Troubleshoot: stubDeps(),
		ToolAudit:    func(e ToolAuditEntry) { audit = append(audit, e) },
	}
	o.Tools.AddTroubleshootTools(ds, o.Troubleshoot)
	return o, &audit
}

// ---- entity resolution + gather planning -----------------------------------

func TestResolveSkillEntitiesFromUIContext(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{})
	cases := []struct {
		name      string
		question  string
		uiContext map[string]string
		want      map[string]string
		wantNote  bool
	}{
		{
			name: "ui context wins", question: "why is bgp down",
			uiContext: map[string]string{"correlation_id": "pa", "device": "edge-1", "seam": "seam-7"},
			want:      map[string]string{"correlation_id": "pa", "device_id": "dev-a", "device": "edge-1", "seam": "seam-7"},
		},
		{
			name: "problem_id is accepted as the case id", question: "explain",
			uiContext: map[string]string{"problem_id": "pa"},
			want:      map[string]string{"correlation_id": "pa"},
		},
		{
			name: "uuid in the question binds the case", question: "explain 8f14e45f-ceea-467a-9c4b-1f2a3b4c5d6e",
			uiContext: nil,
			want:      map[string]string{"correlation_id": "8f14e45f-ceea-467a-9c4b-1f2a3b4c5d6e"},
		},
		{
			name: "hostname token in the question resolves", question: "is edge-1 flapping?",
			uiContext: nil,
			want:      map[string]string{"device_id": "dev-a", "device": "edge-1"},
		},
		{
			name: "an unresolvable hostname is disclosed, never assumed", question: "what about core-99?",
			uiContext: nil,
			want:      map[string]string{},
			wantNote:  true,
		},
		{
			name: "plain English offers nothing to the inventory", question: "the network feels slow",
			uiContext: nil,
			want:      map[string]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ent := o.resolveSkillEntities(context.Background(), runPrincipal(), tc.question, tc.uiContext)
			for k, want := range tc.want {
				got, ok := ent.get(k)
				if !ok || got != want {
					t.Errorf("entity %q = %q (ok=%v), want %q", k, got, ok, want)
				}
			}
			for _, k := range []string{"correlation_id", "device_id", "device", "seam"} {
				if _, expected := tc.want[k]; !expected {
					if got, ok := ent.get(k); ok {
						t.Errorf("entity %q should be unbound, got %q", k, got)
					}
				}
			}
			if got := len(ent.notes) > 0; got != tc.wantNote {
				t.Errorf("notes = %v, want a disclosure note = %v", ent.notes, tc.wantNote)
			}
		})
	}
}

// A cross-tenant caller must not resolve tenant A's device — the same
// ErrNotFound path an unknown name takes (§3a rule 1: no existence signal).
func TestResolveSkillEntitiesIsTenantScoped(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{})
	ent := o.resolveSkillEntities(context.Background(),
		Principal{Tenant: "t-b"}, "what is wrong with edge-1", nil)
	if _, ok := ent.get("device_id"); ok {
		t.Fatal("another tenant's device must never resolve")
	}
	if len(ent.notes) == 0 {
		t.Fatal("the turn must disclose that no device in THIS tenant matched")
	}
}

func TestPlanGather(t *testing.T) {
	sk := runSkill()
	cases := []struct {
		name  string
		ent   skillEntitySet
		want  []string          // tools, in order
		args  map[string]string // expected args of the FIRST planned step
		skips string
	}{
		{
			name: "both entities bound → both steps",
			ent:  skillEntitySet{values: map[string]string{"correlation_id": "pa", "device": "edge-1"}},
			want: []string{"get_rca_verdict", "get_device_health"},
			args: map[string]string{"correlation_id": "pa"},
		},
		{
			name:  "no device → the device step is dropped, never guessed",
			ent:   skillEntitySet{values: map[string]string{"correlation_id": "pa"}},
			want:  []string{"get_rca_verdict"},
			args:  map[string]string{"correlation_id": "pa"},
			skips: "get_device_health",
		},
		{
			name: "no case → the verdict step is dropped",
			ent:  skillEntitySet{values: map[string]string{"device": "edge-1"}},
			want: []string{"get_device_health"},
			args: map[string]string{"device": "edge-1"},
		},
		{
			name: "nothing bound → nothing planned",
			ent:  skillEntitySet{values: map[string]string{}},
			want: nil,
		},
		{
			name: "a blank binding does not satisfy a required argument",
			ent:  skillEntitySet{values: map[string]string{"correlation_id": "   "}},
			want: nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := planGather(sk, tc.ent)
			if len(got) != len(tc.want) {
				t.Fatalf("planned %d steps, want %d (%v)", len(got), len(tc.want), got)
			}
			for i, name := range tc.want {
				if got[i].Tool != name {
					t.Fatalf("step %d = %q, want %q", i, got[i].Tool, name)
				}
			}
			for k, v := range tc.args {
				if got[0].Args[k] != v {
					t.Errorf("first step arg %q = %q, want %q", k, got[0].Args[k], v)
				}
			}
			for _, g := range got {
				if g.Tool == tc.skips {
					t.Errorf("step %q should have been dropped", tc.skips)
				}
			}
		})
	}
}

// A literal from the skill author survives planning; an optional bind that does
// not resolve is simply omitted so the tool runs at its wider scope.
func TestPlanGatherKeepsLiteralsAndDropsUnboundOptionals(t *testing.T) {
	sk := &Skill{
		Name: "probe", Layer: LayerLogs, Version: 1,
		Gather: []GatherStep{{
			Tool: "search_logs",
			Bind: map[string]string{"device": "device"},
			Args: map[string]string{"query": "BGP", "window": "6h"},
		}},
	}
	got := planGather(sk, skillEntitySet{values: map[string]string{}})
	if len(got) != 1 {
		t.Fatalf("a step with only OPTIONAL args must still be planned, got %d", len(got))
	}
	if got[0].Args["query"] != "BGP" || got[0].Args["window"] != "6h" {
		t.Errorf("literals lost: %v", got[0].Args)
	}
	if _, present := got[0].Args["device"]; present {
		t.Errorf("an unresolved optional bind must be omitted, got %v", got[0].Args)
	}
}

func TestPlanGatherRespectsTheCallBudget(t *testing.T) {
	sk := &Skill{Name: "probe", Layer: LayerLogs, Version: 1}
	for i := 0; i < MaxSkillToolCalls+4; i++ {
		sk.Gather = append(sk.Gather, GatherStep{Tool: "get_active_major_incidents",
			Bind: map[string]string{}, Args: map[string]string{}})
	}
	if got := len(planGather(sk, skillEntitySet{values: map[string]string{}})); got != MaxSkillToolCalls {
		t.Fatalf("planned %d calls, want the %d-call budget", got, MaxSkillToolCalls)
	}
}

// ---- answerSkill -----------------------------------------------------------

func TestAnswerSkillGroundsAndAudits(t *testing.T) {
	o, audit := runOrchestrator(t, MockLLM{Reply: "Peer edge-1 is down [verdict:pa]. Check the link."})
	match := SkillMatch{Skill: runSkill(), Score: 4, Reason: "matched bgp down"}
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, match, map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("a turn with evidence must be handled by the skill")
	}
	if ans.Mode != ModeTroubleshootFinding {
		t.Errorf("mode = %q, want %q", ans.Mode, ModeTroubleshootFinding)
	}
	if ans.Skill == nil || ans.Skill.Name != "bgp-session-down" || ans.Skill.Version != 3 || ans.Skill.Layer != "bgp" {
		t.Errorf("provenance stamp = %+v", ans.Skill)
	}
	if len(ans.Lookups) == 0 {
		t.Error("the answer must report which tools actually ran")
	}
	if len(ans.Citations) == 0 {
		t.Error("a grounded answer must carry citations")
	}
	if ans.EvidenceOnly {
		t.Error("a provider answered; the turn must not claim evidence-only")
	}
	// The audit records argument NAMES only — never values (§8 no-PII logging).
	if len(*audit) == 0 {
		t.Fatal("every gather step must be audited")
	}
	for _, e := range *audit {
		if e.Skill != "bgp-session-down" {
			t.Errorf("audit entry lost the skill: %+v", e)
		}
		for _, a := range e.Args {
			switch a {
			case "correlation_id", "device", "device_id", "problem_id", "query", "window":
			default:
				t.Errorf("audit arg %q is not an argument NAME — value leakage", a)
			}
			if strings.Contains(a, "edge-1") || strings.Contains(a, "pa=") {
				t.Errorf("audit leaked an argument VALUE: %q", a)
			}
		}
		for i := 1; i < len(e.Args); i++ {
			if e.Args[i-1] > e.Args[i] {
				t.Errorf("audit arg names must be sorted for stable audit lines: %v", e.Args)
			}
		}
	}
}

// NextActions are built from the authored decisions ONLY, so a hallucinated
// action can never reach the operator's action list.
func TestAnswerSkillNextActionsComeFromDecisions(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{Reply: "Do the following: reboot every core router immediately."})
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "bgp down",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: runSkill()}, map[string]string{"correlation_id": "pa"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	want := []string{
		"Check interface down — when the link beneath it is down.",
		"Escalate to the peer's owner.",
	}
	if len(ans.NextActions) != len(want) {
		t.Fatalf("next actions = %v, want %v", ans.NextActions, want)
	}
	for i, w := range want {
		if ans.NextActions[i] != w {
			t.Errorf("next action %d = %q, want %q", i, ans.NextActions[i], w)
		}
	}
	for _, a := range ans.NextActions {
		if strings.Contains(strings.ToLower(a), "reboot") {
			t.Errorf("a model-invented action reached the action list: %q", a)
		}
	}
}

// A citation id the model invented is stripped before an operator sees it.
func TestAnswerSkillStripsInventedCitations(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{
		Reply: "The peer is down [verdict:pa] and the optics are failing [log:totally-made-up]."})
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "bgp down",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: runSkill()}, map[string]string{"correlation_id": "pa"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	if strings.Contains(ans.Text, "totally-made-up") {
		t.Fatalf("an invented citation id survived verification: %q", ans.Text)
	}
	if !strings.Contains(ans.Text, "verdict:pa") {
		t.Fatalf("a REAL citation id must survive verification: %q", ans.Text)
	}
	joined := strings.Join(ans.Disclaimers, " ")
	if !strings.Contains(joined, "unsupported reference") {
		t.Errorf("stripping must be disclosed, disclaimers = %v", ans.Disclaimers)
	}
}

func TestAnswerSkillDeterministicWithoutAProvider(t *testing.T) {
	o, _ := runOrchestrator(t, nil)
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "bgp down",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: runSkill()}, map[string]string{"correlation_id": "pa"}, nil)
	if !handled {
		t.Fatal("the finding must still ship without a provider")
	}
	if !ans.EvidenceOnly {
		t.Error("a no-provider turn must be flagged evidence-only")
	}
	if ans.ProviderNote == "" {
		t.Error("a no-provider turn must say why there is no narrative")
	}
	if strings.TrimSpace(ans.Text) == "" {
		t.Error("the deterministic summary must not be empty")
	}
	if ans.Provider != "" {
		t.Errorf("no provider ran, but Provider = %q", ans.Provider)
	}
	// Same inputs, same text — the fallback is deterministic.
	again, _ := o.answerSkill(context.Background(), runPrincipal(), "bgp down",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: runSkill()}, map[string]string{"correlation_id": "pa"}, nil)
	if again.Text != ans.Text {
		t.Errorf("the evidence-only summary is not deterministic:\n%q\n%q", ans.Text, again.Text)
	}
}

func TestAnswerSkillFallsBackWhenNothingWasGathered(t *testing.T) {
	o, audit := runOrchestrator(t, MockLLM{Reply: "should never be used"})
	cases := []struct {
		name      string
		uiContext map[string]string
		principal Principal
	}{
		{"no entities resolve → no steps to run", map[string]string{}, runPrincipal()},
		{"every step 404s → nothing gathered", map[string]string{"correlation_id": "pb"}, runPrincipal()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			*audit = nil
			_, handled := o.answerSkill(context.Background(), tc.principal, "bgp down",
				Plan{Intent: "troubleshoot"}, SkillMatch{Skill: runSkill()}, tc.uiContext, nil)
			if handled {
				t.Fatal("a turn that gathered nothing must fall back, not narrate air")
			}
		})
	}
	// The 404 case must still have been audited as not_found.
	*audit = nil
	if _, handled := o.answerSkill(context.Background(), runPrincipal(), "bgp down",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: runSkill()},
		map[string]string{"correlation_id": "pb"}, nil); handled {
		t.Fatal("cross-tenant case id must not produce a skill answer")
	}
	if len(*audit) != 1 || (*audit)[0].Reason != "not_found" || (*audit)[0].Allowed {
		t.Fatalf("expected one denied not_found audit entry, got %+v", *audit)
	}
}

func TestAnswerSkillDisclosesUnwiredAndDeniedTools(t *testing.T) {
	sk := runSkill()
	// A method that names a real, described tool we did NOT register here.
	sk.Tools = append(sk.Tools, "get_topology_context")
	sk.Gather = append(sk.Gather, GatherStep{
		Tool: "get_topology_context",
		Bind: map[string]string{"device_id": "device_id"}, Args: map[string]string{},
	})

	t.Run("not registered on this deployment", func(t *testing.T) {
		o, audit := runOrchestrator(t, MockLLM{Reply: "narrative [verdict:pa]"})
		ans, handled := o.answerSkill(context.Background(), runPrincipal(), "bgp down",
			Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
			map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
		if !handled {
			t.Fatal("the other steps still gathered; the turn must be handled")
		}
		var found bool
		for _, e := range *audit {
			if e.Tool == "get_topology_context" {
				found = true
				if e.Allowed || e.Reason != "not_registered" {
					t.Errorf("want a not_registered denial, got %+v", e)
				}
			}
		}
		if !found {
			t.Error("an unavailable capability must still be audited")
		}
		if len(ans.MissingEvidence) == 0 {
			t.Error("an unavailable capability must surface as MISSING evidence, not silence")
		}
	})

	t.Run("denied by policy", func(t *testing.T) {
		o, audit := runOrchestrator(t, MockLLM{Reply: "narrative [verdict:pa]"})
		o.Policy = NewPolicyEngine(PolicyConfig{DenyTools: []string{"get_device_health"}}, o.Flags)
		_, handled := o.answerSkill(context.Background(), runPrincipal(), "bgp down",
			Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
			map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
		if !handled {
			t.Fatal("the verdict step still gathered; the turn must be handled")
		}
		var denied bool
		for _, e := range *audit {
			if e.Tool == "get_device_health" {
				denied = true
				if e.Allowed || e.Reason != "policy_denied" {
					t.Errorf("want a policy_denied entry, got %+v", e)
				}
			}
		}
		if !denied {
			t.Error("a policy denial must be audited")
		}
	})

	t.Run("caller lacks the permission", func(t *testing.T) {
		o, audit := runOrchestrator(t, MockLLM{Reply: "narrative [verdict:pa]"})
		p := runPrincipal()
		p.Perms = map[string]bool{"correlations:read": true} // no infrastructure:read
		_, handled := o.answerSkill(context.Background(), p, "bgp down",
			Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
			map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
		if !handled {
			t.Fatal("the correlations step still gathered")
		}
		for _, e := range *audit {
			if e.Tool == "get_device_health" && e.Allowed {
				t.Error("a tool the caller may not run must never execute")
			}
		}
	})
}

func TestAnswerSkillRefusesWithoutASkillOrRegistry(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{})
	if _, handled := o.answerSkill(context.Background(), runPrincipal(), "q",
		Plan{}, SkillMatch{}, nil, nil); handled {
		t.Error("a nil skill must not be handled")
	}
	bare := &Orchestrator{DS: newMockDS(), Flags: func(string) bool { return true }}
	if _, handled := bare.answerSkill(context.Background(), runPrincipal(), "q",
		Plan{}, SkillMatch{Skill: runSkill()}, nil, nil); handled {
		t.Error("a nil registry must not be handled")
	}
}

// A skill answer must never widen access: an orchestrator with Skills wired
// still answers every EXCLUDED intent through the classic path.
func TestAskSkillsDoNotPreemptExistingIntents(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{Reply: "narrative"})
	o.Skills = loadTestSkills(t)
	ans, err := o.Ask(context.Background(), runPrincipal(),
		"what is going on right now", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if ans.Skill != nil {
		t.Fatalf("the current-state briefing was hijacked by skill %q", ans.Skill.Name)
	}
	if ans.Mode != ModeCurrentStateSummary {
		t.Fatalf("mode = %q, want the classic current-state summary", ans.Mode)
	}
}

// The point of the whole layer: a bare troubleshooting complaint classifies as
// the "capability" dead end today. With Skills wired it must become a grounded,
// cited finding instead of "here is what I can do".
func TestAskSkillClaimsTheCapabilityDeadEnd(t *testing.T) {
	const q = "bgp neighbor down on edge-1, peer is idle"
	if got := Classify(q, nil).Intent; got != "capability" {
		t.Skipf("precondition changed: %q now classifies as %q, not the capability dead end", q, got)
	}
	bare, _ := runOrchestrator(t, MockLLM{Reply: "narrative"})
	base, err := bare.Ask(context.Background(), runPrincipal(), q, nil)
	if err != nil {
		t.Fatalf("Ask (skills disabled): %v", err)
	}
	if base.Mode != ModeUnavailable {
		t.Fatalf("precondition: without skills this must be the capability answer, got %q", base.Mode)
	}

	o, _ := runOrchestrator(t, MockLLM{Reply: "Peer edge-1 is Idle [verdict:pa]."})
	o.Skills = loadTestSkills(t)
	ans, err := o.Ask(context.Background(), runPrincipal(), q, map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatalf("Ask (skills wired): %v", err)
	}
	if ans.Skill == nil {
		t.Fatalf("the skills layer did not claim the capability dead end (mode %q)", ans.Mode)
	}
	if ans.Mode != ModeTroubleshootFinding {
		t.Fatalf("mode = %q, want %q", ans.Mode, ModeTroubleshootFinding)
	}
	if len(ans.Citations) == 0 {
		t.Error("the replacement answer must be CITED — that is the whole improvement")
	}
}

// A question no skill can ground still gets the honest capability clarification;
// the layer replaces the dead end only when it has evidence.
func TestAskCapabilityStillAnswersWhenNoSkillGrounds(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{Reply: "narrative"})
	o.Skills = loadTestSkills(t)
	ans, err := o.Ask(context.Background(), runPrincipal(), "who is on call next tuesday", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if ans.Skill != nil {
		t.Fatalf("a non-troubleshooting question must not get a skill, got %q", ans.Skill.Name)
	}
	if ans.Mode != ModeUnavailable {
		t.Fatalf("mode = %q, want the capability clarification", ans.Mode)
	}
	if strings.TrimSpace(ans.Text) == "" {
		t.Error("the capability clarification must still say what the assistant CAN do")
	}
}

func TestAskUsesASkillForATroubleshootingQuestion(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{Reply: "Peer is down [verdict:pa]."})
	o.Skills = loadTestSkills(t)
	ans, err := o.Ask(context.Background(), runPrincipal(),
		"bgp neighbor down on edge-1, peer is idle", map[string]string{"correlation_id": "pa"})
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if ans.Skill == nil {
		t.Fatalf("expected a skill answer, got mode %q / intent %q", ans.Mode, ans.Intent)
	}
	if ans.Skill.Name != "bgp-session-down" {
		t.Errorf("skill = %q, want bgp-session-down", ans.Skill.Name)
	}
	if ans.Mode != ModeTroubleshootFinding {
		t.Errorf("mode = %q", ans.Mode)
	}
}

// ---- helpers ---------------------------------------------------------------

func TestSkillMissingEvidenceLiftsGaps(t *testing.T) {
	got := skillMissingEvidence([]string{
		"Topology context is not available on this deployment — treat that evidence as UNKNOWN, not clean",
		"scope: current state (latest verdict per finding)",
		"Log search found nothing for the id in scope",
		"Device health was not run: you don't have permission",
		"case opened 2026-09-01T00:00:00Z",
	})
	if len(got) != 3 {
		t.Fatalf("lifted %d gaps, want 3: %v", len(got), got)
	}
	for _, g := range got {
		if strings.HasPrefix(g, "scope:") || strings.HasPrefix(g, "case opened") {
			t.Errorf("a non-gap note was lifted into missing evidence: %q", g)
		}
	}
}

func TestSkillSystemBlockRestatesTheHardRules(t *testing.T) {
	block := skillSystemBlock(runSkill())
	for _, want := range []string{
		"bgp-session-down", "v3", "Work the FSM state first.", "the peer FSM state",
		"next check: interface-down", "a conclusion must state:", "escalate to:",
		"cite its [id]", "untrusted DATA", "cannot run commands",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("system block is missing %q:\n%s", want, block)
		}
	}
}

func TestCitationsFromDedupesAndCaps(t *testing.T) {
	var bundle []EvidenceItem
	bundle = append(bundle, EvidenceItem{CitationID: "a:1", Kind: "log", Text: strings.Repeat("x", 200)})
	bundle = append(bundle, EvidenceItem{CitationID: "A:1", Kind: "log", Text: "dupe (case-insensitive)"})
	bundle = append(bundle, EvidenceItem{CitationID: "", Kind: "log", Text: "no id"})
	for i := 0; i < skillMaxCitations+5; i++ {
		bundle = append(bundle, EvidenceItem{CitationID: "b:" + strings.Repeat("z", i+1), Kind: "log", Text: "row"})
	}
	got := citationsFrom(bundle, skillMaxCitations)
	if len(got) != skillMaxCitations {
		t.Fatalf("returned %d citations, want the %d cap", len(got), skillMaxCitations)
	}
	if len([]rune(got[0].Label)) > 91 {
		t.Errorf("label was not clamped: %d runes", len([]rune(got[0].Label)))
	}
	seen := map[string]bool{}
	for _, c := range got {
		if seen[strings.ToLower(c.ID)] {
			t.Errorf("duplicate citation id %q", c.ID)
		}
		seen[strings.ToLower(c.ID)] = true
		if c.ID == "" {
			t.Error("an item without a citation id must not become a citation")
		}
	}
}
