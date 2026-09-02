package ai

// skill_chain_test.go — the BOUNDED INVESTIGATION LOOP (IRIS Phase A2).
//
// What is pinned here is the AGENCY and BOUNDS contract, not narrative quality:
//
//   - a deterministic authored condition chains WITHOUT a provider;
//   - the model may pick ONLY from the current skill's own declared handoffs,
//     and a name outside that list is refused, audited, and never logged;
//   - a visited skill is never re-entered (no cycles);
//   - the round, per-turn tool and wall-clock budgets all stop the loop, and
//     each stop is DISCLOSED rather than silently truncating the investigation;
//   - evidence accumulates deduped and capped;
//   - the chain is provenance: every hop says how it was selected, in the answer
//     and in the audit;
//   - entities are resolved ONCE, under the caller's tenant: a later hop can
//     never widen the scope (§3a).

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---- fixtures --------------------------------------------------------------

// scriptLLM answers a fixed script, in order, and records what it was asked. It
// exists so a test can drive the ROUTING turn and the FINAL narration turn
// independently — MockLLM answers every call identically.
type scriptLLM struct {
	replies  []string
	fallback string
	err      error
	systems  []string
	prompts  []string
}

func (s *scriptLLM) Complete(_ context.Context, system string, msgs []LLMMessage) (string, string, error) {
	s.systems = append(s.systems, system)
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Role == "user" {
			s.prompts = append(s.prompts, msgs[i].Content)
			break
		}
	}
	if s.err != nil {
		return "", "script", s.err
	}
	if n := len(s.systems) - 1; n < len(s.replies) {
		return s.replies[n], "script", nil
	}
	if s.fallback != "" {
		return s.fallback, "script", nil
	}
	return "Final narrative.", "script", nil
}

// chainOrchestrator is runOrchestrator with the EMBEDDED skill set wired, which
// is what the chain needs: a hop may only target a skill that actually loaded.
func chainOrchestrator(t *testing.T, llm LLMClient) (*Orchestrator, *[]ToolAuditEntry) {
	t.Helper()
	o, audit := runOrchestrator(t, llm)
	o.Skills = loadTestSkills(t)
	return o, audit
}

// withProblem adds one correlation to the mock DataSource for a tenant.
func withProblem(t *testing.T, o *Orchestrator, tenant string, pr *Problem) {
	t.Helper()
	ds, ok := o.DS.(*mockDS)
	if !ok {
		t.Fatalf("expected the mock DataSource, got %T", o.DS)
	}
	ds.problems[tenant][pr.ID] = pr
}

// linkPhrase is the engine's own wording for "BGP is down because the link
// beneath it is down" — the fixture the design names.
const linkPhrase = "the link beneath the BGP session is down"

func chainNames(ans Answer) []string {
	out := make([]string, 0, len(ans.Chain))
	for _, h := range ans.Chain {
		out = append(out, h.Name)
	}
	return out
}

func auditFor(entries []ToolAuditEntry, tool string) []ToolAuditEntry {
	var out []ToolAuditEntry
	for _, e := range entries {
		if e.Tool == tool {
			out = append(out, e)
		}
	}
	return out
}

// chainTestSet builds a synthetic, always-chaining method graph: a1 → a2 → …
// Every hop is guarded by a condition the first round always satisfies
// (get_rca_verdict returns `finding` evidence), so the ONLY thing that can stop
// the loop is a budget. `steps` gather calls per skill.
func chainTestSet(names []string, steps int) *SkillSet {
	set := &SkillSet{byName: map[string]*Skill{}}
	for i, n := range names {
		sk := &Skill{
			Name: n, Layer: LayerBGP, Version: 1,
			WhenToUse: []string{n}, SymptomKinds: []string{"bgp"},
			Tools:   []string{"get_rca_verdict"},
			LookFor: []string{"anything"},
			Body:    "synthetic method",
			Decisions: []SkillDecision{
				{Kind: DecisionVerdict, Reason: "say what happened"},
			},
		}
		for j := 0; j < steps; j++ {
			sk.Gather = append(sk.Gather, GatherStep{
				Tool: "get_rca_verdict",
				Bind: map[string]string{"correlation_id": "correlation_id"},
				Args: map[string]string{},
			})
		}
		if i+1 < len(names) {
			cond := SkillCondition{Key: CondEvidenceKind, Value: "finding"}
			sk.Decisions = append([]SkillDecision{{
				Kind: DecisionNext, Target: names[i+1], Reason: cond.Human(), Cond: &cond,
			}}, sk.Decisions...)
		}
		set.byName[n] = sk
		set.order = append(set.order, n)
	}
	return set
}

// ---- (a) deterministic authored rules --------------------------------------

// The fixture the design names: "BGP down because the link is down" must chain
// bgp-session-down → interface-down DETERMINISTICALLY — no provider involved in
// the decision at all.
func TestChainRuleDrivenHopBgpToInterfaceDown(t *testing.T) {
	o, audit := chainOrchestrator(t, MockLLM{Reply: "The link beneath the session is down [verdict:plink]."})
	withProblem(t, o, "t-a", &Problem{
		ID: "plink", Title: "BGP peer down on edge-1", OperatorPhrase: linkPhrase,
		Verdict: "confirmed", Confidence: 0.91, Devices: []string{"edge-1"},
		SignalCount: 6, NodeCount: 2,
	})
	sk, ok := o.Skills.Get("bgp-session-down")
	if !ok {
		t.Fatal("bgp-session-down must load")
	}
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk, Reason: "matched bgp down"},
		map[string]string{"correlation_id": "plink", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("the chained turn must be handled")
	}
	if got := chainNames(ans); len(got) != 2 || got[0] != "bgp-session-down" || got[1] != "interface-down" {
		t.Fatalf("chain = %v, want [bgp-session-down interface-down]", got)
	}
	if ans.Chain[0].Selected != ChainSelectedEntry || ans.Chain[0].Round != 1 {
		t.Errorf("first hop = %+v, want the entry selection in round 1", ans.Chain[0])
	}
	if ans.Chain[1].Selected != ChainSelectedRule || ans.Chain[1].Round != 2 {
		t.Errorf("second hop = %+v, want a rule-selected round-2 hop", ans.Chain[1])
	}
	if ans.Chain[1].Reason == "" {
		t.Error("a hop must carry the AUTHORED reason it was taken")
	}
	// Answer.Skill stays the LAST hop, so the existing single-skill contract holds.
	if ans.Skill == nil || ans.Skill.Name != "interface-down" {
		t.Fatalf("Answer.Skill = %+v, want the last hop", ans.Skill)
	}
	// The hop is audited as a rule selection, in the round it was made.
	sel := auditFor(*audit, "next_skill")
	if len(sel) != 1 || sel[0].Reason != "rule_selected" || sel[0].Selected != ChainSelectedRule || sel[0].Round != 1 {
		t.Fatalf("selection audit = %+v", sel)
	}
	if sel[0].Skill != "interface-down" {
		t.Errorf("the selection audit must name the CHOSEN skill, got %q", sel[0].Skill)
	}
	// Every tool entry carries its round and how its skill was selected.
	rounds := map[int]bool{}
	for _, e := range *audit {
		if e.Tool == "next_skill" {
			continue
		}
		if e.Round == 0 || e.Selected == "" {
			t.Errorf("tool audit entry lost its chain position: %+v", e)
		}
		rounds[e.Round] = true
	}
	if !rounds[1] || !rounds[2] {
		t.Errorf("both rounds must appear in the audit, got %v", rounds)
	}
}

// A rule only fires on facts the SERVER derived. Without the engine's phrase the
// same skill, question and tools produce NO deterministic hop.
func TestChainRuleDoesNotFireWithoutTheFact(t *testing.T) {
	o, _ := chainOrchestrator(t, MockLLM{Reply: "Peer is idle [verdict:pa]."})
	sk, _ := o.Skills.Get("bgp-session-down")
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	if got := chainNames(ans); len(got) != 1 || got[0] != "bgp-session-down" {
		t.Fatalf("chain = %v, want the single entry skill", got)
	}
}

// ---- (b) the model's CLOSED choice -----------------------------------------

func TestChainModelDrivenHopIsAcceptedFromTheDeclaredList(t *testing.T) {
	llm := &scriptLLM{replies: []string{
		"The session evidence points at the physical link.\nNEXT: interface-down",
		"Nothing further.\nNEXT: none",
		"Final narrative [verdict:pa].",
	}}
	o, audit := chainOrchestrator(t, llm)
	sk, _ := o.Skills.Get("bgp-session-down")
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	if got := chainNames(ans); len(got) != 2 || got[1] != "interface-down" {
		t.Fatalf("chain = %v, want a model-driven hop to interface-down", got)
	}
	if ans.Chain[1].Selected != ChainSelectedModel {
		t.Errorf("hop selection = %q, want %q", ans.Chain[1].Selected, ChainSelectedModel)
	}
	sel := auditFor(*audit, "next_skill")
	if len(sel) != 1 || sel[0].Reason != "model_selected" || !sel[0].Allowed || sel[0].Round != 1 {
		t.Fatalf("selection audit = %+v", sel)
	}
	// The routing prompt offers ONLY the skill's own declared handoffs, and never
	// a tool the model could ask for.
	if len(llm.systems) < 2 {
		t.Fatalf("expected a routing call and a narration call, got %d", len(llm.systems))
	}
	route := llm.systems[0]
	for _, want := range append(sk.NextSkills(), "NEXT: none") {
		if !strings.Contains(route, want) {
			t.Errorf("routing instructions omit %q:\n%s", want, route)
		}
	}
	for _, banned := range []string{"get_rca_verdict", "search_logs", "run_protocol_diagnostic"} {
		if strings.Contains(route, banned) {
			t.Errorf("the routing turn must never offer a TOOL (%q)", banned)
		}
	}
	// A routing directive is a control line, never operator text.
	if strings.Contains(strings.ToUpper(ans.Text), "NEXT:") {
		t.Errorf("a NEXT directive reached the operator: %q", ans.Text)
	}
	// The final narration is ONE turn over the whole bundle and says so.
	final := llm.systems[len(llm.systems)-1]
	if !strings.Contains(final, "INVESTIGATION PATH") || !strings.Contains(final, "interface-down") {
		t.Errorf("the final system block must summarise the chain:\n%s", final)
	}
}

func TestChainRefusesAModelNameOutsideTheDeclaredList(t *testing.T) {
	for _, proposal := range []string{
		"mac-flap",             // a real skill, but NOT one this skill hands off to
		"get_rca_verdict",      // a tool
		"../../etc/passwd",     // a path
		"interface-down extra", // not a bare name
		"INTERFACE_DOWN",       // not a real name
	} {
		t.Run(proposal, func(t *testing.T) {
			llm := &scriptLLM{replies: []string{"Try this.\nNEXT: " + proposal, "Final [verdict:pa]."}}
			o, audit := chainOrchestrator(t, llm)
			sk, _ := o.Skills.Get("bgp-session-down")
			ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
				Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
				map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
			if !handled {
				t.Fatal("expected a handled turn")
			}
			if got := chainNames(ans); len(got) != 1 {
				t.Fatalf("chain = %v, want the entry skill only", got)
			}
			sel := auditFor(*audit, "next_skill")
			if len(sel) != 1 || sel[0].Reason != "model_selected_invalid" || sel[0].Allowed {
				t.Fatalf("selection audit = %+v, want one refused choice", sel)
			}
			// The invented name is untrusted model text: it must never be logged.
			for _, e := range *audit {
				if strings.Contains(e.Skill, proposal) || strings.Contains(e.Reason, proposal) {
					t.Errorf("the refused model name leaked into the audit: %+v", e)
				}
			}
		})
	}
}

// "NEXT: none" and a reply with no directive at all both end the chain.
func TestChainStopsWhenTheModelProposesNothing(t *testing.T) {
	for name, reply := range map[string]string{
		"explicit none": "The evidence answers it.\nNEXT: none",
		"no directive":  "The evidence answers it.",
		"empty name":    "NEXT:",
	} {
		t.Run(name, func(t *testing.T) {
			o, audit := chainOrchestrator(t, &scriptLLM{replies: []string{reply, "Final [verdict:pa]."}})
			sk, _ := o.Skills.Get("bgp-session-down")
			ans, _ := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
				Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
				map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
			if got := chainNames(ans); len(got) != 1 {
				t.Fatalf("chain = %v, want no hop", got)
			}
			if sel := auditFor(*audit, "next_skill"); len(sel) != 0 {
				t.Fatalf("declining to chain is not a selection: %+v", sel)
			}
		})
	}
}

// A skill already visited is not a candidate — the loop cannot cycle even when
// the model asks for one.
func TestChainRefusesACycle(t *testing.T) {
	llm := &scriptLLM{replies: []string{
		"Read the device's own words.\nNEXT: log-confirmation",
		"Back to the session.\nNEXT: bgp-session-down", // already visited
		"Final [verdict:pa].",
	}}
	o, audit := chainOrchestrator(t, llm)
	sk, _ := o.Skills.Get("bgp-session-down")
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	if got := chainNames(ans); len(got) != 2 || got[1] != "log-confirmation" {
		t.Fatalf("chain = %v, want exactly two hops", got)
	}
	sel := auditFor(*audit, "next_skill")
	if len(sel) != 2 || sel[1].Reason != "model_selected_invalid" {
		t.Fatalf("the re-entry must be refused and audited: %+v", sel)
	}
	seen := map[string]int{}
	for _, h := range ans.Chain {
		seen[h.Name]++
		if seen[h.Name] > 1 {
			t.Fatalf("skill %q ran twice: %v", h.Name, chainNames(ans))
		}
	}
}

// ---- budgets ---------------------------------------------------------------

func TestChainStopsAtTheRoundBudget(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{Reply: "narrative [verdict:pa]"})
	o.Skills = chainTestSet([]string{"a1", "a2", "a3", "a4", "a5", "a6"}, 1)
	sk, _ := o.Skills.Get("a1")
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "chain please",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk}, map[string]string{"correlation_id": "pa"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	if got := len(ans.Chain); got != MaxInvestigationRounds {
		t.Fatalf("chain length = %d, want the %d-round budget", got, MaxInvestigationRounds)
	}
	if !hasNote(ans.MissingEvidence, "round budget") {
		t.Errorf("hitting the round budget must be DISCLOSED, missing evidence = %v", ans.MissingEvidence)
	}
}

func TestChainStopsAtThePerTurnToolBudget(t *testing.T) {
	o, audit := runOrchestrator(t, MockLLM{Reply: "narrative [verdict:pa]"})
	o.Skills = chainTestSet([]string{"a1", "a2", "a3", "a4"}, MaxSkillToolCalls)
	sk, _ := o.Skills.Get("a1")
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "chain please",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk}, map[string]string{"correlation_id": "pa"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	tools := 0
	for _, e := range *audit {
		if e.Tool != "next_skill" {
			tools++
		}
	}
	if tools != MaxChainToolCalls {
		t.Fatalf("ran %d tool calls, want exactly the %d-call per-turn ceiling", tools, MaxChainToolCalls)
	}
	if len(ans.Chain) >= MaxInvestigationRounds {
		t.Errorf("the tool budget must bite before the round budget: %v", chainNames(ans))
	}
	if !hasNote(ans.MissingEvidence, "lookup budget") {
		t.Errorf("hitting the tool budget must be DISCLOSED, missing evidence = %v", ans.MissingEvidence)
	}
}

func TestChainStopsAtTheWallClockBudget(t *testing.T) {
	o, _ := runOrchestrator(t, MockLLM{Reply: "narrative [verdict:pa]"})
	o.Skills = chainTestSet([]string{"a1", "a2", "a3", "a4"}, 1)
	sk, _ := o.Skills.Get("a1")
	// A caller deadline EARLIER than SkillTurnBudget always wins, so the turn
	// gathers its first round and then refuses to start another.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	ans, handled := o.answerSkill(ctx, runPrincipal(), "chain please",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk}, map[string]string{"correlation_id": "pa"}, nil)
	if !handled {
		t.Fatal("expected a handled turn — the first round did gather")
	}
	if got := len(ans.Chain); got != 1 {
		t.Fatalf("chain = %v, want a single round inside the time budget", chainNames(ans))
	}
	if !hasNote(ans.MissingEvidence, "time budget") {
		t.Errorf("hitting the time budget must be DISCLOSED, missing evidence = %v", ans.MissingEvidence)
	}
}

func hasNote(notes []string, want string) bool {
	for _, n := range notes {
		if strings.Contains(strings.ToLower(n), want) {
			return true
		}
	}
	return false
}

// ---- evidence accumulation -------------------------------------------------

func TestChainStateEvidenceDedupeAndCap(t *testing.T) {
	st := newChainState()
	first := st.addEvidence([]EvidenceItem{
		{CitationID: "verdict:pa", Kind: "finding", Text: "one"},
		{CitationID: "topo:dev-a", Kind: "topology", Text: "two"},
	})
	if len(first) != 2 {
		t.Fatalf("accepted %d items, want 2", len(first))
	}
	// The same rows gathered again by the NEXT skill are one fact, not two.
	second := st.addEvidence([]EvidenceItem{
		{CitationID: "VERDICT:PA", Kind: "finding", Text: "one (again)"},
		{CitationID: "log:1", Kind: "log", Text: "three"},
	})
	if len(second) != 1 || second[0].CitationID != "log:1" {
		t.Fatalf("round 2 contributed %+v, want only the new row", second)
	}
	if len(st.bundle) != 3 {
		t.Fatalf("bundle = %d rows, want 3 deduped rows", len(st.bundle))
	}
	// The bundle is re-capped at the prompt budget across rounds.
	big := make([]EvidenceItem, 0, 40)
	for i := 0; i < 40; i++ {
		big = append(big, EvidenceItem{
			CitationID: "big:" + strings.Repeat("z", i+1), Kind: "log",
			Text: strings.Repeat("x", 1000),
		})
	}
	st.addEvidence(big)
	if !st.capped {
		t.Error("exceeding the evidence budget must be recorded")
	}
	if st.chars > skillEvidenceMaxChars {
		t.Errorf("accumulated %d chars, over the %d budget", st.chars, skillEvidenceMaxChars)
	}
}

// Two skills that read the same tool must not double-cite the same row, and the
// answer's citations follow the deduped bundle.
func TestChainDedupesEvidenceAcrossRounds(t *testing.T) {
	o, _ := chainOrchestrator(t, MockLLM{Reply: "The link is down [verdict:plink]."})
	withProblem(t, o, "t-a", &Problem{
		ID: "plink", Title: "BGP peer down on edge-1", OperatorPhrase: linkPhrase,
		Verdict: "confirmed", Confidence: 0.9, Devices: []string{"edge-1"}, SignalCount: 3, NodeCount: 1,
	})
	sk, _ := o.Skills.Get("bgp-session-down")
	ans, _ := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "plink", "device": "edge-1"}, nil)
	if len(ans.Chain) < 2 {
		t.Fatalf("precondition: this turn must chain, got %v", chainNames(ans))
	}
	seen := map[string]bool{}
	for _, c := range ans.Citations {
		if seen[strings.ToLower(c.ID)] {
			t.Errorf("citation %q was returned twice across the chain", c.ID)
		}
		seen[strings.ToLower(c.ID)] = true
	}
	// Both rounds read get_rca_verdict, so the lookup list records both runs
	// while the evidence stays deduped.
	if len(ans.Lookups) < 2 {
		t.Errorf("lookups = %v, want one entry per executed tool call", ans.Lookups)
	}
}

// ---- provenance ------------------------------------------------------------

func TestChainJSONIsBackwardCompatible(t *testing.T) {
	ans := Answer{
		Mode:  ModeTroubleshootFinding,
		Skill: ptrSkillRef(SkillRef{Name: "interface-down", Layer: "physical", Version: 2}),
		Chain: []SkillHop{
			{SkillRef: SkillRef{Name: "bgp-session-down", Layer: "bgp", Version: 3}, Selected: ChainSelectedEntry, Round: 1},
			{SkillRef: SkillRef{Name: "interface-down", Layer: "physical", Version: 2}, Selected: ChainSelectedRule, Round: 2, Reason: "the RCA verdict names a link"},
		},
	}
	raw, err := json.Marshal(ans)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Skill *SkillRef `json:"skill"`
		Chain []struct {
			Name     string `json:"name"`
			Layer    string `json:"layer"`
			Version  int    `json:"version"`
			Selected string `json:"selected"`
			Round    int    `json:"round"`
			Reason   string `json:"reason"`
		} `json:"chain"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Skill == nil || decoded.Skill.Name != "interface-down" {
		t.Fatalf("the existing `skill` stamp must survive: %+v", decoded.Skill)
	}
	if len(decoded.Chain) != 2 || decoded.Chain[0].Name != "bgp-session-down" ||
		decoded.Chain[1].Selected != ChainSelectedRule || decoded.Chain[1].Round != 2 {
		t.Fatalf("chain JSON = %+v", decoded.Chain)
	}
	if decoded.Chain[0].Version != 3 || decoded.Chain[0].Layer != "bgp" {
		t.Errorf("a hop must carry the full skill stamp: %+v", decoded.Chain[0])
	}
	// An answer with no chain must not emit the key at all (older UIs).
	bare, err := json.Marshal(Answer{Mode: ModeTroubleshootFinding})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(bare), "\"chain\"") {
		t.Errorf("an unchained answer must omit `chain`: %s", bare)
	}
}

func TestParseAndStripNextDirective(t *testing.T) {
	cases := []struct {
		text    string
		want    string
		present bool
	}{
		{"Looks physical.\nNEXT: interface-down", "interface-down", true},
		{"NEXT: none", "none", true},
		{"next: Interface-Down", "interface-down", true},
		{"- NEXT: `interface-down`", "interface-down", true},
		{"NEXT: interface-down\nNEXT: mac-flap", "mac-flap", true}, // the LAST directive wins
		{"No idea.", "", false},
		{"NEXT:", "", true},
		{"NEXT: " + strings.Repeat("z", 200), "", true},
	}
	for _, tc := range cases {
		got, present := parseNextDirective(tc.text)
		if got != tc.want || present != tc.present {
			t.Errorf("parseNextDirective(%q) = (%q,%v), want (%q,%v)", tc.text, got, present, tc.want, tc.present)
		}
	}
	if got := stripNextDirective("The link is down.\nNEXT: interface-down"); strings.Contains(got, "NEXT") {
		t.Errorf("stripNextDirective left the directive in: %q", got)
	}
	if got := stripNextDirective("The link is down."); got != "The link is down." {
		t.Errorf("stripNextDirective must not touch ordinary text: %q", got)
	}
}

// A final reply that is NOTHING but a routing directive must degrade to the
// deterministic summary, never to an empty answer.
func TestChainNarrationThatIsOnlyADirectiveFallsBack(t *testing.T) {
	o, _ := chainOrchestrator(t, &scriptLLM{replies: []string{"NEXT: none"}, fallback: "NEXT: none"})
	sk, _ := o.Skills.Get("bgp-session-down")
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("expected a handled turn")
	}
	if strings.TrimSpace(ans.Text) == "" {
		t.Fatal("an answer must never ship empty text")
	}
	if strings.Contains(strings.ToUpper(ans.Text), "NEXT:") {
		t.Errorf("a directive reached the operator: %q", ans.Text)
	}
	if !ans.EvidenceOnly {
		t.Error("a reply with no narrative must be flagged evidence-only")
	}
}

// ---- isolation (§3a) -------------------------------------------------------

// Entities are bound ONCE, from UI context and the question, under the caller's
// tenant. A skill selected in a later round inherits that binding: it cannot
// resolve a device the first round did not, and nothing the MODEL wrote in a
// routing turn is ever offered to the inventory.
func TestChainResolvesEntitiesOnceAndCannotWidenScope(t *testing.T) {
	llm := &scriptLLM{replies: []string{
		// The routing turn names ANOTHER tenant's device in its prose.
		"leaf-2 in the other estate looks similar.\nNEXT: interface-down",
		"Nothing further.\nNEXT: none",
		"Final [verdict:pa].",
	}}
	o, _ := chainOrchestrator(t, llm)
	type ask struct{ tenant, ref string }
	var asked []ask
	base := stubDeps()
	o.Troubleshoot = TroubleshootDeps{
		ResolveDevice: func(ctx context.Context, p Principal, ref string) (DeviceRef, error) {
			asked = append(asked, ask{p.Tenant, ref})
			return base.ResolveDevice(ctx, p, ref)
		},
	}
	o.Tools = Tools(o.DS)
	o.Tools.AddTroubleshootTools(o.DS, o.Troubleshoot)

	sk, _ := o.Skills.Get("bgp-session-down")
	ans, handled := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil)
	if !handled || len(ans.Chain) != 2 {
		t.Fatalf("precondition: this turn must chain to a second skill, got %v", chainNames(ans))
	}
	if len(asked) == 0 {
		t.Fatal("the turn must resolve its entities")
	}
	for _, a := range asked {
		if a.tenant != "t-a" {
			t.Errorf("a resolution ran under tenant %q, not the caller's", a.tenant)
		}
		if strings.Contains(a.ref, "leaf-2") {
			t.Errorf("a name the MODEL wrote was offered to the inventory: %q", a.ref)
		}
	}
	// Resolution happens once per turn, not once per hop: the SECOND round asked
	// the inventory nothing new.
	oneRound := len(asked)
	asked = nil
	llm2 := &scriptLLM{replies: []string{"Nothing further.\nNEXT: none", "Final [verdict:pa]."}}
	o.LLM = llm2
	if _, ok := o.answerSkill(context.Background(), runPrincipal(), "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "pa", "device": "edge-1"}, nil); !ok {
		t.Fatal("the single-round turn must still be handled")
	}
	if len(asked) != oneRound {
		t.Errorf("a chained turn resolved %d times vs %d for one round — the binding is not once-per-turn",
			oneRound, len(asked))
	}
}

// A second-round skill cannot reach a device outside the FIRST round's tenant
// binding: for a caller who cannot see edge-1, every device-bound step of every
// hop is dropped honestly rather than run at a wider scope.
func TestChainSecondRoundCannotReachAnotherTenantsDevice(t *testing.T) {
	o, audit := chainOrchestrator(t, MockLLM{Reply: "The link is down [verdict:pb]."})
	withProblem(t, o, "t-b", &Problem{
		ID: "pb2", Title: "BGP peer down on leaf-2", OperatorPhrase: linkPhrase,
		Verdict: "confirmed", Confidence: 0.8, Devices: []string{"leaf-2"}, SignalCount: 2, NodeCount: 1,
	})
	other := Principal{Tenant: "t-b", Perms: map[string]bool{
		"correlations:read": true, "infrastructure:read": true, "logs:read": true,
	}}
	sk, _ := o.Skills.Get("bgp-session-down")
	// The question and the UI context both name TENANT A's device.
	ans, handled := o.answerSkill(context.Background(), other, "why is bgp down on edge-1",
		Plan{Intent: "troubleshoot"}, SkillMatch{Skill: sk},
		map[string]string{"correlation_id": "pb2", "device": "edge-1"}, nil)
	if !handled {
		t.Fatal("the caller's OWN case still grounds the turn")
	}
	if len(ans.Chain) < 2 {
		t.Fatalf("precondition: the rule must chain this turn, got %v", chainNames(ans))
	}
	for _, e := range *audit {
		for _, a := range e.Args {
			if a == "device" || a == "device_id" {
				t.Errorf("round %d ran %s with a device binding the caller cannot see: %+v", e.Round, e.Tool, e)
			}
		}
	}
	if !hasNote(ans.MissingEvidence, "no device in this tenant's inventory") &&
		!hasNote(ans.Disclaimers, "no device in this tenant's inventory") {
		t.Logf("missing evidence = %v", ans.MissingEvidence)
	}
}
