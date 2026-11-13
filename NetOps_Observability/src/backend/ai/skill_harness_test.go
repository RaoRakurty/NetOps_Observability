// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_harness_test.go — the case runner itself (tracker 337 N-F2): it reaches
// nothing, and each assertion it makes actually fires.

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"netops/backend/internal/irishypo"
)

// ---- it reaches nothing ------------------------------------------------------

type refuseTransport struct{ calls *int }

func (r refuseTransport) RoundTrip(*http.Request) (*http.Response, error) {
	*r.calls++
	return nil, errors.New("the harness reached the network")
}

func TestRunCasesTouchesNothing(t *testing.T) {
	calls := 0
	prev := http.DefaultTransport
	http.DefaultTransport = refuseTransport{calls: &calls}
	t.Cleanup(func() { http.DefaultTransport = prev })

	var touched []string
	env := harnessEnv{onTouch: func(what string) { touched = append(touched, what) }}

	base := loadTestSkills(t)
	for _, name := range base.Names() {
		sk, _ := base.Get(name)
		if rep := runCases(base, sk, env); !rep.Passed() {
			t.Errorf("%s: %+v", name, rep)
		}
	}
	set, sk := overlayRunbook(t)
	if rep := runCases(set, sk, env); !rep.Passed() {
		t.Errorf("the runbook: %+v", rep)
	}
	if len(touched) != 0 {
		t.Errorf("the harness reached a seam it only wires for registration: %v", touched)
	}
	if calls != 0 {
		t.Errorf("the harness made %d HTTP calls", calls)
	}
}

// The seam must be live, or the test above proves nothing.
func TestHarnessTouchSeamFires(t *testing.T) {
	var touched []string
	env := harnessEnv{onTouch: func(what string) { touched = append(touched, what) }}
	ctx := context.Background()
	p := harnessPrincipal()

	ds := harnessDS{env: env}
	if _, err := ds.GetProblem(ctx, p, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetProblem: %v", err)
	}
	if _, err := ds.GetProblemEvidence(ctx, p, "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetProblemEvidence: %v", err)
	}
	if _, err := ds.ListActiveProblems(ctx, p, 1); err != nil {
		t.Errorf("ListActiveProblems: %v", err)
	}
	if _, err := ds.ModuleQuery(ctx, p, "q", nil); err != nil {
		t.Errorf("ModuleQuery: %v", err)
	}
	d := harnessDeps(env, SkillCase{})
	calls := []func() error{
		func() error { _, err := d.ProtocolDiagnostic(ctx, p, DiagnosticRequest{}); return err },
		func() error { _, err := d.SecurityFindings(ctx, p, FindingsQuery{}); return err },
		func() error { _, err := d.TopologyContext(ctx, p, ""); return err },
		func() error { _, err := d.CaseTimeline(ctx, p, ""); return err },
		func() error { _, err := d.DeviceState(ctx, p, DeviceStateRequest{}); return err },
		func() error { _, err := d.BGPWatchlist(ctx, p); return err },
		func() error { _, err := d.BGPRPKI(ctx, p); return err },
		func() error { _, err := d.BGPFeedRecent(ctx, p, "", 1); return err },
		func() error { _, err := d.RecallInvestigations(ctx, p, InvestigationQuery{}); return err },
		func() error { _, err := d.RecentChanges(ctx, p, ChangeQuery{}); return err },
		func() error { _, err := d.ConfigDiff(ctx, p, ConfigDiffRequest{}); return err },
	}
	for _, call := range calls {
		if err := call(); err != nil {
			t.Errorf("a registration seam failed: %v", err)
		}
	}
	if want := 4 + len(calls); len(touched) != want {
		t.Errorf("%d touches reported, want %d: %v", len(touched), want, touched)
	}
	// A touch with no listener is a no-op, not a crash.
	harnessEnv{}.touch("nobody")
}

func TestHarnessImportsNoNetworkPackage(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "skill_harness.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range f.Imports {
		p, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			t.Fatal(uerr)
		}
		if p == "net" || strings.HasPrefix(p, "net/") || strings.Contains(p, "/http") {
			t.Errorf("skill_harness.go imports %s", p)
		}
	}
}

func TestHarnessResolvesOnlyTheFixtureInventory(t *testing.T) {
	c := SkillCase{UI: map[string]string{"device": "acme-core-1"}}
	for ref, wantID := range map[string]string{"edge-1": "dev-a", "dev-a": "dev-a", "acme-core-1": "acme-core-1"} {
		got, err := harnessResolveDevice(c, ref)
		if err != nil || got.ID != wantID {
			t.Errorf("%s: %+v %v", ref, got, err)
		}
	}
	for _, ref := range []string{"", "somebody-elses-router"} {
		if _, err := harnessResolveDevice(c, ref); !errors.Is(err, ErrNotFound) {
			t.Errorf("%q must not resolve: %v", ref, err)
		}
	}
}

// ---- what it reports ---------------------------------------------------------

func TestRunCasesRefusesWhatItCannotRun(t *testing.T) {
	set := loadTestSkills(t)
	if rep := RunCases(set, nil); rep.Passed() || rep.NotRun == "" {
		t.Errorf("nil skill: %+v", rep)
	}
	stranger := &Skill{Name: "not-in-the-set", Cases: []SkillCase{{Name: "c"}}}
	if rep := RunCases(set, stranger); rep.Passed() || !strings.Contains(rep.NotRun, "not in the given set") {
		t.Errorf("stranger: %+v", rep)
	}
	var none *SkillSet
	if rep := RunCases(none, stranger); rep.Passed() {
		t.Errorf("nil set: %+v", rep)
	}
	caseless := *mustSkill(t, set, "mac-flap")
	caseless.Cases = nil
	if rep := RunCases(set, &caseless); rep.Passed() || !strings.Contains(rep.NotRun, "no cases") {
		t.Errorf("no cases: %+v", rep)
	}
}

func TestRunCasesSurvivesACrashingCase(t *testing.T) {
	// A skill with no layer panics in skillTitle. A submission must not be able to
	// take the caller down with it.
	sk := &Skill{Name: "crasher", Origin: SkillOriginTenant, TenantID: "t-a",
		Tools:  []string{"get_active_major_incidents"},
		Gather: []GatherStep{{Tool: "get_active_major_incidents", Bind: map[string]string{}, Args: map[string]string{}}},
		Cases:  []SkillCase{{Name: "boom", Question: "q", Evidence: []string{"finding"}}},
	}
	set := compiledWithExtra(t, sk)
	rep := RunCases(set, sk)
	if rep.Passed() || len(rep.Cases) != 1 || !strings.Contains(strings.Join(rep.Cases[0].Failures, " "), "crashed") {
		t.Fatalf("report = %+v", rep)
	}
}

func mustSkill(t *testing.T, set *SkillSet, name string) *Skill {
	t.Helper()
	sk, ok := set.Get(name)
	if !ok {
		t.Fatalf("%s is not loaded", name)
	}
	return sk
}

// oneCase re-runs one authored case with an extra expectation, so a failure below
// is attributable to that expectation alone.
func oneCase(t *testing.T, name string, mut func(*Skill, *SkillCase)) []string {
	t.Helper()
	set := loadTestSkills(t)
	sk := *mustSkill(t, set, name)
	c := sk.Cases[0]
	mut(&sk, &c)
	return runCaseGuarded(set, &sk, c, harnessEnv{}).Failures
}

func TestExpectNeverToolsFires(t *testing.T) {
	failures := oneCase(t, "bgp-session-down", func(_ *Skill, c *SkillCase) {
		c.ExpectNeverTools = []string{"run_protocol_diagnostic"} // the method really does gather it
	})
	if !strings.Contains(strings.Join(failures, "\n"), `attempted "run_protocol_diagnostic", which this case prohibits`) {
		t.Fatalf("failures = %v", failures)
	}
}

// A denied tool was still ATTEMPTED: the prohibition is about the attempt, and the
// audit is where that is recorded.
func TestExpectNeverToolsFiresOnADeniedAttempt(t *testing.T) {
	failures := oneCase(t, "bgp-session-down", func(_ *Skill, c *SkillCase) {
		c.Tools = map[string]string{"run_protocol_diagnostic": "denied"}
		c.ExpectNeverTools = []string{"run_protocol_diagnostic"}
	})
	if !strings.Contains(strings.Join(failures, "\n"), "which this case prohibits") {
		t.Fatalf("failures = %v", failures)
	}
}

func TestEveryInvokedToolMustBeDeclaredOnTheExpectedPath(t *testing.T) {
	failures := oneCase(t, "log-confirmation", func(sk *Skill, c *SkillCase) {
		// The set's skill is what declares; the entry skill gathers something more.
		sk.Gather = append(append([]GatherStep(nil), sk.Gather...),
			GatherStep{Tool: "get_active_major_incidents", Bind: map[string]string{}, Args: map[string]string{}})
	})
	if !strings.Contains(strings.Join(failures, "\n"), `attempted "get_active_major_incidents", which no method on the expected path declares`) {
		t.Fatalf("failures = %v", failures)
	}
}

func TestExpectHypothesesFires(t *testing.T) {
	set := loadTestSkills(t)
	sk := mustSkill(t, set, "bgp-session-down")
	var c SkillCase
	for _, k := range sk.Cases {
		if len(k.ExpectHypotheses) > 0 {
			c = k
			break
		}
	}
	if c.Name == "" {
		t.Fatal("no compiled case asserts a hypothesis")
	}
	wrong := c
	wrong.ExpectHypotheses = []SkillHypothesisExpect{{ID: c.ExpectHypotheses[0].ID, State: irishypo.Rejected}}
	res := runCaseGuarded(set, sk, wrong, harnessEnv{})
	if !strings.Contains(strings.Join(res.Failures, "\n"), "the case says REJECTED") {
		t.Errorf("a wrong state: %v", res.Failures)
	}
	missing := c
	missing.ExpectHypotheses = []SkillHypothesisExpect{{ID: "control-plane-pressure", State: irishypo.Supported}}
	res = runCaseGuarded(set, sk, missing, harnessEnv{})
	if !strings.Contains(strings.Join(res.Failures, "\n"), "never opened") {
		t.Errorf("an unopened hypothesis: %v", res.Failures)
	}
}

func TestTheCorpusUsesTheNewKeys(t *testing.T) {
	set := loadTestSkills(t)
	never, hyp := 0, 0
	for _, name := range set.Names() {
		for _, c := range mustSkill(t, set, name).Cases {
			never += len(c.ExpectNeverTools)
			hyp += len(c.ExpectHypotheses)
		}
	}
	if never == 0 || hyp == 0 {
		t.Fatalf("expect_never_tools %d, expect_hypotheses %d", never, hyp)
	}
}

func TestTheRunbookStaysDataAssertionFires(t *testing.T) {
	set, sk := overlayRunbook(t)
	chain := []SkillHop{{SkillRef: sk.Ref(), Selected: ChainSelectedEntry, Round: 1}}
	clean := skillSystemBlock(sk)

	f := &caseFailures{}
	assertRunbookStaysData(f, set, chain, &harnessProvider{systems: []string{clean}})
	if len(f.list) != 0 {
		t.Errorf("a clean turn failed: %v", f.list)
	}

	f = &caseFailures{}
	assertRunbookStaysData(f, set, chain, &harnessProvider{systems: []string{clean + sk.Body}})
	if !strings.Contains(strings.Join(f.list, "\n"), "reached a system prompt") {
		t.Errorf("a leaked body: %v", f.list)
	}

	f = &caseFailures{}
	assertRunbookStaysData(f, set, chain, &harnessProvider{systems: []string{"no fence here"}})
	if !strings.Contains(strings.Join(f.list, "\n"), "does not carry the data-not-instructions fence") {
		t.Errorf("a missing fence: %v", f.list)
	}

	// A runbook line that merely repeats the server's own words is not a leak.
	sk.Body = "HARD RULES FOR THIS TURN:"
	f = &caseFailures{}
	assertRunbookStaysData(f, set, chain, &harnessProvider{systems: []string{skillSystemBlock(sk)}})
	if len(f.list) != 0 {
		t.Errorf("shared server wording failed: %v", f.list)
	}
}

// For a runbook, "the verdict reached the model" means the USER message.
func TestRunbookVerdictIsCheckedInTheUserMessage(t *testing.T) {
	sk := parseRunbook(t, "t-a")
	o := &Orchestrator{}
	c := SkillCase{ExpectVerdict: []string{"carrier circuit"}}
	system := skillSystemBlock(sk)

	f := &caseFailures{}
	assertCaseVerdict(f, o, &harnessProvider{systems: []string{system},
		prompts: []string{o.skillPrompt("q", sk, nil, nil, SkillMatch{})}}, sk, c)
	if len(f.list) != 0 {
		t.Errorf("a verdict in the user message failed: %v", f.list)
	}

	f = &caseFailures{}
	assertCaseVerdict(f, o, &harnessProvider{systems: []string{system}, prompts: []string{"nothing"}}, sk, c)
	if !strings.Contains(strings.Join(f.list, "\n"), "never reached the narration's user message") {
		t.Errorf("a verdict that never arrived: %v", f.list)
	}
}

func TestATenantRunbooksCasesRunThroughTheSameRunner(t *testing.T) {
	set, sk := overlayRunbook(t)
	rep := RunCases(set, sk)
	if !rep.Passed() {
		t.Fatalf("%+v", rep)
	}
	if rep.Origin != SkillOriginTenant || rep.Version != 2 || len(rep.Cases) != 2 {
		t.Errorf("report = %+v", rep)
	}
	for _, c := range rep.Cases {
		if len(c.Chain) == 0 || len(c.Tools) == 0 {
			t.Errorf("case %q reports no path: %+v", c.Name, c)
		}
	}
}

// ---- the fingerprint ---------------------------------------------------------

func TestHarnessFingerprintIsStable(t *testing.T) {
	tiers := TierModels{Default: "m", Fast: "f", Strong: "s"}
	got := HarnessFingerprint(tiers)
	if len(got) != 64 {
		t.Fatalf("fingerprint = %q", got)
	}
	for i := 0; i < 5; i++ {
		if HarnessFingerprint(tiers) != got {
			t.Fatal("the fingerprint depends on map order")
		}
	}
}

// Every input, flipped on its own, moves the fingerprint.
func TestHarnessFingerprintCoversEveryInput(t *testing.T) {
	flips := map[string]func(*harnessInputs){
		"system prompt":     func(h *harnessInputs) { h.systemPrompt += "x" },
		"template version":  func(h *harnessInputs) { h.templateVersion += "x" },
		"fence":             func(h *harnessInputs) { h.fence += "x" },
		"tool metas":        func(h *harnessInputs) { h.toolMetas += "x" },
		"tool allowlist":    func(h *harnessInputs) { h.toolAllowlist += "x" },
		"state facets":      func(h *harnessInputs) { h.stateFacets += "x" },
		"fact values":       func(h *harnessInputs) { h.factValues += "x" },
		"contract versions": func(h *harnessInputs) { h.contractVersions += "x" },
		"hypothesis ids":    func(h *harnessInputs) { h.hypothesisIDs += "x" },
		"compiled skills":   func(h *harnessInputs) { h.compiledSkills += "x" },
		"tier models":       func(h *harnessInputs) { h.tierModels += "x" },
	}
	base := liveHarnessInputs(TierModels{Default: "m"})
	want := base.fingerprint()
	for name, flip := range flips {
		h := base
		flip(&h)
		if h.fingerprint() == want {
			t.Errorf("flipping %s does not move the fingerprint", name)
		}
	}
	// A byte cannot move between two inputs unnoticed.
	left, right := base, base
	left.systemPrompt += "x"
	right.fence = "x" + base.fence
	if left.fingerprint() == right.fingerprint() {
		t.Error("a byte moved across an input boundary without moving the fingerprint")
	}
}

// liveFlip proves HarnessFingerprint READS a table, not merely that it hashes a
// field. Tests in this package do not run in parallel.
func TestHarnessFingerprintReadsTheLiveTables(t *testing.T) {
	tiers := TierModels{Default: "m"}
	flips := map[string]func() (restore func()){
		"tool allowlist": func() func() {
			skillToolAllowlist["fingerprint_probe"] = true
			return func() { delete(skillToolAllowlist, "fingerprint_probe") }
		},
		"tool metas": func() func() {
			toolMetas["fingerprint_probe"] = toolMeta{description: "probe"}
			return func() { delete(toolMetas, "fingerprint_probe") }
		},
		"a tool's description": func() func() {
			was := toolMetas["search_logs"]
			m := was
			m.description += "x"
			toolMetas["search_logs"] = m
			return func() { toolMetas["search_logs"] = was }
		},
		"state facets": func() func() {
			skillStateFacets["fingerprint_probe"] = map[string]bool{"x": true}
			return func() { delete(skillStateFacets, "fingerprint_probe") }
		},
		"a contract version": func() func() {
			was := toolContracts["search_logs"]
			c := was
			c.Version++
			toolContracts["search_logs"] = c
			return func() { toolContracts["search_logs"] = was }
		},
	}
	want := HarnessFingerprint(tiers)
	for name, flip := range flips {
		restore := flip()
		moved := HarnessFingerprint(tiers)
		restore()
		if moved == want {
			t.Errorf("changing %s does not move the fingerprint", name)
		}
	}
	if HarnessFingerprint(tiers) != want {
		t.Fatal("a flip was not restored")
	}

	live := liveHarnessInputs(tiers)
	if live.systemPrompt != (&Orchestrator{}).baseSystemPrompt() {
		t.Error("the fingerprint does not read the base system prompt")
	}
	if live.fence != DataNotInstructionsFence() {
		t.Error("the fingerprint does not read the fence")
	}
	if live.templateVersion != strconv.Itoa(skillPromptTemplateVersion) {
		t.Error("the fingerprint does not read the template version")
	}
	for _, d := range irishypo.Catalogue() {
		if !strings.Contains(live.hypothesisIDs, d.ID) {
			t.Errorf("the fingerprint does not read hypothesis %s", d.ID)
		}
	}
	set := loadTestSkills(t)
	for _, name := range set.Names() {
		at := name + "@" + strconv.Itoa(mustSkill(t, set, name).Version)
		if !strings.Contains(live.compiledSkills, at) {
			t.Errorf("the fingerprint does not read %s", at)
		}
	}
}

func TestHarnessFingerprintFollowsTheModels(t *testing.T) {
	base := HarnessFingerprint(TierModels{Default: "m"})
	for name, tiers := range map[string]TierModels{
		"default": {Default: "other"},
		"fast":    {Default: "m", Fast: "other"},
		"strong":  {Default: "m", Strong: "other"},
	} {
		if HarnessFingerprint(tiers) == base {
			t.Errorf("changing the %s model does not move the fingerprint", name)
		}
	}
	// Two configurations that call the same models are the same configuration.
	if HarnessFingerprint(TierModels{Default: "m", Fast: "m", Strong: "m"}) != base {
		t.Error("an explicit override equal to the default moved the fingerprint")
	}
}
