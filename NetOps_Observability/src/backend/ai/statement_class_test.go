// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// statement_class_test.go — statement classes and their grounding rules
// (tracker 337 N-B4). Unit tests drive groundStatements / rewriteChangeCauses
// over a server-built context; end-to-end tests drive the real explain and
// skill paths, and replay the N-H1 golden coincident-change cases.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func hasDisclaimer(disc []string, sub string) bool {
	for _, d := range disc {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}

// ctxWith builds a statement context from (tool, item) pairs.
func ctxWith(verdict string, pairs ...any) *statementContext {
	sc := &statementContext{verdict: verdict}
	for i := 0; i+1 < len(pairs); i += 2 {
		sc.stamp(pairs[i+1].(EvidenceItem), pairs[i].(string))
	}
	return sc
}

var (
	itLog      = EvidenceItem{CitationID: "log:os:1", Kind: "log", Text: "edge-1 Ethernet1/1 changed state to down"}
	itEngine   = EvidenceItem{CitationID: "hypothesis:p1:0", Kind: "finding", Text: "candidate cause: Optical loss of signal on edge-1 — confirmed", CauseRole: CauseRoleEngine}
	itCand     = EvidenceItem{CitationID: "hypothesis:p1:1", Kind: "finding", Text: "candidate cause: High CPU on edge-1 — suspected", CauseRole: CauseRoleCandidate}
	itCandChg  = EvidenceItem{CitationID: "hypothesis:p1:2", Kind: "finding", Text: "candidate cause: Configuration change on edge-1 at 10:02 — suspected", CauseRole: CauseRoleCandidate, Change: true}
	itChange   = EvidenceItem{CitationID: "config:dev-a:9f2c", Kind: "config", Text: "edge-1 — changed on 2026-10-01T10:02:00Z (+3/-1 lines)"}
	itRecall   = EvidenceItem{CitationID: "inv:7", Kind: "finding", Text: "prior conclusion: optic failure on edge-1"}
	itDoc      = EvidenceItem{CitationID: "doc:bfd", Kind: "doc", Text: "BFD timers guide"}
	itDerived  = EvidenceItem{CitationID: "query:1", Kind: "finding", Text: "42 interfaces down in the window"}
	itNoClass  = EvidenceItem{CitationID: "mystery:1", Kind: "finding", Text: "an item from an unclassified tool"}
	itVerdict  = EvidenceItem{CitationID: "verdict:p1", Kind: "finding", Text: "P-1 — Optical loss of signal on edge-1; verdict confirmed", CauseRole: CauseRoleEngine}
	itProblemB = EvidenceItem{CitationID: "log:os:9", Kind: "log", Text: "TENANT-B-ONLY evidence row"}
)

func only(t *testing.T, g statementOutcome) Statement {
	t.Helper()
	if len(g.statements) != 1 {
		t.Fatalf("statements = %+v, want exactly one", g.statements)
	}
	return g.statements[0]
}

// ---- each class's grounding rule, positive and negative --------------------

func TestObservedNeedsAnObservedCitation(t *testing.T) {
	sc := ctxWith("", "search_logs", itLog)
	st := only(t, groundStatements("Ethernet1/1 went down at 10:06 [log:os:1].", sc))
	if st.Class != ClassObserved || !st.Grounded || len(st.Citations) != 1 || st.Citations[0] != "log:os:1" {
		t.Errorf("a sentence citing a live read must be OBSERVED and grounded: %+v", st)
	}
	// Negative: the same claim with no citation is never presented as an
	// observation — it is downgraded, and says so.
	st = only(t, groundStatements("Ethernet1/1 went down at 10:06.", sc))
	if st.Class == ClassObserved || st.Grounded || st.Note == "" {
		t.Errorf("an uncited claim must be downgraded with a note, got %+v", st)
	}
	// An item from a tool with no class supports no class.
	sc = ctxWith("", "mystery_tool", itNoClass)
	st = only(t, groundStatements("Something happened [mystery:1].", sc))
	if st.Grounded {
		t.Errorf("an unclassified tool's item must ground nothing: %+v", st)
	}
}

func TestCorrelixRCANeedsTheEnginesEvidence(t *testing.T) {
	sc := ctxWith("suspected", "get_problem_evidence", itEngine, "search_logs", itLog)
	st := only(t, groundStatements("Correlix's analysis ranks the optical loss first [hypothesis:p1:0].", sc))
	if st.Class != ClassCorrelixRCA || !st.Grounded {
		t.Errorf("a Correlix claim citing the engine must be CORRELIX_RCA and grounded: %+v", st)
	}
	// Attributed to Correlix but citing only a log line: downgraded, because
	// the turn does hold the engine's evidence.
	st = only(t, groundStatements("Correlix's analysis ranks the optical loss first [log:os:1].", sc))
	if st.Class != ClassCorrelixRCA || st.Grounded || st.Note == "" {
		t.Errorf("a Correlix claim without an engine citation must be downgraded: %+v", st)
	}
	// Negative: no engine evidence in the turn at all — fabricated authority.
	sc = ctxWith("", "search_logs", itLog)
	g := groundStatements("Correlix's analysis identified a fibre cut on edge-1. Ethernet1/1 went down [log:os:1].", sc)
	if g.ungrounded != 1 || strings.Contains(g.text, "fibre cut") || !strings.Contains(g.text, "went down") {
		t.Errorf("a Correlix claim with no engine evidence in the turn must be removed: %+v", g)
	}
	// A hedged statement about the engine is the honest disclosure: kept.
	g = groundStatements("Correlix has not identified a cause for this yet.", sc)
	if g.ungrounded != 0 || len(g.statements) != 1 {
		t.Errorf("an honest, hedged statement about the engine must survive: %+v", g)
	}
}

func TestHistoricalNeedsAPastInvestigation(t *testing.T) {
	sc := ctxWith("", "recall_investigations", itRecall, "search_logs", itLog)
	st := only(t, groundStatements("A past investigation on edge-1 concluded an optic failure [inv:7].", sc))
	if st.Class != ClassHistorical || !st.Grounded {
		t.Errorf("a history claim citing recall must be HISTORICAL and grounded: %+v", st)
	}
	sc = ctxWith("", "search_logs", itLog)
	g := groundStatements("A past investigation on edge-1 concluded an optic failure.", sc)
	if g.ungrounded != 1 || len(g.statements) != 0 {
		t.Errorf("a history claim with no recalled investigation must be removed: %+v", g)
	}
}

func TestDocumentationNeedsADocsCitation(t *testing.T) {
	sc := ctxWith("", "search_docs", itDoc)
	st := only(t, groundStatements("According to the documentation, BFD needs matching timers on both ends [doc:bfd].", sc))
	if st.Class != ClassDocumentation || !st.Grounded {
		t.Errorf("a docs claim citing docs must be DOCUMENTATION and grounded: %+v", st)
	}
	sc = ctxWith("", "search_logs", itLog)
	g := groundStatements("According to the documentation, this platform drops BFD under load.", sc)
	if g.ungrounded != 1 {
		t.Errorf("a docs claim with no documentation in the turn must be removed: %+v", g)
	}
	// Guidance was shown without a citable id (the problem path's playbooks):
	// downgraded, not removed.
	sc.docsInTurn = true
	st = only(t, groundStatements("According to the documentation, this platform drops BFD under load.", sc))
	if st.Class != ClassDocumentation || st.Grounded || st.Note == "" {
		t.Errorf("an uncited docs claim with guidance in the turn must be downgraded: %+v", st)
	}
}

func TestDerivedIsAComputedResultOrDowngradedReading(t *testing.T) {
	sc := ctxWith("", "compile_query", itDerived)
	st := only(t, groundStatements("42 interfaces were down in the window [query:1].", sc))
	if st.Class != ClassDerived || !st.Grounded {
		t.Errorf("a sentence citing a computed result must be DERIVED and grounded: %+v", st)
	}
	st = only(t, groundStatements("That looks like a power event.", sc))
	if st.Class != ClassDerived || st.Grounded {
		t.Errorf("an uncited reading must be DERIVED and not grounded: %+v", st)
	}
}

func TestRecommendationIsAdviceButCannotCarryACause(t *testing.T) {
	sc := ctxWith("", "search_logs", itLog)
	for _, s := range []string{"Next: check the optic on edge-1.", "- Compare the running configuration with the previous capture.", "You should reseat the optic."} {
		st := only(t, groundStatements(s, sc))
		if st.Class != ClassRecommendation || !st.Grounded {
			t.Errorf("%q must be a RECOMMENDATION: %+v", s, st)
		}
	}
	// Negative: a recommendation that asserts a cause the engine did not
	// confirm is judged as the cause claim it is.
	g := groundStatements("Check the optic, because the outage was caused by it [log:os:1].", sc)
	if g.unconfirmedCause != 1 || len(g.statements) != 0 {
		t.Errorf("a recommendation smuggling a cause must be removed: %+v", g)
	}
}

// ---- R2: the engine's OWN cause only ----------------------------------------

func TestCauseSentenceNeedsTheEnginesOwnConfirmedCause(t *testing.T) {
	cases := []struct {
		name, verdict, text string
		keep, foreign       bool
	}{
		{"confirmed, own cause", "confirmed", "The root cause is the optical loss of signal on edge-1 [hypothesis:p1:0].", true, false},
		{"confirmed, own cause plus an observation", "confirmed", "The link loss was caused by the optical loss of signal [hypothesis:p1:0] [log:os:1].", true, false},
		{"confirmed, a DIFFERENT ranked cause", "confirmed", "The link loss was caused by high CPU on edge-1 [hypothesis:p1:1].", false, true},
		{"confirmed, own and a different cause together", "confirmed", "The outage resulted in loss because of high CPU [hypothesis:p1:1] [hypothesis:p1:0].", false, true},
		{"confirmed, only an observation cited", "confirmed", "The root cause is a BGP reset on core-1 [log:os:1].", false, true},
		{"confirmed, uncited", "confirmed", "The root cause is a BGP reset on core-1.", false, true},
		{"confirmed, own cause but blames a change", "confirmed", "The root cause is the configuration change behind the optical loss [hypothesis:p1:0].", false, true},
		{"suspected, own hypothesis", "suspected", "The loss led to the outage [hypothesis:p1:0].", false, false},
		{"no verdict, active voice", "", "High CPU triggered the BGP session loss [log:os:1].", false, false},
		{"hedged under no verdict", "", "The outage was possibly caused by high CPU [log:os:1].", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := ctxWith(c.verdict, "get_problem_evidence", itEngine, "get_problem_evidence", itCand, "search_logs", itLog)
			g := groundStatements(c.text, sc)
			kept := len(g.statements) == 1
			if kept != c.keep {
				t.Fatalf("kept = %v, want %v: %+v", kept, c.keep, g)
			}
			if !c.keep && (g.foreignCause == 1) != c.foreign {
				t.Errorf("foreign = %d, want %v", g.foreignCause, c.foreign)
			}
			if c.keep && !c.foreign && c.verdict == "confirmed" && g.statements[0].Class != ClassCorrelixRCA {
				t.Errorf("a kept cause sentence is the engine's statement: %+v", g.statements[0])
			}
		})
	}
}

// ---- R5 / R6: a change is temporally correlated unless the engine says so ---

func TestChangeNamedAsCauseIsRewordedWithThePosition(t *testing.T) {
	cases := []struct {
		name, verdict string
		chain         *changeChainView
		item          EvidenceItem
		tool, cite    string
		want          string
	}{
		{"candidate on a confirmed verdict", "confirmed", nil, itCandChg, "get_problem_evidence", "hypothesis:p1:2", "unconfirmed candidate cause"},
		{"change register, no analysis", "", nil, itChange, "get_recent_changes", "config:dev-a:9f2c", "no Correlix analysis in scope"},
		{"not in the chain", "suspected", &changeChainView{}, itChange, "get_recent_changes", "config:dev-a:9f2c", "not in Correlix's causal chain"},
		{"step of an unestablished chain", "suspected", &changeChainView{step: 2, relation: "INFERRED"}, itChange, "get_recent_changes", "config:dev-a:9f2c", "step 2 of Correlix's proposed sequence (inferred)"},
		{"contradicted chain", "confirmed", &changeChainView{step: 1, contradicted: true}, itChange, "get_recent_changes", "config:dev-a:9f2c", "a sequence the evidence contradicts"},
		{"chain unread", "", &changeChainView{unread: true}, itChange, "get_recent_changes", "config:dev-a:9f2c", "could not be read"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sc := ctxWith(c.verdict, "get_problem_evidence", itEngine, c.tool, c.item)
			sc.chain = c.chain
			in := "The outage was caused by the change [" + c.cite + "]. Next: review it."
			out, n := rewriteChangeCauses(in, sc)
			if n != 1 || !strings.Contains(out, CoincidentChangeWording) || !strings.Contains(out, c.want) {
				t.Fatalf("rewrite = %q (n=%d), want the wording and %q", out, n, c.want)
			}
			if strings.Contains(out, "was caused by the change") || !strings.Contains(out, "["+c.cite+"]") || !strings.HasSuffix(out, "Next: review it.") {
				t.Errorf("the cause clause must go, the citation and the rest must stay: %q", out)
			}
			// The class pass recognises the server's sentence and keeps it.
			g := groundStatements(out, sc)
			if g.removed() != 0 || len(g.statements) != 2 || g.statements[0].Note == "" || !g.statements[0].Grounded {
				t.Errorf("the reworded sentence is the server's, grounded and noted: %+v", g)
			}
		})
	}
}

func TestEstablishedChangeMayBeNamedAsTheCause(t *testing.T) {
	sc := ctxWith("confirmed", "get_recent_changes", itChange, "get_rca_verdict", itVerdict)
	sc.chain = &changeChainView{step: 1, relation: RelationObserved, established: true}
	in := "The outage was caused by the change on edge-1 [config:dev-a:9f2c]."
	out, n := rewriteChangeCauses(in, sc)
	if n != 0 || out != in {
		t.Fatalf("an engine-established change must not be reworded: %q", out)
	}
	if g := groundStatements(out, sc); g.removed() != 0 {
		t.Errorf("an engine-established change is the engine's own cause: %+v", g)
	}
}

func TestCoincidentChangeWordingOnANonCauseSentence(t *testing.T) {
	sc := ctxWith("confirmed", "get_problem_evidence", itEngine, "get_recent_changes", itChange)
	sc.incident = true
	g := groundStatements("A configuration change was pushed to edge-1 at 10:02 [config:dev-a:9f2c].", sc)
	if g.annotated != 1 || !strings.Contains(g.text, "[config:dev-a:9f2c] ("+CoincidentChangeWording+").") {
		t.Errorf("a change near an incident carries the wording: %q", g.text)
	}
	// Already worded honestly: not repeated.
	g = groundStatements("A change at 10:02 [config:dev-a:9f2c] coincided with the flap.", sc)
	if g.annotated != 0 {
		t.Errorf("an already-temporal sentence must not be annotated: %q", g.text)
	}
	// No incident in scope: a change listing is just a change listing.
	sc.incident = false
	if g = groundStatements("A configuration change was pushed at 10:02 [config:dev-a:9f2c].", sc); g.annotated != 0 {
		t.Errorf("no incident in scope, no annotation: %q", g.text)
	}
}

func TestStatementsReproduceTheText(t *testing.T) {
	sc := ctxWith("suspected", "search_logs", itLog, "get_problem_evidence", itEngine)
	text := "Ethernet1/1 went down [log:os:1].  Correlix ranks the optic first [hypothesis:p1:0]!\nNext: reseat it."
	g := groundStatements(text, sc)
	if joinStatements(g.statements) != g.text || g.text != text {
		t.Errorf("statements must concatenate to the text:\n%q\n%q", joinStatements(g.statements), g.text)
	}
}

func TestHedgeWordInsideACitationIsNotAHedge(t *testing.T) {
	// "hypothesis" is a hedge word, and also every explain-path citation id.
	if !overclaims("The fault is confirmed as the optic [hypothesis:p1:0].") {
		t.Error("a citation id must not exempt an overclaim")
	}
	if overclaims("The optic is a hypothesis Correlix has not confirmed [hypothesis:p1:0].") {
		t.Error("a hedge in the prose still exempts")
	}
}

// ---- grounding facts are stamped at the source -------------------------------

func TestRankedHypothesesCarryCauseRoleAndChange(t *testing.T) {
	blob := `{"ranking":{"hypotheses":[
	  {"id":"optic-los","title":"Optical loss of signal","confidence":0.9,"satisfied":["controller_policy_change","optic_rx_power_low"],
	   "verdict":{"verdict_tier":"confirmed","modality_coverage":["device_telemetry","management_plane"]}},
	  {"id":"config-change","title":"Configuration change on edge-1","confidence":0.1}]}}`
	items := RankedHypothesisItems("abcd1234-0000", "#/x", ParseRankedHypotheses(blob))
	by := map[string]EvidenceItem{}
	for _, it := range items {
		by[it.CitationID] = it
	}
	if it := by["hypothesis:abcd1234:0"]; it.CauseRole != CauseRoleEngine || it.Change {
		t.Errorf("rank 0 is the engine's cause and not a change: %+v", it)
	}
	if it := by["hypothesis:abcd1234:1"]; it.CauseRole != CauseRoleCandidate || !it.Change {
		t.Errorf("rank 1 is a candidate change: %+v", it)
	}
	if it := by["controller:abcd1234"]; it.CauseRole != CauseRoleEngine || !it.Change {
		t.Errorf("the controller-reported policy change is engine evidence and a change: %+v", it)
	}
	// Server-only facts never reach the wire (the model's tool reply, the UI).
	raw, err := json.Marshal(by["hypothesis:abcd1234:1"])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "candidate\"") || strings.Contains(string(raw), "Change") {
		t.Errorf("grounding facts leaked into JSON: %s", raw)
	}
}

func TestEveryDeclaredToolHasAStatementClass(t *testing.T) {
	valid := map[string]bool{ClassObserved: true, ClassCorrelixRCA: true, ClassDerived: true, ClassHistorical: true, ClassDocumentation: true}
	// Every tool the model or a skill can reach: the agent manifest's declared
	// tools and the skill gather allowlist.
	names := map[string]bool{}
	for name := range toolMetas {
		names[name] = true
	}
	for name := range skillToolAllowlist {
		names[name] = true
	}
	for name := range names {
		if !valid[ToolStatementClass(name)] {
			t.Errorf("tool %s has no statement class — its evidence would ground nothing", name)
		}
	}
	for name, class := range toolStatementClass {
		if !valid[class] {
			t.Errorf("tool %s maps to %q, which is not an evidence class", name, class)
		}
	}
}

// ---- the causal-chain read --------------------------------------------------

func TestChangeChainFrom(t *testing.T) {
	chain := []RCACausalLink{
		{Number: 1, Relation: RelationObserved, Kinds: []string{"interface_down"}},
		{Number: 2, Relation: RelationObserved, Kinds: []string{"config_change"}},
	}
	v := changeChainFrom(RCAResult{Verdict: "confirmed", RootCause: RCARootCause{Identified: true}, CausalChain: chain})
	if v.step != 2 || !v.established {
		t.Errorf("an observed change step under an identified, confirmed cause is established: %+v", v)
	}
	if v = changeChainFrom(RCAResult{Verdict: "suspected", CausalChain: chain}); v.established || v.step != 2 {
		t.Errorf("a suspected analysis establishes nothing: %+v", v)
	}
	if v = changeChainFrom(RCAResult{Verdict: "confirmed", RootCause: RCARootCause{Identified: true}, PrimaryContradicted: true, CausalChain: chain}); v.established || !v.contradicted {
		t.Errorf("a contradicted sequence establishes nothing: %+v", v)
	}
	if v = changeChainFrom(RCAResult{Verdict: "confirmed", CausalChain: chain[:1]}); v.step != 0 || v.established {
		t.Errorf("no change kind in the chain: %+v", v)
	}
}

// TestChangeChainReadIsTenantScoped (§3a): the chain read goes through the
// tenant-scoped RCAResult seam under the get_causal_chain gate. Another
// tenant's incident — even one whose chain ESTABLISHES a change — reads as
// absent, and a principal the gate refuses gets "could not be read", never
// another tenant's analysis.
func TestChangeChainReadIsTenantScoped(t *testing.T) {
	established := RCAResult{Verdict: "confirmed", RootCause: RCARootCause{Identified: true},
		CausalChain: []RCACausalLink{{Number: 1, Relation: RelationObserved, Kinds: []string{"config_change"}}}}
	byTenant := map[string]map[string]RCAResult{"t-b": {"corr-b": established}, "t-a": {"corr-a": {Verdict: "suspected"}}}
	deps := TroubleshootDeps{RCAResult: func(_ context.Context, p Principal, id string) (RCAResult, error) {
		if r, ok := byTenant[p.Tenant][id]; ok {
			return r, nil
		}
		return RCAResult{}, ErrNotFound
	}}
	reg := &ToolRegistry{byName: map[string]AITool{}}
	reg.AddRCATools(deps)
	o := &Orchestrator{Tools: reg, Troubleshoot: deps, Flags: func(string) bool { return true }}
	sc := ctxWith("", "get_recent_changes", itChange)
	read := func(p Principal, corr string) *changeChainView {
		return o.readChangeChain(context.Background(), p, skillEntitySet{values: map[string]string{"correlation_id": corr}}, sc)
	}
	if v := read(tenantA(), "corr-b"); v == nil || v.established || v.step != 0 || v.unread {
		t.Errorf("tenant B's established chain must read as absent for tenant A: %+v", v)
	}
	if v := read(tenantB(), "corr-b"); v == nil || !v.established {
		t.Errorf("tenant B reads its own chain: %+v", v)
	}
	if v := read(Principal{Tenant: "t-b"}, "corr-b"); v == nil || !v.unread || v.established {
		t.Errorf("a principal the gate refuses gets an unread chain, not the analysis: %+v", v)
	}
	if v := read(tenantA(), "bad id with spaces"); v != nil {
		t.Errorf("a malformed id names no incident: %+v", v)
	}
	broken := &Orchestrator{Tools: reg, Flags: func(string) bool { return true }, Troubleshoot: TroubleshootDeps{
		RCAResult: func(context.Context, Principal, string) (RCAResult, error) {
			return RCAResult{}, errors.New("store down")
		}}}
	if v := broken.readChangeChain(context.Background(), tenantA(), skillEntitySet{values: map[string]string{"correlation_id": "corr-a"}}, sc); v == nil || !v.unread {
		t.Errorf("a failed read is unread, never 'not in the chain': %+v", v)
	}
}

// ---- end to end: the explain path -------------------------------------------

func TestExplainPathShipsClassifiedStatements(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Reply: "The root cause is the BGP peer down on edge-1 [problem:pa]. " +
		"edge-1 logged the adjacency change [log:os:1]. That pattern is typical of a flapping link. Next: verify the peering link."},
		Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), tenantA(), "explain problem pa", map[string]string{"problem_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if joinStatements(ans.Statements) != ans.Text {
		t.Fatalf("statements must spell the text:\n%q\n%q", joinStatements(ans.Statements), ans.Text)
	}
	want := []struct {
		class    string
		grounded bool
	}{{ClassCorrelixRCA, true}, {ClassCorrelixRCA, true}, {ClassDerived, false}, {ClassRecommendation, true}}
	if len(ans.Statements) != len(want) {
		t.Fatalf("statements = %+v", ans.Statements)
	}
	for i, w := range want {
		if ans.Statements[i].Class != w.class || ans.Statements[i].Grounded != w.grounded {
			t.Errorf("statement %d = %+v, want %s grounded=%v", i, ans.Statements[i], w.class, w.grounded)
		}
	}
	for _, c := range ans.Citations {
		if c.Class == "" {
			t.Errorf("citation %s carries no class", c.ID)
		}
	}
	// The wire form carries the class per sentence.
	raw, _ := json.Marshal(ans)
	if !strings.Contains(string(raw), `"statements":[{"text":`) || !strings.Contains(string(raw), `"class":"RECOMMENDATION"`) {
		t.Errorf("the answer payload must expose statements: %s", raw)
	}
}

func TestExplainPathEvidenceOnlyIsClassifiedAsServerText(t *testing.T) {
	ds := newMockDS()
	o := &Orchestrator{DS: ds, Tools: Tools(ds), Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), tenantA(), "explain problem pa", map[string]string{"problem_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	if !ans.EvidenceOnly || len(ans.Statements) == 0 || joinStatements(ans.Statements) != ans.Text {
		t.Fatalf("an evidence-only answer is classified too: %+v", ans.Statements)
	}
	for _, st := range ans.Statements {
		if !st.Grounded {
			t.Errorf("server-written text is grounded by construction: %+v", st)
		}
	}
}

// TestStatementsNeverCiteAnotherTenantsEvidence (§3a): a model reply that
// cites tenant B's evidence id while answering for tenant A ships no such
// citation — not in the text, not in any statement — and B's evidence text
// appears nowhere in A's answer.
func TestStatementsNeverCiteAnotherTenantsEvidence(t *testing.T) {
	ds := newMockDS()
	ds.evidence["pb"] = []EvidenceItem{itProblemB}
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Reply: "edge-1 logged the adjacency change [log:os:1]. " +
		"leaf-2 is also down [log:os:9]. The root cause is the BGP peer down on edge-1 [problem:pa] [log:os:9]."},
		Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), tenantA(), "explain problem pa", map[string]string{"problem_id": "pa"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(ans)
	if strings.Contains(string(raw), "log:os:9") || strings.Contains(string(raw), "TENANT-B-ONLY") {
		t.Fatalf("tenant B's evidence reached tenant A's answer: %s", raw)
	}
	for _, st := range ans.Statements {
		for _, c := range st.Citations {
			found := false
			for _, ac := range ans.Citations {
				if ac.ID == c {
					found = true
				}
			}
			if !found {
				t.Errorf("statement cites %s, which is not in the caller's evidence", c)
			}
		}
	}
	// And tenant B's own incident is not reachable from A at all.
	ans, err = o.Ask(context.Background(), tenantA(), "explain problem pb", map[string]string{"problem_id": "pb"})
	if err != nil {
		t.Fatal(err)
	}
	if raw, _ = json.Marshal(ans); strings.Contains(string(raw), "TENANT-B-ONLY") || len(ans.Statements) != 0 && strings.Contains(joinStatements(ans.Statements), "leaf-2") {
		t.Errorf("tenant B's incident leaked: %s", raw)
	}
}

func TestStatementGuardsAreCounted(t *testing.T) {
	sink := newRecordingSink()
	o := &Orchestrator{Score: sink}
	sc := ctxWith("confirmed", "get_problem_evidence", itEngine, "get_problem_evidence", itCandChg, "get_problem_evidence", itCand, "search_logs", itLog)
	_, _, _, disc := o.applyStatementClasses("The outage was caused by the change [hypothesis:p1:2]. "+
		"The outage was caused by high CPU [hypothesis:p1:1]. Correlix has seen this recurring on edge-1 in a past investigation. "+
		"Ethernet1/1 went down at 10:06 [log:os:1]. Next: check the optic.", "fallback summary that is long enough to stand", ClassCorrelixRCA, sc, nil, nil)
	if sink.guards[GuardChangeCausality] != 1 || sink.guards[GuardUnsupportedCause] != 1 || sink.guards[GuardUngroundedStatement] != 1 {
		t.Errorf("guards = %v", sink.guards)
	}
	for _, want := range []string{"reworded", "other than the one Correlix confirmed", "holds no evidence from"} {
		if !hasDisclaimer(disc, want) {
			t.Errorf("missing disclosure %q in %v", want, disc)
		}
	}
}

func TestNothingUsableLeftFallsBackToServerSummary(t *testing.T) {
	sc := ctxWith("confirmed", "get_problem_evidence", itEngine, "get_problem_evidence", itCand)
	o := &Orchestrator{}
	fb := "Confirmed: optical loss of signal on edge-1 [hypothesis:p1:0]."
	text, sts, badges, disc := o.applyStatementClasses("It was caused by high CPU [hypothesis:p1:1].", fb, ClassCorrelixRCA, sc, nil, nil)
	if text != fb || joinStatements(sts) != fb || !hasDisclaimer(disc, "evidence-only summary") || len(badges) == 0 {
		t.Errorf("fallback = %q / %+v / %v", text, sts, disc)
	}
}

// ---- end to end: the skill path ---------------------------------------------

// runSkillWith runs one skill turn through the golden harness's real path,
// with the given scripted tools and model reply.
func runSkillWith(t *testing.T, c *goldenIncidentCase) Answer {
	t.Helper()
	o, err := runGoldenIncident(t, loadTestSkills(t), c)
	if err != nil {
		t.Fatal(err)
	}
	return o.ans
}

// TestSkillConfirmedVerdictForADifferentCause: the engine confirmed an optical
// loss; the model names high CPU, citing a log line. Removed, disclosed, and
// the engine's own cause stands.
func TestSkillConfirmedVerdictForADifferentCause(t *testing.T) {
	c := &goldenIncidentCase{Path: goldenPathSkill, Skill: "log-confirmation", Question: "show me the logs for edge-1",
		UI:      map[string]string{"device": "edge-1", "correlation_id": "cc09aaaa-0000-4000-8000-000000000009"},
		Tenants: map[string]goldenTenant{"t-a": {Devices: []goldenDevice{{ID: "dev-a", Name: "edge-1"}}}},
		Tools: map[string]goldenToolFixture{
			"get_rca_verdict": {Items: []EvidenceItem{{CitationID: "verdict:cc09aaaa", Kind: "finding",
				Text: "P-9 — Optical loss of signal on edge-1; verdict confirmed", CauseRole: CauseRoleEngine}},
				Signals: []string{CondVerdictTier + "=confirmed"}},
			"search_logs": {Items: []EvidenceItem{{CitationID: "log:os:2", Kind: "log", Text: "edge-1 CPU 97%"}}},
		},
		ModelReply: "The root cause is high CPU on edge-1 [log:os:2]. The root cause is the optical loss of signal on edge-1 [verdict:cc09aaaa]. Next: reseat the optic.",
	}
	c.Principal.Tenant = "t-a"
	c.Principal.Perms = []string{"correlations:read", "infrastructure:read", "logs:read"}
	ans := runSkillWith(t, c)
	if strings.Contains(ans.Text, "high CPU") || !strings.Contains(ans.Text, "optical loss of signal") {
		t.Errorf("only the engine's own cause may stand: %q", ans.Text)
	}
	if !hasDisclaimer(ans.Disclaimers, "other than the one Correlix confirmed") {
		t.Errorf("removal must be disclosed: %v", ans.Disclaimers)
	}
	if joinStatements(ans.Statements) != ans.Text || len(ans.Statements) != 2 || ans.Statements[0].Class != ClassCorrelixRCA {
		t.Errorf("statements = %+v", ans.Statements)
	}
}

// TestGoldenCoincidentChangeCarriesTheExactWording replays the N-H1
// coincident-change cases and checks what the golden harness's surface check
// cannot: the NARRATIVE itself (not only a disclaimer) carries the exact
// wording, as a server-reworded, grounded statement, and the statements spell
// the text.
func TestGoldenCoincidentChangeCarriesTheExactWording(t *testing.T) {
	set := loadTestSkills(t)
	ran := 0
	for _, c := range loadGoldenIncidents(t) {
		if c.Category != "coincident_change" || c.ExpectedFailure != "" {
			continue
		}
		c := c
		wantWording := false
		for _, s := range c.Expect.RequiredText {
			if strings.Contains(s, "temporally correlated") {
				wantWording = true
			}
		}
		t.Run(c.ID, func(t *testing.T) {
			o, err := runGoldenIncident(t, set, &c)
			if err != nil {
				t.Fatal(err)
			}
			ans := o.ans
			if joinStatements(ans.Statements) != ans.Text {
				t.Fatalf("statements must spell the text:\n%q\n%q", joinStatements(ans.Statements), ans.Text)
			}
			if !wantWording {
				return
			}
			if !strings.Contains(ans.Text, CoincidentChangeWording) {
				t.Fatalf("the narrative must carry %q: %q", CoincidentChangeWording, ans.Text)
			}
			noted := false
			for _, st := range ans.Statements {
				if strings.Contains(st.Text, CoincidentChangeWording) && st.Grounded && strings.Contains(st.Note, "Reworded by Correlix") {
					noted = true
				}
			}
			if !noted {
				t.Errorf("the reworded sentence must be marked as the server's: %+v", ans.Statements)
			}
		})
		ran++
	}
	if ran < 4 {
		t.Fatalf("expected the four coincident-change cases, ran %d", ran)
	}
}

func TestSkillSystemBlockCarriesTheWording(t *testing.T) {
	set := loadTestSkills(t)
	sk, ok := set.Get("log-confirmation")
	if !ok {
		t.Fatal("log-confirmation skill missing")
	}
	if !strings.Contains(skillSystemBlock(sk), CoincidentChangeWording) {
		t.Error("the narration contract must state the coincident-change wording")
	}
}

// ---- the copilot agent loop ------------------------------------------------

func TestGroundAgentNarrative(t *testing.T) {
	probConfirmed := EvidenceItem{CitationID: "problem:p1", Kind: "finding", Text: "P-1 — optic loss; verdict confirmed", CauseRole: CauseRoleEngine, Verdict: "confirmed"}
	probSuspected := EvidenceItem{CitationID: "problem:p2", Kind: "finding", Text: "P-2 — DIA loss; verdict suspected", CauseRole: CauseRoleEngine, Verdict: "suspected"}
	// One confirmed incident: its own cause stands; a log-cited cause does not.
	g := GroundAgentNarrative("The root cause is the optic loss [problem:p1]. It was caused by a fibre cut [log:os:1]. Next: reseat the optic.",
		[]AgentToolEvidence{{Tool: "get_problem", Items: []EvidenceItem{probConfirmed}}, {Tool: "search_logs", Items: []EvidenceItem{itLog}}}, nil)
	if !strings.Contains(g.Text, "optic loss [problem:p1]") || strings.Contains(g.Text, "fibre cut") || joinStatements(g.Statements) != g.Text {
		t.Errorf("agent grounding = %+v", g)
	}
	// Two incidents with different verdicts: a cause for the suspected one is
	// removed, the confirmed one's own cause stands.
	g = GroundAgentNarrative("The DIA loss is due to the provider [problem:p2]. The root cause is the optic loss [problem:p1].",
		[]AgentToolEvidence{{Tool: "get_problem", Items: []EvidenceItem{probConfirmed, probSuspected}}}, nil)
	if strings.Contains(g.Text, "provider") || !strings.Contains(g.Text, "optic loss") {
		t.Errorf("per-incident verdicts: %q", g.Text)
	}
	// A product answer with no incident in view is left alone (no certainty
	// gate on a general answer), and a docs id the model was shown grounds it.
	g = GroundAgentNarrative("Correlix confirms a cause only when two evidence classes agree [doc:verdicts].", nil, []string{"doc:verdicts"})
	if g.Text != "Correlix confirms a cause only when two evidence classes agree [doc:verdicts]." || len(g.Statements) != 1 || g.Statements[0].Class != ClassDocumentation {
		t.Errorf("a docs-grounded product answer must stand: %+v", g)
	}
	// Nothing survives: the honest fallback, never an empty answer.
	g = GroundAgentNarrative("It was caused by a fibre cut.", nil, nil)
	if g.Text != agentFallbackText || len(g.Disclaimers) == 0 {
		t.Errorf("fallback = %+v", g)
	}
}

// ---- the live-state briefing: one verdict per incident -----------------------

func TestBriefingJudgesEachCauseAgainstItsOwnIncident(t *testing.T) {
	mk := func() *statementContext {
		sc := &statementContext{perIncident: true}
		sc.stampIncident("problem:p1", "p1", "confirmed", "P-1 — Optical loss on edge-1 (Confirmed, high)")
		sc.stampIncident("problem:p2", "p2", "suspected", "P-2 — DIA loss at isp-gw-1 (Suspected, medium)")
		sc.stampIncident("problem:p3", "p3", "confirmed", "P-3 — Power loss in rack 4 (Confirmed, high)")
		return sc
	}
	cases := []struct {
		name, text      string
		keep, foreign   bool
		unconfirmedWant int
	}{
		{"a confirmed incident's own cause", "P-1 was caused by an optical loss on edge-1 [problem:p1].", true, false, 0},
		{"a suspected incident's cause", "The DIA loss was caused by the upstream provider [problem:p2].", false, false, 1},
		{"one cause merged across two confirmed incidents", "The power loss [problem:p3] caused the optical loss [problem:p1].", false, true, 0},
		{"one cause merged across confirmed and suspected", "The optic failure [problem:p1] caused the DIA loss [problem:p2].", false, false, 1},
		{"uncited cause with a confirmed incident in view", "Everything is due to a fibre cut.", false, true, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := groundStatements(c.text, mk())
			if kept := len(g.statements) == 1; kept != c.keep {
				t.Fatalf("kept = %v, want %v: %+v", kept, c.keep, g)
			}
			if !c.keep && (g.foreignCause == 1) != c.foreign {
				t.Errorf("foreign = %d, want %v", g.foreignCause, c.foreign)
			}
			if g.unconfirmedCause != c.unconfirmedWant {
				t.Errorf("unconfirmed = %d, want %d", g.unconfirmedCause, c.unconfirmedWant)
			}
		})
	}
}

func TestBriefingShipsStatementsAndKeepsAConfirmedIncidentsCause(t *testing.T) {
	ds := newMockDS() // t-a: "pa" confirmed, "BGP peer down on edge-1"
	o := &Orchestrator{DS: ds, Tools: Tools(ds), LLM: MockLLM{Reply: "One incident is active. " +
		"It was caused by the BGP peer down on edge-1 [problem:pa]. Next: work pa first."},
		Flags: func(string) bool { return false }}
	ans, err := o.Ask(context.Background(), tenantA(), "what is going on right now", nil)
	if err != nil {
		t.Fatal(err)
	}
	if ans.Mode != ModeCurrentStateSummary {
		t.Fatalf("routed to %s, want the live-state briefing", ans.Mode)
	}
	if !strings.Contains(ans.Text, "caused by the BGP peer down") {
		t.Errorf("a confirmed incident's own cause must survive the briefing: %q", ans.Text)
	}
	if joinStatements(ans.Statements) != ans.Text || len(ans.Statements) != 3 {
		t.Fatalf("statements = %+v", ans.Statements)
	}
	if ans.Statements[1].Class != ClassCorrelixRCA || ans.Statements[2].Class != ClassRecommendation || ans.Statements[0].Grounded {
		t.Errorf("classes = %+v", ans.Statements)
	}
}
