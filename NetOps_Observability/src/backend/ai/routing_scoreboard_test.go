// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// routing_scoreboard_test.go — the question router's scoreboard (tracker 337
// N-G4). Every golden question is asked and the router's FIRST claim is
// scored against the class the corpus expects:
//
//	testdata/routing_golden.json            → its labelled class (GATED)
//	skill CASES that name a method          → investigation (GATED)
//	docs items (golden-qa.json)             → reported: how many get a product
//	                                          answer (a ratchet, not a label —
//	                                          that set labels RETRIEVAL, and some
//	                                          of its items are live or data
//	                                          questions by design)
//
// (Data questions are scored by the N-C6 compiler corpus, which runs the real
// grammar; this file scores the arms' ORDER.)
//
// Then the same corpus is asked again with an ADVERSARIAL model that always
// answers the tie-break "ROUTE: data" and a data arm that answers whenever the
// tie-break lets the model compile run. The proof that deterministic arms
// still win: every question routes identically except those where the
// tie-break was actually asked, and it is asked only for questions whose
// deterministic claim was a method (the contested case).
//
// Floors ratchet (raise when the measured value rises, never lower). The
// table is written to $GITHUB_STEP_SUMMARY in the iris-gates CI job.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// Ratchet floors, measured 2026-10-17 (raise when the measured value rises).
const (
	minRoutingLane      = 1.0 // routing_golden.json, every label
	minMethodLane       = 1.0 // skill CASES that name a method
	minDocsProductCount = 115 // docs items answered as product (of 127 docs+decline)
)

type routingGolden struct {
	Items []struct {
		ID, Expect, Question string
	} `json:"items"`
}

type routeQ struct {
	lane, id, question string
	ui                 map[string]string
	intent             string
}

func classOfClaim(d RouteDecision) RequestClass {
	switch d.Arm {
	case ArmData:
		return ClassData
	case ArmSkill:
		return ClassInvestigation
	case ArmPageHelp, ArmExplain, ArmCapability:
		return ClassProduct
	}
	c, _ := ClassFor(d.Mode, "")
	return c
}

// countingRouteLLM always says "data" to the tie-break and counts only those
// calls; any other prompt gets a neutral narrative.
type countingRouteLLM struct{ tieBreaks map[string]int }

func (c *countingRouteLLM) Complete(_ context.Context, system string, msgs []LLMMessage) (string, string, error) {
	if system == tieBreakSystem {
		q := ""
		if len(msgs) > 0 {
			q = msgs[len(msgs)-1].Content
		}
		c.tieBreaks[q]++
		return "ROUTE: data", "test", nil
	}
	return "Fixture narrative.", "test", nil
}

func scoreboardQuestions(t *testing.T) []routeQ {
	t.Helper()
	var qs []routeQ
	raw, err := os.ReadFile("testdata/routing_golden.json")
	if err != nil {
		t.Fatal(err)
	}
	var rg routingGolden
	if err := json.Unmarshal(raw, &rg); err != nil {
		t.Fatal(err)
	}
	for _, it := range rg.Items {
		qs = append(qs, routeQ{lane: "routing", id: it.ID, question: it.Question, intent: it.Expect})
	}
	gs := loadGolden(t)
	for _, cat := range []string{GoldenDocs, GoldenDecline} {
		for _, it := range gs.Category(cat) {
			qs = append(qs, routeQ{lane: "docs", id: it.ID, question: it.Question})
		}
	}
	set := loadTestSkills(t)
	for _, name := range set.Names() {
		sk, _ := set.Get(name)
		for _, c := range sk.Cases {
			if c.ExpectSelect != "" && c.ExpectSelect != caseSelectNone {
				qs = append(qs, routeQ{lane: "method", id: name + "/" + c.Name, question: c.Question, ui: c.UI})
			}
		}
	}
	return qs
}

func routeAll(t *testing.T, qs []routeQ, llm LLMClient) []RouteDecision {
	t.Helper()
	set := loadTestSkills(t)
	out := make([]RouteDecision, len(qs))
	for i, q := range qs {
		var got RouteDecision
		o := &Orchestrator{
			DS: newMockDS(), Docs: goldenIndex(), Skills: set, LLM: llm,
			Flags: func(string) bool { return true },
			// The data arm answers only when the tie-break let the model
			// compile run — the adversarial half of the invariance proof.
			NLQuery: func(ctx context.Context, _ Principal, _ string, opts DataOpts) (DataAnswer, error) {
				if opts.BeforeModel != nil && opts.BeforeModel(ctx) {
					return DataAnswer{Status: DataAnswered, Text: "rows"}, nil
				}
				return DataAnswer{Status: DataNotData}, nil
			},
			Routed: func(d RouteDecision) { got = d },
		}
		if _, err := o.Ask(context.Background(), tenantA(), q.question, q.ui); err != nil {
			t.Fatalf("%s: %v", q.id, err)
		}
		if got.Arm == "" {
			t.Fatalf("%s: no arm claimed the question", q.id)
		}
		out[i] = got
	}
	return out
}

func TestRoutingScoreboard(t *testing.T) {
	qs := scoreboardQuestions(t)
	base := routeAll(t, qs, nil)

	type tally struct{ ok, total int }
	lanes := map[string]*tally{"routing": {}, "method": {}, "docs": {}}
	var misroutes []string
	for i, q := range qs {
		c := classOfClaim(base[i])
		ok := false
		switch q.lane {
		case "routing":
			switch q.intent {
			case "not_product":
				ok = c != ClassProduct
			default:
				ok = string(c) == q.intent
			}
		case "method":
			ok = base[i].Arm == ArmSkill
		case "docs":
			ok = c == ClassProduct
		}
		lanes[q.lane].total++
		if ok {
			lanes[q.lane].ok++
		} else if q.lane != "docs" || testing.Verbose() {
			misroutes = append(misroutes, fmt.Sprintf("%s %s → %s/%s", q.lane, q.id, base[i].Arm, base[i].Mode))
		}
	}

	// Adversarial model: the tie-break always says "data".
	llm := &countingRouteLLM{tieBreaks: map[string]int{}}
	adv := routeAll(t, qs, llm)
	changed, asked := 0, 0
	for _, n := range llm.tieBreaks {
		asked += n
	}
	for i := range qs {
		if adv[i].Arm == base[i].Arm {
			continue
		}
		changed++
		if base[i].Arm != ArmSkill || adv[i].Arm != ArmData {
			t.Errorf("DETERMINISTIC ARM LOST: %s moved %s → %s; only a contested method claim may move, and only to data", qs[i].id, base[i].Arm, adv[i].Arm)
		}
	}
	if changed != asked {
		t.Errorf("the model was asked %d times but %d decisions moved — a call outside the contested set, or a move without one", asked, changed)
	}

	sort.Strings(misroutes)
	var b strings.Builder
	b.WriteString("## Iris routing scoreboard\n\n| Lane | Routed as expected |\n|---|---|\n")
	for _, name := range []string{"routing", "method", "docs"} {
		l := lanes[name]
		fmt.Fprintf(&b, "| %s | %d/%d (%.1f %%) |\n", name, l.ok, l.total, 100*float64(l.ok)/float64(max(l.total, 1)))
	}
	fmt.Fprintf(&b, "\nContested questions (tie-break asked under an adversarial model): %d of %d.\n", asked, len(qs))
	if len(misroutes) > 0 {
		b.WriteString("\nMisroutes:\n")
		for _, m := range misroutes {
			b.WriteString("- " + m + "\n")
		}
	}
	t.Log("\n" + b.String())
	if p := os.Getenv("GITHUB_STEP_SUMMARY"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o600) // #nosec G304 -- the runner's own summary file
		if err == nil {
			_, werr := f.WriteString(b.String() + "\n")
			if cerr := f.Close(); werr == nil {
				werr = cerr
			}
			if werr != nil {
				t.Errorf("step summary: %v", werr)
			}
		}
	}
	for name, floor := range map[string]float64{"routing": minRoutingLane, "method": minMethodLane} {
		l := lanes[name]
		if l.total == 0 {
			t.Errorf("lane %s is empty — the scoreboard would prove nothing", name)
			continue
		}
		if r := float64(l.ok) / float64(l.total); r < floor {
			t.Errorf("lane %s fell below its floor: %.3f < %.2f", name, r, floor)
		}
	}
	if lanes["docs"].ok < minDocsProductCount {
		t.Errorf("docs items answered as product fell to %d (floor %d)", lanes["docs"].ok, minDocsProductCount)
	}
}
