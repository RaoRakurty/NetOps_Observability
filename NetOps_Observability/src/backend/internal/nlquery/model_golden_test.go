// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nlquery_test

// model_golden_test.go — the offline harness for the MODEL path (tracker 337
// N-C6 item; N-C5 fallback). Every golden phrasing the deterministic grammar
// leaves Unparsed goes through modelc.Fallback with a FAKE model, so CI
// measures the pipeline around the model — prompt assembly, the strict
// decode, the entity/widening/value guards, the validator and the repair loop
// — without calling a provider:
//
//	oracle   answers with the corpus's own expected query. Acceptance is the
//	         share of CORRECT model answers the pipeline lets through (a guard
//	         that refuses right answers shows up here); answered precision is
//	         how often an accepted answer is the expected one.
//	repair   answers first with a misspelled metric, then correctly: proves the
//	         repair loop turns a closed-code refusal into a right answer.
//	widen    drops every entity the question names;
//	foreign  swaps an entity for tenant B's;
//	tenant   adds a tenant field;
//	         — each must be accepted NEVER (safety, 100 %).
//
// A reject/decline case must never yield an accepted query, whatever the model
// says. The same harness runs against a real provider in the build-tagged
// model_eval_test.go (never in CI).

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/modelc"
	"netops/backend/internal/nlquery/resolve"
)

// Model-path floors (ratchet: raise when the measured value rises).
const (
	minOracleAcceptance      = 0.60
	minOracleAnsweredPrec    = 0.99
	minRepairAcceptanceRatio = 0.95 // repaired acceptances / oracle acceptances
	// maxUnguardedWidening caps phrasings where a widened answer passes because
	// nothing in the question resolved (ratchet: lower it, never raise it).
	maxUnguardedWidening = 10
)

// phrasing is one question the grammar left to the model.
type phrasing struct {
	c        *goldenCase
	question string
	cx       compile.Context
	sc       fixtureScope
	det      compile.Result
}

// harness runs the grammar over the corpus and returns the phrasings it left
// Unparsed, with the grammar's own tallies.
func unparsedPhrasings(t *testing.T, cat *catalog.Catalog, w *world) (out []phrasing, total int) {
	t.Helper()
	comp := compile.Compiler{Cat: cat, R: resolve.Resolver{Cat: cat, L: fixtureLookups{w: w}, Topo: fixtureLookups{w: w}}}
	for _, c := range loadCases(t) {
		loc, err := time.LoadLocation(firstNonEmpty(c.Context.TZ, "UTC"))
		if err != nil {
			t.Fatal(err)
		}
		cx := compile.Context{Loc: loc, Now: w.now, IncidentID: c.Context.IncidentID}
		if len(c.Context.PriorAST) > 0 {
			cx.PriorAST = decodeAST(t, c.ID+" prior", c.Context.PriorAST)
		}
		for _, q := range append([]string{c.Question}, c.Paraphrases...) {
			total++
			res, err := comp.Compile(context.Background(), q, cx)
			if err != nil {
				t.Fatal(err)
			}
			if res.Unparsed {
				out = append(out, phrasing{c: c, question: q, cx: cx, sc: fixtureScope{w: w, cross: c.Context.Cross}, det: res})
			}
		}
	}
	return out, total
}

// modelTally is the model path's scoreboard.
type modelTally struct {
	reach, answerable, accepted, correct, calls int
	refusals                                    map[string]int
	safety                                      []string
	// acceptedWithRefs: phrasings whose accepted query named entities (key:
	// case id + question) — the ones whose entities the resolver DID find.
	acceptedWithRefs map[string]bool
	acceptedKeys     []string
}

func (m *modelTally) String() string {
	return fmt.Sprintf("reach %d (answerable %d) · accepted %d (%.3f of answerable) · answered precision %d/%d (%.3f) · model calls %d · refusals %v",
		m.reach, m.answerable, m.accepted, ratio(m.accepted, m.answerable), m.correct, m.accepted, ratio(m.correct, m.accepted), m.calls, m.refusals)
}

func ratio(a, b int) float64 {
	if b == 0 {
		return 1
	}
	return float64(a) / float64(b)
}

// runModelPath runs every phrasing through the fallback with the model the
// factory builds for it, scoring accuracy and safety.
func runModelPath(t *testing.T, cat *catalog.Catalog, w *world, ps []phrasing, factory func(p phrasing) modelc.Model) *modelTally {
	t.Helper()
	tally := &modelTally{refusals: map[string]int{}, acceptedWithRefs: map[string]bool{}}
	for _, p := range ps {
		tally.reach++
		f := modelc.Fallback{Cat: cat, L: fixtureLookups{w: w}, Model: factory(p),
			// Leave-one-out: the case's own example is never retrieved for it.
			SkipExample: func(id string) bool { return id == p.c.ID }}
		out, err := f.Compile(context.Background(), p.question, p.cx, p.sc, p.det)
		if err != nil {
			t.Fatalf("%s %q: %v", p.c.ID, p.question, err)
		}
		tally.calls += out.Calls
		if !out.Accepted() {
			tally.refusals[out.Refusal]++
			if testing.Verbose() && os.Getenv("NLQ_MODEL_TRACE") != "" && len(p.c.Expect.AST) > 0 {
				t.Logf("REFUSED %s %s %q", out.Refusal, p.c.ID, p.question)
			}
		} else if testing.Verbose() && os.Getenv("NLQ_MODEL_TRACE") != "" {
			t.Logf("ACCEPTED %s %q %s", p.c.ID, p.question, canon(out.Result.AST))
		}
		answerable := len(p.c.Expect.AST) > 0
		if answerable {
			tally.answerable++
		}
		if !out.Accepted() {
			continue
		}
		// SAFETY: never an accepted query for a question the corpus refuses;
		// never another tenant's entity.
		if !answerable {
			tally.safety = append(tally.safety, fmt.Sprintf("%s %q: corpus refuses it, model path accepted %s", p.c.ID, p.question, canon(out.Result.AST)))
			continue
		}
		for _, r := range out.Result.AST.Refs {
			if w.owner[r.ID] != "" && w.owner[r.ID] != w.a.Tenant && !p.c.Context.Cross {
				tally.safety = append(tally.safety, fmt.Sprintf("%s %q: foreign entity %s accepted", p.c.ID, p.question, r.ID))
			}
		}
		tally.accepted++
		key := p.c.ID + "|" + p.question
		tally.acceptedKeys = append(tally.acceptedKeys, key)
		if len(out.Result.AST.Refs) > 0 {
			tally.acceptedWithRefs[key] = true
		}
		got := canon(out.Result.AST)
		want := []json.RawMessage{p.c.Expect.AST}
		want = append(want, p.c.Expect.Alternates...)
		for i, raw := range want {
			if got == canon(decodeAST(t, fmt.Sprintf("%s want %d", p.c.ID, i), raw)) {
				tally.correct++
				break
			}
		}
	}
	return tally
}

// ---- fake models -----------------------------------------------------------------

type scripted struct{ replies []string }

func (s *scripted) Complete(_ context.Context, _ string, msgs []modelc.Message) (string, error) {
	i := len(msgs) / 2 // 1 message → reply 0; after one repair (3 messages) → reply 1 …
	if i >= len(s.replies) {
		i = len(s.replies) - 1
	}
	return s.replies[i], nil
}

func envelope(q any) string {
	b, err := json.Marshal(map[string]any{"ast": q, "unmatched_names": []string{}})
	if err != nil {
		panic(err)
	}
	return string(b)
}

// expectedOrRejected is the corpus's answer: the expected query, else the
// query the corpus says must be rejected, else an honest "cannot".
func expectedOrRejected(p phrasing) json.RawMessage {
	switch {
	case len(p.c.Expect.AST) > 0:
		return p.c.Expect.AST
	case len(p.c.Expect.RejectedAST) > 0:
		return p.c.Expect.RejectedAST
	}
	return json.RawMessage("null")
}

func oracle(p phrasing) modelc.Model {
	return &scripted{replies: []string{envelope(expectedOrRejected(p))}}
}

func mutated(p phrasing, mut func(q *ast.AST)) string {
	raw := expectedOrRejected(p)
	if string(raw) == "null" {
		return envelope(nil)
	}
	q, err := ast.Decode(raw)
	if err != nil {
		return envelope(nil)
	}
	mut(q)
	return envelope(q)
}

func TestModelPathAgainstTheGoldenCorpus(t *testing.T) {
	cat := catalog.MustLoad()
	w := loadWorld(t)
	ps, total := unparsedPhrasings(t, cat, w)
	if len(ps) == 0 {
		t.Fatal("the grammar left nothing to the model — the harness is not looking")
	}
	foreignOf := func(typ string) string {
		for id, owner := range w.owner {
			if owner == w.b.Tenant && w.typeOf[id] == typ {
				return id
			}
		}
		return w.b.Devices[0].ID
	}

	or := runModelPath(t, cat, w, ps, oracle)
	t.Logf("golden phrasings %d, left Unparsed by the grammar %d", total, len(ps))
	t.Logf("oracle : %s", or)

	rp := runModelPath(t, cat, w, ps, func(p phrasing) modelc.Model {
		first := mutated(p, func(q *ast.AST) {
			if q.Metric != "" {
				q.Metric = strings.TrimSuffix(q.Metric, "_pct") + "_pcnt"
			} else {
				q.Type = ast.QueryType(strings.Replace(string(q.Type), "_list", "_lst", 1))
			}
		})
		return &scripted{replies: []string{first, envelope(expectedOrRejected(p))}}
	})
	t.Logf("repair : %s", rp)

	adversaries := map[string]func(p phrasing) modelc.Model{
		"widen": func(p phrasing) modelc.Model {
			if len(p.c.Expect.AST) == 0 || len(decodeAST(t, p.c.ID, p.c.Expect.AST).Refs) == 0 {
				return &scripted{replies: []string{envelope(nil)}}
			}
			return &scripted{replies: []string{mutated(p, func(q *ast.AST) { q.Refs = nil })}}
		},
		"foreign": func(p phrasing) modelc.Model {
			return &scripted{replies: []string{mutated(p, func(q *ast.AST) {
				if len(q.Refs) == 0 {
					q.Refs = []ast.EntityRef{{Type: "device", ID: foreignOf("device")}}
					return
				}
				q.Refs[0].ID = foreignOf(q.Refs[0].Type)
			})}}
		},
		"tenant": func(p phrasing) modelc.Model {
			r := mutated(p, func(*ast.AST) {})
			return &scripted{replies: []string{strings.Replace(r, `"v":1,`, `"v":1,"tenant":"`+w.b.Tenant+`",`, 1)}}
		},
	}
	for name, factory := range adversaries {
		adv := runModelPath(t, cat, w, ps, factory)
		t.Logf("%-7s: %s", name, adv)
		for _, s := range adv.safety {
			t.Errorf("SAFETY %s: %s", name, s)
		}
		if name != "widen" {
			// A swapped id (even one a cross-tenant caller could see) and a
			// tenant field are refused outright, always.
			if adv.accepted > 0 {
				t.Errorf("SAFETY %s: %d adversarial answers accepted", name, adv.accepted)
			}
			continue
		}
		// Widening is refused wherever the resolver found what the question
		// names (the oracle's right answer used those entities): dropping them
		// can never pass. Where the resolver found nothing (a lower-case name
		// like "dx", or an entity only a prior turn or the incident knew),
		// the guard has nothing to hold the model to, and only the model's own
		// unmatched_names stands between it and a widened answer — reported,
		// and capped so it can only shrink.
		unguarded := 0
		for _, k := range adv.acceptedKeys {
			if or.acceptedWithRefs[k] {
				t.Errorf("SAFETY widen: %s — a query that dropped resolved entities was accepted", k)
			} else {
				unguarded++
			}
		}
		t.Logf("widen  : %d accepted where no entity was resolvable (model honesty is the only guard there)", unguarded)
		if unguarded > maxUnguardedWidening {
			t.Errorf("unguarded widening grew to %d (> %d)", unguarded, maxUnguardedWidening)
		}
	}
	for _, s := range append(or.safety, rp.safety...) {
		t.Errorf("SAFETY: %s", s)
	}
	if got := ratio(or.accepted, or.answerable); got < minOracleAcceptance {
		t.Errorf("oracle acceptance %.3f fell below its floor %.2f — a guard is refusing right answers", got, minOracleAcceptance)
	}
	if got := ratio(or.correct, or.accepted); got < minOracleAnsweredPrec {
		t.Errorf("oracle answered precision %.3f < %.2f", got, minOracleAnsweredPrec)
	}
	if got := ratio(rp.accepted, or.accepted); got < minRepairAcceptanceRatio {
		t.Errorf("the repair loop recovered %.3f of the oracle's acceptances (< %.2f)", got, minRepairAcceptanceRatio)
	}
}
