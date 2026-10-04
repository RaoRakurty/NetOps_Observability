// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nlquery_test

// compile_golden_test.go — the deterministic compiler (N-C5) measured against
// the golden corpus. Two different kinds of assertion:
//
//   SAFETY (must be 100%, always): every question the corpus says must be
//   refused as an action / injection / cross-tenant request is DECLINED; no
//   compiled query ever validates to something the corpus says must be
//   refused; nothing compiled names an entity outside tenant A.
//
//   ACCURACY (measured, ratcheted): the share of answerable questions (and
//   their paraphrases) the grammar compiles to the expected query or an
//   accepted alternate. What the grammar does not recognise is reported
//   Unparsed — the model fallback's job — never guessed. The floors below
//   only ever move UP.

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/nlquery/compile"
	"netops/backend/internal/nlquery/resolve"
	"netops/backend/internal/nlquery/validate"
)

// Accuracy floors (ratchet: raise when the measured value rises; never lower).
const (
	minQuestionAccuracy   = 0.70
	minParaphraseAccuracy = 0.36
	// Per-metric floors (N-C6). Coverage is reported, not floored: an honesty
	// fix that turns a wrong compile into "not understood" LOWERS coverage and
	// raises answered precision, which is the trade this design wants.
	minEntityPrecision   = 0.88
	minExecutableRate    = 0.97
	minAnsweredPrecision = 0.85
)

// fixtureLookups is tenant A's world as the root would present it.
type fixtureLookups struct{ w *world }

func tail(id string) string { return id[strings.IndexByte(id, ':')+1:] }

func (l fixtureLookups) Aliases(context.Context) ([]resolve.Alias, error) {
	var out []resolve.Alias
	for _, s := range l.w.a.Sites {
		for _, a := range s.Aliases {
			out = append(out, resolve.Alias{EntityType: "site", EntityID: s.ID, Alias: a})
		}
	}
	for _, p := range l.w.a.Providers {
		out = append(out, resolve.Alias{EntityType: "provider", EntityID: p.ID, Alias: tail(p.ID)})
		if first := strings.Fields(p.Name); len(first) > 0 {
			out = append(out, resolve.Alias{EntityType: "provider", EntityID: p.ID, Alias: first[0]})
		}
	}
	return out, nil
}

func (l fixtureLookups) Inventory(_ context.Context, types []string) ([]resolve.Named, error) {
	want := map[string]bool{}
	for _, t := range types {
		want[t] = true
	}
	var out []resolve.Named
	add := func(typ, id string, names ...string) {
		if want[typ] {
			out = append(out, resolve.Named{Type: typ, ID: id, Names: append(names, tail(id))})
		}
	}
	for _, s := range l.w.a.Sites {
		add("site", s.ID, s.Name)
	}
	for _, d := range l.w.a.Devices {
		add("device", d.ID, d.Name)
	}
	for _, c := range l.w.a.Circuits {
		add("circuit", c.ID)
	}
	for _, p := range l.w.a.Providers {
		add("provider", p.ID, p.Name)
	}
	for _, a := range l.w.a.Applications {
		add("application", a.ID, a.Name)
	}
	for _, p := range l.w.a.ProbeTargets {
		add("probe_target", p.ID)
	}
	return out, nil
}

func (l fixtureLookups) Visible(_ context.Context, _ string, id string) (bool, error) {
	return l.w.owner[id] == l.w.a.Tenant, nil
}

// Neighbors is tenant A's adjacency view: every link record either tenant's
// collectors saw, restricted to devices tenant A owns — the root's
// gatherTopoLinks(visibleDevices) does the same, so the trap link from a
// tenant-B device is never a neighbour.
func (l fixtureLookups) Neighbors(_ context.Context, deviceID string) ([]resolve.Named, error) {
	devs := map[string]resolve.Named{}
	for _, d := range l.w.a.Devices {
		devs[d.ID] = resolve.Named{Type: "device", ID: d.ID, Names: []string{d.Name, tail(d.ID)}, Role: d.Role}
	}
	if _, ok := devs[deviceID]; !ok {
		return nil, nil
	}
	var out []resolve.Named
	for _, inv := range []*inventory{l.w.a, l.w.b} {
		for _, ln := range inv.Links {
			other := ""
			switch deviceID {
			case ln.A:
				other = ln.B
			case ln.B:
				other = ln.A
			}
			if n, ok := devs[other]; ok {
				out = append(out, n)
			}
		}
	}
	return out, nil
}

// canon is the semantic encoding: filter and entity ORDER carries no meaning,
// so both are sorted before comparing.
func canon(a *ast.AST) string {
	c := a.Clone()
	if c == nil {
		return ""
	}
	sort.Slice(c.Filters, func(i, j int) bool { return c.Filters[i].Field+c.Filters[i].Op < c.Filters[j].Field+c.Filters[j].Op })
	sort.Slice(c.Refs, func(i, j int) bool { return c.Refs[i].Type+c.Refs[i].ID < c.Refs[j].Type+c.Refs[j].ID })
	b, _ := json.Marshal(c)
	return string(b)
}

type score struct{ ok, total int }

func (s score) rate() float64 {
	if s.total == 0 {
		return 1
	}
	return float64(s.ok) / float64(s.total)
}

func TestCompilerAgainstTheGoldenCorpus(t *testing.T) {
	cat := catalog.MustLoad()
	w := loadWorld(t)
	cases := loadCases(t)
	ctx := context.Background()
	comp := compile.Compiler{Cat: cat, R: resolve.Resolver{Cat: cat, L: fixtureLookups{w: w}, Topo: fixtureLookups{w: w}}}

	perCat := map[string]*score{}
	var qScore, pScore score
	// Per-metric numbers over every answerable phrasing (N-C6):
	//   entity precision   — refs the compiler emitted that the expected query
	//                        (or an alternate) also names: a WRONG entity is
	//                        worse than none;
	//   executable rate    — compiled queries that validate in scope;
	//   answered precision — of the phrasings it compiled at all, the share it
	//                        compiled exactly right ("when it answers, it is
	//                        right");
	//   coverage           — the share it compiled at all (the rest go to the
	//                        model fallback or a clarifying question).
	var entityP, executable, answeredP, coverage score
	var misses []string

	for _, c := range cases {
		loc, err := time.LoadLocation(firstNonEmpty(c.Context.TZ, "UTC"))
		if err != nil {
			t.Fatalf("%s: tz: %v", c.ID, err)
		}
		cx := compile.Context{Loc: loc, Now: w.now, IncidentID: c.Context.IncidentID}
		if len(c.Context.PriorAST) > 0 {
			cx.PriorAST = decodeAST(t, c.ID+" prior", c.Context.PriorAST)
		}
		sc := fixtureScope{w: w, cross: c.Context.Cross}
		questions := append([]string{c.Question}, c.Paraphrases...)
		for qi, question := range questions {
			res, err := comp.Compile(ctx, question, cx)
			if err != nil {
				t.Fatalf("%s %q: %v", c.ID, question, err)
			}
			// SAFETY 1: actions / injection / cross-tenant are declined.
			if c.Expect.Decline == compile.DeclineNotAQuery && res.AST != nil {
				v, vr := validate.Validate(ctx, cat, sc, res.AST)
				if vr.Valid && v != nil {
					t.Errorf("SAFETY %s %q: must be refused, compiled to a valid query %s", c.ID, question, canon(res.AST))
				}
			}
			// SAFETY 2: nothing compiled names another tenant's entity.
			if res.AST != nil {
				for _, r := range res.AST.Refs {
					if w.owner[r.ID] != "" && w.owner[r.ID] != w.a.Tenant {
						t.Errorf("SAFETY %s %q: compiled a foreign entity %s", c.ID, question, r.ID)
					}
				}
			}
			// SAFETY 3: a question the corpus says to reject never compiles to
			// a query that VALIDATES.
			if c.Expect.RejectCode != "" && res.AST != nil {
				if _, vr := validate.Validate(ctx, cat, sc, res.AST); vr.Valid {
					t.Errorf("SAFETY %s %q: corpus expects %s, compiled query validates: %s", c.ID, question, c.Expect.RejectCode, canon(res.AST))
				}
			}
			if len(c.Expect.AST) == 0 {
				continue // accuracy is only scored on answerable cases
			}
			want := []string{canon(decodeAST(t, c.ID, c.Expect.AST))}
			for i, alt := range c.Expect.Alternates {
				want = append(want, canon(decodeAST(t, fmt.Sprintf("%s alt %d", c.ID, i), alt)))
			}
			got := ""
			if res.AST != nil {
				got = canon(res.AST)
			}
			hit := false
			for _, wv := range want {
				hit = hit || got == wv
			}
			coverage.total++
			if res.AST != nil {
				coverage.ok++
				answeredP.total++
				if hit {
					answeredP.ok++
				} else if testing.Verbose() && qi == 0 {
					t.Logf("WRONG %s %q\n    got  %s\n    want %s", c.ID, question, got, want[0])
				}
				executable.total++
				if _, vr := validate.Validate(ctx, cat, sc, res.AST); vr.Valid {
					executable.ok++
				}
				expected := map[string]bool{}
				for _, raw := range append([]json.RawMessage{c.Expect.AST}, c.Expect.Alternates...) {
					for _, r := range decodeAST(t, c.ID+" refs", raw).Refs {
						expected[r.Type+"|"+r.ID] = true
					}
				}
				for _, r := range res.AST.Refs {
					entityP.total++
					if expected[r.Type+"|"+r.ID] {
						entityP.ok++
					} else if testing.Verbose() {
						t.Logf("ENTITY-MISS %s %q → %s|%s (expected %v)", c.ID, question, r.Type, r.ID, expected)
					}
				}
			}
			s := perCat[c.Category]
			if s == nil {
				s = &score{}
				perCat[c.Category] = s
			}
			if qi == 0 {
				qScore.total++
				s.total++
				if hit {
					qScore.ok++
					s.ok++
				} else if len(misses) < 400 {
					misses = append(misses, fmt.Sprintf("%s %q\n    got  %s\n    want %s", c.ID, question, orUnparsed(got, res), want[0]))
				}
			} else {
				pScore.total++
				if hit {
					pScore.ok++
					if testing.Verbose() {
						t.Logf("PARA-HIT %s %q", c.ID, question)
					}
				} else if testing.Verbose() && res.AST == nil {
					t.Logf("PARA-UNPARSED %s %q %v", c.ID, question, res.NotUnderstood)
				}
			}
		}
	}
	var cats []string
	for k := range perCat {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	var b strings.Builder
	fmt.Fprintf(&b, "deterministic compiler vs golden corpus: questions %d/%d (%.2f), paraphrases %d/%d (%.2f)\n",
		qScore.ok, qScore.total, qScore.rate(), pScore.ok, pScore.total, pScore.rate())
	fmt.Fprintf(&b, "entity precision %d/%d (%.3f) · executable %d/%d (%.3f) · answered precision %d/%d (%.3f) · coverage %d/%d (%.3f)\n",
		entityP.ok, entityP.total, entityP.rate(), executable.ok, executable.total, executable.rate(),
		answeredP.ok, answeredP.total, answeredP.rate(), coverage.ok, coverage.total, coverage.rate())
	for _, k := range cats {
		fmt.Fprintf(&b, "  %-18s %d/%d\n", k, perCat[k].ok, perCat[k].total)
	}
	t.Log(b.String())
	if testing.Verbose() {
		t.Log("misses:\n" + strings.Join(misses, "\n"))
	}
	for _, f := range []struct {
		name       string
		got, floor float64
	}{
		{"entity precision", entityP.rate(), minEntityPrecision},
		{"executable rate", executable.rate(), minExecutableRate},
		{"answered precision", answeredP.rate(), minAnsweredPrecision},
	} {
		if f.got < f.floor {
			t.Errorf("%s fell below its ratchet floor: %.3f < %.2f", f.name, f.got, f.floor)
		}
	}
	if qScore.rate() < minQuestionAccuracy || pScore.rate() < minParaphraseAccuracy {
		t.Fatalf("accuracy fell below its ratchet floor (questions %.2f < %.2f or paraphrases %.2f < %.2f)",
			qScore.rate(), minQuestionAccuracy, pScore.rate(), minParaphraseAccuracy)
	}
}

func orUnparsed(got string, r compile.Result) string {
	switch {
	case got != "":
		return got
	case r.Decline != "":
		return "(declined " + r.Decline + ")"
	case len(r.Clarify) > 0:
		return fmt.Sprintf("(clarify %d candidates)", len(r.Clarify))
	}
	return fmt.Sprintf("(unparsed: %v)", r.NotUnderstood)
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}
