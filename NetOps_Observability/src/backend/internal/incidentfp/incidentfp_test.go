// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package incidentfp

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)

func fp(id string, mod func(*Parts)) Fingerprint {
	p := Parts{TenantID: "t-a", CorrelationID: id, Signature: "sig.wan.dia-loss", OwnerDomain: "wan", SeamType: "dia", Owner: "isp",
		OccurredAt: t0}
	if mod != nil {
		mod(&p)
	}
	return FromParts(p, t0)
}

func TestWeightsSumToOne(t *testing.T) {
	if s := wSignature + wChain + wEntities + wSeam + wSymptoms + wPath + wDomain; math.Abs(s-1) > 1e-9 {
		t.Fatalf("weights sum to %v", s)
	}
}

// The worked examples in score.go are pinned.
func TestWorkedExamples(t *testing.T) {
	subject := fp("s", func(p *Parts) { p.Devices = []string{"edge-1"}; p.Seams = []string{"seam:dfw-comcast"} })
	weak := fp("w", func(p *Parts) { p.Devices = []string{"edge-9"} }) // signature + provider class + domain only
	s, _, _, gate := Score(subject, weak)
	if !gate || math.Abs(s-0.355) > 1e-9 {
		t.Fatalf("weak example: %.3f gate=%v, want .355 gated", s, gate)
	}
	similar := fp("m", func(p *Parts) {
		p.Devices = []string{"edge-1"}
		p.Seams = []string{"seam:dfw-comcast"}
		p.OwnerDomain = "dc"
	})
	if s, _, _, _ := Score(subject, similar); math.Abs(s-0.60) > 1e-9 {
		t.Fatalf("similar example: %.3f, want .60", s)
	}
	strongS := fp("s2", func(p *Parts) {
		p.Devices = []string{"edge-1"}
		p.Seams = []string{"seam:x"}
		p.OwnerDomain = "dc"
		p.ChainStepKinds = [][]string{{"interface_down"}, {"bgp_session_down"}}
		p.SymptomKinds = []string{"loss"}
	})
	strongC := strongS
	strongC.CorrelationID = "s3"
	if s, _, _, _ := Score(strongS, strongC); math.Abs(s-0.93) > 1e-9 {
		t.Fatalf("strong example: %.3f, want .93", s)
	}
}

// Domain or provider overlap alone never makes a match.
func TestHardGate(t *testing.T) {
	subject := fp("s", func(p *Parts) { p.Signature = "undetermined"; p.Devices = []string{"edge-1"} })
	cand := fp("c", func(p *Parts) { p.Signature = "undetermined"; p.Devices = []string{"edge-2"}; p.Paths = []string{"p1"} })
	if _, _, _, gate := Score(subject, cand); gate {
		t.Fatal("no signature, no chain, different device: the gate must refuse")
	}
	if usableSignature("undetermined") != "" || usableSignature("  ") != "" {
		t.Fatal("an undetermined signature never matches")
	}
}

// Below the threshold the answer says so — and the near miss appears nowhere.
func TestBelowThresholdIsNoSimilarIncidentAndLeaksNothing(t *testing.T) {
	subject := fp("subject-1", func(p *Parts) { p.Devices = []string{"edge-1"}; p.Seams = []string{"seam:dfw"} })
	near := fp("near-miss-9", func(p *Parts) { p.Devices = []string{"edge-7"} }) // .355
	r := Rank(subject, []Fingerprint{near, subject}, "180d")
	if r.Verdict != VerdictNone || len(r.Matches) != 0 || r.Examined != 1 {
		t.Fatalf("result: %+v", r)
	}
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "near-miss-9") || strings.Contains(string(b), "0.36") {
		t.Fatalf("the near miss leaked: %s", b)
	}
	if !strings.Contains(r.Note, "none is similar enough") || r.Caveat == "" {
		t.Fatalf("note: %q", r.Note)
	}
	empty := Rank(subject, nil, "180d")
	if empty.Note == r.Note || !strings.Contains(empty.Note, "No closed incidents") {
		t.Fatalf("empty history and none-above-threshold must say different things: %q / %q", empty.Note, r.Note)
	}
	// Exactly at the threshold is included.
	at := fp("at", func(p *Parts) { p.Devices = []string{"edge-1"}; p.Seams = []string{"seam:dfw"}; p.OwnerDomain = "dc" })
	if r := Rank(subject, []Fingerprint{at}, "180d"); r.Verdict != VerdictSimilar || len(r.Matches) != 1 || r.Matches[0].Strength != "similar" {
		t.Fatalf("a .60 candidate must be returned as similar: %+v", r)
	}
}

func TestFingerprintDerivation(t *testing.T) {
	f := FromParts(Parts{CorrelationID: "x", Signature: " SIG.A ", Devices: []string{"Edge-1", "edge-1", ""},
		ChainStepKinds: [][]string{{"a", "a"}, {"b"}, {"b", "c"}}, SymptomKinds: []string{"Loss"}}, t0)
	if f.Signature != "sig.a" || len(f.Devices) != 1 || strings.Join(f.ChainKinds, ">") != "a>b>c" || f.ChainKey == "" {
		t.Fatalf("derivation: %+v", f)
	}
	c := FromParts(Parts{CorrelationID: "x", ChainStepKinds: [][]string{{"a"}}, ChainContradicted: true}, t0)
	if len(c.ChainKinds) != 0 || c.ChainKey != "" || !c.Partial() {
		t.Fatal("a contradicted chain contributes nothing")
	}
	var many []string
	for i := 0; i < 50; i++ {
		many = append(many, strings.Repeat("d", i+1))
	}
	if g := FromParts(Parts{Devices: many}, t0); len(g.Devices) != maxEntities {
		t.Fatalf("entity bound: %d", len(g.Devices))
	}
}

func TestRankOrderAndCap(t *testing.T) {
	subject := fp("s", func(p *Parts) { p.Devices = []string{"edge-1"}; p.Seams = []string{"seam:x"} })
	var cands []Fingerprint
	for i := 0; i < 9; i++ {
		c := fp(string(rune('a'+i)), func(p *Parts) {
			p.Devices = []string{"edge-1"}
			p.Seams = []string{"seam:x"}
			p.OccurredAt = t0.Add(time.Duration(i) * time.Hour)
		})
		cands = append(cands, c)
	}
	r := Rank(subject, cands, "180d")
	if len(r.Matches) != MaxMatches || r.Matches[0].CorrelationID != "i" {
		t.Fatalf("cap %d / recency tie-break first=%s", len(r.Matches), r.Matches[0].CorrelationID)
	}
	if _, ok := WindowFor("7d"); ok {
		t.Fatal("the window vocabulary is closed")
	}
	if d, ok := WindowFor(""); !ok || d != 180*24*time.Hour {
		t.Fatal("default window")
	}
}

func TestRecallServiceBuildsWithinBudgetAndStores(t *testing.T) {
	subject := fp("subj", func(p *Parts) { p.Devices = []string{"edge-1"}; p.Seams = []string{"seam:x"} })
	var cands []Fingerprint
	for i := 0; i < 12; i++ {
		cands = append(cands, Fingerprint{CorrelationID: string(rune('a' + i)), Signature: subject.Signature, Devices: []string{"edge-1"}, OccurredAt: t0})
	}
	cands = append(cands, Fingerprint{CorrelationID: "unrelated", Signature: "sig.other", Devices: []string{"core-9"}})
	builds, gotTenant := 0, ""
	store := NewMemStore(100)
	d := Deps{
		Store: store,
		Candidates: func(_ context.Context, tenant string, _ time.Time) ([]Fingerprint, error) {
			gotTenant = tenant
			return cands, nil
		},
		Build: func(_ context.Context, tenant, id string) (Fingerprint, error) {
			builds++
			f := fp(id, func(p *Parts) { p.Devices = []string{"edge-1"}; p.Seams = []string{"seam:x"} })
			return f, nil
		},
		Now: func() time.Time { return t0.Add(time.Hour) },
	}
	r, err := d.Recall(context.Background(), "t-a", subject, "")
	if err != nil {
		t.Fatal(err)
	}
	if gotTenant != "t-a" || builds != EnrichBudget || r.Verdict != VerdictSimilar || r.Examined != 13 {
		t.Fatalf("tenant=%q builds=%d verdict=%s examined=%d", gotTenant, builds, r.Verdict, r.Examined)
	}
	// The built ones were written through: a second recall builds only the rest.
	builds = 0
	if _, err := d.Recall(context.Background(), "t-a", subject, ""); err != nil {
		t.Fatal(err)
	}
	if builds != 12-EnrichBudget {
		t.Fatalf("second recall built %d, want %d", builds, 12-EnrichBudget)
	}
	if _, err := d.Recall(context.Background(), "t-a", subject, "7d"); !errors.Is(err, ErrBadWindow) {
		t.Fatal("closed window vocabulary")
	}
	// No key shared with anything: none similar, but history was compared.
	lone := fp("lone", func(p *Parts) { p.Signature = "sig.none"; p.Devices = []string{"zz"} })
	r, _ = d.Recall(context.Background(), "t-a", lone, "")
	if r.Verdict != VerdictNone || !strings.Contains(r.Note, "none is similar") {
		t.Fatalf("lone: %+v", r)
	}
	// Another tenant's store rows are never read for this tenant.
	if got, _ := store.Get(context.Background(), "t-b", []string{"a", "b"}); len(got) != 0 {
		t.Fatal("tenant B read tenant A's fingerprints")
	}
}
