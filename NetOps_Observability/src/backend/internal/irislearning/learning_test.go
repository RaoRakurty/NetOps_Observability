// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irislearning

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/entityalias"
	"netops/backend/internal/incidentfp"
	"netops/backend/internal/irisquerylog"
	"netops/backend/internal/iristriage"
	"netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/catalog"
	"netops/backend/internal/orgcontext"
	"netops/backend/internal/rcaresolution"
	"netops/backend/internal/tenantrunbook"
)

const (
	tA    = "t-a"
	tB    = "t-b"
	alice = "u-alice"
	bob   = "u-bob"
	carol = "u-carol"
)

var now = time.Date(2026, 11, 14, 12, 0, 0, 0, time.UTC)

// ── fixtures (lab-shaped) ───────────────────────────────────────────────────

func caseID(n int) string { return "00000000-0000-4000-8000-0000000000" + string(rune('a'+n/10)) + string(rune('0'+n%10)) }

// labInputs: four cEdge-80 incidents fixed by a provider ticket (one with an
// operator note carrying a carrier name), two vEdge-51 transient incidents,
// two operators correcting answers to mean site:dallas-hq while saying "dallas
// box", and six flow questions Iris had no tool for.
func labInputs() Inputs {
	in := Inputs{Now: now, Fingerprints: map[string]incidentfp.Fingerprint{}}
	add := func(n int, device string, kind rcaresolution.Kind, note string, daysAgo int) {
		id := caseID(n)
		in.Fingerprints[id] = incidentfp.Fingerprint{TenantID: tA, CorrelationID: id, Devices: []string{device, "10.255.255.80"}}
		in.Resolutions = append(in.Resolutions, rcaresolution.Resolution{ID: "r" + id, TenantID: tA, CorrelationID: id, Kind: kind,
			Note: note, CreatedBy: bob, CreatedAt: now.Add(-time.Duration(daysAgo) * 24 * time.Hour)})
	}
	add(1, "cEdge-80", rcaresolution.KindProviderTicket, "Carrier X ticket 4411, fibre cut", 3)
	add(2, "cEdge-80", rcaresolution.KindProviderTicket, "", 10)
	add(3, "cEdge-80", rcaresolution.KindProviderTicket, "", 20)
	add(4, "cEdge-80", rcaresolution.KindProviderTicket, "", 400) // outside the lookback
	add(5, "cEdge-80", rcaresolution.KindProviderTicket, "", 30)
	add(6, "vEdge-51", rcaresolution.KindNoActionTransient, "", 2)
	add(7, "vEdge-51", rcaresolution.KindNoActionTransient, "", 5)

	dallas := ast.EntityRef{Type: "site", ID: "site:dallas-hq"}
	wrong := irisquerylog.Entity{Type: "site", ID: "site:austin", Method: "partial"}
	q := func(id, who, question string) irisquerylog.Record {
		return irisquerylog.Record{ID: id, Principal: who, Question: question, At: now.Add(-time.Hour),
			Entities: []irisquerylog.Entity{wrong},
			Corrections: []irisquerylog.Correction{{At: now.Add(-time.Hour), By: who, Kind: irisquerylog.KindWrongEntity,
				CorrectedAST: &ast.AST{Refs: []ast.EntityRef{dallas}}}}}
	}
	in.Queries = append(in.Queries,
		q("q1", alice, "why is the dallas box slow"),
		q("q2", carol, "show errors on the dallas box"),
		q("q3", alice, "dallas box loss today"))
	for i := 0; i < 6; i++ {
		in.Queries = append(in.Queries, irisquerylog.Record{ID: "m" + string(rune('0'+i)), Principal: alice,
			Question: "top talkers on the wan secret-project-x", Outcome: irisquerylog.OutcomeMiss,
			MissClass: iristriage.NoTool, Intent: "flow_top", At: now.Add(-time.Duration(i) * time.Hour)})
	}
	return in
}

// memAliases mirrors tenant.Collection's default-closed semantics.
type memAliases struct{ m map[string]entityalias.Alias }

func (c *memAliases) All(t string, cross bool) []entityalias.Alias {
	var out []entityalias.Alias
	for _, a := range c.m {
		if cross || a.TenantID == t {
			out = append(out, a)
		}
	}
	return out
}
func (c *memAliases) Get(t string, _ bool, id string) (entityalias.Alias, bool) {
	a, ok := c.m[t+"\x00"+id]
	return a, ok
}
func (c *memAliases) Upsert(a entityalias.Alias) error { c.m[a.TenantID+"\x00"+a.Key()] = a; return nil }
func (c *memAliases) Delete(t string, _ bool, id string) bool {
	_, ok := c.m[t+"\x00"+id]
	delete(c.m, t+"\x00"+id)
	return ok
}

type rig struct {
	store   *MemStore
	targets Targets
	aliases *entityalias.Store
	ctx     *orgcontext.MemStore
	rbs     *tenantrunbook.MemStore
}

func newRig() rig {
	al := &entityalias.Store{C: &memAliases{m: map[string]entityalias.Alias{}}, Cat: catalog.MustLoad()}
	oc := orgcontext.NewMemStore()
	rb := tenantrunbook.NewMemStore(tenantrunbook.Config{ToolNames: ai.ToolNames})
	return rig{store: NewMemStore(), aliases: al, ctx: oc, rbs: rb,
		targets: Targets{Context: oc, Runbooks: rb, Aliases: al, ToolNames: ai.ToolNames}}
}

func seeAll(context.Context, string, string) (bool, error) { return true, nil }

func offer(t *testing.T, r rig, tenant string, in Inputs) []Proposal {
	t.Helper()
	if _, _, err := r.store.Offer(context.Background(), tenant, Generate(in), now); err != nil {
		t.Fatal(err)
	}
	ps, err := r.store.List(context.Background(), tenant)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func find(ps []Proposal, g Generator, frag string) (Proposal, bool) {
	for _, p := range ps {
		if p.Generator == g && strings.Contains(p.Subject, frag) {
			return p, true
		}
	}
	return Proposal{}, false
}

// ── generators ──────────────────────────────────────────────────────────────

func TestGenerateIsDeterministic(t *testing.T) {
	a, b := Generate(labInputs()), Generate(labInputs())
	if !reflect.DeepEqual(a, b) {
		t.Fatal("the same inputs gave different proposals")
	}
	if len(a) != 3 {
		var subj []string
		for _, p := range a {
			subj = append(subj, p.Subject)
		}
		t.Fatalf("want 3 proposals (cEdge-80 provider, dallas alias, flow gap), got %d: %v", len(a), subj)
	}
}

func TestResolutionPatternNeedsThreeCasesInTheLookback(t *testing.T) {
	ps := Generate(labInputs())
	p, ok := find(ps, GenResolutionPattern, "cedge-80|provider_ticket")
	if !ok {
		t.Fatal("no cEdge-80 provider proposal")
	}
	if p.EvidenceCount != 4 {
		t.Fatalf("evidence count %d, want 4 (the 400-day-old case is outside the lookback)", p.EvidenceCount)
	}
	if p.Context.Kind != orgcontext.KindCarrierRelationship || p.Context.Scope != orgcontext.ScopeTenant {
		t.Fatalf("draft %+v", p.Context)
	}
	if !HasPlaceholder(p.Context.Body) {
		t.Fatal("the carrier draft must leave the carrier for a person to fill in")
	}
	if _, ok := find(ps, GenResolutionPattern, "vedge-51"); ok {
		t.Fatal("two transient cases are below the threshold of three")
	}
}

func TestOperatorNotesNeverEnterADraft(t *testing.T) {
	for _, p := range Generate(labInputs()) {
		for _, text := range []string{p.Title, p.Why, draftText(p)} {
			if strings.Contains(text, "Carrier X") || strings.Contains(text, "4411") {
				t.Fatalf("%s carries the operator's note: %q", p.Subject, text)
			}
		}
	}
	p, _ := find(Generate(labInputs()), GenResolutionPattern, "cedge-80")
	quoted := false
	for _, e := range p.Evidence {
		quoted = quoted || strings.Contains(e.Quote, "Carrier X")
	}
	if !quoted {
		t.Fatal("the reviewer should see the operator's note as quoted evidence")
	}
}

func draftText(p Proposal) string {
	switch {
	case p.Context != nil:
		return p.Context.Key + "\n" + p.Context.Body
	case p.Alias != nil:
		return p.Alias.Alias
	case p.Runbook != nil:
		return p.Runbook.Name + "\n" + p.Runbook.SkillMD
	}
	return ""
}

func TestNoAddressReachesADraft(t *testing.T) {
	for _, p := range Generate(labInputs()) {
		if strings.Contains(draftText(p), "10.255.255.80") || strings.Contains(p.Title, "10.255") {
			t.Fatalf("%s carries a management address", p.Subject)
		}
	}
}

func TestAliasPhraseNeedsTwoPeople(t *testing.T) {
	p, ok := find(Generate(labInputs()), GenEntityCorrection, "site:dallas-hq")
	if !ok {
		t.Fatal("no alias proposal")
	}
	if p.Alias.Alias != "dallas box" || p.Alias.EntityID != "site:dallas-hq" {
		t.Fatalf("alias draft %+v", p.Alias)
	}
	// One person alone, however often, proposes nothing.
	in := labInputs()
	for i := range in.Queries {
		in.Queries[i].Principal = alice
		for j := range in.Queries[i].Corrections {
			in.Queries[i].Corrections[j].By = alice
		}
	}
	if _, ok := find(Generate(in), GenEntityCorrection, "dallas"); ok {
		t.Fatal("an alias was proposed from one person's wording")
	}
}

func TestAliasAlreadyInUseIsNotProposed(t *testing.T) {
	in := labInputs()
	in.Aliases = []entityalias.Alias{{TenantID: tA, EntityType: "site", EntityID: "site:dallas-hq", Alias: "dallas box",
		Norm: catalog.NormalizeAlias("dallas box")}}
	if p, ok := find(Generate(in), GenEntityCorrection, "dallas"); ok && p.Alias.Alias == "dallas box" {
		t.Fatal("proposed an alias that already exists")
	}
}

func TestMissClusterDraftsAMOPWithoutQuestionText(t *testing.T) {
	p, ok := find(Generate(labInputs()), GenMissCluster, "flow-top")
	if !ok {
		t.Fatal("no miss-cluster proposal")
	}
	if strings.Contains(draftText(p), "secret-project-x") || strings.Contains(p.Why, "secret-project-x") {
		t.Fatal("a colleague's question text was copied into a proposal")
	}
	if _, err := tenantrunbook.Parse(tA, p.Runbook.Name, tenantrunbook.KindMOP, tenantrunbook.Source{SkillMD: p.Runbook.SkillMD}, ai.ToolNames()); err != nil {
		t.Fatalf("the procedure draft does not parse as a MOP: %v", err)
	}
	// Wording misses are Iris's to fix, not the team's.
	in := labInputs()
	for i := range in.Queries {
		if in.Queries[i].Outcome == irisquerylog.OutcomeMiss {
			in.Queries[i].MissClass = iristriage.Wording
		}
	}
	if _, ok := find(Generate(in), GenMissCluster, ""); ok {
		t.Fatal("wording misses produced a runbook proposal")
	}
}

// ── store ───────────────────────────────────────────────────────────────────

func TestOfferIsIdempotentAndKeepsDecisions(t *testing.T) {
	r := newRig()
	ps := offer(t, r, tA, labInputs())
	if len(ps) != 3 {
		t.Fatalf("want 3 stored, got %d", len(ps))
	}
	p, _ := find(ps, GenMissCluster, "")
	if _, err := Dismiss(context.Background(), r.store, tA, bob, p.ID, "we document flows elsewhere", now); err != nil {
		t.Fatal(err)
	}
	added, refreshed, err := r.store.Offer(context.Background(), tA, Generate(labInputs()), now.Add(time.Hour))
	if err != nil || added != 0 || refreshed != 0 {
		t.Fatalf("a second refresh changed things: added=%d refreshed=%d err=%v", added, refreshed, err)
	}
	got, _ := r.store.Get(context.Background(), tA, p.ID)
	if got.State != StateDismissed {
		t.Fatal("a refresh re-opened a dismissed proposal")
	}
}

func TestDismissNeedsAReason(t *testing.T) {
	r := newRig()
	p := offer(t, r, tA, labInputs())[0]
	if _, err := Dismiss(context.Background(), r.store, tA, bob, p.ID, "  ", now); err == nil {
		t.Fatal("dismissed without a reason")
	}
}

// ── review: nothing activates without a second person ──────────────────────

func adoptContext(t *testing.T, r rig) Proposal {
	t.Helper()
	p, _ := find(offer(t, r, tA, labInputs()), GenResolutionPattern, "cedge-80")
	if _, err := Adopt(context.Background(), r.store, r.targets, tA, alice, p.ID, Edit{}, seeAll, now); !errors.Is(err, ErrUnfinished) {
		t.Fatalf("adopting a draft with {{…}} left: %v", err)
	}
	body := "cEdge-80: its MPLS circuit is CX-7781, run by Carrier X; open tickets through the Carrier X NOC portal."
	out, err := Adopt(context.Background(), r.store, r.targets, tA, alice, p.ID, Edit{Body: body}, seeAll, now)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAdoptingAFactSendsItForReviewAndNothingMore(t *testing.T) {
	r := newRig()
	p := adoptContext(t, r)
	if p.State != StateAdopted || p.AdoptedBy != alice || p.TargetID == "" || p.TargetVersion != 1 {
		t.Fatalf("after adopt: %+v", p)
	}
	facts, _ := r.ctx.ActiveFacts(context.Background(), tA)
	if len(facts) != 0 {
		t.Fatal("adopting activated a fact")
	}
	if st := r.targets.TargetState(context.Background(), tA, p); st != string(orgcontext.StatePending) {
		t.Fatalf("target state %q, want pending", st)
	}
	doc, _ := r.ctx.Get(context.Background(), tA, p.TargetID)
	if doc.Versions[0].Author != alice {
		t.Fatal("the fact's author must be the person who adopted it, not the system")
	}
}

func TestTheAdopterCannotApproveTheirOwnFact(t *testing.T) {
	r := newRig()
	p := adoptContext(t, r)
	if _, err := Approve(context.Background(), r.store, r.targets, tA, alice, p.ID, seeAll, now); !errors.Is(err, orgcontext.ErrSelfApproval) {
		t.Fatalf("self-approval: %v", err)
	}
	out, err := Approve(context.Background(), r.store, r.targets, tA, bob, p.ID, seeAll, now)
	if err != nil {
		t.Fatal(err)
	}
	if out.State != StateApplied || out.DecidedBy != bob {
		t.Fatalf("after approve: %+v", out)
	}
	facts, _ := r.ctx.ActiveFacts(context.Background(), tA)
	if len(facts) != 1 || !strings.Contains(facts[0].Body, "CX-7781") {
		t.Fatalf("active facts %+v", facts)
	}
}

func TestAliasNeedsTwoPeopleAndPassesItsChecks(t *testing.T) {
	r := newRig()
	p, _ := find(offer(t, r, tA, labInputs()), GenEntityCorrection, "dallas")
	if _, err := Adopt(context.Background(), r.store, r.targets, tA, alice, p.ID, Edit{}, func(context.Context, string, string) (bool, error) { return false, nil }, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("an alias to an entity the person cannot see: %v", err)
	}
	p2, err := Adopt(context.Background(), r.store, r.targets, tA, alice, p.ID, Edit{}, seeAll, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.aliases.List(tA, false)) != 0 {
		t.Fatal("adopting an alias wrote it")
	}
	if _, err := Approve(context.Background(), r.store, r.targets, tA, alice, p2.ID, seeAll, now); !errors.Is(err, ErrSelfApproval) {
		t.Fatalf("alias self-approval: %v", err)
	}
	if _, err := Approve(context.Background(), r.store, r.targets, tA, bob, p2.ID, seeAll, now); err != nil {
		t.Fatal(err)
	}
	got := r.aliases.List(tA, false)
	if len(got) != 1 || got[0].Alias != "dallas box" || got[0].Source != entityalias.SourceSuggestion || got[0].CreatedBy != alice {
		t.Fatalf("aliases %+v", got)
	}
}

func TestAliasThatAlreadyMeansSomethingElseIsRefused(t *testing.T) {
	r := newRig()
	p, _ := find(offer(t, r, tA, labInputs()), GenEntityCorrection, "dallas")
	if _, err := r.aliases.Put(entityalias.Alias{TenantID: tA, EntityType: "site", EntityID: "site:austin", Alias: "dallas box", CreatedBy: carol}); err != nil {
		t.Fatal(err)
	}
	if _, err := Adopt(context.Background(), r.store, r.targets, tA, alice, p.ID, Edit{}, seeAll, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting alias: %v", err)
	}
}

func TestRunbookProposalBecomesADraftApprovedElsewhere(t *testing.T) {
	r := newRig()
	p, _ := find(offer(t, r, tA, labInputs()), GenMissCluster, "")
	out, err := Adopt(context.Background(), r.store, r.targets, tA, alice, p.ID, Edit{}, seeAll, now)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := r.rbs.Get(context.Background(), tA, out.TargetID)
	if err != nil || rb.Versions[0].State != orgcontext.StateDraft || rb.Versions[0].Author != alice {
		t.Fatalf("runbook %+v err %v", rb, err)
	}
	if _, err := Approve(context.Background(), r.store, r.targets, tA, bob, out.ID, seeAll, now); !errors.Is(err, ErrReviewElse) {
		t.Fatalf("a runbook was approved from the learning queue: %v", err)
	}
}

// ── §3a ─────────────────────────────────────────────────────────────────────

func TestAnotherTenantsProposalIsNotFound(t *testing.T) {
	r := newRig()
	p := offer(t, r, tA, labInputs())[0]
	if _, err := r.store.Get(context.Background(), tB, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant B read A's proposal: %v", err)
	}
	if _, err := Adopt(context.Background(), r.store, r.targets, tB, carol, p.ID, Edit{}, seeAll, now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant B adopted A's proposal: %v", err)
	}
	if _, err := Dismiss(context.Background(), r.store, tB, carol, p.ID, "not ours", now); !errors.Is(err, ErrNotFound) {
		t.Fatalf("tenant B dismissed A's proposal: %v", err)
	}
	if ps, _ := r.store.List(context.Background(), tB); len(ps) != 0 {
		t.Fatal("tenant B lists A's proposals")
	}
}
