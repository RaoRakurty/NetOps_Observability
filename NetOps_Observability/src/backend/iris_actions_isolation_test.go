// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// iris_actions_isolation_test.go — Iris's approval-gated writes (tracker 337
// N-I4) over the real server wiring. org_isolation_test.go is the template.
//
// The fixture: two tenants; tenant A's case has an OPEN ServiceNow ticket
// linked through the tenant's own ticketing connection. The ITSM adapter is
// FAKED: nothing leaves the test. What is proved:
//
//   - nothing is proposed unless the AI add-on, investigations, the Iris
//     actions kill switch, the workspace's own toggle and its kind allowlist
//     all say so; a proposal sends nothing;
//   - the note goes only to the ticket linked to the case, never one a client
//     names; a link gone by approval time sends nothing;
//   - two people: the person Iris answered cannot approve, an API key cannot
//     decide, a second administrator runs it ONCE, a replay is a 409;
//   - the kill switch turned off after the proposal stops the approval;
//   - §3a: tenant B never sees, approves or rejects tenant A's requests, an
//     as_tenant walk is ignored, the all-tenants view must choose a workspace;
//   - the approval and its execution land in the decision ledger (surface
//     "action"), hashes only.

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/ai"
	"netops/backend/internal/aidecision"
	"netops/backend/internal/aientitlement"
	"netops/backend/internal/irisaction"
	"netops/backend/internal/ticketing"
)

// fakeTicketAdapter records what would have been sent to the ITSM system.
type fakeTicketAdapter struct {
	mu    sync.Mutex
	notes []string
	refs  []ticketing.Ref
}

func (f *fakeTicketAdapter) Name() string                                              { return "servicenow" }
func (f *fakeTicketAdapter) ValidateConfig(ticketing.SystemConfig) error               { return nil }
func (f *fakeTicketAdapter) HealthCheck(context.Context, ticketing.SystemConfig) error { return nil }
func (f *fakeTicketAdapter) CreateIncident(context.Context, ticketing.SystemConfig, ticketing.Payload) (ticketing.Ref, error) {
	panic("an Iris action must never open a ticket")
}
func (f *fakeTicketAdapter) UpdateIncident(context.Context, ticketing.SystemConfig, ticketing.Ref, ticketing.Payload) error {
	panic("an Iris action must never update ticket fields")
}
func (f *fakeTicketAdapter) AddWorkNote(_ context.Context, _ ticketing.SystemConfig, ref ticketing.Ref, note string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notes = append(f.notes, note)
	f.refs = append(f.refs, ref)
	return nil
}
func (f *fakeTicketAdapter) ResolveIncident(context.Context, ticketing.SystemConfig, ticketing.Ref, string) error {
	panic("an Iris action must never resolve a ticket")
}
func (f *fakeTicketAdapter) LookupByCorrelationID(context.Context, ticketing.SystemConfig, string) (ticketing.Ref, bool, error) {
	return ticketing.Ref{}, false, nil
}
func (f *fakeTicketAdapter) FetchIncident(_ context.Context, _ ticketing.SystemConfig, ref ticketing.Ref) (ticketing.RemoteIncident, bool, error) {
	return ticketing.RemoteIncident{Number: ref.Number, SysID: ref.SysID, State: 2}, true, nil
}

func (f *fakeTicketAdapter) sent() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.notes...)
}

const (
	actCorrA   = "11111111-aaaa-4aaa-8aaa-111111111111"
	actTicketA = "INC0012345"
)

type actionsFix struct {
	s                    *server
	h                    http.Handler
	alice, bob, reviewer jwtClaims
	tenantA, tenantB     string
	adapter              *fakeTicketAdapter
}

func actionsFixture(t *testing.T) *actionsFix {
	t.Helper()
	s, h, alice, bob, reviewer := ctxFixture(t)
	f := &actionsFix{s: s, h: h, alice: alice, bob: bob, reviewer: reviewer}
	f.tenantA, _ = principalTenant(alice)
	f.tenantB, _ = principalTenant(bob)
	setAIModelsForTest(t, s, true, true)
	if _, err := s.features.Seed(aientitlement.SwitchActions, true, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	both := ai.ActionSettings{Enabled: true, Kinds: []string{string(irisaction.KindITSMNote), string(irisaction.KindInvestigationNote)}}
	for _, tn := range []string{f.tenantA, f.tenantB} {
		// Actions are an investigation feature: the workspace's investigation
		// grant is part of ai.investigate.
		if _, err := s.aiTenantCfg.SetEntitlement(tn, false, true, 0, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := s.aiTenantCfg.SetActions(tn, both); err != nil {
			t.Fatal(err)
		}
	}
	// Tenant A: its own ServiceNow connection and an OPEN ticket linked to the case.
	cred := strings.Join([]string{"not", "a", "credential"}, "-")
	s.itsmCfg = ticketing.NewITSMConfigStoreForTest(map[string]itsmConfig{
		itsmKey(f.tenantA): {ServiceNow: serviceNowConfig{Enabled: true, InstanceURL: "https://sn.example.test", User: "svc", Password: cred}},
	})
	s.ticketing = ticketing.NewMemStore()
	if err := s.ticketing.PutLink(context.Background(), ticketing.Link{
		TenantID: canonicalCorrTenant(f.tenantA), CorrObjectID: actCorrA, ExternalSystem: "servicenow",
		TicketNumber: actTicketA, SysID: "sys-abc", Status: "open", CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	s.irisMemory = ai.NewInvestigationFileStore(filepath.Join(t.TempDir(), "iris_investigations.json"))
	s.aiDecisions = aidecision.NewMemStore()
	s.aiDecisionMetrics = aidecision.NewMetrics()
	f.adapter = &fakeTicketAdapter{}
	svc := irisaction.NewService(irisaction.NewMemStore())
	if err := irisaction.Register[irisaction.ITSMNote](svc, irisaction.KindITSMNote,
		&irisTicketNoteExec{srv: s, adapters: map[string]ticketing.Adapter{"servicenow": f.adapter}}); err != nil {
		t.Fatal(err)
	}
	if err := irisaction.Register[irisaction.InvestigationNote](svc, irisaction.KindInvestigationNote, irisMemoryNoteExec{srv: s}); err != nil {
		t.Fatal(err)
	}
	s.irisActions = svc
	return f
}

func actSeed(corr string) ai.ActionSeed {
	return ai.ActionSeed{
		Target: ai.InvestigationTarget{CorrelationID: corr},
		Engine: &ai.InvestigationEngine{Tier: "confirmed", Statement: "BGP session to the carrier is down"},
		Title:  "BGP peer down on edge-1",
		Text:   "The BGP peer to the carrier went Idle after the WAN link flapped [ev-1].",
		Citations: []ai.Citation{
			{ID: "ev-1", Label: "edge-1 BGP Idle"}, {ID: "ev-2", Label: "Gi0/1 flaps"},
		},
		Skills: []string{"bgp-session-down"},
	}
}

func (f *actionsFix) propose(t *testing.T, c jwtClaims, corr string) []ai.ActionProposal {
	t.Helper()
	fn := f.s.aiProposeActions(c)
	if fn == nil {
		t.Fatal("no proposal step wired")
	}
	return fn(context.Background(), ai.Principal{}, actSeed(corr))
}

func cardOf(cards []ai.ActionProposal, k irisaction.Kind) (ai.ActionProposal, bool) {
	for _, c := range cards {
		if c.Kind == string(k) {
			return c, true
		}
	}
	return ai.ActionProposal{}, false
}

func TestIrisActionsProposedOnlyWhenEverythingIsOn(t *testing.T) {
	f := actionsFixture(t)
	cards := f.propose(t, f.alice, actCorrA)
	it, ok := cardOf(cards, irisaction.KindITSMNote)
	if !ok || it.Status != string(irisaction.StatusProposed) || it.ID == "" || !strings.Contains(it.Summary, actTicketA) {
		t.Fatalf("ticket-note card: %+v (all %+v)", it, cards)
	}
	mem, ok := cardOf(cards, irisaction.KindInvestigationNote)
	if !ok || mem.Status != string(irisaction.StatusProposed) {
		t.Fatalf("memory card: %+v", mem)
	}
	if len(f.adapter.sent()) != 0 {
		t.Fatal("proposing sent a note")
	}
	// The request holds the case's OWN linked ticket and the evidence it rests on.
	r, err := f.s.irisActions.Get(context.Background(), f.tenantA, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	p, err := irisaction.DecodePayload(r.Kind, r.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if n := p.(irisaction.ITSMNote); n.TicketRef != actTicketA || n.System != "servicenow" || !strings.Contains(n.Note, "edge-1 BGP Idle") {
		t.Fatalf("payload: %+v", n)
	}
	if r.ProposedBy != f.alice.Sub || len(r.Citations) != 2 {
		t.Fatalf("request: %+v", r)
	}

	// Each switch off → nothing proposed.
	off := func(name string, set func(), undo func()) {
		t.Helper()
		set()
		defer undo()
		if got := f.propose(t, f.alice, "22222222-aaaa-4aaa-8aaa-222222222222"); len(got) != 0 {
			t.Errorf("%s: proposed %+v", name, got)
		}
	}
	off("kill switch", func() {
		if _, _, err := f.s.features.Set(aientitlement.SwitchActions, false, "", "owner", time.Now()); err != nil {
			t.Fatal(err)
		}
	}, func() {
		// A risky switch turns back on only with its own name as the acknowledgement.
		if _, _, err := f.s.features.Set(aientitlement.SwitchActions, true, aientitlement.SwitchActions, "owner", time.Now()); err != nil {
			t.Fatal(err)
		}
	})
	off("workspace toggle", func() {
		if _, err := f.s.aiTenantCfg.SetActions(f.tenantA, ai.ActionSettings{}); err != nil {
			t.Fatal(err)
		}
	}, func() {
		if _, err := f.s.aiTenantCfg.SetActions(f.tenantA, ai.ActionSettings{Enabled: true,
			Kinds: []string{string(irisaction.KindITSMNote), string(irisaction.KindInvestigationNote)}}); err != nil {
			t.Fatal(err)
		}
	})
	off("empty allowlist", func() {
		if _, err := f.s.aiTenantCfg.SetActions(f.tenantA, ai.ActionSettings{Enabled: true}); err != nil {
			t.Fatal(err)
		}
	}, func() {
		if _, err := f.s.aiTenantCfg.SetActions(f.tenantA, ai.ActionSettings{Enabled: true,
			Kinds: []string{string(irisaction.KindITSMNote), string(irisaction.KindInvestigationNote)}}); err != nil {
			t.Fatal(err)
		}
	})
}

// A case with no linked ticket gets no ticket note — Iris never opens one or
// names one; tenant B's case has no link in tenant B.
func TestIrisActionsTicketComesOnlyFromTheCasesLink(t *testing.T) {
	f := actionsFixture(t)
	cards := f.propose(t, f.bob, actCorrA) // tenant B, same case id, no link in B
	it, ok := cardOf(cards, irisaction.KindITSMNote)
	if !ok || it.Status != "not_proposed" || it.ID != "" || !strings.Contains(it.Note, "no open ticket") {
		t.Fatalf("tenant B must not reach tenant A's ticket: %+v", it)
	}
}

func TestIrisActionsTwoPeopleOverHTTP(t *testing.T) {
	f := actionsFixture(t)
	cards := f.propose(t, f.alice, actCorrA)
	it, _ := cardOf(cards, irisaction.KindITSMNote)
	path := "/api/ai/actions/" + it.ID

	if code, m := ctxCall(t, f.h, f.alice, http.MethodPost, path+"/approve", `{}`); code != http.StatusForbidden {
		t.Fatalf("the person Iris answered approving: %d %v", code, m)
	}
	bot := f.reviewer
	bot.Sub = "apikey:k1"
	if code, _ := ctxCall(t, f.h, bot, http.MethodPost, path+"/approve", `{}`); code != http.StatusForbidden {
		t.Fatalf("an API key approving: %d", code)
	}
	if len(f.adapter.sent()) != 0 {
		t.Fatal("a refused approval sent the note")
	}
	code, m := ctxCall(t, f.h, f.reviewer, http.MethodPost, path+"/approve", `{"reason":"matches what we saw"}`)
	if code != http.StatusOK || m["status"] != string(irisaction.StatusExecuted) {
		t.Fatalf("second administrator approving: %d %v", code, m)
	}
	sent := f.adapter.sent()
	if len(sent) != 1 || sent[0] != m["preview"] || f.adapter.refs[0].SysID != "sys-abc" {
		t.Fatalf("the note sent must be exactly the approved text on the linked ticket: %v", sent)
	}
	if code, _ := ctxCall(t, f.h, f.reviewer, http.MethodPost, path+"/approve", `{}`); code != http.StatusConflict {
		t.Fatalf("a replayed approval: %d", code)
	}
	if len(f.adapter.sent()) != 1 {
		t.Fatalf("a replay sent again: %d", len(f.adapter.sent()))
	}
	// The ledger has the approval and the execution, hashes only.
	entries, err := f.s.aiDecisions.List(context.Background(), f.tenantA, false, aidecision.ListFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var approved, executed, verified bool
	for _, e := range entries {
		if e.Surface != aidecision.SurfaceAction {
			continue
		}
		switch e.EventType {
		case aidecision.ApprovalReceived:
			approved = e.ArgsSHA256 != "" && e.Tool == "propose_itsm_update"
		case aidecision.ExecutionStarted:
			executed = true
		case aidecision.VerificationCompleted:
			verified = e.Outcome == string(irisaction.StatusExecuted)
		}
	}
	if !approved || !executed || !verified {
		t.Fatalf("ledger: approved=%v executed=%v verified=%v (%d entries)", approved, executed, verified, len(entries))
	}
}

func TestIrisActionsMemoryNoteLandsOnlyAfterApproval(t *testing.T) {
	f := actionsFixture(t)
	cards := f.propose(t, f.alice, actCorrA)
	mem, _ := cardOf(cards, irisaction.KindInvestigationNote)
	recall := func() int {
		rows, err := f.s.irisMemory.Recall(context.Background(), f.tenantA, false, ai.InvestigationQuery{CorrelationID: actCorrA, Limit: 5})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if recall() != 0 {
		t.Fatal("the finding was saved before anyone approved it")
	}
	if code, m := ctxCall(t, f.h, f.reviewer, http.MethodPost, "/api/ai/actions/"+mem.ID+"/approve", `{}`); code != http.StatusOK {
		t.Fatalf("approve: %d %v", code, m)
	}
	if recall() != 1 {
		t.Fatal("the approved finding was not saved")
	}
	rows, _ := f.s.irisMemory.Recall(context.Background(), f.tenantB, false, ai.InvestigationQuery{CorrelationID: actCorrA, Limit: 5})
	if len(rows) != 0 {
		t.Fatal("tenant B recalls tenant A's finding")
	}
}

func TestIrisActionsKillSwitchStopsApproval(t *testing.T) {
	f := actionsFixture(t)
	it, _ := cardOf(f.propose(t, f.alice, actCorrA), irisaction.KindITSMNote)
	if _, _, err := f.s.features.Set(aientitlement.SwitchActions, false, "", "owner", time.Now()); err != nil {
		t.Fatal(err)
	}
	if code, m := ctxCall(t, f.h, f.reviewer, http.MethodPost, "/api/ai/actions/"+it.ID+"/approve", `{}`); code != http.StatusForbidden {
		t.Fatalf("approval with the kill switch off: %d %v", code, m)
	}
	if len(f.adapter.sent()) != 0 {
		t.Fatal("the kill switch was off and the note went out")
	}
}

func TestIrisActionsLinkGoneAtApprovalSendsNothing(t *testing.T) {
	f := actionsFixture(t)
	it, _ := cardOf(f.propose(t, f.alice, actCorrA), irisaction.KindITSMNote)
	if err := f.s.ticketing.PutLink(context.Background(), ticketing.Link{
		TenantID: canonicalCorrTenant(f.tenantA), CorrObjectID: actCorrA, ExternalSystem: "servicenow",
		TicketNumber: actTicketA, SysID: "sys-abc", Status: "resolved", UpdatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	code, m := ctxCall(t, f.h, f.reviewer, http.MethodPost, "/api/ai/actions/"+it.ID+"/approve", `{}`)
	if code != http.StatusBadGateway || m["status"] != string(irisaction.StatusFailed) {
		t.Fatalf("approving a note for a closed ticket: %d %v", code, m)
	}
	if len(f.adapter.sent()) != 0 {
		t.Fatal("a note went to a ticket that is no longer open")
	}
}

func TestIrisActionsTenantIsolationOverHTTP(t *testing.T) {
	f := actionsFixture(t)
	it, _ := cardOf(f.propose(t, f.alice, actCorrA), irisaction.KindITSMNote)
	code, m := ctxCall(t, f.h, f.bob, http.MethodGet, "/api/ai/actions", "")
	if code != http.StatusOK || m["open"].(float64) != 0 || len(m["requests"].([]any)) != 0 {
		t.Fatalf("tenant B's list: %d %v", code, m)
	}
	for _, c := range []struct{ method, path, body string }{
		{http.MethodGet, "/api/ai/actions/" + it.ID, ""},
		{http.MethodGet, "/api/ai/actions/" + it.ID + "?as_tenant=" + f.tenantA, ""},
		{http.MethodPost, "/api/ai/actions/" + it.ID + "/approve", `{}`},
		{http.MethodPost, "/api/ai/actions/" + it.ID + "/reject", `{"reason":"not ours"}`},
	} {
		if code, _ := ctxCall(t, f.h, f.bob, c.method, c.path, c.body); code != http.StatusNotFound {
			t.Errorf("tenant B %s %s: %d, want 404", c.method, c.path, code)
		}
	}
	if len(f.adapter.sent()) != 0 {
		t.Fatal("a cross-tenant call sent something")
	}
	// The platform owner's all-tenants view must choose a workspace.
	owner := f.alice
	owner.Role, owner.Tenant, owner.ActingTenant = "admin", "", ""
	if !isPlatformOwner(owner) {
		t.Fatal("fixture: not a platform owner")
	}
	if code, _ := ctxCall(t, f.h, owner, http.MethodGet, "/api/ai/actions", ""); code != http.StatusBadRequest {
		t.Fatalf("all-tenants view: %d, want 400 (choose a workspace)", code)
	}
}

func TestIrisActionsSettingsNeedAdminAndAcknowledgement(t *testing.T) {
	f := actionsFixture(t)
	if _, err := f.s.aiTenantCfg.SetActions(f.tenantA, ai.ActionSettings{}); err != nil {
		t.Fatal(err)
	}
	if code, _ := ctxCall(t, f.h, f.alice, http.MethodPut, "/api/ai/actions/settings", `{"enabled":true,"kinds":["itsm_note"]}`); code != http.StatusBadRequest {
		t.Fatalf("turning actions on without the acknowledgement: %d", code)
	}
	code, m := ctxCall(t, f.h, f.alice, http.MethodPut, "/api/ai/actions/settings", `{"enabled":true,"kinds":["itsm_note"],"acknowledged":true}`)
	if code != http.StatusOK || !f.s.aiTenantCfg.ActionsFor(f.tenantA).Enabled {
		t.Fatalf("turning actions on: %d %v", code, m)
	}
	if got := f.s.aiTenantCfg.ActionsFor(f.tenantB); len(got.Kinds) != 2 {
		t.Fatalf("tenant A's change touched tenant B: %+v", got)
	}
	viewer := f.alice
	viewer.Role = "viewer"
	if code, _ := ctxCall(t, f.h, viewer, http.MethodPut, "/api/ai/actions/settings", `{"enabled":false}`); code != http.StatusForbidden {
		t.Fatalf("a viewer changing the settings: %d", code)
	}
}
