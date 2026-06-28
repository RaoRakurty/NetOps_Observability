package main

import (
	"context"
	"testing"
	"time"
)

// ticketing_sweeper_test.go — the policy→enqueue sweeper (#78 P3). Covers the
// pure per-object decision (create / hold / update), tenant-scoped policy
// resolution + default fallback, and — the mandatory §3a guard — that the
// sweep's enqueue path stamps each action with the OBJECT'S OWN tenant so a
// scoped caller can never see another tenant's queued ticket.

// confirmedCustomerFacts is the minimal facts a customer-facing confirmed fault
// presents — enough to pass the default policy.
func confirmedCustomerFacts() corrTicketFacts {
	return corrTicketFacts{
		Verdict:           "confirmed",
		Confidence:        0.9,
		PeakSeverity:      "crit",
		HasAffectedEntity: true,
		AffectedScope:     "leaf1 → wan-r2",
		AffectedEntities:  []string{"leaf1"},
		WindowStart:       time.Date(2026, 6, 27, 10, 0, 0, 0, time.UTC),
		WindowEnd:         time.Date(2026, 6, 27, 10, 10, 0, 0, time.UTC),
	}
}

func sampleView() rcaPathView {
	return rcaPathView{
		CorrObjectID: "936cc7fe-0000-0000-0000-000000000001",
		Verdict:      "confirmed",
		Confidence:   0.9,
		Title:        "Confirmed local link fault on leaf1 Gi0/1",
		Summary:      "Link down corroborated across two independent planes.",
		Path:         rcaPath{Source: "leaf1", Destination: "wan-r2"},
	}
}

func TestDecideSweepAction(t *testing.T) {
	now := time.Date(2026, 6, 27, 10, 11, 0, 0, time.UTC)
	policy := defaultIncidentPolicy("t_a")
	view := sampleView()

	// 1) Confirmed customer-facing fault, no existing link → CREATE.
	if act := decideSweepAction(view, confirmedCustomerFacts(), policy, nil, "", now); act.kind != "create" {
		t.Fatalf("confirmed customer fault should create, got %q", act.kind)
	}

	// 2) Undetermined → hold (no grounded cause).
	undet := confirmedCustomerFacts()
	undet.Verdict = "undetermined"
	if act := decideSweepAction(view, undet, policy, nil, "", now); act.kind != "" {
		t.Fatalf("undetermined must not ticket, got %q", act.kind)
	}

	// 3) Internal-only monitoring → hold (#76, never a customer ticket).
	internal := confirmedCustomerFacts()
	internal.Internal = true
	iv := view
	iv.Internal = true
	if act := decideSweepAction(iv, internal, policy, nil, "", now); act.kind != "" {
		t.Fatalf("internal monitoring must not ticket, got %q", act.kind)
	}

	// 4) Already-open ticket whose state is unchanged → hold (no churn).
	created := buildTicketPayload(view, confirmedCustomerFacts(), policy, "")
	openLink := &ticketLink{
		TenantID: "t_a", CorrObjectID: view.CorrObjectID, ExternalSystem: "servicenow",
		Status: "open", LastPayloadHash: payloadHash(created),
	}
	if act := decideSweepAction(view, confirmedCustomerFacts(), policy, openLink, "", now); act.kind != "" {
		t.Fatalf("open ticket with unchanged state must not re-enqueue, got %q", act.kind)
	}

	// 5) Open ticket whose RCA state MOVED ON (payload hash differs) → UPDATE.
	staleLink := *openLink
	staleLink.LastPayloadHash = "deadbeefdeadbeef"
	if act := decideSweepAction(view, confirmedCustomerFacts(), policy, &staleLink, "", now); act.kind != "update" {
		t.Fatalf("open ticket with changed state should update, got %q", act.kind)
	}
}

func TestSweeperResolvePolicy(t *testing.T) {
	ctx := context.Background()
	st := newMemTicketingStore()
	sw := &ticketSweeper{store: st}

	// No configured policy → default-on MVP policy, stamped with the tenant.
	p := sw.resolvePolicy(ctx, "t_a")
	if p.ID != "default" || !p.Enabled || p.TenantID != "t_a" {
		t.Fatalf("no policy should fall back to default-on for the tenant, got %+v", p)
	}

	// Tenant A configures a (disabled) policy → it is honored, NOT overridden by
	// the default — a tenant can opt OUT.
	_ = st.PutPolicy(ctx, incidentPolicy{ID: "p1", TenantID: "t_a", ExternalSystem: "servicenow", Enabled: false})
	if p := sw.resolvePolicy(ctx, "t_a"); p.Enabled {
		t.Fatalf("an explicit disabled policy must be honored, got enabled=%v", p.Enabled)
	}

	// Tenant B's resolution is independent of A's configuration.
	if p := sw.resolvePolicy(ctx, "t_b"); p.ID != "default" || !p.Enabled {
		t.Fatalf("tenant B must resolve its own default, got %+v", p)
	}
}

// TestSweeperCanonicalizesGlobalTenant is a regression guard for the silent
// global-tenant policy miss caught during the live #78 create-leg validation: the
// engine writes a platform/global object with tenant_id="", but the platform admin
// configures that tenant's incident policy under the canonical id "global"
// (principalTenant). Before the fix the sweeper resolved policy for "" and, finding
// no row (RLS / scopeVisible "" != "global"), silently fell back to the default
// policy — so a configured global policy could never take effect.
func TestSweeperCanonicalizesGlobalTenant(t *testing.T) {
	if got := canonicalCorrTenant(""); got != TenantGlobal {
		t.Fatalf("canonicalCorrTenant(%q) = %q, want %q", "", got, TenantGlobal)
	}
	if got := canonicalCorrTenant("  "); got != TenantGlobal {
		t.Fatalf("blank tenant must canonicalize to global, got %q", got)
	}
	if got := canonicalCorrTenant("t_a"); got != "t_a" {
		t.Fatalf("a real tenant id must pass through unchanged, got %q", got)
	}

	ctx := context.Background()
	st := newMemTicketingStore()
	sw := &ticketSweeper{store: st}

	// The platform admin's global policy is stored under the canonical "global" id.
	gp := incidentPolicy{ID: "g1", TenantID: TenantGlobal, ExternalSystem: "servicenow", Enabled: true, MinVerdict: "suspected"}
	if err := st.PutPolicy(ctx, gp); err != nil {
		t.Fatal(err)
	}
	// Raw "" misses it (the bug); the canonicalized tenant resolves it (the fix).
	if p := sw.resolvePolicy(ctx, ""); p.ID == "g1" {
		t.Fatal("precondition: raw \"\" must NOT match the global policy (else the bug never existed)")
	}
	if p := sw.resolvePolicy(ctx, canonicalCorrTenant("")); p.ID != "g1" {
		t.Fatalf("global object must resolve the configured global policy, got id=%q (default fallback?)", p.ID)
	}
}

func TestSweeperEnqueueIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	st := newMemTicketingStore()
	policy := defaultIncidentPolicy("")
	view := sampleView()

	// Two tenants' objects both decide CREATE; the sweep enqueues each under the
	// object's OWN tenant (derived from the candidate row, never a request body).
	act := decideSweepAction(view, confirmedCustomerFacts(), policy, nil, "", time.Now().UTC())
	if act.kind != "create" {
		t.Fatalf("precondition: expected create, got %q", act.kind)
	}
	if err := enqueueTicketCreate(ctx, st, "t_a", "servicenow", act.payload); err != nil {
		t.Fatal(err)
	}
	if err := enqueueTicketCreate(ctx, st, "t_b", "servicenow", act.payload); err != nil {
		t.Fatal(err)
	}

	// A scoped caller sees ONLY its own queued ticket — no cross-tenant leak.
	aOut, _ := st.ListOutbox(ctx, "t_a", false)
	if len(aOut) != 1 || aOut[0].TenantID != "t_a" {
		t.Fatalf("tenant A outbox leaked across tenants: %+v", aOut)
	}
	bOut, _ := st.ListOutbox(ctx, "t_b", false)
	if len(bOut) != 1 || bOut[0].TenantID != "t_b" {
		t.Fatalf("tenant B outbox leaked across tenants: %+v", bOut)
	}
}
