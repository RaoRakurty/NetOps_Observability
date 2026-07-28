package main

import (
	"context"
	"encoding/json"
	"math/rand"
	"netops/backend/internal/rca"
	"netops/backend/internal/ticketing"
	"strings"
	"testing"
	"time"
)

// Local copies of the rca test-fixture builders (testSig/testMeta moved into
// internal/rca with the wave-2 report family; test helpers cannot cross
// package boundaries). Kept in the sweeper's shape only.
func testSig(kind, lane, observer, entityType, entityID, sev, ts string, attached bool, extra map[string]any) map[string]any {
	sig := map[string]any{
		"signal_id": "s-" + kind + "-" + ts, "kind": kind, "modality_class": lane,
		"observer_id": observer, "entity_type": entityType, "entity_id": entityID,
		"severity": sev, "ts": ts, "attached": attached,
		"value": float64(0), "baseline": float64(0), "metric_name": "", "attrs": "{}",
		"probe_scope": "", "clear_ts": "",
	}
	for k, v := range extra {
		sig[k] = v
	}
	return sig
}

func testMeta(state, verdict, topHyp string, hyp map[string]any) map[string]any {
	blob := "{}"
	if hyp != nil {
		b, _ := json.Marshal(map[string]any{"ranking": map[string]any{"hypotheses": []any{hyp}}})
		blob = string(b)
	}
	return map[string]any{
		"version": float64(3), "state": state, "verdict_tier": verdict,
		"top_hypothesis": topHyp, "top_confidence": 0.5,
		"window_start": "2026-07-12 18:10:00", "window_end": "2026-07-12 18:30:00",
		"hypotheses": blob, "affected": "{}", "app_impact": "{}", "evidence_missing": "[]",
	}
}

// ticketing_sweeper_test.go — the policy→enqueue sweeper (#78 P3). Covers the
// pure per-object decision (create / hold / update), tenant-scoped policy
// resolution + default fallback, and — the mandatory §3a guard — that the
// sweep's enqueue path stamps each action with the OBJECT'S OWN tenant so a
// scoped caller can never see another tenant's queued ticket.

// confirmedCustomerFacts is the minimal facts a customer-facing confirmed fault
// presents — enough to pass the default policy.
func confirmedCustomerFacts() ticketing.CorrFacts {
	return ticketing.CorrFacts{
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
	policy := ticketing.DefaultIncidentPolicy("t_a")
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
	openLink := &ticketing.Link{
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

// The emitter-side consistency gate (audit D11): facts carrying a P1
// contradiction are HELD with an observable reason — never enqueued, never
// silently dropped — while clean facts pass through unchanged and the §11
// validation-scenario suppression (rca-canary contract) is untouched.
func TestDecideSweepActionConsistencyGate(t *testing.T) {
	now := time.Date(2026, 6, 27, 10, 11, 0, 0, time.UTC)
	policy := ticketing.DefaultIncidentPolicy("t_a")
	view := sampleView()

	// P1-contradictory facts → create suppressed with reason.
	bad := confirmedCustomerFacts()
	bad.ConsistencyIssues = []string{"recovered_before_last_anomaly: closure recovery evidence at X precedes anomalous evidence through Y"}
	act := decideSweepAction(view, bad, policy, nil, "", now)
	if act.kind != "" {
		t.Fatalf("contradictory facts enqueued a %q action", act.kind)
	}
	if !strings.Contains(act.suppressionReason, "recovered_before_last_anomaly") {
		t.Fatalf("suppression reason missing/opaque: %q", act.suppressionReason)
	}

	// Update path is gated too.
	created := buildTicketPayload(view, confirmedCustomerFacts(), policy, "")
	stale := &ticketing.Link{
		TenantID: "t_a", CorrObjectID: view.CorrObjectID, ExternalSystem: "servicenow",
		Status: "open", LastPayloadHash: "deadbeefdeadbeef",
	}
	_ = created
	if act := decideSweepAction(view, bad, policy, stale, "", now); act.kind != "" || act.suppressionReason == "" {
		t.Fatalf("contradictory update not held: kind=%q reason=%q", act.kind, act.suppressionReason)
	}

	// Clean facts pass through unchanged.
	if act := decideSweepAction(view, confirmedCustomerFacts(), policy, nil, "", now); act.kind != "create" || act.suppressionReason != "" {
		t.Fatalf("clean facts should create: kind=%q reason=%q", act.kind, act.suppressionReason)
	}

	// §11 canary: a validation scenario is suppressed by the POLICY (its own
	// reason), not hijacked by the consistency gate — and never enqueues.
	canary := confirmedCustomerFacts()
	canary.Validation = true
	canary.ConsistencyIssues = nil
	if act := decideSweepAction(view, canary, policy, nil, "", now); act.kind != "" || act.suppressionReason != "" {
		t.Fatalf("validation scenario handling changed: kind=%q reason=%q", act.kind, act.suppressionReason)
	}
}

// rca.TicketFactConsistencyIssues — the cheap fact-level P1 validation the sweeper
// consumes, exercised over raw signal rows (no report recomposition).
func TestTicketFactConsistencyIssues(t *testing.T) {
	anom := func(ts string) map[string]any {
		return testSig("probe_loss", "active_probe", "prober-1", "path", "prober-1->10.1.1.1", "crit", ts, true, nil)
	}
	clear := func(ts string) map[string]any {
		return testSig("probe_loss_clear", "active_probe", "prober-1", "path", "prober-1->10.1.1.1", "info", ts, false,
			map[string]any{"clear_ts": ts})
	}

	// closed object, recovery evidence PRECEDING later anomalies → P1 issue.
	rows := []map[string]any{anom("2026-07-12 18:00:00"), clear("2026-07-12 18:05:00"), anom("2026-07-12 18:20:00")}
	issues := rca.TicketFactConsistencyIssues("closed", rows)
	if len(issues) != 1 || !strings.Contains(issues[0], "recovered_before_last_anomaly") {
		t.Fatalf("issues = %v", issues)
	}

	// same evidence on an OPEN object: no closure claim, no contradiction.
	if issues := rca.TicketFactConsistencyIssues("open", rows); len(issues) != 0 {
		t.Fatalf("open object flagged: %v", issues)
	}

	// clean closed recovery (clear after last anomaly) → no issue.
	cleanRows := []map[string]any{anom("2026-07-12 18:00:00"), clear("2026-07-12 18:25:00")}
	if issues := rca.TicketFactConsistencyIssues("closed", cleanRows); len(issues) != 0 {
		t.Fatalf("clean closure flagged: %v", issues)
	}

	// buildCorrTicketFacts wires the gate onto the facts the sweeper decides on.
	meta := testMeta("closed", "confirmed", "sig.ent.access.uplink-down", nil)
	facts := buildCorrTicketFacts(meta, rows, sampleView())
	if len(facts.ConsistencyIssues) != 1 {
		t.Fatalf("facts.ConsistencyIssues = %v", facts.ConsistencyIssues)
	}
}

func TestSweeperResolvePolicy(t *testing.T) {
	ctx := context.Background()
	st := ticketing.NewMemStore()
	sw := &ticketSweeper{store: st}

	// No configured policy → default-on MVP policy, stamped with the tenant.
	p := sw.resolvePolicy(ctx, "t_a", "servicenow")
	if p.ID != "default" || !p.Enabled || p.TenantID != "t_a" {
		t.Fatalf("no policy should fall back to default-on for the tenant, got %+v", p)
	}

	// Tenant A configures a (disabled) policy → it is honored, NOT overridden by
	// the default — a tenant can opt OUT.
	_ = st.PutPolicy(ctx, ticketing.IncidentPolicy{ID: "p1", TenantID: "t_a", ExternalSystem: "servicenow", Enabled: false})
	if p := sw.resolvePolicy(ctx, "t_a", "servicenow"); p.Enabled {
		t.Fatalf("an explicit disabled policy must be honored, got enabled=%v", p.Enabled)
	}

	// Tenant B's resolution is independent of A's configuration.
	if p := sw.resolvePolicy(ctx, "t_b", "servicenow"); p.ID != "default" || !p.Enabled {
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
	st := ticketing.NewMemStore()
	sw := &ticketSweeper{store: st}

	// The platform admin's global policy is stored under the canonical "global" id.
	gp := ticketing.IncidentPolicy{ID: "g1", TenantID: TenantGlobal, ExternalSystem: "servicenow", Enabled: true, MinVerdict: "suspected"}
	if err := st.PutPolicy(ctx, gp); err != nil {
		t.Fatal(err)
	}
	// Raw "" misses it (the bug); the canonicalized tenant resolves it (the fix).
	if p := sw.resolvePolicy(ctx, "", "servicenow"); p.ID == "g1" {
		t.Fatal("precondition: raw \"\" must NOT match the global policy (else the bug never existed)")
	}
	if p := sw.resolvePolicy(ctx, canonicalCorrTenant(""), "servicenow"); p.ID != "g1" {
		t.Fatalf("global object must resolve the configured global policy, got id=%q (default fallback?)", p.ID)
	}
}

func TestSweeperEnqueueIsTenantScoped(t *testing.T) {
	ctx := context.Background()
	st := ticketing.NewMemStore()
	policy := ticketing.DefaultIncidentPolicy("")
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
	aOut, _, _ := st.ListOutbox(ctx, "t_a", false, ticketing.MaxPage, 0)
	if len(aOut) != 1 || aOut[0].TenantID != "t_a" {
		t.Fatalf("tenant A outbox leaked across tenants: %+v", aOut)
	}
	bOut, _, _ := st.ListOutbox(ctx, "t_b", false, ticketing.MaxPage, 0)
	if len(bOut) != 1 || bOut[0].TenantID != "t_b" {
		t.Fatalf("tenant B outbox leaked across tenants: %+v", bOut)
	}
}

// TestCanonicalCorrTenant_RoundTrip pins the ONE platform/global equivalence
// rule across the three normalizers that must cancel out along the ticketing
// path (object row → canonicalCorrTenant → store keys via normTenant →
// connector via itsmKey). Every platform representation converges on "global",
// the connector key round-trips to the env-seeded "" slot, and two distinct
// real tenants NEVER collapse (the §3a security bound on canonicalization).
func TestCanonicalCorrTenant_RoundTrip(t *testing.T) {
	for in, want := range map[string]string{
		"": TenantGlobal, "  ": TenantGlobal, "global": TenantGlobal,
		"GLOBAL": TenantGlobal, " Global ": TenantGlobal,
		"t_acme": "t_acme", "T_ACME": "t_acme",
	} {
		if got := canonicalCorrTenant(in); got != want {
			t.Fatalf("canonicalCorrTenant(%q) = %q, want %q", in, got, want)
		}
	}
	// Connector lookup: the canonical global tenant resolves to the env-seeded
	// platform connector slot (""), a real tenant to its own slot.
	if got := itsmKey(canonicalCorrTenant("")); got != "" {
		t.Fatalf("itsmKey(canonical global) = %q, want \"\" (platform connector)", got)
	}
	if got := itsmKey(canonicalCorrTenant("t_acme")); got != "t_acme" {
		t.Fatalf("itsmKey(canonical tenant) = %q, want t_acme", got)
	}
	// Distinct tenants never collapse.
	if canonicalCorrTenant("t_a") == canonicalCorrTenant("t_b") {
		t.Fatal("canonicalization collapsed two distinct tenants")
	}
}

// TestResolvePolicy_OrderIndependent is the property test for the 2026-07-10
// bug class: policy selection must NEVER depend on insertion order, map
// iteration, or row order. Across shuffled insertion orders (and Go's already
// randomized map iteration in the mem store), the single enabled policy always
// wins and the resolution state is stable.
func TestResolvePolicy_OrderIndependent(t *testing.T) {
	ids := []string{"p1", "p2", "p3", "p4", "p5", "p6"}
	for seed := 0; seed < 20; seed++ {
		rng := rand.New(rand.NewSource(int64(seed)))
		order := append([]string(nil), ids...)
		rng.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		winner := ids[seed%len(ids)]

		store := ticketing.NewMemStore()
		for _, id := range order {
			if err := store.PutPolicy(context.Background(), ticketing.IncidentPolicy{
				ID: id, TenantID: "t_prop", Name: id, ExternalSystem: "servicenow",
				Enabled: id == winner, MinVerdict: "confirmed",
			}); err != nil {
				t.Fatalf("seed %d: put %s: %v", seed, id, err)
			}
		}
		res := (&ticketSweeper{store: store}).resolvePolicyState(context.Background(), "t_prop", "servicenow")
		if res.state != policyStateActive || res.policy.ID != winner {
			t.Fatalf("seed %d (order %v): resolved %q/%s, want %q/active", seed, order, res.policy.ID, res.state, winner)
		}
	}
}
