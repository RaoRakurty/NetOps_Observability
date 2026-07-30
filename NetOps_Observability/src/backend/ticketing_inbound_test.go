package backend

import (
	"context"
	"netops/backend/internal/ticketing"
	"testing"
	"time"
)

// ── syncer integration (real adapter ⇄ httptest mock ServiceNow) ─────────────

// TestInboundSyncer_AppendsPhasesAndDedupes drives the full inbound loop against
// the mock: file a ticket, simulate a human moving it through ServiceNow states,
// run the syncer, and assert the human-phase audit rows appear (and don't double
// on a second pass). This is the live path the #84 timeline renders.
func TestInboundSyncer_AppendsPhasesAndDedupes(t *testing.T) {
	t.Setenv("SSRF_ALLOW_PRIVATE", "true")
	m := newMockServiceNow()
	defer m.Close()
	ctx := context.Background()
	st := ticketing.NewMemStore()

	// File the ticket (as the outbound worker would).
	ref, err := m.adapter().CreateIncident(ctx, m.cfg(), samplePayload("obj-1"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	_ = st.PutLink(ctx, ticketing.Link{
		TenantID: "t_a", CorrObjectID: "obj-1", ExternalSystem: "servicenow",
		SysID: ref.SysID, TicketNumber: ref.Number, InstanceURL: m.srv.URL, Status: "open",
	})

	sy := ticketing.NewStateSyncer(st, func(context.Context, string, string) (ticketing.SystemConfig, bool, error) {
		return m.cfg(), true, nil
	})
	sy.SetAdapterForTest("servicenow", m.adapter())
	now := time.Now().UTC()

	// Nothing moved yet (state New / unset) → no human phases.
	if n, _ := sy.Tick(ctx, now); n != 0 {
		t.Fatalf("a brand-new ticket should yield no phases, appended %d", n)
	}

	// Simulate a human picking it up in ServiceNow (In Progress + work_start).
	m.mu.Lock()
	m.incidents[ref.SysID]["state"] = "2"
	m.incidents[ref.SysID]["work_start"] = "2026-06-28 10:05:00"
	m.mu.Unlock()

	if n, _ := sy.Tick(ctx, now); n == 0 {
		t.Fatal("in-progress ticket must append acknowledged/mitigation_started")
	}
	audit, _, _ := st.ListAudit(ctx, "t_a", false, "obj-1", ticketing.MaxPage, 0)
	if !hasAuditAction(audit, auditActionAcknowledged) {
		t.Fatalf("expected acknowledged in audit, got %+v", auditActions(audit))
	}

	// Second pass must NOT double-stamp (idempotent against the audit ledger).
	before := len(audit)
	_, _ = sy.Tick(ctx, now)
	after, _, _ := st.ListAudit(ctx, "t_a", false, "obj-1", ticketing.MaxPage, 0)
	if len(after) != before {
		t.Fatalf("re-sync double-stamped: %d → %d", before, len(after))
	}

	// Resolve it in ServiceNow → resolved appended + link advanced.
	m.mu.Lock()
	m.incidents[ref.SysID]["state"] = "6"
	m.incidents[ref.SysID]["resolved_at"] = "2026-06-28 10:30:00"
	m.mu.Unlock()

	_, _ = sy.Tick(ctx, now)
	audit, _, _ = st.ListAudit(ctx, "t_a", false, "obj-1", ticketing.MaxPage, 0)
	if !hasAuditAction(audit, auditActionResolve) {
		t.Fatalf("expected resolved in audit, got %+v", auditActions(audit))
	}
	link, _, _ := st.GetLink(ctx, "t_a", false, "obj-1", "servicenow")
	if link.Status != "resolved" {
		t.Fatalf("link status should advance to resolved, got %q", link.Status)
	}

	// And the #84 bridge surfaces the full human timeline from these rows.
	facts, connected := ticketAuditToITSMFacts(audit, link, true)
	if !connected || facts.Acknowledged.IsZero() || facts.Resolved.IsZero() {
		t.Fatalf("bridge must render acknowledged+resolved from synced audit: %+v", facts)
	}
}

func auditActions(a []ticketing.AuditEntry) []string {
	out := make([]string, 0, len(a))
	for _, e := range a {
		out = append(out, e.Action)
	}
	return out
}

func hasAuditAction(a []ticketing.AuditEntry, action string) bool {
	for _, e := range a {
		if e.Action == action && e.Result == "ok" {
			return true
		}
	}
	return false
}
