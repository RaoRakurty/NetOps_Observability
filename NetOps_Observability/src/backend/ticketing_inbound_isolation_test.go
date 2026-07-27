package main

import (
	"context"
	"netops/backend/internal/ticketing"
	"testing"
	"time"
)

// ticketing_inbound_isolation_test.go — syncer-level tenant isolation for the
// inbound ServiceNow state sync (CLAUDE.md §3a): syncing ONE tenant's link must
// write only under that tenant, never touch another tenant's audit/link rows,
// and a tenant with no configured connection stays fully dormant (zero writes).

// stubFetchAdapter implements only the read path the inbound syncer uses; the
// embedded nil interface makes any other (unexpected) adapter call panic loudly.
type stubFetchAdapter struct {
	ticketAdapter
	inc   snowIncident
	calls int
}

func (a *stubFetchAdapter) FetchIncident(_ context.Context, _ ticketSystemConfig, _ ticketRef) (snowIncident, bool, error) {
	a.calls++
	return a.inc, true, nil
}

func seedInboundLinks(t *testing.T, st *memTicketingStore) {
	t.Helper()
	ctx := context.Background()
	for _, l := range []ticketing.Link{
		{TenantID: "t_a", CorrObjectID: "obj-a", ExternalSystem: "servicenow",
			SysID: "sysA001", TicketNumber: "INC0000001", InstanceURL: "https://t-a.example", Status: "open"},
		{TenantID: "t_b", CorrObjectID: "obj-b", ExternalSystem: "servicenow",
			SysID: "sysB001", TicketNumber: "INC0000002", InstanceURL: "https://t-b.example", Status: "open"},
	} {
		if err := st.PutLink(ctx, l); err != nil {
			t.Fatalf("seed link %s: %v", l.CorrObjectID, err)
		}
	}
}

// TestInboundSyncerIsolation_SyncOneTenantOnly: running syncLink for t_a's link
// appends the observed phases under t_a ONLY — t_b's audit and link stay
// untouched, and every appended row carries the link's own TenantID.
func TestInboundSyncerIsolation_SyncOneTenantOnly(t *testing.T) {
	ctx := context.Background()
	st := newMemTicketingStore()
	seedInboundLinks(t, st)

	adapter := &stubFetchAdapter{inc: snowIncident{
		State:      snowStateResolved,
		WorkStart:  tAt("2026-06-28T10:05:00Z"),
		ResolvedAt: tAt("2026-06-28T10:30:00Z"),
	}}
	sy := &ticketStateSyncer{
		store:    st,
		adapters: map[string]ticketAdapter{"servicenow": adapter},
		resolveConn: func(_ context.Context, tenant, system string) (ticketSystemConfig, bool, error) {
			return ticketSystemConfig{System: system, InstanceURL: "https://" + tenant + ".example"}, true, nil
		},
		lookback: 14 * 24 * time.Hour,
	}

	linkA, found, err := st.GetLink(ctx, "t_a", false, "obj-a", "servicenow")
	if err != nil || !found {
		t.Fatalf("seeded t_a link not found: found=%v err=%v", found, err)
	}
	if n := sy.syncLink(ctx, linkA, time.Now().UTC()); n == 0 {
		t.Fatal("resolved incident must append phase rows for t_a")
	}

	// t_a gained the phases, and every appended row is stamped with the link's
	// TenantID (never the request/adapter side).
	auditA, _, err := st.ListAudit(ctx, "t_a", false, "obj-a", ticketMaxPage, 0)
	if err != nil {
		t.Fatalf("list t_a audit: %v", err)
	}
	for _, a := range []string{auditActionAcknowledged, auditActionResolve} {
		if !hasAuditAction(auditA, a) {
			t.Fatalf("t_a audit missing %q, got %+v", a, auditActions(auditA))
		}
	}
	for _, e := range auditA {
		if e.TenantID != "t_a" {
			t.Fatalf("appended row carries tenant %q, want t_a", e.TenantID)
		}
	}

	// t_b is untouched: nothing visible in its own scope, nothing under its
	// object even at cross scope (no mis-stamped rows), and no leak of t_a's
	// rows into t_b's view.
	if got, _, _ := st.ListAudit(ctx, "t_b", false, "obj-b", ticketMaxPage, 0); len(got) != 0 {
		t.Fatalf("t_b audit must be empty, got %+v", auditActions(got))
	}
	if got, _, _ := st.ListAudit(ctx, "", true, "obj-b", ticketMaxPage, 0); len(got) != 0 {
		t.Fatalf("no rows may exist under obj-b at any scope, got %+v", auditActions(got))
	}
	if got, _, _ := st.ListAudit(ctx, "t_b", false, "obj-a", ticketMaxPage, 0); len(got) != 0 {
		t.Fatalf("t_b must not see t_a's audit, got %+v", auditActions(got))
	}

	// Link advance is equally scoped: t_a resolved, t_b still open.
	if l, _, _ := st.GetLink(ctx, "t_a", false, "obj-a", "servicenow"); l.Status != "resolved" {
		t.Fatalf("t_a link status = %q, want resolved", l.Status)
	}
	if l, _, _ := st.GetLink(ctx, "t_b", false, "obj-b", "servicenow"); l.Status != "open" {
		t.Fatalf("t_b link status = %q, want open (untouched)", l.Status)
	}
}

// TestInboundSyncerIsolation_DormantTenantNoWrites: resolver ok=false (tenant has
// no configured connection) → the syncer never calls the provider and writes
// nothing — the dormant-tenant guarantee.
func TestInboundSyncerIsolation_DormantTenantNoWrites(t *testing.T) {
	ctx := context.Background()
	st := newMemTicketingStore()
	seedInboundLinks(t, st)

	adapter := &stubFetchAdapter{inc: snowIncident{
		State:      snowStateResolved,
		ResolvedAt: tAt("2026-06-28T10:30:00Z"),
	}}
	sy := &ticketStateSyncer{
		store:    st,
		adapters: map[string]ticketAdapter{"servicenow": adapter},
		resolveConn: func(context.Context, string, string) (ticketSystemConfig, bool, error) {
			return ticketSystemConfig{}, false, nil
		},
		lookback: 14 * 24 * time.Hour,
	}

	linkB, found, err := st.GetLink(ctx, "t_b", false, "obj-b", "servicenow")
	if err != nil || !found {
		t.Fatalf("seeded t_b link not found: found=%v err=%v", found, err)
	}
	if n := sy.syncLink(ctx, linkB, time.Now().UTC()); n != 0 {
		t.Fatalf("dormant tenant appended %d rows, want 0", n)
	}
	if adapter.calls != 0 {
		t.Fatalf("dormant tenant must not reach the provider, got %d calls", adapter.calls)
	}
	if got, _, _ := st.ListAudit(ctx, "", true, "", ticketMaxPage, 0); len(got) != 0 {
		t.Fatalf("dormant sync wrote audit rows: %+v", auditActions(got))
	}
	if l, _, _ := st.GetLink(ctx, "t_b", false, "obj-b", "servicenow"); l.Status != "open" {
		t.Fatalf("dormant sync mutated link status to %q", l.Status)
	}
}
