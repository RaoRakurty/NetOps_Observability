// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// inbound_sync_test.go — the pure state→observation mapper and the syncer-level
// tenant-isolation suite (CLAUDE.md §3a), moved in-package with the syncer
// (P2 RA.4). The end-to-end pass against the mock ServiceNow (plus the #84
// bridge) stays in main with the fixtures it needs.

import (
	"context"
	"testing"
	"time"
)

func tAt(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func obsByAction(obs []lifecycleObservation) map[string]time.Time {
	m := map[string]time.Time{}
	for _, o := range obs {
		if m[o.Action].IsZero() {
			m[o.Action] = o.At
		}
	}
	return m
}

func auditActions(a []AuditEntry) []string {
	out := make([]string, 0, len(a))
	for _, e := range a {
		out = append(out, e.Action)
	}
	return out
}

func hasAuditAction(a []AuditEntry, action string) bool {
	for _, e := range a {
		if e.Action == action && e.Result == "ok" {
			return true
		}
	}
	return false
}

// ── pure state→observation mapper ────────────────────────────────────────────

func TestSnowIncidentObservations_InProgress(t *testing.T) {
	obs := snowIncidentObservations(RemoteIncident{
		State:     SnowStateInProgress,
		WorkStart: tAt("2026-06-28T10:05:00Z"),
		UpdatedAt: tAt("2026-06-28T10:06:00Z"),
	})
	got := obsByAction(obs)
	if got[AuditActionAcknowledged].IsZero() {
		t.Fatal("in-progress with work_start must yield acknowledged")
	}
	if !got[AuditActionMitigationStarted].Equal(tAt("2026-06-28T10:05:00Z")) {
		t.Fatalf("mitigation_started = %v, want work_start", got[AuditActionMitigationStarted])
	}
	if !got[AuditActionResolve].IsZero() || !got[AuditActionClosed].IsZero() {
		t.Fatal("a non-resolved ticket must not emit resolved/closed")
	}
}

func TestSnowIncidentObservations_ResolvedAndClosed(t *testing.T) {
	obs := snowIncidentObservations(RemoteIncident{
		State:      SnowStateClosed,
		WorkStart:  tAt("2026-06-28T10:05:00Z"),
		ResolvedAt: tAt("2026-06-28T10:30:00Z"),
		ClosedAt:   tAt("2026-06-28T11:00:00Z"),
	})
	got := obsByAction(obs)
	if !got[AuditActionResolve].Equal(tAt("2026-06-28T10:30:00Z")) {
		t.Fatalf("resolved = %v, want resolved_at", got[AuditActionResolve])
	}
	if !got[AuditActionClosed].Equal(tAt("2026-06-28T11:00:00Z")) {
		t.Fatalf("closed = %v, want closed_at", got[AuditActionClosed])
	}
}

func TestSnowIncidentObservations_CustomFields(t *testing.T) {
	obs := snowIncidentObservations(RemoteIncident{
		State:          SnowStateResolved,
		AcknowledgedAt: tAt("2026-06-28T10:02:00Z"),
		MitigatedAt:    tAt("2026-06-28T10:18:00Z"),
		RecoveredAt:    tAt("2026-06-28T10:22:00Z"),
		ResolvedAt:     tAt("2026-06-28T10:30:00Z"),
	})
	got := obsByAction(obs)
	for _, a := range []string{AuditActionAcknowledged, AuditActionMitigated, AuditActionRecovered, AuditActionResolve} {
		if got[a].IsZero() {
			t.Fatalf("custom-driven phase %q must populate", a)
		}
	}
}

func TestSnowIncidentObservations_HonestEmpty(t *testing.T) {
	// In progress but with NO timestamp anywhere → no acknowledged invented.
	obs := snowIncidentObservations(RemoteIncident{State: SnowStateInProgress})
	if len(obs) != 0 {
		t.Fatalf("no timestamps must yield no observations, got %+v", obs)
	}
}

// ── syncer-level tenant isolation (§3a) ──────────────────────────────────────

// stubFetchAdapter implements only the read path the inbound syncer uses; the
// embedded nil interface makes any other (unexpected) adapter call panic loudly.
type stubFetchAdapter struct {
	Adapter
	inc   RemoteIncident
	calls int
}

func (a *stubFetchAdapter) FetchIncident(_ context.Context, _ SystemConfig, _ Ref) (RemoteIncident, bool, error) {
	a.calls++
	return a.inc, true, nil
}

func seedInboundLinks(t *testing.T, st *MemStore) {
	t.Helper()
	ctx := context.Background()
	for _, l := range []Link{
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
	st := NewMemStore()
	seedInboundLinks(t, st)

	adapter := &stubFetchAdapter{inc: RemoteIncident{
		State:      SnowStateResolved,
		WorkStart:  tAt("2026-06-28T10:05:00Z"),
		ResolvedAt: tAt("2026-06-28T10:30:00Z"),
	}}
	sy := &StateSyncer{
		store:    st,
		adapters: map[string]Adapter{"servicenow": adapter},
		resolveConn: func(_ context.Context, tenant, system string) (SystemConfig, bool, error) {
			return SystemConfig{System: system, InstanceURL: "https://" + tenant + ".example"}, true, nil
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
	auditA, _, err := st.ListAudit(ctx, "t_a", false, "obj-a", MaxPage, 0)
	if err != nil {
		t.Fatalf("list t_a audit: %v", err)
	}
	for _, a := range []string{AuditActionAcknowledged, AuditActionResolve} {
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
	if got, _, _ := st.ListAudit(ctx, "t_b", false, "obj-b", MaxPage, 0); len(got) != 0 {
		t.Fatalf("t_b audit must be empty, got %+v", auditActions(got))
	}
	if got, _, _ := st.ListAudit(ctx, "", true, "obj-b", MaxPage, 0); len(got) != 0 {
		t.Fatalf("no rows may exist under obj-b at any scope, got %+v", auditActions(got))
	}
	if got, _, _ := st.ListAudit(ctx, "t_b", false, "obj-a", MaxPage, 0); len(got) != 0 {
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
	st := NewMemStore()
	seedInboundLinks(t, st)

	adapter := &stubFetchAdapter{inc: RemoteIncident{
		State:      SnowStateResolved,
		ResolvedAt: tAt("2026-06-28T10:30:00Z"),
	}}
	sy := &StateSyncer{
		store:    st,
		adapters: map[string]Adapter{"servicenow": adapter},
		resolveConn: func(context.Context, string, string) (SystemConfig, bool, error) {
			return SystemConfig{}, false, nil
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
	if got, _, _ := st.ListAudit(ctx, "", true, "", MaxPage, 0); len(got) != 0 {
		t.Fatalf("dormant sync wrote audit rows: %+v", auditActions(got))
	}
	if l, _, _ := st.GetLink(ctx, "t_b", false, "obj-b", "servicenow"); l.Status != "open" {
		t.Fatalf("dormant sync mutated link status to %q", l.Status)
	}
}
