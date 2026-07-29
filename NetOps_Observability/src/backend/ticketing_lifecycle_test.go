package main

import (
	"netops/backend/internal/ticketing"
	"testing"
	"time"

	"netops/backend/timeintel"
)

func tAt(s string) time.Time {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return ts
}

func auditEntry(action, result, at string) ticketing.AuditEntry {
	return ticketing.AuditEntry{Action: action, Result: result, At: tAt(at), ExternalSystem: "servicenow"}
}

// TestTicketAudit_OutboundToday: with only the outbound worker's create+resolve
// rows (what exists with NO real ServiceNow — against the mock or a real instance),
// the timeline gets real "ticket filed" + "resolved" timings and reads connected.
func TestTicketAudit_OutboundToday(t *testing.T) {
	audit := []ticketing.AuditEntry{
		auditEntry("create", "ok", "2026-06-28T10:00:00Z"),
		auditEntry("update", "ok", "2026-06-28T10:05:00Z"),        // not a phase → ignored
		auditEntry("add_work_note", "ok", "2026-06-28T10:06:00Z"), // ignored
		auditEntry("resolve", "ok", "2026-06-28T10:30:00Z"),
	}
	f, connected := ticketAuditToITSMFacts(audit, ticketing.Link{}, false)
	if !connected {
		t.Fatal("a filed ticket must read workflowConnected=true")
	}
	if !f.TicketCreated.Equal(tAt("2026-06-28T10:00:00Z")) {
		t.Fatalf("ticket_created = %v, want 10:00", f.TicketCreated)
	}
	if !f.Resolved.Equal(tAt("2026-06-28T10:30:00Z")) {
		t.Fatalf("resolved = %v, want 10:30", f.Resolved)
	}
	// Human phases that need an inbound sync stay INCOMPLETE — honest, not guessed.
	if !f.Acknowledged.IsZero() || !f.Mitigated.IsZero() || !f.Recovered.IsZero() {
		t.Fatalf("inbound-only phases must stay zero today, got %+v", f)
	}
}

// TestTicketAudit_FailedRowsIgnored: a failed/retrying attempt didn't move the
// ticket, so it must not stamp a phase.
func TestTicketAudit_FailedRowsIgnored(t *testing.T) {
	audit := []ticketing.AuditEntry{
		auditEntry("create", "dead_letter", "2026-06-28T10:00:00Z"),
		auditEntry("create", "", "2026-06-28T10:01:00Z"),
	}
	f, connected := ticketAuditToITSMFacts(audit, ticketing.Link{}, false)
	if !f.TicketCreated.IsZero() {
		t.Fatalf("non-ok create must not stamp ticket_created, got %v", f.TicketCreated)
	}
	if connected {
		t.Fatal("no successful action and no link → not connected")
	}
}

// TestTicketAudit_LinkFallback: the link advanced but the create/resolve audit row
// is absent (the at-most-once correlation-id recovery path) — fall back to the link.
func TestTicketAudit_LinkFallback(t *testing.T) {
	synced := tAt("2026-06-28T11:00:00Z")
	link := ticketing.Link{
		Status:       "resolved",
		CreatedAt:    tAt("2026-06-28T09:45:00Z"),
		LastSyncedAt: &synced,
	}
	f, connected := ticketAuditToITSMFacts(nil, link, true)
	if !connected {
		t.Fatal("a found link is connected")
	}
	if !f.TicketCreated.Equal(tAt("2026-06-28T09:45:00Z")) {
		t.Fatalf("ticket_created fallback = %v, want link CreatedAt", f.TicketCreated)
	}
	if !f.Resolved.Equal(synced) {
		t.Fatalf("resolved fallback = %v, want link LastSyncedAt", f.Resolved)
	}
}

// TestTicketAudit_SeamlessWhenServiceNowConnected is the forward-compatibility
// guard: the moment an INBOUND ServiceNow state sync appends the human-phase audit
// rows (the documented write-contract), the SAME reader + derive path light up the
// WHOLE incident timeline — no #84 rework. This is what makes "connect ServiceNow
// tomorrow and it just works" true.
func TestTicketAudit_SeamlessWhenServiceNowConnected(t *testing.T) {
	audit := []ticketing.AuditEntry{
		auditEntry(auditActionCreate, "ok", "2026-06-28T10:00:00Z"),
		auditEntry(auditActionAcknowledged, "ok", "2026-06-28T10:04:00Z"),
		auditEntry(auditActionMitigationStarted, "ok", "2026-06-28T10:09:00Z"),
		auditEntry(auditActionMitigated, "ok", "2026-06-28T10:20:00Z"),
		auditEntry(auditActionRecovered, "ok", "2026-06-28T10:25:00Z"),
		auditEntry(auditActionResolve, "ok", "2026-06-28T10:30:00Z"),
		auditEntry(auditActionClosed, "ok", "2026-06-28T11:00:00Z"),
	}
	f, connected := ticketAuditToITSMFacts(audit, ticketing.Link{}, true)
	if !connected {
		t.Fatal("connected")
	}
	want := map[string]time.Time{
		"created": f.TicketCreated, "ack": f.Acknowledged, "mit_start": f.MitigationStarted,
		"mitigated": f.Mitigated, "recovered": f.Recovered, "resolved": f.Resolved, "closed": f.Closed,
	}
	for name, got := range want {
		if got.IsZero() {
			t.Fatalf("phase %q must populate once inbound rows arrive, got zero", name)
		}
	}

	// And the #84 derive path must surface all seven human phases as itsm-sourced.
	lc := timeintel.DeriveLifecycle(timeintel.CorrTimeFacts{}, f)
	for _, ev := range []timeintel.EventType{
		timeintel.EvTicketCreated, timeintel.EvAcknowledged, timeintel.EvMitigationStarted,
		timeintel.EvMitigated, timeintel.EvRecovered, timeintel.EvResolved, timeintel.EvClosed,
	} {
		st, ok := lc[ev]
		if !ok {
			t.Fatalf("lifecycle missing %q after inbound sync", ev)
		}
		if st.Source != timeintel.SrcITSM {
			t.Fatalf("phase %q must be itsm-sourced, got %q", ev, st.Source)
		}
	}
}

// TestTicketAudit_EmptyIsHonest: no ticket at all → everything incomplete, not
// connected (the calculator then names the gap rather than inventing a zero).
func TestTicketAudit_EmptyIsHonest(t *testing.T) {
	f, connected := ticketAuditToITSMFacts(nil, ticketing.Link{}, false)
	if connected {
		t.Fatal("no link, no audit → not connected")
	}
	if !f.TicketCreated.IsZero() || !f.Resolved.IsZero() {
		t.Fatalf("empty input must yield zero facts, got %+v", f)
	}
}
