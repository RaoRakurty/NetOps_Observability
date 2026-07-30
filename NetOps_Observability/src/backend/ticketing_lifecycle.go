package main

import (
	"netops/backend/internal/ticketing"
	"netops/backend/timeintel"
	"strings"
	"time"
)

// ticketing_lifecycle.go — the bridge from #78 (RCA→ServiceNow ticketing) into
// #84 (RCA Time Intelligence). The `ticket_audit_log` is an append-only,
// tenant-scoped event ledger: every ticket action carries an `at` timestamp + an
// `action`. This folds that ledger onto the human/ITSM phases of the incident
// timeline so the time decomposition fills in REAL ticket timings without a second
// data path or any engine change.
//
// Forward-compatible by design ("works seamlessly the moment ServiceNow is
// connected"): the outbound worker emits create/resolve today, so "ticket filed"
// and "resolved" populate the instant a ticket is filed — against a real
// ServiceNow OR the bundled mock. The granular human phases
// (acknowledged/mitigated/recovered/closed) are produced the moment an INBOUND
// ServiceNow state sync appends audit rows with the actions below; the reader,
// derive path, and UI are already ready for them, so no #84 rework is needed.
//
// THE CONSTANTS BELOW ARE THE WRITE-CONTRACT the future inbound sync must emit
// (action + result="ok"); keep the inbound writer and this reader in lockstep.

// ticketLifecycleAction is the canonical audit `action` vocabulary that maps to an
// incident-timeline phase. The outbound worker emits the first two today; an
// inbound ServiceNow state sync (future) appends the human-phase group.
// The vocabulary itself moved to internal/ticketing (actions.go, P2 RA.4) —
// the inbound writer lives there now; these aliases keep main's reader (this
// bridge) and its tests in lockstep with it.
const (
	auditActionCreate            = ticketing.AuditActionCreate
	auditActionResolve           = ticketing.AuditActionResolve
	auditActionAcknowledged      = ticketing.AuditActionAcknowledged
	auditActionMitigationStarted = ticketing.AuditActionMitigationStarted
	auditActionMitigated         = ticketing.AuditActionMitigated
	auditActionRecovered         = ticketing.AuditActionRecovered
	auditActionClosed            = ticketing.AuditActionClosed
)

// ticketAuditToITSMFacts folds a correlation's ticket audit trail (+ its link)
// into the human/ITSM-side timestamps the time-decomposition consumes, and reports
// whether the ITSM workflow is connected at all (a ticket exists for this object).
// Pure + deterministic so it is unit-tested in isolation; callers pass ListAudit
// output and the link.
//
// Only result=="ok" rows count — a failed/retrying attempt did not move the ticket.
// The FIRST occurrence of each action wins (the instant that phase began). Link
// fallbacks cover the case where the link advanced but the matching audit row is
// absent (e.g. an at-most-once create whose link store advanced via the
// correlation-id recovery path rather than a fresh create audit).
func ticketAuditToITSMFacts(audit []ticketing.AuditEntry, link ticketing.Link, linkFound bool) (timeintel.ITSMTimeFacts, bool) {
	f := timeintel.ITSMTimeFacts{}
	setFirst := func(dst *time.Time, at time.Time) {
		if at.IsZero() || !dst.IsZero() {
			return // first non-zero wins
		}
		*dst = at.UTC()
	}
	for _, e := range audit {
		if !strings.EqualFold(strings.TrimSpace(e.Result), "ok") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(e.Action)) {
		case auditActionCreate:
			setFirst(&f.TicketCreated, e.At)
		case auditActionAcknowledged:
			setFirst(&f.Acknowledged, e.At)
		case auditActionMitigationStarted:
			setFirst(&f.MitigationStarted, e.At)
		case auditActionMitigated:
			setFirst(&f.Mitigated, e.At)
		case auditActionRecovered:
			setFirst(&f.Recovered, e.At)
		case auditActionResolve, "resolved":
			setFirst(&f.Resolved, e.At)
		case auditActionClosed:
			setFirst(&f.Closed, e.At)
		}
	}

	// Link fallbacks: a live link implies the ticket was filed even if the create
	// audit row is missing; a resolved link implies a resolve time.
	if linkFound {
		if f.TicketCreated.IsZero() && !link.CreatedAt.IsZero() {
			f.TicketCreated = link.CreatedAt.UTC()
		}
		if f.Resolved.IsZero() && link.Status == "resolved" && link.LastSyncedAt != nil {
			f.Resolved = link.LastSyncedAt.UTC()
		}
	}

	// The workflow is "connected" once a ticket exists for this object (a link, or
	// any ITSM phase observed) — so the bottleneck logic stops reading "workflow not
	// connected" the moment a ticket is filed.
	workflowConnected := linkFound ||
		!f.TicketCreated.IsZero() || !f.Acknowledged.IsZero() ||
		!f.Resolved.IsZero() || !f.Closed.IsZero()
	return f, workflowConnected
}
