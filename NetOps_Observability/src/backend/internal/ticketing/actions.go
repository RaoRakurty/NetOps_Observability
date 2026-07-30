package ticketing

// actions.go — the canonical ticket-audit `action` vocabulary (P2 RA.4): the
// WRITE-CONTRACT between the outbound worker, the inbound state sync (both
// emit action + result="ok") and the #84 timeline bridge that reads it. Keep
// writers and readers in lockstep through these constants.
const (
	AuditActionCreate            = "create"             // → ticket_created (outbound, live today)
	AuditActionResolve           = "resolve"            // → resolved        (outbound, live today)
	AuditActionAcknowledged      = "acknowledged"       // → acknowledged    (inbound)
	AuditActionMitigationStarted = "mitigation_started" // → mitigation_started (inbound)
	AuditActionMitigated         = "mitigated"          // → mitigated       (inbound)
	AuditActionRecovered         = "recovered"          // → recovered       (inbound)
	AuditActionClosed            = "closed"             // → closed          (inbound)
)
