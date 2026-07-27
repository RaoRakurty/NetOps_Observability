// Package ticketing holds the pure domain core of RCA-driven auto-ticketing
// (#78): the data records, the corr-object fact projection, and the I/O-free
// incident-policy decision.
//
// One RCA correlation object → at most one external ticket. Every type here is
// keyed by corr_object_id, never by a raw alert id (the primary rule). These
// are plain data records; the pure decision logic lives in policy.go. The
// payload assembly (buildCorrTicketFacts / buildTicketPayload) stays with the
// integrator in package main — it is built on rcaPathView, which belongs to a
// domain that has not moved.
package ticketing

import "time"

// IncidentPolicy decides ticket-worthiness for one (tenant, external system).
// The MVP predicate (see EvalTicketDecision): customer-facing AND
// (verdict ≥ min_verdict) AND (a suspected verdict additionally needs critical
// severity when suspected_requires_critical). Internal/debug-only and
// probe-only objects are excluded unless explicitly allowed.
type IncidentPolicy struct {
	ID                      string `json:"id"`
	TenantID                string `json:"tenant_id"`
	Name                    string `json:"name"`
	ExternalSystem          string `json:"external_system"`
	Enabled                 bool   `json:"enabled"`
	MinVerdict              string `json:"min_verdict"` // suspected | confirmed
	RequireCustomerFacing   bool   `json:"require_customer_facing"`
	AllowProbeOnly          bool   `json:"allow_probe_only"`
	AllowInternalMonitoring bool   `json:"allow_internal_monitoring"`
	// AllowValidationScenarios: explicit opt-in for a validation canary to file
	// REAL tickets (§11 — default false: test traffic never pages production).
	AllowValidationScenarios  bool   `json:"allow_validation_scenarios"`
	SuspectedRequiresCritical bool   `json:"suspected_requires_critical"`
	RequirePersistenceSeconds int    `json:"require_persistence_seconds"`
	SuppressFlappingSeconds   int    `json:"suppress_flapping_seconds"`
	AssignmentGroup           string `json:"assignment_group"`
	DefaultImpact             int    `json:"default_impact"`
	DefaultUrgency            int    `json:"default_urgency"`
	// Per-verdict ServiceNow priority mapping (0 = automatic escalation:
	// confirmed+critical → 1/1 = P1, confirmed → urgency 1 = P2, suspected uses
	// the defaults above). Explicit values win outright — the customer decides.
	ImpactConfirmedCritical  int            `json:"impact_confirmed_critical,omitempty"`
	UrgencyConfirmedCritical int            `json:"urgency_confirmed_critical,omitempty"`
	ImpactConfirmed          int            `json:"impact_confirmed,omitempty"`
	UrgencyConfirmed         int            `json:"urgency_confirmed,omitempty"`
	Filters                  map[string]any `json:"filters,omitempty"`
	CreatedAt                time.Time      `json:"created_at"`
	UpdatedAt                time.Time      `json:"updated_at"`
}

// DefaultIncidentPolicy is the MVP policy used when a tenant has configured none:
// customer-facing confirmed faults (and suspected-critical) open a ServiceNow
// incident; everything internal/probe-only/undetermined is held.
func DefaultIncidentPolicy(tenant string) IncidentPolicy {
	return IncidentPolicy{
		ID:                        "default",
		TenantID:                  tenant,
		Name:                      "Default ServiceNow incident policy",
		ExternalSystem:            "servicenow",
		Enabled:                   true,
		MinVerdict:                "suspected",
		RequireCustomerFacing:     true,
		AllowProbeOnly:            false,
		AllowInternalMonitoring:   false,
		AllowValidationScenarios:  false,
		SuspectedRequiresCritical: true,
		DefaultImpact:             2,
		DefaultUrgency:            2,
	}
}

// Link binds an RCA object to its external ticket — the dedupe anchor.
// One per (TenantID, CorrObjectID, ExternalSystem).
type Link struct {
	TenantID        string     `json:"tenant_id"`
	CorrObjectID    string     `json:"corr_object_id"`
	ExternalSystem  string     `json:"external_system"`
	InstanceURL     string     `json:"instance_url"`
	TicketNumber    string     `json:"ticket_number"`
	SysID           string     `json:"sys_id"`
	DedupeKey       string     `json:"dedupe_key"`
	Status          string     `json:"status"` // pending|open|updated|resolved|failed
	LastVerdict     string     `json:"last_verdict"`
	LastConfidence  float64    `json:"last_confidence"`
	LastPayloadHash string     `json:"last_payload_hash"`
	LastSyncedAt    *time.Time `json:"last_synced_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// Open reports whether the link represents a live ticket (so the policy
// must not open a second). pending/failed are NOT live — a failed create may
// retry, a pending one is mid-flight in the outbox (idempotency-keyed there).
func (l Link) Open() bool {
	return l.Status == "open" || l.Status == "updated"
}

// OutboxItem is one reliable, retryable external action. The worker (P2)
// claims due rows with SKIP LOCKED so ticketing never blocks correlation.
type OutboxItem struct {
	TenantID       string         `json:"tenant_id"`
	ID             string         `json:"id"`
	CorrObjectID   string         `json:"corr_object_id"`
	ExternalSystem string         `json:"external_system"`
	Action         string         `json:"action"` // create|update|add_work_note|resolve|reopen
	IdempotencyKey string         `json:"idempotency_key"`
	Payload        map[string]any `json:"payload"`
	Status         string         `json:"status"` // pending|sent|failed|retrying|dead_letter
	RetryCount     int            `json:"retry_count"`
	MaxRetries     int            `json:"max_retries"`
	NextRetryAt    time.Time      `json:"next_retry_at"`
	LastError      string         `json:"last_error"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// AuditEntry records one action for the compliance trail.
type AuditEntry struct {
	TenantID       string    `json:"tenant_id"`
	ID             string    `json:"id"`
	CorrObjectID   string    `json:"corr_object_id"`
	ExternalSystem string    `json:"external_system"`
	Action         string    `json:"action"`
	Actor          string    `json:"actor"` // system | user:<id>
	OldStatus      string    `json:"old_status"`
	NewStatus      string    `json:"new_status"`
	PayloadHash    string    `json:"payload_hash"`
	Result         string    `json:"result"`
	Error          string    `json:"error"`
	At             time.Time `json:"at"`
}

// ── payload + decision (assembled/decided by the pure functions) ─────────────

// Payload is the provider-agnostic ticket body built from the RCA object.
// The ServiceNow adapter (P2) maps this onto u_correlix_* fields; Jira/PD later
// reuse the same payload. Carries the RCA diagnosis, not raw alert noise.
type Payload struct {
	CorrObjectID      string   `json:"corr_object_id"`
	ExternalSystem    string   `json:"external_system"`
	Title             string   `json:"title"`   // "Suspected|Confirmed <fault> on <entity/path>"
	Verdict           string   `json:"verdict"` // undetermined|suspected|confirmed
	Confidence        float64  `json:"confidence"`
	Signature         string   `json:"signature,omitempty"`
	Summary           string   `json:"summary"`
	RecommendedAction string   `json:"recommended_action"`
	Owner             string   `json:"owner,omitempty"`
	AffectedScope     string   `json:"affected_scope,omitempty"`
	AffectedEntities  []string `json:"affected_entities,omitempty"`
	EvidenceUsed      []string `json:"evidence_used,omitempty"`
	MissingEvidence   []string `json:"missing_evidence,omitempty"`
	ImpactedApps      []string `json:"impacted_apps,omitempty"`
	RCAURL            string   `json:"rca_url"`
	Impact            int      `json:"impact"`
	Urgency           int      `json:"urgency"`
	AssignmentGroup   string   `json:"assignment_group,omitempty"`
}

// Decision is the pure verdict of the incident policy: open a ticket or
// hold, with an operator-readable reason (surfaced verbatim in the UI's
// Recommended-Action blocked-reason text — no raw-alert language).
type Decision struct {
	Create bool   `json:"create"`
	Reason string `json:"reason"`
}
