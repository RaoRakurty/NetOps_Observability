// Package timeintel is the pure core of RCA Time Intelligence (Incident Time
// Decomposition): it turns an incident's lifecycle events into source-attributed,
// honestly-incomplete time-phase metrics and a "where did the time go" driver.
//
// Product principle (owner): this is NOT a "MTTR dashboard" and NEVER claims
// "Correlix cut MTTR 80%". It decomposes every incident into measurable phases and
// shows exactly WHERE time was saved or lost — detection, correlation, root-domain
// isolation (MTTI, the differentiator), owner identification, evidence readiness,
// acknowledgement, mitigation, recovery, resolution.
//
// Honesty rules (hard): a missing start/end event yields an INCOMPLETE metric (named
// missing event), never a bogus zero. An inferred timestamp (e.g. impact-start
// inferred from the earliest customer-impacting signal) flags the metric is_inferred
// and propagates the lowest constituent confidence. Pure stdlib; no DB, no I/O.
package timeintel

import "time"

// EventType is a point on the incident lifecycle. The set mirrors the
// detect→respond→recover lifecycle with post-incident learning.
type EventType string

const (
	EvImpactStarted        EventType = "impact_started"
	EvFirstSignal          EventType = "first_signal"
	EvDetected             EventType = "detected"
	EvCorrelationStarted   EventType = "correlation_started"
	EvCorrelationCompleted EventType = "correlation_completed"
	EvRcaCandidate         EventType = "rca_candidate_generated"
	EvRootDomainIdentified EventType = "root_domain_identified"
	EvOwnerIdentified      EventType = "owner_identified"
	EvEvidenceReady        EventType = "evidence_ready"
	EvTicketCreated        EventType = "ticket_created"
	EvAcknowledged         EventType = "acknowledged"
	EvMitigationStarted    EventType = "mitigation_started"
	EvMitigated            EventType = "mitigated"
	EvRecovered            EventType = "recovered"
	EvResolved             EventType = "resolved"
	EvClosed               EventType = "closed"
	EvPostmortemCompleted  EventType = "postmortem_completed"
)

// TimestampSource records HOW a lifecycle timestamp was obtained — central to the
// honesty bar: an inferred or synthetic stamp must never read as ground truth.
type TimestampSource string

const (
	SrcObserved    TimestampSource = "observed"     // measured directly (signal/engine)
	SrcInferred    TimestampSource = "inferred"     // derived/approximated (e.g. impact from earliest signal)
	SrcUserEntered TimestampSource = "user_entered" // a human typed it (audited)
	SrcITSM        TimestampSource = "itsm"          // from ServiceNow/Jira/PagerDuty/Slack
	SrcSynthetic   TimestampSource = "synthetic"     // generated (lab/test)
	SrcImported    TimestampSource = "imported"      // backfilled from an external system
)

// MetricName is a decomposed time phase. MTBF/MTTF are reliability rollups computed
// separately (over many incidents), not per-incident phases.
type MetricName string

const (
	MetricTTD           MetricName = "ttd"            // time to detect:        detected − impact_started
	MetricTTC           MetricName = "ttc"            // time to correlate:     correlation_completed − first_signal
	MetricTTI           MetricName = "tti"            // time to ISOLATE:        root_domain_identified − first_signal  (the differentiator)
	MetricTTE           MetricName = "tte"            // time to evidence:      evidence_ready − first_signal
	MetricTTA           MetricName = "tta"            // time to acknowledge:   acknowledged − ticket_created
	MetricTTM           MetricName = "ttm"            // time to mitigate:      mitigated − detected
	MetricTTRRecovery   MetricName = "ttr_recovery"   // recovered − impact_started
	MetricTTRResolution MetricName = "ttr_resolution" // closed − impact_started
)

// AllMetrics is the canonical compute order (detect → … → resolve).
var AllMetrics = []MetricName{
	MetricTTD, MetricTTC, MetricTTI, MetricTTE, MetricTTA, MetricTTM, MetricTTRRecovery, MetricTTRResolution,
}

// EventStamp is one resolved lifecycle timestamp with its provenance.
type EventStamp struct {
	At         time.Time       `json:"at"`
	Source     TimestampSource `json:"timestamp_source"`
	Confidence float64         `json:"confidence"` // 0..1; 1 = certain
}

// Lifecycle is the best-known stamp per event type for one incident (the latest /
// highest-trust per type is resolved upstream before calculation).
type Lifecycle map[EventType]EventStamp

// TimeMetric is one computed phase. An INCOMPLETE metric (Complete=false) names the
// MissingEvent and carries no duration — never a fabricated zero.
type TimeMetric struct {
	Name               MetricName `json:"metric_name"`
	Complete           bool       `json:"complete"`
	StartedAt          *time.Time `json:"started_at,omitempty"`
	EndedAt            *time.Time `json:"ended_at,omitempty"`
	DurationMs         int64      `json:"duration_ms"` // meaningful only when Complete
	StartEvent         EventType  `json:"start_event_type"`
	EndEvent           EventType  `json:"end_event_type"`
	Confidence         float64    `json:"confidence"`
	IsInferred         bool       `json:"is_inferred"`
	BlockedBy          string     `json:"blocked_by,omitempty"`    // why incomplete (human hint)
	MissingEvent       string     `json:"missing_event,omitempty"` // the absent lifecycle event
	CalculatedAt       time.Time  `json:"calculated_at"`
	CalculationVersion string     `json:"calculation_version"`
}

// TimeLossDriver is the single phase that dominated the incident's elapsed time —
// the "where did the time go" answer.
type TimeLossDriver string

const (
	DriverDetection       TimeLossDriver = "detection"
	DriverCorrelation     TimeLossDriver = "correlation"
	DriverEvidenceMissing TimeLossDriver = "evidence_missing"
	DriverOwnership       TimeLossDriver = "ownership"
	DriverAcknowledgement TimeLossDriver = "acknowledgement"
	DriverMitigation      TimeLossDriver = "mitigation"
	DriverProviderRepair  TimeLossDriver = "provider_repair"
	DriverUnknown         TimeLossDriver = "unknown"
)
