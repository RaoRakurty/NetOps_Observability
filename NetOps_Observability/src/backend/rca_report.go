package main

// rca_report.go — the canonical, server-side RCA report view model (owner
// directive 2026-07-12; design: docs/design/rca-report-overhaul.md).
//
// The report is a PURE derivation over the same tenant-scoped slice the
// timeline and rca-path-view read (loadCorrSlice + mergeTimelineEvidence) plus
// the ticket link — no engine re-decision, no stored prose. Honesty rules are
// enforced HERE, in the builder, not in the template:
//
//   unknown is not zero · missing is not healthy · correlated is not caused ·
//   a recovered signal is not a resolved root cause · one evidence class never
//   confirms · a recovery time that was not captured is said so, never invented.
//
// Four INDEPENDENT state dimensions replace the old single "RCA state" badge:
// incident (lifecycle), analysis (evidence maturity), impact (customer effect,
// telemetry-qualified), ticket (workflow). "Recovered" applies to the incident,
// never to the analysis.

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// ---- typed view model --------------------------------------------------------

type rcaReport struct {
	ReportID      string `json:"report_id"`
	CorrelationID string `json:"correlation_id"`
	DisplayID     string `json:"display_id"` // P-XXXXXX (problemDisplayID)
	Version       int    `json:"version"`
	ReportType    string `json:"report_type"` // see reportTypeFor
	Title         string `json:"title"`
	Subtitle      string `json:"subtitle,omitempty"`
	// Validation: every anomalous signal declares a non-production purpose —
	// the document watermarks itself and claims no production severity (§11/§24).
	Validation  bool   `json:"validation"`
	GeneratedAt string `json:"generated_at"` // UTC, canonical

	// AtAGlance (#113 point 2): the document's FIRST section — where it
	// happened · what possibly happened · possible owner(s) — rendered above
	// the management summary together with the causality path (broken areas
	// red). Composed from fault localization / scope / hypotheses / ownership;
	// it never introduces a claim those sections don't already make.
	AtAGlance rcaAtAGlance `json:"at_a_glance"`

	States rcaReportStates `json:"states"`
	Times  rcaReportTimes  `json:"times"`
	Scope  rcaReportScope  `json:"scope"`
	// IssueContext: the resolved interpretation context (IssueContextResolver)
	// — issue family, classifications, prohibited claims, applicable actions.
	IssueContext rcaIssueContext    `json:"issue_context"`
	Summary      rcaReportSummaries `json:"summary"`
	Signals      rcaSignalSummary   `json:"signal_summary"`
	// Evidence: the NOC evidence read (owner directive 2026-07-18) — symptoms ·
	// independent sources · density, verdict reason in operator words; the raw
	// observation count demoted to a muted trailing fact.
	Evidence rcaEvidenceSummary `json:"evidence_summary"`
	// Accounting: the derived evidence-accounting presentation block (Phase D) —
	// canonical evidence groups, classified sources, independent confirming
	// sources, and the operator lineage ladder. Derived once from the Phase B
	// EvidenceAccounting; every renderer consumes it, none recomputes a count.
	Accounting rcaAccountingView `json:"evidence_accounting"`
	Coverage   []rcaEvidenceLane `json:"evidence_coverage"`
	// Cloud change events observed in/near the window. Empty = none observed
	// (the section is omitted, not rendered as healthy).
	CloudChanges []rcaCloudChange `json:"cloud_changes,omitempty"`
	Hypotheses   []rcaHypothesis  `json:"hypotheses"`
	// Cascade: the top hypothesis's causal propagation ladder (§ epic D2 — the
	// workspace had it; the exported report, a terminal consumer, did not).
	Cascade []rcaCascadeStage `json:"cascade,omitempty"`
	// SingleHypothesis: render "Current hypothesis", not "Hypothesis ranking".
	SingleHypothesis bool `json:"single_hypothesis"`
	// Phases: the generic incident phase ladder (P1.2) — detection through
	// component recovery, residual degradation, service recovery, monitoring.
	Phases []rcaIncidentPhase `json:"phases,omitempty"`
	// FaultLocalization is WHERE the evidence converges (a domain/seam/object
	// boundary). It is never the root cause: localization narrows, cause explains.
	FaultLocalization rcaFaultLocalization `json:"fault_localization"`
	RootCause         rcaRootCause         `json:"root_cause"`
	Ownership         rcaOwnership         `json:"ownership"`
	Decision          rcaDecision          `json:"decision"`
	Actions           []rcaAction          `json:"next_actions"`
	// Promotion (#113 point 3): whether this case is a PROMOTED real outage —
	// only then does the endpoint render the html/pdf DOCUMENT. Set by the HTTP
	// layer (it owns the manual-promotion store); candidates keep full JSON
	// access, so the workspace tier is unaffected.
	Promotion rcaPromotionStatus `json:"promotion"`
	// Quality: the StateConsistencyValidator's record for this document. Errors
	// downgrade the report type — a contradictory document never ships as final.
	Quality rcaReportQuality `json:"quality"`
	// Merge: present ONLY when this is a merged/superseded source case. It carries
	// the surviving incident id, the transferred side-effect responsibilities and
	// the authoritative-state record (P1 merged-incident lifecycle).
	Merge  *rcaIncidentMerge `json:"merge,omitempty"`
	Ticket map[string]any    `json:"ticket,omitempty"` // ticketStatusView passthrough
	// The §7 ordered spine block (rcaPathBlock passthrough) — the topology
	// section renders ONLY measured/declared structure, never invented paths.
	Path any `json:"path,omitempty"`
	// Topology is the report-facing projection of the measured spine (§15):
	// service/vantage names primary, addresses secondary, seam + state per hop.
	// Available=false renders as an honest absence, never an invented diagram.
	Topology rcaTopologyView `json:"topology"`
	// PathAttribution is the path-causality RCA P2 on-path device attribution
	// (design §2.4): the named upstream-most on-path cause, its verdict lift, the
	// explained-away/discounted faults, the honesty-cap reason, and the discovered
	// typed path the cause sits on. nil (omitted) when the engine attributed no
	// on-path cause — an honest absence, never an invented one.
	PathAttribution *rcaPathAttribution `json:"path_attribution,omitempty"`

	// mgmtTrimmed: the management summary exceeded the word cap and dropped
	// lower-priority sentences — surfaced as a P2 quality warning.
	mgmtTrimmed bool

	// accounting: the canonical EvidenceAccounting for this case (Phase B). Not
	// rendered this phase — Phases D/E consume it (presentation + quality gate).
	accounting EvidenceAccounting
	// accountingErr: non-nil when the accounting model derived contradictory counts
	// (an invariant violation). The Phase E gate blocks a report carrying this.
	accountingErr error
}

// rcaObserverRegistry is the package-level observer classification registry
// (env-driven global defaults; per-tenant structured policy injected when wired).
var rcaObserverRegistry = newObserverRegistry(nil)

// evidenceAccounting exposes the derived accounting (and any invariant error) for
// the quality gate and tests. Kept a method so the unexported fields have a reader.
func (r *rcaReport) evidenceAccounting() (EvidenceAccounting, error) {
	return r.accounting, r.accountingErr
}

type rcaSpineHopView struct {
	Index    int    `json:"index"`
	Label    string `json:"label"`
	Address  string `json:"address,omitempty"`
	Kind     string `json:"kind"`
	Boundary string `json:"boundary,omitempty"`
	State    string `json:"state"`
	SeamID   string `json:"seam_id,omitempty"`
	// Fault marks the verdict-gated drop point (broken|suspected) — the path's
	// causality, rendered red in the document exactly as on the canvas.
	Fault    string `json:"fault,omitempty"`
	Provider string `json:"provider,omitempty"`
}

type rcaTopologyView struct {
	Available  bool   `json:"available"`
	Reason     string `json:"reason,omitempty"`
	VantageID  string `json:"vantage_id,omitempty"`
	ObservedAt string `json:"observed_at,omitempty"`
	Stale      bool   `json:"stale"`
	// RelationToIncident (P1.8): pre_incident | incident_time |
	// post_recovery_validation | historical_context | unknown. A path captured
	// after recovery is recovery VALIDATION — it can never establish
	// incident-time root cause; the note states so explicitly.
	RelationToIncident string            `json:"relation_to_incident,omitempty"`
	TemporalNote       string            `json:"temporal_note,omitempty"`
	Hops               []rcaSpineHopView `json:"hops,omitempty"`
	// DropPoint: the path's own causality sentence (set when a fault hop exists).
	DropPoint string `json:"drop_point,omitempty"`
}

// stampTopologyTemporalRole classifies the attached path observation's
// temporal role against the incident window (P1.8, audit D9).
func stampTopologyTemporalRole(rep *rcaReport) {
	t := &rep.Topology
	if !t.Available || t.ObservedAt == "" {
		return
	}
	obs, ok := parseChTS(strings.TrimSuffix(t.ObservedAt, " UTC"))
	if !ok {
		t.RelationToIncident = "unknown"
		return
	}
	first, okF := parseChTS(strings.TrimSuffix(rep.Times.FirstObserved, " UTC"))
	last, okL := parseChTS(strings.TrimSuffix(rep.Times.LastAnomalous, " UTC"))
	switch {
	case okF && obs.Before(first):
		t.RelationToIncident = "pre_incident"
		t.TemporalNote = "This path was measured BEFORE the incident began — historical context, not incident-time evidence."
	case okL && obs.After(last):
		t.RelationToIncident = "post_recovery_validation"
		t.TemporalNote = "This path was measured AFTER the last anomalous observation — it validates the current/recovered state and cannot establish incident-time root cause."
	case okF:
		t.RelationToIncident = "incident_time"
	default:
		t.RelationToIncident = "unknown"
	}
}

type rcaReportStates struct {
	// Incident lifecycle is separate from recovery assessment (§1/§17 of the
	// truthfulness spec): signals aging out of the window is NOT recovery.
	Incident string `json:"incident"` // active | recovering | recovered | no_longer_observed | closed | merged | superseded
	// Lifecycle is the canonical lifecycle state (rcaCanonicalLifecycles). It is
	// the same value as Incident today; the field exists so "merged" is a first-
	// class lifecycle, never free-text prose (P1 merged-incident lifecycle).
	Lifecycle string `json:"lifecycle"`
	// Recovery is asserted ONLY from observed recovery evidence, reconciled
	// across scopes (P1.1): component recovery never recovers the service.
	Recovery      string `json:"recovery"`       // explicitly_confirmed | component_only | failed_validation | inferred | not_observed
	RecoveryBasis string `json:"recovery_basis"` // human sentence: what (if anything) proved recovery
	// Per-scope recovery assessments (RecoveryReconciler output).
	RecoveryComponent rcaRecoveryScopeState `json:"recovery_component"`
	RecoveryService   rcaRecoveryScopeState `json:"recovery_service"`
	Analysis          string                `json:"analysis"` // retained for API compat: observed | suspected | probable | confirmed | inconclusive
	// Dimensional analysis states (owner feedback: no single umbrella flag).
	Symptom        string `json:"symptom"`          // observed | confirmed
	FaultDomain    string `json:"fault_domain"`     // not_localized | suspected | probable | confirmed
	Mechanism      string `json:"mechanism"`        // unknown | under_investigation | confirmed
	RootCauseState string `json:"root_cause_state"` // not_identified | under_investigation | confirmed
	Impact         string `json:"impact"`           // confirmed | detected | none_detected | not_observable | unknown
	// §5 impact axes: a failed synthetic proves the SYNTHETIC transaction failed;
	// real-user impact needs real-traffic evidence (flow collapse, LB/app errors).
	ImpactSynthetic string `json:"impact_synthetic"` // confirmed | none_detected | not_observable
	// Real-user impact is observability-aware (P1.5): a flow-volume change is an
	// INDICATOR, never confirmation; "none_detected" requires sufficient coverage.
	ImpactRealUser string `json:"impact_real_user"` // confirmed | detected | indicator_detected | none_detected | not_observable
	Ticket         string `json:"ticket"`           // not_opened | held | opened | resolved | failed
	// Severity is the peak ATTACHED-EVIDENCE severity (a fact about signals).
	Severity string `json:"severity"` // info|warn|high|crit|unknown
	// SeverityIncident is the INCIDENT severity (P1.11): policy-derived from
	// corroboration, impact and confidence — never bare max-signal severity.
	SeverityIncident    string   `json:"severity_incident"` // info|warn|high|crit|not_applicable|unknown
	SeverityReasonCodes []string `json:"severity_reason_codes,omitempty"`
	// §19: severity is never a bare adjective — what carried it and how much.
	// SeverityBasis describes the EVIDENCE-peak severity (a fact about signals).
	SeverityBasis string `json:"severity_basis"`
	// SeverityIncidentBasis explains the INCIDENT severity from policy inputs
	// (environment, impact, corroboration, recovery/residual state) — never the
	// circular "peak of the attached evidence" (P1 severity basis).
	SeverityIncidentBasis string `json:"severity_incident_basis"`
	// Monitoring is evaluated against report-generation time — never described
	// as running past its own end.
	Monitoring string `json:"monitoring"` // not_started | active | completed
	// Confidence carries its basis so "Medium" is never a bare adjective.
	Confidence      string `json:"confidence"` // High | Medium | Low
	ConfidenceBasis string `json:"confidence_basis"`
}

type rcaReportTimes struct {
	FirstObserved string `json:"first_observed,omitempty"` // earliest anomalous evidence
	LastAnomalous string `json:"last_anomalous,omitempty"` // latest anomalous evidence
	// RecoveredAt is set ONLY when the incident-level recovery gate passed:
	// observed recovery evidence at/after the last qualifying anomaly in every
	// participating scope. A component-up time never lands here (P1.1).
	RecoveredAt       string `json:"recovered_at,omitempty"`
	RecoveredCaptured bool   `json:"recovered_captured"`
	// ComponentRecoveredAt: the last observed component-status recovery. It is
	// reported separately and never presented as incident recovery.
	ComponentRecoveredAt string `json:"component_recovered_at,omitempty"`
	DurationMS           int64  `json:"duration_ms,omitempty"`
	// DurationBasis states what the duration measures:
	// to_recovery | to_last_observation | elapsed_still_active | unknown
	DurationBasis   string `json:"duration_basis"`
	MonitoringUntil string `json:"monitoring_until,omitempty"`
	WindowStart     string `json:"window_start"`
	WindowEnd       string `json:"window_end"`
}

// classifyServiceScope derives the §12 service classification from what the
// targets themselves are — an operator-actionable split, never a guess about
// unobserved infrastructure: private address → customer-managed internal;
// public address → public endpoint; DNS name → external / third-party service.
func classifyServiceScope(targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	t := targets[0]
	if ip := net.ParseIP(strings.Split(t, ":")[0]); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() {
			return "customer-managed internal application"
		}
		return "public endpoint"
	}
	if strings.Contains(t, ".") {
		return "external / third-party service"
	}
	return ""
}

type rcaReportScope struct {
	Services []string `json:"services,omitempty"` // named apps/services (operator identifiers)
	// §12: what KIND of service the subject is — ownership and next actions
	// differ between a customer-managed app and a third-party SaaS.
	ServiceClassification string   `json:"service_classification,omitempty"`
	Targets               []string `json:"targets,omitempty"` // probe/impact targets (service name first, IP secondary)
	Devices               []string `json:"devices,omitempty"`
	Sites                 []string `json:"sites,omitempty"`
	Regions               []string `json:"regions,omitempty"`
	Accounts              []string `json:"accounts,omitempty"`
	Vantages              []string `json:"vantages,omitempty"` // observing vantages that saw anomalies
	Seams                 []string `json:"seams,omitempty"`    // provider boundaries in the grounding context
	PathsCount            int      `json:"paths_count,omitempty"`
}

type rcaReportSummaries struct {
	// Management: what happened / still happening / duration / impact
	// (telemetry-qualified) / cause status / decision / next. ~100-140 words.
	Management string `json:"management"`
	// NOC quick-read: structured fields, 30-second scan.
	Noc []rcaKV `json:"noc"`
	// WhySuspected / WhyNotConfirmed: evidence-specific, never circular.
	WhySuspected    string   `json:"why_suspected,omitempty"`
	WhyNotConfirmed []string `json:"why_not_confirmed,omitempty"`
	RequiredConfirm string   `json:"required_confirmation,omitempty"`
}

type rcaCascadeStage struct {
	Stage     string `json:"stage"`
	Witnessed bool   `json:"witnessed"`
	Root      bool   `json:"root"`
	Note      string `json:"note"`
}

type rcaKV struct {
	K string `json:"k"`
	V string `json:"v"`
}

// rcaEvidenceSummary — the NOC evidence read (docs/design/rca-evidence-summary.md):
// distinct SYMPTOMS · INDEPENDENT SOURCES · duration are the headline; each
// symptom carries a render-side time-density series (repetition made visible,
// never counted as evidence); the verdict names its reason in operator words;
// the raw observation total is the LAST, muted line. A raw count never appears
// without its unit of meaning, and the word "signals" never reaches the UI.
type rcaEvidenceSummary struct {
	SymptomCount       int             `json:"symptom_count"`
	IndependentSources int             `json:"independent_sources"`
	SourceNames        []string        `json:"source_names,omitempty"`
	VerdictReason      string          `json:"verdict_reason"`
	Symptoms           []rcaSymptomRow `json:"symptoms"`
	Observations       int             `json:"observations"`     // raw rows collected — muted, collapsed
	LastObservation    string          `json:"last_observation"` // freshness, e.g. "18s ago"
}

// rcaSymptomRow is one distinct manifestation: NOC label + which source class
// saw it + onset/latest + a bucketed observation-density series for the bar.
type rcaSymptomRow struct {
	Label        string `json:"label"`
	Kind         string `json:"kind"`
	Source       string `json:"source"`
	First        string `json:"first"`
	Last         string `json:"last"`
	Observations int    `json:"observations"`
	Buckets      []int  `json:"buckets"`
}

type rcaSignalSummary struct {
	Total     int `json:"total"`
	Attached  int `json:"attached"`
	Anomalous int `json:"anomalous"` // attached, non-clear
	Clears    int `json:"clears"`
	// EvidenceGroups (P1.7): distinct (observer, entity) groups among the
	// anomalous evidence — derived signals from one measurement source count
	// once. Signal counts are volume; groups are the deduplicated evidence.
	EvidenceGroups  int    `json:"evidence_group_count"`
	UniqueObservers int    `json:"unique_observers"`
	PeakSeverity    string `json:"peak_severity"`
	// Probe detail — present only when active-probe evidence exists. Values are
	// included only when actually measured; absent means unknown, not zero.
	Probe *rcaProbeSummary `json:"probe,omitempty"`
}

type rcaProbeSummary struct {
	Observations     int      `json:"observations"`
	Failed           int      `json:"failed"`
	AffectedVantages []string `json:"affected_vantages,omitempty"`
	FailureStages    []string `json:"failure_stages,omitempty"`
	PeakLossPct      *float64 `json:"peak_loss_pct,omitempty"`
	BaselineRttMs    *float64 `json:"baseline_rtt_ms,omitempty"`
	PeakRttMs        *float64 `json:"peak_rtt_ms,omitempty"`
	FirstFailed      string   `json:"first_failed,omitempty"`
	LastFailed       string   `json:"last_failed,omitempty"`
	// Independence is stated only when known (verdict gate); never assumed.
	IndependenceNote string `json:"independence_note,omitempty"`
	// LastTransaction: the most recent FAILED synthetic check's per-phase
	// results — the actual protocol outcome, not just "it failed".
	LastTransaction *rcaProbeTransaction `json:"last_transaction,omitempty"`
}

// rcaProbeTransaction is one measured check transaction (per-phase timings and
// outcome). Absent fields were not measured — never zero.
type rcaProbeTransaction struct {
	Target     string   `json:"target,omitempty"`
	Method     string   `json:"method,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`
	FailClass  string   `json:"fail_class,omitempty"`
	DNSMs      *float64 `json:"dns_ms,omitempty"`
	TCPMs      *float64 `json:"tcp_ms,omitempty"`
	TLSMs      *float64 `json:"tls_ms,omitempty"`
	TTFBMs     *float64 `json:"ttfb_ms,omitempty"`
	TotalMs    *float64 `json:"total_ms,omitempty"`
	At         string   `json:"at,omitempty"`
}

type rcaEvidenceLane struct {
	Class string `json:"class"` // engine modality key
	Label string `json:"label"` // NOC label
	// Availability: available | no_data. State: anomalous | normal | no_data |
	// not_applicable. "No data" is coverage ABSENCE — it never reads as healthy
	// and never contributes to confidence.
	Availability string `json:"availability"`
	State        string `json:"state"`
	Observations int    `json:"observations"`
	Anomalous    int    `json:"anomalous"`
	Finding      string `json:"finding"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	// Coverage quality (P1): full | partial | none | not_applicable. A lane that
	// observed cleanly but did not span the full incident window is PARTIAL —
	// "no anomaly observed during available coverage", never a clean green Normal.
	Coverage        string `json:"coverage"`
	MissingInterval string `json:"missing_interval,omitempty"`
	// CountsTowardConfidence: this lane is among the verdict gate's trusted /
	// covering modalities for the top hypothesis.
	CountsTowardConfidence bool `json:"counts_toward_confidence"`
	// Assessment is the canonical Phase C coverage verdict for this lane (quality
	// state, overlap/ratio, leading/trailing/internal gaps, cadence provenance,
	// eligibility + reason codes). The legacy State/Coverage/MissingInterval fields
	// above are DERIVED from it; Phase D renders the richer struct directly.
	Assessment *CoverageAssessment `json:"assessment,omitempty"`
}

type rcaCloudChange struct {
	Kind        string `json:"kind"` // cloud_change | cloud_audit | security_policy_change
	Provider    string `json:"provider,omitempty"`
	EventSource string `json:"event_source,omitempty"`
	RequestID   string `json:"request_id,omitempty"` // provider event key
	Account     string `json:"account,omitempty"`
	Region      string `json:"region,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Actor       string `json:"actor,omitempty"`
	At          string `json:"at"`
	// DeltaSeconds: change time minus first anomalous observation (negative =
	// change preceded the symptom). Present only when both times are known.
	DeltaSeconds *int64 `json:"delta_seconds,omitempty"`
	// Relationship: same_resource | same_service | same_account_region |
	// temporal_only. Never a causal claim.
	Relationship string `json:"relationship"`
	Attached     bool   `json:"attached"`
	Explanation  string `json:"explanation"`
}

type rcaHypothesis struct {
	// Type separates a symptom classification from a causal hypothesis (§15).
	Type string `json:"type"`
	// Taxonomy (P1.9): the observation and the causal role are INDEPENDENT
	// axes — a condition can be confirmed as observed AND ruled out as origin.
	ObservationState string   `json:"observation_state"` // not_observed | observed | confirmed
	CausalRole       string   `json:"causal_role"`       // possible_origin | probable_origin | downstream_consequence | symptom | ruled_out_as_origin
	CandidacyState   string   `json:"candidacy_state"`   // active | ruled_out | not_ranked_as_cause
	Rank             int      `json:"rank"`
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Problem          string   `json:"problem"` // what the possible problem is → the suspect
	Domain           string   `json:"domain,omitempty"`
	Confidence       float64  `json:"confidence"`
	Label            string   `json:"label"` // engine confidence_label
	Supporting       []string `json:"supporting,omitempty"`
	Contradicted     bool     `json:"contradicted"`
	Contradicting    []string `json:"contradicting,omitempty"`
	Missing          []string `json:"missing,omitempty"`
	ConfirmWhen      []string `json:"confirm_when,omitempty"`
	Owner            string   `json:"owner,omitempty"`
}

// rcaFaultLocalization (P1.3/P1.4): where the evidence converges — a seam,
// domain or object boundary. Localization NARROWS the fault; it never names
// the cause. The seam/locus that used to be presented as "root cause" lives
// here now.
type rcaFaultLocalization struct {
	Localized  bool     `json:"localized"`
	Statement  string   `json:"statement"`
	Object     string   `json:"object,omitempty"`
	ObjectType string   `json:"object_type,omitempty"` // e.g. "ipsec seam (localization domain)"
	Evidence   []string `json:"evidence,omitempty"`
}

// rcaRootCause may claim identification ONLY when a causal mechanism AND a
// causal object are established (P1.3). A confirmed fault condition, a
// confirmed signature, seam grounding or high confidence never set it.
type rcaRootCause struct {
	Identified bool     `json:"identified"`
	Statement  string   `json:"statement"` // best-hypothesis "possibly because of X" wording when false
	Mechanism  string   `json:"mechanism,omitempty"`
	Object     string   `json:"object,omitempty"`
	ObjectType string   `json:"object_type,omitempty"`
	Owner      string   `json:"owner,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	// #113 point 4 cause honesty: an unidentified root cause never renders as a
	// bare "not identified" — the best live hypothesis is named as "possibly
	// because of X" together with its evidence STATE: what is in hand and what
	// is still missing (hypothesis gaps + the object's own evidence_missing).
	// All empty when no hypothesis has supporting evidence (honest absence).
	PossibleCause   string   `json:"possible_cause,omitempty"`
	EvidenceKnown   []string `json:"evidence_known,omitempty"`
	EvidenceMissing []string `json:"evidence_missing,omitempty"`
}

type rcaOwnerCandidate struct {
	Team   string `json:"team"`
	Reason string `json:"reason"`
}

// rcaAtAGlance — the owner-mandated first section (#113 point 2): where · what
// possibly happened · possible owner(s). The causality path renders alongside it
// from rcaReport.Topology (broken areas red, rcaPathGraphSVG). Wording rules:
// "possible owner(s)" whenever the root cause is unconfirmed; "possibly because
// of X" for an unconfirmed best hypothesis — never a bare claim, never a bare
// "not identified".
type rcaAtAGlance struct {
	Where      string `json:"where"`
	WhereBasis string `json:"where_basis,omitempty"` // localization | scope | none
	What       string `json:"what"`                  // what (possibly) happened
	// OwnersLabel: "Owner" only when the root cause is identified with an
	// owner; otherwise "Possible owner(s)".
	OwnersLabel  string   `json:"owners_label"`
	Owners       []string `json:"owners"`
	OwnersReason string   `json:"owners_reason,omitempty"`
}

type rcaOwnership struct {
	TriageOwner     string              `json:"triage_owner"` // NOC unless evidence says otherwise
	TriageReason    string              `json:"triage_reason"`
	SuspectedDomain string              `json:"suspected_domain"` // Undetermined until evidence
	Candidates      []rcaOwnerCandidate `json:"candidates,omitempty"`
	// TechnicalOwner: the internal team investigating. An external provider is
	// never handed accountability without demarcation (P1.10).
	TechnicalOwner    string `json:"technical_owner,omitempty"`
	ExternalCandidate string `json:"external_candidate,omitempty"`
	// Demarcation: not_started | local_checks_pending | provider_boundary_confirmed
	Demarcation      string `json:"demarcation,omitempty"`
	DemarcationBasis string `json:"demarcation_basis,omitempty"`
	EscalationOwner  string `json:"escalation_owner"`
	EscalationReason string `json:"escalation_reason"`
}

type rcaDecision struct {
	Decision   string `json:"decision"` // Open incident | Investigate | Monitor | Hold
	Reason     string `json:"reason"`
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	// Explicit, policy-driven mechanics — never vague prose.
	OpenThreshold    string `json:"open_threshold"`
	MonitoringWindow string `json:"monitoring_window"`
	AutoCloseWhen    string `json:"auto_close_when"`
	ReopenWhen       string `json:"reopen_when"`
	EscalateWhen     string `json:"escalate_when"`
	// Escalation as an EXECUTED state, never future-tense prose when its
	// conditions already hold at report time (owner feedback).
	EscalationState string `json:"escalation_state"` // triggered | armed
	EscalationAt    string `json:"escalation_at,omitempty"`
	// Auto-close eligibility evaluated at report time: monitoring completed
	// without recurrence ⇒ eligible even when historical impact was confirmed.
	AutoCloseEligible bool `json:"auto_close_eligible"`
	// Ticket RECOMMENDATION vs EXECUTION are separate states (P1.12): the
	// policy's recommendation, its reason, and — when they disagree with the
	// executed ticket state — an explicit explanation. Never a silent split.
	TicketRecommended     string `json:"ticket_recommended"` // open | hold
	TicketRecommendReason string `json:"ticket_recommend_reason"`
	TicketExecutionNote   string `json:"ticket_execution_note,omitempty"`
}

type rcaAction struct {
	Priority int    `json:"priority"`
	Action   string `json:"action"`
	Owner    string `json:"owner"`
	// OperationalPriority (P1 model): "P1" = immediate restoration/containment,
	// must be worked now; "P2" = diagnostic/corrective/prevention after
	// stabilization. Labelled separately from incident severity by design.
	OperationalPriority string `json:"operational_priority"`
	Purpose             string `json:"purpose,omitempty"` // restoration | discrimination | validation | monitoring
	ExpectedResult      string `json:"expected_result,omitempty"`
	EscalateWhen        string `json:"escalate_when,omitempty"`
}

// ---- vocabulary --------------------------------------------------------------

// Lane labels — the Go mirror of frontend MODALITY_META (labels.ts). When a
// mapping is added on one side, add it on the other.
var rcaLaneLabel = map[string]string{
	"device_telemetry": "Device health",
	"control_plane":    "Routing & link events",
	"passive_flow":     "Traffic flow",
	"active_probe":     "Active checks",
	"management_plane": "Controller / management plane",
}

var rcaLaneOrder = []string{"device_telemetry", "control_plane", "passive_flow", "active_probe", "management_plane"}

// Owner tokens (catalog verdict.owner) → team language. Mirror of OWNER_LABEL
// in labels.ts.
var rcaOwnerTeam = map[string]string{
	"netops": "NetOps", "network_ops": "NetOps", "isp": "ISP / carrier",
	"carrier": "Carrier", "cloud_provider": "Cloud provider", "app_team": "Application team",
	"colo_provider": "Colo provider", "sdwan_vendor": "SD-WAN vendor", "platform": "Platform operations",
}

// Failure stage from probe/synthetic signal kinds — the NOC's "where in the
// transaction did it die" axis. Derived, since no stage column exists.
func rcaFailureStage(kind string) string {
	switch {
	case strings.Contains(kind, "dns"):
		return "DNS"
	case strings.Contains(kind, "tcp"):
		return "TCP connect"
	case strings.Contains(kind, "tls"), strings.Contains(kind, "cert"):
		return "TLS"
	case strings.Contains(kind, "http"):
		return "HTTP"
	case strings.Contains(kind, "timeout"):
		return "Timeout"
	case strings.Contains(kind, "icmp"), kind == "probe_loss":
		return "Packet loss"
	case strings.Contains(kind, "rtt"), strings.Contains(kind, "latency"):
		return "Latency"
	default:
		return ""
	}
}

// App-impact / customer-facing evidence kinds (mirror of the confirmability
// audit's APP_GROUNDABLE set, display side).
// rcaStateUp buffers a semantic up-state event until firstObs is known.
type rcaStateUp struct {
	sig map[string]any
	ts  time.Time
}

// rcaIsRecoveryStateSignal reports whether a signal is semantic recovery
// evidence (§17): a *_status kind asserting the resource came back
// (state up/established/…, severity info) — e.g. ipsec_tunnel_status up.
// Status lanes signal recovery this way rather than with *_clear kinds.
func rcaIsRecoveryStateSignal(sig map[string]any) bool {
	kind := fmt.Sprintf("%v", sig["kind"])
	if !strings.HasSuffix(kind, "_status") {
		return false
	}
	if strings.ToLower(fmt.Sprintf("%v", sig["severity"])) != "info" {
		return false
	}
	a, _ := sig["attrs"].(string)
	if a == "" {
		return false
	}
	var at struct {
		State string `json:"state"`
	}
	if json.Unmarshal([]byte(a), &at) != nil {
		return false
	}
	switch strings.ToLower(at.State) {
	case "up", "established", "reachable", "healthy", "ok":
		return true
	}
	return false
}

// rcaIsRealUserImpactKind: evidence produced by REAL user sessions or the
// serving infrastructure itself (§5) — the only kinds that may support a
// real-user impact CLAIM. A failed synthetic check is never in this set, and
// neither is a flow-volume delta (see rcaIsRealUserIndicatorKind).
func rcaIsRealUserImpactKind(kind, entityType string) bool {
	switch kind {
	case "lb_5xx", "lb_target_unhealthy", "app_error_rate_high", "app_latency_high", "lb_4xx_high":
		return true
	case "cloud_health":
		return entityType == "app"
	}
	return false
}

// rcaIsRealUserIndicatorKind: real-traffic INDICATORS (P1.5). A traffic-volume
// change shows real traffic behaved differently; it does not prove failed user
// transactions — demand shifts, routing changes and collection loss all
// produce the same delta. Indicator, never confirmation.
func rcaIsRealUserIndicatorKind(kind string) bool {
	switch kind {
	case "flow_volume_anomaly", "flow_reset_anomaly", "flow_completion_anomaly":
		return true
	}
	return strings.HasPrefix(kind, "flow_") && !strings.HasSuffix(kind, "_clear")
}

// rcaIsSyntheticImpactKind: a customer-path synthetic/probe failure — proves
// the configured transaction failed from that vantage, nothing more (§5).
func rcaIsSyntheticImpactKind(kind, probeScope string) bool {
	if strings.HasPrefix(kind, "synthetic_") || strings.HasPrefix(kind, "probe_") {
		return probeScope == "customer_path"
	}
	return false
}

var rcaCloudChangeKinds = map[string]bool{
	"cloud_change": true, "cloud_audit": true, "security_policy_change": true,
}

// parseChTS parses ClickHouse toString() datetimes ("2026-07-12 19:50:45[.123]").
func parseChTS(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func fmtUTC(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") + " UTC" }

// fmtDur renders a duration for operators ("3m 15s", "1h 04m").
func fmtDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh %02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm %02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// ---- hypotheses blob decoding --------------------------------------------------

type rcaHypBlob struct {
	Ranking struct {
		Hypotheses []struct {
			ID              string   `json:"id"`
			Title           string   `json:"title"`
			Confidence      float64  `json:"confidence"`
			ConfidenceLabel string   `json:"confidence_label"`
			Contradicted    bool     `json:"contradicted"`
			Contradictions  []string `json:"contradictions"`
			Satisfied       []string `json:"satisfied"`
			Missing         []string `json:"missing"`
			BlastRadius     string   `json:"blast_radius"`
			CausalChain     []struct {
				Stage     string   `json:"stage"`
				Witnessed bool     `json:"witnessed"`
				Root      bool     `json:"root"`
				Note      string   `json:"note"`
				Kinds     []string `json:"kinds"`
			} `json:"causal_chain"`
			Verdict struct {
				Tier              string   `json:"verdict_tier"`
				Owner             string   `json:"owner"`
				Layer             string   `json:"layer"`
				Reasons           []string `json:"reasons"`
				FirstSteps        []string `json:"first_steps"`
				IndependentPair   []string `json:"independent_pair"`
				ModalityCoverage  []string `json:"modality_coverage"`
				ObserverCoverage  []string `json:"observer_coverage"`
				TrustedModalities []string `json:"trusted_modalities"`
			} `json:"verdict"`
		} `json:"hypotheses"`
	} `json:"ranking"`
	GroundingContext struct {
		Seams []struct {
			SeamID   string `json:"seam_id"`
			SeamType string `json:"seam_type"`
		} `json:"seams"`
	} `json:"grounding_context"`
}

// cascadeStages projects the TOP hypothesis's causal chain for the report.
// Witnessed rungs carry evidence; unwitnessed rungs stay visible and honest
// ("not observed" is part of the propagation story, not a claim).
// rcaHypothesisType classifies a hypothesis for the report (§15): an
// experience/degradation signature is a SYMPTOM CLASSIFICATION — it names what
// was observed, never a cause. Everything else proposes a causal domain.
func rcaHypothesisType(id string) string {
	l := strings.ToLower(id)
	if strings.Contains(l, "experience") || strings.Contains(l, "degraded") {
		return "symptom classification"
	}
	return "causal hypothesis"
}

// providerChangeNoun renders "An AWS" / "An Azure" / "A cloud" with the right
// article and brand casing for the change-correlation sentences.
func providerChangeNoun(p string) string {
	switch strings.ToLower(p) {
	case "aws":
		return "An AWS"
	case "azure":
		return "An Azure"
	case "gcp":
		return "A GCP"
	case "":
		return "A cloud"
	}
	return "A " + p
}

func cascadeStages(hb rcaHypBlob) []rcaCascadeStage {
	if len(hb.Ranking.Hypotheses) == 0 {
		return nil
	}
	var out []rcaCascadeStage
	for _, c := range hb.Ranking.Hypotheses[0].CausalChain {
		note := c.Note
		if note == "" && len(c.Kinds) > 0 {
			parts := make([]string, 0, len(c.Kinds))
			for _, k := range c.Kinds {
				parts = append(parts, strings.ReplaceAll(k, "_", " "))
			}
			note = strings.Join(parts, " · ")
		}
		out = append(out, rcaCascadeStage{Stage: c.Stage, Witnessed: c.Witnessed, Root: c.Root, Note: note})
	}
	return out
}

func decodeHypotheses(meta map[string]any) rcaHypBlob {
	var hb rcaHypBlob
	if h, ok := meta["hypotheses"].(string); ok && h != "" {
		// best-effort: absent/malformed blob → empty ranking (renders honestly)
		_ = json.Unmarshal([]byte(h), &hb)
	}
	return hb
}

// ---- the builder ---------------------------------------------------------------

type rcaReportInput struct {
	ID      string
	Meta    map[string]any
	Signals []map[string]any // AFTER mergeTimelineEvidence (attached/link_status stamped)
	Edges   []map[string]any
	Ticket  map[string]any // ticketStatusView output ("state": …)
	Policy  incidentPolicy
	// PolicyConfigured: false → Policy is the platform default, and the report
	// says so instead of implying tenant intent.
	PolicyConfigured bool
	Path             any // rcaPathBlock output (may be nil)
	Now              time.Time
	// SurvivingIncidentID: for a merged/superseded source case, the terminal
	// surviving correlation id the handler resolved (resolveMergeChain, tenant-
	// scoped). Empty in unit tests → the builder falls back to meta["merged_into"].
	SurvivingIncidentID string
}

func buildRcaReport(in rcaReportInput) rcaReport {
	meta := in.Meta
	hb := decodeHypotheses(meta)
	verdict := strings.ToLower(fmt.Sprintf("%v", meta["verdict_tier"]))
	state := strings.ToLower(fmt.Sprintf("%v", meta["state"]))
	// The ranking blob is the live analysis; the scalar column can lag it
	// (Phase 0 finding D1b: report title disagreed with the workspace on the
	// same case). Prefer the ranking's leader whenever it is present.
	topHyp := fmt.Sprintf("%v", meta["top_hypothesis"])
	if len(hb.Ranking.Hypotheses) > 0 && hb.Ranking.Hypotheses[0].ID != "" {
		topHyp = hb.Ranking.Hypotheses[0].ID
	}
	version := int(asFloat(meta["version"]))

	// ---- classify the slice ----------------------------------------------------
	var (
		anomalous, clears        []map[string]any
		observers                = map[string]bool{}
		anomObservers            = map[string]bool{}
		laneTotal, laneAnomalous = map[string]int{}, map[string]int{}
		laneMin, laneMax         = map[string]time.Time{}, map[string]time.Time{}
		// laneObs: the full per-observation timestamp series per lane, feeding the
		// Phase C coverage engine's rich path (internal-gap + inter-arrival cadence).
		laneObs                 = map[string][]time.Time{}
		firstObs, lastObs       time.Time
		peakSevRank             int
		peakSev                 = "unknown"
		peakSevKind             string
		sevCounts               = map[string]int{}
		impactAnomalies         int
		impactSynthetic         int
		impactRealUser          int
		impactRealUserIndicator int
		realUserLanesPresent    bool
		changes                 []rcaCloudChange
		stateUps                []rcaStateUp
	)
	sevRank := map[string]int{"info": 1, "warn": 2, "high": 3, "crit": 4}
	for _, sig := range in.Signals {
		kind := fmt.Sprintf("%v", sig["kind"])
		lane := fmt.Sprintf("%v", sig["modality_class"])
		attached, _ := sig["attached"].(bool)
		ts, tsOK := parseChTS(fmt.Sprintf("%v", sig["ts"]))
		if tsOK {
			if laneMin[lane].IsZero() || ts.Before(laneMin[lane]) {
				laneMin[lane] = ts
			}
			if ts.After(laneMax[lane]) {
				laneMax[lane] = ts
			}
			laneObs[lane] = append(laneObs[lane], ts)
		}
		laneTotal[lane]++
		// Semantic recovery evidence (§17): status lanes signal recovery as
		// state=up/established events, not *_clear kinds. Buffer them — only
		// an up observed AFTER the first anomaly is recovery (a healthy
		// assertion from before the fault proves nothing about it).
		if rcaIsRecoveryStateSignal(sig) {
			if tsOK {
				stateUps = append(stateUps, rcaStateUp{sig: sig, ts: ts})
			}
			continue
		}
		if strings.HasSuffix(kind, "_clear") {
			// observed recovery evidence; the RecoveryReconciler reads clear_ts/ts
			clears = append(clears, sig)
			continue
		}
		if o := fmt.Sprintf("%v", sig["observer_id"]); o != "" && o != "<nil>" {
			observers[o] = true
		}
		if !attached {
			continue
		}
		anomalous = append(anomalous, sig)
		laneAnomalous[lane]++
		if o := fmt.Sprintf("%v", sig["observer_id"]); o != "" && o != "<nil>" {
			anomObservers[o] = true
		}
		if tsOK {
			if firstObs.IsZero() || ts.Before(firstObs) {
				firstObs = ts
			}
			if ts.After(lastObs) {
				lastObs = ts
			}
		}
		sev := strings.ToLower(fmt.Sprintf("%v", sig["severity"]))
		sevCounts[sev]++
		if sevRank[sev] > peakSevRank {
			peakSevRank, peakSev = sevRank[sev], sev
			peakSevKind = kind
		}
		entityType := fmt.Sprintf("%v", sig["entity_type"])
		probeScope := fmt.Sprintf("%v", sig["probe_scope"])
		switch {
		case rcaIsRealUserImpactKind(kind, entityType):
			impactAnomalies++
			impactRealUser++
		case rcaIsRealUserIndicatorKind(kind):
			impactAnomalies++
			impactRealUserIndicator++
		case rcaIsSyntheticImpactKind(kind, probeScope):
			impactAnomalies++
			impactSynthetic++
		}
		if rcaCloudChangeKinds[kind] {
			changes = append(changes, decodeCloudChange(sig, true))
		}
	}
	// unattached cloud changes in the window still matter (§8) — temporal context
	for _, sig := range in.Signals {
		kind := fmt.Sprintf("%v", sig["kind"])
		attached, _ := sig["attached"].(bool)
		if rcaCloudChangeKinds[kind] && !attached && !strings.HasSuffix(kind, "_clear") {
			changes = append(changes, decodeCloudChange(sig, false))
		}
	}
	// real-user impact is observable only where real-traffic telemetry exists:
	// the passive-flow lane, or LB/app-edge kinds (they ride device_telemetry).
	realUserLanesPresent = laneTotal["passive_flow"] > 0 || impactRealUser > 0
	for _, sig := range in.Signals {
		switch fmt.Sprintf("%v", sig["kind"]) {
		case "lb_5xx", "lb_target_unhealthy", "app_error_rate_high", "app_latency_high", "lb_4xx_high":
			realUserLanesPresent = true
		}
	}

	// ---- evidence coverage (Phase C/D) --------------------------------------------
	// Built here — BEFORE the impact axes — so the impact renderers are DRIVEN by the
	// same per-lane CoverageAssessment (impact_eligible) instead of an ad-hoc min/max
	// slack test. Both impact axes and both renderers read one assessment, so they can
	// never disagree (kills the false "none detected" on insufficient coverage).
	tenant := fmt.Sprintf("%v", meta["tenant_id"])
	coverage := buildEvidenceCoverage(tenant, laneTotal, laneAnomalous, laneObs, laneMin, laneMax, hb, firstObs, lastObs, in.Now)

	// ---- states -------------------------------------------------------------------
	// Recovery is an ASSESSMENT, not a synonym for "the window closed": an
	// object that quiesced because its signals aged out has merely stopped
	// being observed (§17 — "no additional data" is not "successful recovery").
	// Merge buffered semantic up-events: only those after the first anomaly
	// are recovery evidence for THIS fault.
	for _, su := range stateUps {
		if !firstObs.IsZero() && su.ts.After(firstObs) {
			clears = append(clears, su.sig)
		}
	}
	// RecoveryReconciler (P1.1): component recovery vs service recovery are
	// reconciled per scope; incident-level recovery exists only when the last
	// recovery evidence is at/after the last qualifying anomaly in every
	// participating scope. A tunnel-up while probes keep failing is component
	// recovery + residual degradation, never incident recovery.
	ra := reconcileRecovery(anomalous, clears)
	recovered := ra.At // zero unless the incident-level gate passed
	recoveryState, recoveryBasis := "not_observed", "No recovery evidence was captured."
	switch {
	case ra.Confirmed:
		recoveryState = "explicitly_confirmed"
		recoveryBasis = fmt.Sprintf("%s; last recovery evidence observed %s, at/after the final qualifying anomaly in every participating scope.",
			countNoun(len(clears), "recovery observation"), fmtUTC(ra.At))
	case ra.Service.State == "failed_validation":
		recoveryState = "failed_validation"
		recoveryBasis = ra.Service.Basis
	case ra.Component.State == "explicitly_confirmed":
		recoveryState = "component_only"
		recoveryBasis = ra.Component.Basis + " End-to-end service recovery is not confirmed."
	case ra.Component.State == "failed_validation":
		recoveryState = "failed_validation"
		recoveryBasis = ra.Component.Basis
	}
	incident := "active"
	mergedLifecycle, isMerged := rcaMergeIncidentState(state)
	switch {
	case isMerged:
		// A merged/superseded source is a TOMBSTONE, never "closed": lifecycle,
		// monitoring, ticketing and restoration transfer to the surviving
		// incident. Recovery is NOT overridden to "not applicable" — the
		// reconciled service-recovery state at merge time is a fact the survivor
		// inherits and the report must state (P1 merged-incident lifecycle).
		incident = mergedLifecycle
	case state == "closed" && ra.Confirmed:
		incident = "recovered"
	case state == "closed":
		incident = "no_longer_observed"
		// Ending only by time is an INFERENCE, stated as one — never "recovered".
		// Partial (component-only / failed-validation) recovery keeps its more
		// specific basis; pure silence is stated as inference.
		if recoveryState == "not_observed" {
			recoveryState = "inferred"
			recoveryBasis = "Inferred from quiescence: the anomalous observations stopped and the window closed; no explicit recovery evidence was captured."
		}
	case ra.Confirmed:
		incident = "recovering"
		// Recovery evidence exists but anomalies continued after it, or a scope's
		// validation failed → the incident is STILL FAILING; it stays active.
	}

	analysis := "observed"
	label := ""
	contradictedTop := false
	if len(hb.Ranking.Hypotheses) > 0 {
		h0 := hb.Ranking.Hypotheses[0]
		label = strings.ToLower(h0.ConfidenceLabel)
		contradictedTop = h0.Contradicted
	}
	switch {
	case verdict == "confirmed":
		analysis = "confirmed"
	case label == "likely":
		analysis = "probable"
	case verdict == "suspected":
		analysis = "suspected"
	}
	if contradictedTop && analysis != "confirmed" {
		// leading cause ruled out and nothing confirmed → the analysis is honest
		// about being inconclusive, not "suspected" of a dead hypothesis.
		alive := false
		for _, h := range hb.Ranking.Hypotheses {
			if !h.Contradicted && (h.Confidence > 0 || len(h.Satisfied) > 0) {
				alive = true
				break
			}
		}
		if !alive {
			analysis = "inconclusive"
		}
	}

	// Coverage sufficiency (P1.6, Phase D): "no anomaly detected" is a claim about
	// the whole window — valid ONLY when the lane's CoverageAssessment is
	// impact-eligible (complete coverage across the incident, no scope/health veto).
	// This replaces the old min/max slack test with the SAME per-lane assessment
	// every renderer reads, so the axes and the renderers can never disagree.
	// §5 axes. A failed configured check IS the synthetic-transaction impact —
	// a fact, not a hypothesis. Real-user impact needs real-traffic evidence,
	// and a flow-volume delta is an INDICATOR, never confirmation (P1.5).
	impactSyn := "not_observable"
	switch {
	case impactSynthetic > 0:
		impactSyn = "confirmed"
	case laneTotal["active_probe"] > 0 && laneAnomalous["active_probe"] == 0 &&
		coverageImpactEligible(coverage, "active_probe"):
		impactSyn = "none_detected"
	}
	impactRU := "not_observable"
	switch {
	case impactRealUser > 0 && analysis == "confirmed":
		impactRU = "confirmed"
	case impactRealUser > 0:
		impactRU = "detected"
	case impactRealUserIndicator > 0 || laneAnomalous["passive_flow"] > 0:
		// P1.5: ANY anomalous real-traffic observation is an INDICATOR — the
		// classification is lane-based, never kind-name-based, so provider flow
		// kinds (cloud_flow_log, …) can never fall through to a no-impact claim.
		// One uncorroborated traffic class from one observer NEVER grounds
		// "none detected": the lane that raised the case cannot also clear it.
		impactRU = "indicator_detected"
	case realUserLanesPresent && coverageImpactEligible(coverage, "passive_flow"):
		// A definitive real-user "none detected" needs impact-eligible flow coverage
		// (complete). A partial lane (P-027379: 78.8% + 2m13s trailing gap) is NOT
		// eligible → stays not_observable, killing the false "none detected".
		impactRU = "none_detected"
	}
	// Overall impact summarizes the axes; it never claims more than the
	// strongest axis. "Missing evidence is not evidence of no impact."
	// A "none detected" CLAIM additionally requires sufficient multi-class
	// coverage (P1.6): both the synthetic and the real-traffic axis observed
	// the window and neither carried an anomaly. A single covering class is
	// partial coverage — it can honestly report its own axis, never the claim.
	var impact string
	switch {
	case impactRU == "confirmed":
		impact = "confirmed"
	case impactSyn == "confirmed" || impactRU == "detected":
		impact = "detected"
	case impactRU == "indicator_detected":
		impact = "indicator_detected"
	case impactSyn == "none_detected" && impactRU == "none_detected":
		impact = "none_detected"
	case impactSyn == "none_detected" || impactRU == "none_detected":
		impact = "unknown" // partial coverage — cannot ground a no-impact claim
	default:
		impact = "not_observable"
	}

	// §11/§24: a case whose every anomalous signal declares a non-production
	// purpose is a VALIDATION scenario — watermarked, production severity N/A.
	validation := len(anomalous) > 0
	for _, sig := range anomalous {
		if !isValidationSignal(sig) {
			validation = false
			break
		}
	}

	// §19: severity carries its basis — the signal kind at the peak plus the
	// severity mix, so a single loud probe is visibly a single loud probe.
	sevBasis := "no anomalous evidence attached"
	if peakSevKind != "" {
		mix := []string{}
		for _, lv := range []string{"crit", "high", "warn"} {
			if sevCounts[lv] > 0 {
				mix = append(mix, fmt.Sprintf("%d %s", sevCounts[lv], lv))
			}
		}
		sevBasis = fmt.Sprintf("peak of the attached evidence, carried by %s (%s of %d anomalous observations)",
			strings.ReplaceAll(peakSevKind, "_", " "), strings.Join(mix, " / "), len(anomalous))
	}
	if validation {
		sevBasis += "; validation scenario — production severity not applicable"
	}

	// Incident severity (P1.11): NEVER the bare maximum of attached signal
	// severities. Derived from corroboration (evidence classes + observers),
	// analysis maturity and impact; capped with explicit reason codes when a
	// single uncorroborated signal carries the peak. Evidence-peak severity
	// stays reported separately as a fact about the signals.
	sevIncident := peakSev
	var sevCodes []string
	anomLanes := 0
	for _, n := range laneAnomalous {
		if n > 0 {
			anomLanes++
		}
	}
	switch {
	case validation:
		sevIncident = "not_applicable"
		sevCodes = append(sevCodes, "validation_scenario_production_severity_suppressed")
	case len(anomalous) == 0:
		sevIncident = "unknown"
		sevCodes = append(sevCodes, "no_anomalous_evidence")
	default:
		sevCodes = append(sevCodes, "peak_signal_severity_"+peakSev)
		corroborated := anomLanes >= 2 && len(anomObservers) >= 2
		// only CONFIRMED real-user impact exempts from the single-stream cap; a
		// synthetic failure is one uncorroborated stream like any other
		impactBacked := impactRU == "confirmed"
		switch {
		case corroborated || analysis == "confirmed":
			sevCodes = append(sevCodes, "corroborated_evidence")
		case sevRank[peakSev] >= sevRank["crit"] && !impactBacked:
			// one uncorroborated signal stream cannot declare a production CRIT
			sevIncident = "high"
			sevCodes = append(sevCodes, "capped_single_stream_uncorroborated")
			if anomLanes <= 1 {
				sevCodes = append(sevCodes, "single_evidence_class")
			}
			if len(anomObservers) <= 1 {
				sevCodes = append(sevCodes, "single_observer")
			}
			if anomLanes <= 1 && len(anomObservers) <= 1 && analysis != "probable" {
				sevIncident = "warn"
				sevCodes = append(sevCodes, "capped_pending_validation")
			}
		case anomLanes <= 1 && len(anomObservers) <= 1 && sevRank[peakSev] >= sevRank["high"] &&
			analysis != "probable" && !impactBacked:
			sevIncident = "warn"
			sevCodes = append(sevCodes, "single_evidence_class", "single_observer", "capped_pending_validation")
		}
	}
	// Incident-severity basis (P1): policy inputs, never "peak of the evidence".
	sevIncidentBasis := rcaSeverityIncidentBasis(sevIncident, validation, impactSyn, impactRU, analysis, len(anomObservers), anomLanes, ra)

	// ---- scope + issue context (the single resolver) ----------------------------
	// The IssueContextResolver consolidates what used to be distributed across
	// the action-family table, classifyServiceScope and rcaHypothesisType: one
	// resolved context every downstream consumer reads.
	scope := buildRcaScope(meta, anomalous, hb)
	kindCounts := map[string]int{}
	kindObservers := map[string]map[string]bool{}
	for _, sig := range anomalous {
		k := fmt.Sprintf("%v", sig["kind"])
		kindCounts[k]++
		if kindObservers[k] == nil {
			kindObservers[k] = map[string]bool{}
		}
		if o := fmt.Sprintf("%v", sig["observer_id"]); o != "" && o != "<nil>" {
			kindObservers[k][o] = true
		}
	}
	ictx := resolveIssueContext(rcaIssueContextInput{
		Analysis: analysis, RecoveryState: recoveryState, ImpactRU: impactRU,
		Validation: validation, Hyp: hb, Targets: scope.Targets,
		LaneAnomalous: laneAnomalous, KindCounts: kindCounts,
		Anomalous: anomalous, Changes: changes,
	})
	scope.ServiceClassification = ictx.ServiceClassification

	// ── merged-incident lifecycle (P1) ──────────────────────────────────────
	// A merged/superseded source is a tombstone that transfers every operational
	// side effect to the surviving incident. The merge record is derived here so
	// downstream wording (decision, ownership, actions, NOC) reads one resolved
	// authority instead of re-deriving fragments.
	var merge *rcaIncidentMerge
	if isMerged {
		evidenceIDs := make([]string, 0, len(anomalous))
		for _, sig := range anomalous {
			if sid := fmt.Sprintf("%v", sig["signal_id"]); sid != "" && sid != "<nil>" {
				evidenceIDs = append(evidenceIDs, sid)
			}
		}
		merge = buildIncidentMerge(in.ID, asString(meta["merged_into"]), in.SurvivingIncidentID,
			ra.Service.State, scope, evidenceIDs)
		if mv := asString(meta["merged_at"]); mv != "" {
			merge.MergedAt = mv
		}
		if mv := asString(meta["merge_reason"]); mv != "" {
			merge.MergeReason = mv
		}
	}

	// ── dimensional analysis states ──
	symptom := "observed"
	if len(anomalous) > 0 {
		symptom = "confirmed" // the anomaly itself is a fact once evidence exists
	}
	topIsSymptom := ictx.topIsSymptom
	faultDomain := "not_localized"
	switch {
	case analysis == "confirmed" && !topIsSymptom:
		faultDomain = "confirmed"
	case analysis == "probable" && !topIsSymptom:
		faultDomain = "probable"
	case analysis == "suspected" && !topIsSymptom:
		faultDomain = "suspected"
	}
	// P1.3: a confirmed fault CONDITION or DOMAIN never confirms the failure
	// mechanism — "tunnel down" is confirmed; WHY it went down (auth, rekey,
	// peer outage, underlay…) requires its own causal evidence, which the
	// engine does not yet collect. Mechanism therefore caps at investigation.
	mechanism := "unknown"
	switch {
	case analysis == "confirmed" && !topIsSymptom:
		mechanism = "under_investigation"
	case analysis == "suspected" || analysis == "probable":
		mechanism = "under_investigation"
	}
	rootState := "not_identified"

	// Ticket EXECUTION state — what actually happened (the persisted link).
	ticketState := "not_opened"
	if in.Ticket != nil {
		switch fmt.Sprintf("%v", in.Ticket["state"]) {
		case "open", "updated", "pending":
			ticketState = "opened"
		case "resolved":
			ticketState = "resolved"
		case "failed":
			ticketState = "failed"
		default:
			ticketState = "not_opened"
		}
	}
	// Ticket state after a merge (P1): responsibility transfers to the surviving
	// incident. The source report never shows an ambiguous "Not opened" — the
	// meaning is "ticket responsibility transferred", an explicit execution state.
	if isMerged && ticketState != "opened" && ticketState != "resolved" {
		ticketState = "transferred_to_survivor"
	}
	// Ticket RECOMMENDATION (P1.12) — the same pure policy decision the sweeper
	// uses, evaluated on this report's facts, so recommendation and execution
	// are reconciled ON the document instead of contradicting each other.
	probeOnly := len(anomalous) > 0
	for _, sig := range anomalous {
		if fmt.Sprintf("%v", sig["modality_class"]) != "active_probe" {
			probeOnly = false
			break
		}
	}
	wStart, _ := parseChTS(fmt.Sprintf("%v", meta["window_start"]))
	wEnd, _ := parseChTS(fmt.Sprintf("%v", meta["window_end"]))
	// The policy consumes the RECONCILED incident severity (P1.11) — a capped
	// single-stream anomaly must not open tickets as if it were CRIT.
	ticketRec := evalTicketDecision(corrTicketFacts{
		Verdict: verdict, Validation: validation, ProbeOnly: probeOnly,
		PeakSeverity: sevIncident, HasAffectedEntity: len(anomalous) > 0,
		WindowStart: wStart, WindowEnd: wEnd,
	}, in.Policy, nil, in.Now)
	ticketRecommended, ticketRecReason := "hold", ticketRec.Reason
	if ticketRec.Create {
		ticketRecommended = "open"
	}
	ticketExecNote := ""
	switch {
	case ticketState == "not_opened" && ticketRecommended == "hold" && len(anomalous) > 0:
		ticketState = "held" // policy hold, with the policy's own reason below
	case ticketState == "not_opened" && ticketRecommended == "open":
		ticketExecNote = "Policy recommends opening a ticket, but no ticket exists yet — creation is pending execution or the ticketing integration is not connected for this tenant."
	}

	// ---- confidence (engine-derived, basis stated) -------------------------------
	confidence, basis := "Low", "single evidence class; no independent corroboration"
	if len(hb.Ranking.Hypotheses) > 0 {
		v := hb.Ranking.Hypotheses[0].Verdict
		nMod, nObs := len(v.ModalityCoverage), len(v.ObserverCoverage)
		switch {
		case analysis == "confirmed":
			confidence = "High"
			basis = fmt.Sprintf("independent confirmation across %d evidence classes and %d observers", nMod, nObs)
		case nMod >= 2 && nObs >= 2:
			confidence = "Medium"
			basis = fmt.Sprintf("%d evidence classes from %d observers align, but no fully independent confirming pair", nMod, nObs)
		default:
			basis = fmt.Sprintf("evidence rests on %s from %s", countNoun(maxInt(nMod, 1), "evidence class"), strings.ToLower(countNoun(maxInt(nObs, 1), "observer")))
		}
	}

	// ---- times -------------------------------------------------------------------
	times := rcaReportTimes{
		WindowStart:   fmt.Sprintf("%v", meta["window_start"]),
		WindowEnd:     fmt.Sprintf("%v", meta["window_end"]),
		DurationBasis: "unknown",
	}
	if !firstObs.IsZero() {
		times.FirstObserved = fmtUTC(firstObs)
	}
	if !lastObs.IsZero() {
		times.LastAnomalous = fmtUTC(lastObs)
	}
	if !recovered.IsZero() && (incident == "recovered" || incident == "recovering" || incident == "closed") {
		times.RecoveredAt = fmtUTC(recovered)
		times.RecoveredCaptured = true
	}
	// Component recovery time is reported SEPARATELY (P1.1) — it bounds the
	// component outage, never the incident.
	times.ComponentRecoveredAt = ra.Component.At
	switch {
	case times.RecoveredCaptured && !firstObs.IsZero():
		times.DurationMS = recovered.Sub(firstObs).Milliseconds()
		times.DurationBasis = "to_recovery"
	case incident == "active" && !firstObs.IsZero():
		times.DurationMS = in.Now.Sub(firstObs).Milliseconds()
		times.DurationBasis = "elapsed_still_active"
	case !firstObs.IsZero() && !lastObs.IsZero():
		times.DurationMS = lastObs.Sub(firstObs).Milliseconds()
		times.DurationBasis = "to_last_observation"
	}
	if !firstObs.IsZero() && firstObs.Equal(lastObs) && !times.RecoveredCaptured &&
		incident != "active" && incident != "recovering" {
		// §9: a closed window holding ONE failed observation bounds nothing —
		// never fabricate a zero duration. (An open incident keeps its honest
		// elapsed-since-first-observation figure.)
		times.DurationBasis = "single_observation"
		times.DurationMS = 0
	}
	monitorWindow := time.Duration(in.Policy.SuppressFlappingSeconds) * time.Second
	if monitorWindow <= 0 {
		monitorWindow = 30 * time.Minute
	}
	// Monitoring state is evaluated against report-generation time (§17): a
	// window that ended before this report was generated is COMPLETED, never
	// described as still running.
	monitoring := "not_started"
	if times.RecoveredCaptured {
		until := recovered.Add(monitorWindow)
		times.MonitoringUntil = fmtUTC(until)
		if in.Now.Before(until) {
			monitoring = "active"
		} else {
			monitoring = "completed_no_recurrence"
		}
	}

	// ---- signal summary ------------------------------------------------------------
	sigSummary := buildSignalSummary(in.Signals, anomalous, clears, observers, peakSev, hb)

	// ---- evidence accounting (Phase B) ---------------------------------------------
	// Derive the canonical evidence counts ONCE from the stored records (window
	// slice + verdict blob + observer registry). Its invariant error feeds the Phase
	// E quality gate; the Phase D renderers consume `accountingView` (derived below),
	// the coverage lanes were built earlier (before the impact axes).
	accounting, accountingErr := buildEvidenceAccounting(accountingInput{
		TenantID:      tenant,
		CorrelationID: in.ID,
		Signals:       in.Signals,
		Hyp:           hb,
		Registry:      rcaObserverRegistry,
	})
	// The single evidence-accounting presentation block (Phase D): customer view +
	// operator lineage ladder, derived — never recomputed by a renderer.
	accountingView := buildAccountingView(accounting, coverage)

	// ---- cloud change correlation -----------------------------------------------------
	for i := range changes {
		classifyCloudChange(&changes[i], firstObs, scope)
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].At < changes[j].At })

	// ---- hypotheses --------------------------------------------------------------------
	hyps := buildHypothesesView(hb, kindCounts, kindObservers)

	// ---- fault localization vs root cause (P1.3/P1.4, audit D2) -------------------
	// The seam/locus the evidence converges on is the FAULT LOCALIZATION DOMAIN.
	// It narrows where the fault lives; it never names the cause. Root cause
	// stays unidentified until a causal mechanism AND causal object are
	// established — which a signature verdict alone can never do.
	loc := rcaFaultLocalization{Statement: "The fault has not been localized to a specific domain or object."}
	if analysis == "confirmed" {
		locus := groundedLocus(in.Edges)
		// §16: a transport-family fault (underlay/tunnel/ipsec) localizes to the
		// SEAM — the tunnel/VPN resource — never to the application endpoint the
		// probes happened to target. The seam is declared grounding context, so
		// naming it is evidence, not inference.
		if len(hb.Ranking.Hypotheses) > 0 && len(hb.GroundingContext.Seams) > 0 {
			topID := hb.Ranking.Hypotheses[0].ID
			if strings.Contains(topID, "underlay") || strings.Contains(topID, "tunnel") || strings.Contains(topID, "ipsec") {
				// Pick the seam the anomalous evidence itself names (attrs.seam_id
				// on the ipsec signals) — a merged window can ground several
				// seams, and only one of them died.
				evidenceSeams := map[string]int{}
				for _, sig := range anomalous {
					if a, ok := sig["attrs"].(string); ok && a != "" {
						var at struct {
							SeamID string `json:"seam_id"`
						}
						if json.Unmarshal([]byte(a), &at) == nil && at.SeamID != "" {
							evidenceSeams[at.SeamID]++
						}
					}
				}
				// A merged window can carry faults on several seams — the one
				// with the MOST anomalous evidence is the case's subject.
				sm, best := hb.GroundingContext.Seams[0], 0
				for _, cand := range hb.GroundingContext.Seams {
					if n := evidenceSeams[cand.SeamID]; n > best {
						sm, best = cand, n
					}
				}
				locus = sm.SeamID
				loc = rcaFaultLocalization{
					Localized:  true,
					Statement:  fmt.Sprintf("Fault localized to the %s seam %s by independent evidence. The seam is a localization domain — it narrows the fault; it is not the root-cause object.", sm.SeamType, sm.SeamID),
					Object:     sm.SeamID,
					ObjectType: strings.ToLower(orDefault(sm.SeamType, "seam")) + " seam (localization domain)",
					// P1: render the ACTUAL matched case evidence (kinds + signal /
					// observer counts), never the humanized signature CLAUSE — a
					// Boolean rule expression ("Packet loss or … or Cloud health") is
					// the matching rule, not evidence.
					Evidence: supportingCaseEvidence(hb.Ranking.Hypotheses[0].Satisfied, kindCounts, kindObservers),
				}
			}
		}
		if !loc.Localized && locus != "" {
			loc = rcaFaultLocalization{
				Localized:  true,
				Statement:  fmt.Sprintf("Fault localized to %s by independent evidence.", aiEntityLabel(locus)),
				Object:     locus,
				ObjectType: "grounded entity (localization boundary)",
			}
			if len(hb.Ranking.Hypotheses) > 0 {
				loc.Evidence = supportingCaseEvidence(hb.Ranking.Hypotheses[0].Satisfied, kindCounts, kindObservers)
			}
		}
		if !loc.Localized {
			loc.Statement = "The fault condition is confirmed, but the evidence does not converge on a single fault object."
		}
	}
	root := rcaRootCause{Identified: false, Statement: "Root cause has not been identified."}
	// #113 point 4 cause honesty: pair every unidentified root cause with the
	// best live hypothesis ("possibly because of X") and its evidence state —
	// what is in hand, what is still missing (hypothesis gaps + the object's own
	// evidence_missing shortfalls). A bare "not identified" is a dead end for the
	// reader; an honest hypothesis with named gaps is actionable. When NO
	// hypothesis has evidence, the absence itself is stated — never a guess.
	if top := firstLiveCauseHypothesis(hyps); top != nil {
		root.PossibleCause = orDefault(top.Problem, top.Title)
		root.EvidenceKnown = firstN(top.Supporting, 4)
		root.EvidenceMissing = firstN(top.Missing, 4)
		for _, m := range decodeEvidenceMissing(meta) {
			if len(root.EvidenceMissing) >= 6 {
				break
			}
			root.EvidenceMissing = appendUnique(root.EvidenceMissing, m)
		}
		root.Statement = fmt.Sprintf(
			"Root cause has not been identified — possibly because of %s (unconfirmed best hypothesis).",
			strings.TrimRight(root.PossibleCause, "."))
	}
	switch {
	case analysis == "confirmed" && loc.Localized:
		root.Statement = fmt.Sprintf("The fault condition is confirmed and localized to %s. The underlying root cause — the causal mechanism and originating object — remains under investigation.", loc.Object)
	case analysis == "confirmed":
		root.Statement = "The fault condition is confirmed. The underlying root cause remains under investigation."
	}

	// ---- ownership ---------------------------------------------------------------------------
	// Root-cause state may reach "confirmed" ONLY via an identified mechanism +
	// causal object (root.Identified). Fault-domain confirmation, seam
	// grounding and verdict tier all cap at under_investigation (P1.3).
	switch {
	case root.Identified && root.Mechanism != "" && root.Object != "":
		rootState = "confirmed"
	case analysis == "confirmed" || analysis == "suspected" || analysis == "probable":
		rootState = "under_investigation"
	}
	ownership := buildOwnership(analysis, loc.Localized, ictx.ServiceClassification, hb, sigSummary, kindCounts)

	// ---- decision (policy-driven) ---------------------------------------------------------------
	decision := buildDecision(analysis, incident, recoveryState, impact, monitoring, fmtUTC(in.Now), in.Policy, in.PolicyConfigured, monitorWindow)
	decision.TicketRecommended = ticketRecommended
	decision.TicketRecommendReason = ticketRecReason
	if isMerged {
		// A merged source neither monitors nor tickets nor escalates on its own —
		// every side effect is the surviving incident's (P1 merge ownership). The
		// decision, ticket recommendation and escalation are all TRANSFERRED, never
		// left as ambiguous local states.
		applyMergeToDecision(&decision, merge)
	} else {
		if ticketExecNote == "" && decision.EscalationState == "triggered" &&
			(ticketState == "not_opened" || ticketState == "held") {
			// Escalation and ticketing reached different states — say why, never
			// leave "Ticket: not opened / Escalation: TRIGGERED" unexplained.
			ticketExecNote = "Escalation conditions are met while the ticket is " + strings.ReplaceAll(ticketState, "_", " ") +
				": " + orDefault(ticketRecReason, "the ticket decision is governed by the ticketing policy shown above") + "."
		}
		decision.TicketExecutionNote = ticketExecNote
	}

	// ---- incident phases (P1.2) ----------------------------------------------------------------
	phases := buildIncidentPhases(firstObs, ra, times.MonitoringUntil)

	// ---- wording ----------------------------------------------------------------------------------
	title, subtitle, problemNoun := buildRcaTitle(topHyp, analysis, incident, scope, laneAnomalous, changes)
	whySusp, whyNot, required := buildWhyWording(analysis, hb, sigSummary, laneAnomalous)

	mgmt, mgmtTrimmed := buildManagementSummary(problemNoun, scope, times, incident, analysis, impact, impactSyn, impactRU, monitoring, decision, sigSummary, monitorWindow, ra, merge)

	// ---- actions (contextual planner, P1.13) --------------------------------------------------------
	actions := planActions(rcaActionInput{
		Analysis: analysis, Incident: incident, Hyp: hb, Signals: sigSummary,
		Decision: decision, Ownership: ownership, Ctx: ictx,
		LaneAnomalous: laneAnomalous, KindCounts: kindCounts,
		Residual: ra.ResidualAfterComponent, Validation: validation,
		Merge: merge,
	})

	// ---- NOC quick-read -------------------------------------------------------------------------------
	noc := buildNocQuickRead(incident, recoveryState, analysis, impact, impactSyn, impactRU, ticketState, monitoring, times, scope, sigSummary, coverage, ownership, actions, ra, merge)

	rep := rcaReport{
		ReportID:      "rr-" + strings.ReplaceAll(in.ID, "-", "")[:12] + fmt.Sprintf("-v%d", version),
		CorrelationID: in.ID,
		DisplayID:     problemDisplayID(in.ID),
		Version:       version,
		ReportType:    reportTypeFor(rootState, analysis, incident),
		Title:         title,
		Subtitle:      subtitle,
		Validation:    validation,
		GeneratedAt:   fmtUTC(in.Now),
		Merge:         merge,
		States: rcaReportStates{
			Incident: incident, Lifecycle: incident, Recovery: recoveryState, RecoveryBasis: recoveryBasis,
			RecoveryComponent: ra.Component, RecoveryService: ra.Service,
			Analysis: analysis,
			Symptom:  symptom, FaultDomain: faultDomain, Mechanism: mechanism, RootCauseState: rootState,
			Impact:          impact,
			ImpactSynthetic: impactSyn, ImpactRealUser: impactRU,
			Ticket:   ticketState,
			Severity: peakSev, SeverityIncident: sevIncident, SeverityReasonCodes: sevCodes,
			SeverityBasis: sevBasis, SeverityIncidentBasis: sevIncidentBasis, Monitoring: monitoring,
			Confidence: confidence, ConfidenceBasis: basis,
		},
		AtAGlance:         buildAtAGlance(loc, scope, hyps, ownership, root, analysis),
		Times:             times,
		Scope:             scope,
		IssueContext:      ictx,
		Summary:           rcaReportSummaries{Management: mgmt, Noc: noc, WhySuspected: whySusp, WhyNotConfirmed: whyNot, RequiredConfirm: required},
		Signals:           sigSummary,
		Evidence:          buildEvidenceSummary(anomalous, laneAnomalous, accountingView, analysis, sigSummary, firstObs, lastObs, in.Now),
		Accounting:        accountingView,
		Coverage:          coverage,
		CloudChanges:      changes,
		Hypotheses:        hyps,
		SingleHypothesis:  len(hyps) <= 1,
		Cascade:           cascadeStages(hb),
		Phases:            phases,
		FaultLocalization: loc,
		RootCause:         root,
		Ownership:         ownership,
		Decision:          decision,
		Actions:           actions,
		Ticket:            in.Ticket,
		Path:              in.Path,
		mgmtTrimmed:       mgmtTrimmed,
		accounting:        accounting,
		accountingErr:     accountingErr,
	}
	// Path-causality RCA P2: the on-path device attribution the engine wrote to the
	// attribution column (design §2.4). Pure passthrough decode — nil when no
	// on-path cause was attributed, so the section is omitted, never invented.
	rep.PathAttribution = decodePathAttribution(meta)

	// ReportQualityGate: the StateConsistencyValidator runs on the FINISHED
	// document. Errors downgrade the report type — a contradictory document is
	// never emitted as a final assessment (P1 gate).
	applyReportQualityGate(&rep, in.Now)
	return rep
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// reportTypeFor — the document may only call itself an RCA when the ROOT CAUSE
// actually concluded (mechanism + causal object, P1.3). A confirmed fault
// condition alone yields a fault-confirmed incident analysis, never an "RCA".
func reportTypeFor(rootState, analysis, incident string) string {
	if incident == "merged" || incident == "superseded" {
		// A merged source report is an incident analysis handed to the survivor —
		// it names the merge in its type so the state is unmissable (P1 header).
		switch analysis {
		case "confirmed":
			return "Incident Analysis — Merged / Fault Confirmed"
		default:
			return "Incident Analysis — Merged"
		}
	}
	switch {
	case rootState == "confirmed":
		return "Root Cause Analysis"
	case analysis == "confirmed":
		return "Incident Analysis — Fault Confirmed"
	case analysis == "probable":
		return "Preliminary Incident Analysis"
	case analysis == "inconclusive":
		return "Incident Analysis — Cause Inconclusive"
	default:
		return "Incident Assessment"
	}
}

// groundedLocus — the entity the grounded topo edges converge on (same rule the
// rca-path-view uses; duplicated intentionally small to stay pure/local).
func groundedLocus(edges []map[string]any) string {
	shareCount := map[string]int{}
	for _, e := range edges {
		if fmt.Sprintf("%v", e["grounding_kind"]) == "topo" {
			if ref := fmt.Sprintf("%v", e["grounding_ref"]); strings.HasPrefix(ref, "shared:") {
				shareCount[strings.TrimPrefix(ref, "shared:")]++
			}
		}
	}
	locus, best := "", 0
	for k, n := range shareCount {
		if n > best || (n == best && (locus == "" || k < locus)) {
			best, locus = n, k
		}
	}
	return locus
}

func decodeCloudChange(sig map[string]any, attached bool) rcaCloudChange {
	attrs := map[string]any{}
	if a, ok := sig["attrs"].(string); ok && a != "" {
		_ = json.Unmarshal([]byte(a), &attrs)
	}
	str := func(k string) string {
		if v, ok := attrs[k]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	provider := str("provider")
	if provider == "" {
		src := str("event_source")
		switch {
		case strings.Contains(src, "amazonaws"), strings.Contains(src, "aws"):
			provider = "AWS"
		case strings.Contains(src, "azure"), strings.Contains(src, "microsoft"):
			provider = "Azure"
		case strings.Contains(src, "google"), strings.Contains(src, "gcp"):
			provider = "GCP"
		}
	}
	at := ""
	if t, ok := parseChTS(fmt.Sprintf("%v", sig["ts"])); ok {
		at = fmtUTC(t)
	}
	res := str("resource_id")
	if res == "" {
		res = fmt.Sprintf("%v", sig["entity_id"])
	}
	return rcaCloudChange{
		Kind: fmt.Sprintf("%v", sig["kind"]), Provider: provider,
		EventSource: str("event_source"), RequestID: str("request_id"),
		Account: str("account"), Region: str("region"),
		Resource: res, Actor: str("actor"), At: at, Attached: attached,
	}
}

func classifyCloudChange(c *rcaCloudChange, firstObs time.Time, scope rcaReportScope) {
	if t, ok := parseChTS(strings.TrimSuffix(c.At, " UTC")); ok && !firstObs.IsZero() {
		d := int64(t.Sub(firstObs).Seconds())
		c.DeltaSeconds = &d
	}
	inScope := func(list []string, v string) bool {
		for _, s := range list {
			if v != "" && (s == v || strings.Contains(s, v) || strings.Contains(v, s)) {
				return true
			}
		}
		return false
	}
	switch {
	case inScope(scope.Services, c.Resource) || inScope(scope.Targets, c.Resource):
		c.Relationship = "same_resource"
	case c.Attached:
		c.Relationship = "same_service"
	case inScope(scope.Regions, c.Region) || inScope(scope.Accounts, c.Account):
		c.Relationship = "same_account_region"
	default:
		c.Relationship = "temporal_only"
	}
	// Honest, non-causal explanation (§8: temporal proximity never confirms).
	when := "in the incident window"
	if c.DeltaSeconds != nil {
		d := *c.DeltaSeconds
		if d <= 0 {
			when = fmt.Sprintf("%s before the first anomalous observation", fmtDur(time.Duration(-d)*time.Second))
		} else {
			when = fmt.Sprintf("%s after the first anomalous observation", fmtDur(time.Duration(d)*time.Second))
		}
	}
	switch c.Relationship {
	case "same_resource":
		c.Explanation = fmt.Sprintf("%s change occurred %s and touched a resource mapped to the affected service. The timing and resource relationship support investigation, but causation is not confirmed.", providerChangeNoun(c.Provider), when)
	case "same_service":
		c.Explanation = fmt.Sprintf("%s change occurred %s and is correlated into this case as evidence. Causation is not confirmed.", providerChangeNoun(c.Provider), when)
	case "same_account_region":
		c.Explanation = fmt.Sprintf("%s change occurred %s in the same account/region. No direct resource relationship to the affected service was demonstrated.", providerChangeNoun(c.Provider), when)
	default:
		c.Explanation = fmt.Sprintf("%s change occurred %s. Only temporal proximity relates it to this incident — no resource or service relationship was demonstrated.", providerChangeNoun(c.Provider), when)
	}
}
