# RCA Production-Hardening Pass — case P-5FE421 (owner spec, BINDING)

Owner directive 2026-07-13 (queued AFTER the Service View program, task #12).
Targeted hardening — NOT a redesign. PRESERVE the already-shipped improvements:
active-vs-recovered handling, recovery-not-observed, elapsed duration, synthetic
vs real-user impact split, triggered escalation, evidence coverage states,
measured-path rendering, hypothesis type labels, dynamic NOC/management sections.

Trace every defect from raw events → normalized signals → evidence groups →
provenance/independence → path localization → fault-domain → causal/root-cause →
impact → ownership/demarcation → severity policy → escalation/actions → report
view model → HTML/PDF layout. Implement, migrate, add regression tests, generate
a corrected P-5FE421 PDF, render EVERY page to images, inspect visually, fix
contradictions + pagination.

## P0 — Root-cause semantics (the biggest one)
Confirmed fault LOCALIZATION is being treated as confirmed ROOT CAUSE. Split
into four canonical states: FaultDomainAssessment (unknown|suspected|probable|
confirmed), FaultObjectAssessment (not_identified|suspected|probable|confirmed),
FailureMechanismAssessment (unknown|under_investigation|suspected|probable|
confirmed), RootCauseAssessment (not_identified|under_investigation|suspected|
probable|confirmed|inconclusive).
For P-5FE421 the truth is: fault_domain_state=confirmed,
fault_domain=vpn_underlay_private_path; fault_object_state=not_identified,
fault_object_id=null; failure_mechanism_state=under_investigation;
root_cause_state=not_identified, root_cause_object_id=null.
root_cause_state must NEVER be derived from: confirmed verdict, confirmed
hypothesis, confirmed fault domain, seam grounding, two evidence classes, or
high confidence. Add root_cause_limitations reason codes
(exact_failed_component_not_identified, provider_demarcation_not_proven,
gateway_local_checks_pending, remote_peer_reachability_pending).

## P0 — Report type + header
Report type by analytical maturity: "Confirmed Fault Analysis" / "Preliminary
Root Cause Analysis" — NOT final "Root Cause Analysis". Header must state:
Incident, Recovery, Fault, Fault domain, Fault object, Root cause, Confidence
(scoped: "High for fault localization"), Synthetic path impact, Real-user
impact, Business impact, Ticket, Escalation, Severity. Ban ambiguous
"Analysis: Confirmed" / "Impact: Confirmed". Every confidence value names WHAT
it applies to.

## P0 — Seam object semantics
A seam is a failure-DOMAIN boundary, not a device/interface/circuit/root-cause
object/owner. Canonical object roles: affected_target, affected_service,
affected_path, fault_localization_domain, last_responding_object,
first_unobserved_boundary, suspected_fault_object, confirmed_fault_object,
causal_object, root_cause_object. Render "Fault localized to: VPN-underlay
domain represented by seam sm-…" with a descriptive name ("AWS us-west-2
private VPN path") — never "Root cause: sm-…", never bare opaque IDs.

## P0 — Path break-boundary semantics
The report marks a RESPONDING NVA as BREAK POINT — too definitive. Split into
last_responding_hop, first_nonresponding_hop, visibility_boundary,
failure_localization_boundary, confirmed_failed_hop(null here). Render the NVA
as "Last responding hop", then a visibility/failure boundary separator, then the
non-responding hops. No red failure badge on a responding object. Wording must
acknowledge traceroute limits (TTL filtering, tunnel opacity, firewall
suppression; missing hops ≠ forwarding failure).

## P0 — Traffic-flow coverage completeness
Flow shows Available/Normal on ~1 second of coverage in a 4m24s incident.
Implement coverage-quality assessment per evidence source: availability,
temporal_coverage_ratio, scope/source/destination/application/site match,
expected vs observed volume, freshness, collector_health, sampling_rate,
confidence_contribution, impact_observability. States: complete|substantial|
partial|minimal|stale|irrelevant|unavailable|not_configured|unknown.
temporal_coverage_ratio = overlap(evidence, incident window) / window duration.
P-5FE421 → minimal, <1%, impact_observability=insufficient. Never green
"Normal" unless coverage threshold + scope relevance + expected traffic +
healthy collection. "No anomalous flow record" ≠ "normal traffic".

## P0 — Impact model
Replace generic Impact:Confirmed with dimensions: synthetic_transaction_impact,
synthetic_path_impact, representative_segment_impact,
service_availability_impact, real_user_impact, business_impact, current_impact,
historical_impact — each with state, observability, evidence_ids,
coverage_quality, confidence, reason_codes. P-5FE421: synthetic_path=confirmed,
representative_segment=confirmed (lan-vantage-1), real_user=not_confirmed with
observability=insufficient, business=unknown. NEVER "Real-user impact: none
detected".

## P0 — Ownership + provider demarcation
No carrier ownership before demarcation proof. Stages: incident_coordinator,
current_technical_owner, suspected_domain_owner, external_provider_candidate,
confirmed_accountable_owner, root_cause_owner. DemarcationAssessment:
not_started|local_side_checks_pending|local_side_healthy|
provider_boundary_suspected|provider_boundary_confirmed|remote_side_suspected|
remote_side_confirmed|inconclusive. P-5FE421: coordinator=NOC,
technical_owner=Network/Cloud Network Engineering, carrier=candidate only,
confirmed_accountable_owner=null, demarcation=local_side_checks_pending.

## P0 — Observer / source / vantage / execution accounting
Counts contradict (4 checks, 35 executions, 4 observers, 5 independent
observers, 4 "vantages" incl. api+prober). Define separately: TestDefinition,
TestExecution, MeasurementObservation, RawEvidenceSource, LogicalVantage,
ControlPlaneSource, IndependentObserver, DerivedSignal. API/collectors are NOT
vantages. Invariants: independent_observer_count <= unique_raw_source_count and
<= unique_provenance_group_count. Management summary must not cite ambiguous
observer counts.

## P0 — Evidence deduplication
packet_loss and synthetic_icmp_loss are the same probe executions. Add
EvidenceGroup (group_id, raw_source_ids, execution_ids, measurement_family,
canonical_finding, derived_signal_ids, observer_id, vantage_id,
independence_group_id). Customer report shows the canonical finding ONCE;
derived signals only in debug view. Duplicated derivatives must not contribute
to confidence, observer count, evidence-class count, severity, or hypothesis
support.

## P0 — Hypothesis state model
Fields: hypothesis_kind (symptom|fault_condition|fault_domain|
failure_mechanism|root_cause_candidate), observation_state (not_observed|
suspected|confirmed), causal_role (possible_origin|probable_origin|
confirmed_origin|downstream_consequence|correlated_effect|unrelated|
ruled_out_as_origin), candidacy_state (active|deprioritized|ruled_out|
confirmed). Resolves the "IPsec tunnel down = Confirmed AND Ruled out"
contradiction: observed=confirmed, causal_role=downstream_consequence,
candidacy=ruled_out_as_origin, with the reason stated.

## P0 — Hypothesis content + filtering
Sections: Observed symptoms / Confirmed fault conditions / Root-cause candidates
/ Alternative explanations considered. SaaS-experience-degraded moves OUT of
causal ranking (its "no network-path fault demonstrated" text must never appear
when a network fault is confirmed). Filter/deprioritize latency-only DIA
hypotheses under complete-loss + underlay-down evidence. P-5FE421 candidates:
local gateway/next-hop failure; provider underlay impairment; remote peer/public
address failure; cloud NVA/route/security failure beyond the boundary.

## P0 — Actual case evidence, never rule expressions
"Packet loss or Response-time change or Synthetic icmp loss or Cloud health"
must never appear. Render the actual observations with timestamps/counts. Rule
syntax lives only in debug/operator views.

## P1 — Severity basis (no max-of-derived-signals shortcut)
Incident severity inputs: environment, production_scope, service_criticality/
tier, complete_outage vs degraded, duration, sites, services,
representative_vantage_count, real_user_impact, business_impact, redundancy,
failover_success, recurrence, fault_domain, operator_override. Store
severity_policy_id/version, reason codes, inputs, override + actor,
evaluated_at. Validation scenarios: "Scenario: Validation / Simulated severity:
CRIT / Production severity: Not applicable". The policy name "PDI validation
(confirmed-only)" must trigger a visible validation label.

## P1 — Policy trace (executed state, not prose)
Per decision: policy_id, version, evaluated_at, input_facts, matched/unmatched/
unknown conditions, result, action_execution_state, action_executed_at,
suppression, override. Escalation already triggered ⇒ "Further escalate if …",
never repeat the original trigger as a future action.

## P1 — State-aware next actions
Only actions whose tests participated (no DNS/TCP/TLS/HTTP inspection here).
Six actions for P-5FE421 (local gateway egress; outer-path trace to peer;
independent external vantage reachability; validate failed executions; validate
real-user impact coverage; establish provider demarcation). Each carries
action_id, owner, status, expected_output, due_at/timeout, blocking_state,
completion_evidence, next_handoff, further_escalation_condition.

## P1 — Ownership wording + NOC quick read
Ownership explanation must not say "until fault domain is identified" when the
domain is confirmed. NOC quick-read fields listed in the spec (symptom, fault
condition, fault domain, fault object, root cause, synthetic path impact,
real-user impact + observability, business impact, ticket, escalation,
coordinator, technical owner, carrier ownership, first/last observed, elapsed,
independent confirming sources, active vantages, control-plane sources, failed
executions, recovery observations, last responding object, failure boundary,
next action). Ban Analysis:Confirmed / Impact:Confirmed / "none detected".

## P1 — Management summary (≤150 words)
Model paragraph in the spec: no root-cause-confirmed claim, no carrier
ownership, no broad customer-impact claim; states active + no recovery evidence,
localization confidence, coverage limitation, and names the technical owner.

## P1 — Evidence coverage table columns
Evidence class, Availability, Coverage quality, State, Relevant observations,
Time coverage, Incident overlap, Scope relevance, Confidence contribution,
Impact contribution. Green only when coverage adequate + scope matched + fresh +
genuinely normal.

## P2 — Layout
No hypothesis row split across pages; hypothesis section contiguous; Root Cause/
Ownership never interleaved into the table; break-inside: avoid; start a new page
when space is insufficient; headers travel with rows. Section order: symptoms →
confirmed fault conditions → root-cause candidates → alternatives → fault
localization → ownership → next actions. Top-3 active candidates in the main
report; the rest in an appendix. Target 4 pages + optional appendix.

## Data model / migrations
FaultAssessment, RootCauseAssessment, EvidenceCoverageAssessment,
ObserverAccounting, PathLocalization, DemarcationAssessment,
HypothesisAssessment, SeverityAssessment (fields enumerated in the spec).
Migration rules: preserve historical rendering; never map legacy
root_cause_confirmed to the new confirmed state (recalculate, else mark
legacy-derived/unknown); immutable tenant IDs; RLS/FORCE RLS; old APIs
temporarily compatible with deprecation notes.

## Tenant scoping
Every new record/join tenant-scoped (fault domains, seams, path hops, evidence
groups, observer groups, coverage assessments, demarcation, ownership, policy
traces, PDFs, background jobs, cache + dedup keys). Negative cross-tenant tests
for each. Never trust tenant IDs from a request payload.

## Regression tests (22, enumerated in the spec)
Confirmed domain/unknown object; seam ≠ root cause; carrier not proven; carrier
confirmed; minimal flow coverage; complete coverage; observer accounting; API is
not a vantage; derived duplicates grouped; responding last hop (no break badge);
unknown hop = boundary only; confirmed condition ruled out as origin; symptom
out of causal ranking; irrelevant latency hypothesis filtered; no rule
expressions; severity basis; validation policy label; already-triggered
escalation; ownership explanation consistency; hypothesis pagination; PDF
snapshot; tenant isolation.

## Acceptance criteria + final deliverables
See the spec's two closing sections — 27 deliverables including the audit, the
before/after state table for P-5FE421, corrected PDF path, rendered page images,
visual inspection findings, remaining limitations, deferred items, commit hash.
Do not stop after analysis; verify everything actually claimed.
