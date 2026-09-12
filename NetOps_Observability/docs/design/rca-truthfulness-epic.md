# RCA Truthfulness Epic — owner mission spec (2026-07-13, BINDING)

Owner directive, received verbatim 2026-07-13. Scope: correct the incident-analysis,
evidence-independence, recovery, impact, fault-localization, root-cause, severity,
ownership, policy, ticketing, and PDF-report logic demonstrated by two generated
reports: `incident-report-P-F74D28.pdf` (IPsec tunnel down / cloud private path) and
`incident-report-P-814009.pdf` (SaaS / application experience degraded,
`portal.rca-canary.example` / `rca_canary_app`). The reports' visual presentation is
strong; the decision model overstates recovery, impact, independence, fault
localization, and root cause. **Template rewording alone is out of bounds — the whole
derivation path must be corrected**: raw source event → test execution → observations
→ normalized signals → derived findings → evidence groups → evidence independence →
symptom assessment → fault-domain localization → failure-mechanism assessment →
root-cause assessment → impact assessment → recovery assessment → severity →
ownership → policy evaluation → ticket/escalation execution → report view model →
HTML/PDF rendering. Implementation must land with migrations + tests, regenerate both
deterministic reports, and every rendered PDF page must be visually inspected before
completion is reported.

## Case A — IPsec report defects (P-F74D28)
Contradictions to eliminate: "Recovered" with recovered-at "Not captured" and 0
recovery signals; blanket "Analysis: Confirmed"/"Root cause: Confirmed" while the
mechanism (IKE auth, peer reachability, DPD, rekey/lifetime, PFS mismatch) is still
under investigation; "Customer impact: Confirmed" with traffic-flow evidence "No
data"; auto-close requiring *no* customer-impact evidence although historical impact
is already confirmed; escalation described as future although its displayed conditions
are already true; monitoring described active past its own interval; the app endpoint
IP used as root-cause object instead of the tunnel/VPN resource; a healthy path
captured ~34 min later shown without labeling it post-recovery validation.
Corrected representation: symptom = packet loss **confirmed**; fault = IPsec tunnel
down **confirmed**; fault domain = cloud private VPN path **confirmed**; failure
mechanism = **under investigation**; root cause = **not yet identified**;
synthetic/client-segment reachability impact = confirmed; real-user impact =
unknown/not observable; recovery = explicit, inferred, or unknown per evidence.

## Case B — SaaS report defects (P-814009)
Defects: one configured check + two failed observations claimed as "two independent
observers"; device-health evidence that is actually derived from the same synthetic
execution; all evidence at one timestamp; failure stages listed as "HTTP, Packet
loss" with no HTTP status/transaction detail; no measured path; CRIT severity from a
single synthetic failure; Application-team ownership by default; signature catalog
expressions shown as causality evidence; next actions asking the NOC to confirm the
already-"confirmed" hypothesis; root-cause object = the hostname.
Corrected initial interpretation: confirmed symptom = a synthetic application check
failed; synthetic transaction impact confirmed for that vantage/test; actual customer
impact unknown/not observable absent real-user/flow/app/support/SLO evidence; fault
domain unknown until failure stage + differential tests localize; failure mechanism
unknown until DNS/TCP/TLS/HTTP/content/proxy/path/LB/app evidence identifies it; root
cause not identified; affected endpoint = portal.rca-canary.example; root-cause
object = none. "SaaS/application experience degraded" is a symptom / incident
classification, NEVER a causal hypothesis.

## Phase 0 — current-implementation audit (deliver findings BEFORE implementing)
Locate + document all 26: test-definition model; test execution model; probe
step/result model; observation model; normalized signal model; derived finding model;
evidence-class assignment; evidence-independence gate; incident grouping; recovery
detection; confidence calculation; verdict/state calculation; impact calculation;
fault-domain selection; root-cause selection; object-role selection; severity
calculation; ownership recommendation; hypothesis catalog + matching; ticket policy;
escalation policy; monitoring-window evaluation; report data API/view model; HTML/PDF
rendering; tenant-scoped report queries; lab/test/validation/debug signal handling.
Specifically determine whether the implementation wrongly equates any of: multiple
signals from one execution == independent observers; different evidence labels ==
independent evidence; endpoint-health finding derived from a probe == independent
device health; black-box failure == root cause; affected hostname == causal object;
failed synthetic transaction == real-user impact; last anomaly == confirmed recovery;
no additional data == successful recovery; one failed sample == known duration; ICMP
non-response == packet-loss fault; signature rule conditions == case evidence;
confirmed symptom == confirmed fault domain; confirmed fault == confirmed root cause;
opened ticket == completed escalation; test fixture == production customer incident.

## §1 Canonical analysis state model
Separate: incident lifecycle (candidate/active/no_longer_observed/recovered/resolved/
closed); recovery assessment (not_observed/inferred/explicitly_confirmed/
operator_confirmed/not_observable/unknown); symptom (observed/suspected/confirmed);
fault-domain localization (not_localized/suspected/probable/confirmed); failure
mechanism (unknown/under_investigation/suspected/probable/confirmed); root cause
(not_identified/under_investigation/suspected/probable/confirmed/inconclusive);
impact dimensions (synthetic_transaction/service_path/service_availability/real_user/
business, current vs historical); ticket state (not_opened/held/opened/escalated/
resolved/closed); monitoring state (not_started/waiting_for_recovery/active/
completed_no_recurrence/completed_with_recurrence/cancelled). No single ambiguous
"Analysis: Confirmed" / "Impact: Confirmed" field. Adapt to existing Correlix
conventions rather than duplicating fields.

## §2 Raw provenance & derivation lineage
Canonical ids: test_definition_id, scheduled_run_id, execution_id, step_id,
packet_series_id, observation_id, raw_event_id, normalized_signal_id, finding_id,
evidence_group_id, incident_id, correlation_id. Every derived signal/finding
references its origin. One HTTP execution yielding DNS/TCP/TLS/status/duration
observations + synthetic-failure + endpoint-health findings is ONE observer unless an
independent raw source exists. Reports distinguish definitions/executions/steps/
measurements/signals/findings/observers. Correct pluralization ("One automated
check", never "1 automated check(s)").

## §3 Evidence independence
Computed from provenance, not class names. Dimensions: distinct raw source, test
execution, worker, logical vantage, collector, control plane, measurement method,
failure mechanism, path, resolver, proxy, egress, underlying event. Not independent:
loss+RTT from one ICMP series; HTTP status + generic synthetic-failure from one
request; raw event + its normalized copy; duplicate ingestion retries; a finding and
its source signal. Store independence reason codes. Reports list actual confirming
observers (source, type, raw event/execution, vantage, timestamp, independence
basis). One independent observer ⇒ confidence/verdict must say so.

## §4 Evidence-class semantics
Device health must come from a device/workload/app-component/LB/cloud-resource/infra
source (instance status, pod readiness, LB target health, app health endpoint,
service error metric, process health, saturation, cloud health event) — never
assigned merely because a synthetic endpoint check failed (those stay active-check:
HTTP/TLS canary fail, synthetic endpoint-down, ICMP loss, TCP probe fail). Findings
derived from synthetics are `active_check_derived`, not a second device-health class.
Expose exact evidence subtype + source in the report.

## §5 Synthetic vs real-user impact
Impact levels: synthetic transaction (confirmed when the test failed);
representative segment (only when the vantage represents that segment); service-path
(reachability/transaction failure proven for the tested path); real-user (only with
real-user/traffic evidence: NetFlow completion changes, fw session failures, proxy
transaction failures, RUM, app request metrics, access/error logs, LB request
failures, authenticated session failures, service-desk cases, SLO burn, customer
reports, revenue loss); business (only with business/SLO evidence). For P-814009
absent more evidence: synthetic confirmed, representative-vantage confirmed,
real-user NOT OBSERVABLE, business UNKNOWN, affected users UNKNOWN. Never "customer
impact is confirmed by independent evidence" off synthetic-only signals.

## §6 Synthetic test result model
Store/report full transaction outcomes. DNS: qname/qtype/resolver/rcode/addresses/
mismatch/duration/DNSSEC. TCP: dst addr+port, src, result, timeout/refusal/reset,
duration. TLS: version, handshake result, failure reason, cert validity, hostname
validation, issuer, expiry, duration. HTTP: method, sanitized URL, expected vs actual
status, redirects, duration, TTFB, content/header assertions, body size, timeout
stage. ICMP: sent/replies/loss/RTT distribution/destination/expected-behavior/
baseline. Never just "HTTP, Packet loss" — show per-stage outcomes.

## §7 Failure stage vs symptom
Canonical stages: dns_resolution, tcp_connect, proxy_connect, tls_handshake,
http_request, http_response, redirect, content_validation, authentication,
application_transaction, icmp_reachability, path_trace, unknown. Symptoms/metrics
separate: packet_loss, latency_high, timeout, connection_refused, connection_reset,
certificate_invalid, HTTP_4xx, HTTP_5xx, unexpected_content. Packet loss is not a
protocol stage.

## §8 Target capability & baseline validation
Per target/test: protocol expected?, supported?, recent successful baseline?,
baseline success/latency/loss, last known good, expected status, maintenance state,
allowlist/policy. Public SaaS may block ICMP by design: if never succeeded / not
expected → "Not applicable or unsupported", ZERO confidence contribution. Require
known-good baseline, explicit expectation, or validated policy before unsupported
ICMP loss confirms anything.

## §9 Sample cadence & duration bounds
Capture last_success_before, first_failure, last_failure, first_success_after,
cadence, missed executions, min/max duration, duration certainty. Single failed
sample ⇒ "Single failed execution; exact duration unknown" or bounded window (e.g.
near-zero to 2 min for 60s cadence). No post-failure success ⇒ recovery cannot be
confirmed. Never omit duration silently.

## §10 Debounce, persistence, incident creation
Distinguish isolated failed execution / alert candidate / sustained degradation /
incident / critical incident. A single failed synthetic must not auto-become CRIT
unless a documented tier-zero policy allows it and evidence is trustworthy. Policies:
N consecutive, M-of-N, multi-vantage, synthetic+white-box, SLO burn, real-user
impact, explicit provider-down. Keep immediate detection for genuinely critical
checks with the reason visible. Flap/transient suppression without hiding real brief
outages.

## §11 Validation / lab / canary safety
`rca_canary_app` + "PDI validation" ⇒ validation scenario. Canonical fields:
environment, production_scope, signal_purpose (production/staging/lab/demo/
validation/fault_injection/debug), validation_scenario_id, customer_visible,
ticket_side_effects_allowed, paging_allowed, report_visibility, debug_only, lab_test.
Rules: lab/debug/fault-injection evidence never confirms production customer impact;
validation scenarios never open real PD/Jira/SN incidents unless explicitly
configured; test scenarios watermarked; test data out of production management
reports; debug-only signals excluded from customer verdicts; production-ticket side
effects need explicit policy + tenant authorization. Negative tests: a validation
canary cannot create a CRIT production incident, page a production team, claim
customer impact, consume production SLO budgets, or appear as a customer RCA.

## §12 SaaS/application fault-domain model
Classify service: customer_managed_internal_app / customer_managed_public_app /
third_party_saas / cloud_managed_service / private_cloud_app / public_endpoint /
unknown. Never recommend internal K8s/LB checks for third-party SaaS Correlix doesn't
observe. Failure domains: vantage host, client segment, local DNS, proxy/SWG, local
fw, branch egress, ISP/Internet, SaaS DNS/front door, CDN/WAF, TLS/cert, SaaS LB,
SaaS app, auth provider, third-party dependency, unknown. Ownership by
classification: third-party SaaS → NOC coordinates, NetOps/Security own local path,
vendor-mgmt owns escalation; App team is NOT automatically owner. Customer-managed →
app owner only after app evidence.

## §13 Differential localization matrix
Single vantage + single target cannot localize. Differential evidence: same target
from other vantages (everywhere ⇒ target-side; one site ⇒ local); other targets from
same vantage (many fail ⇒ local DNS/proxy/egress; one ⇒ target-specific); hostname vs
direct IP (hostname-only ⇒ DNS/front-door); alternate resolver; protocol progression
(DNS fails ⇒ DNS domain; DNS ok TCP fails ⇒ path/fw/listener; TCP ok TLS fails ⇒
TLS/cert/SNI; TLS ok HTTP 5xx ⇒ app/front-door; HTTP ok content fails ⇒ app/content);
public control endpoint (also fails ⇒ local egress); provider status API. Represent
matrix in case model + report (test, result, implication, confidence contribution,
timestamp, vantage). Absence of network telemetry is NOT evidence of application
fault.

## §14 No-path evidence behavior
No measured path ⇒ do not localize to endpoint; do not confirm ISP/WAN/tunnel/app
topology; topology fit unknown; reduce localization confidence; recommend
path/differential validation. Render "Network path: Not measured" + consequence
statement. "No network fault demonstrated" ≠ "application fault demonstrated".

## §15 Hypothesis taxonomy
Symptoms are not causal hypotheses ("SaaS/application experience degraded" is the
symptom). Valid hypotheses are stage-grounded (DNS resolution failure for the SaaS
hostname; proxy rejected/timed out; TCP to SaaS edge failed; TLS/cert validation
failed; front door 5xx; content assertion failed; local DIA degraded; provider
regional incident; synthetic worker/test misconfiguration). Every hypothesis carries:
type (symptom/fault domain/mechanism/root cause), rank, confidence, supporting +
contradicting + missing evidence, topology fit, temporal fit, independence basis,
confirm action, disprove action, proposed owner + reason. Signature catalog
expressions ("Synthetic HTTP fail OR …") are matching rules — operator/debug view
only; customer reports show actual case evidence.

## §16 Root-cause & object roles
Separate: test target, affected endpoint, affected service, affected user segment,
observed faulty component, fault-domain object, causal object, root-cause object.
P-814009: target portal.rca-canary.example, service rca_canary_app, transaction
failed, faulty component not localized, root-cause object NOT IDENTIFIED. A hostname
is a target/service identifier, not the causal component. Root-cause object only when
causality is established (resolver config, proxy policy, cert, SaaS LB, deployment,
CDN/WAF rule, provider incident, egress circuit, test misconfiguration).

## §17 Recovery & monitoring
Recovery evidence: successful execution after failure, resource-up event, app health
restored, real traffic restored, operator confirmation, policy-based inference from a
stable period. Store explicit_recovered_at, inferred_recovered_at, recovery_basis,
recovery_confidence, last_anomalous_at, first_success_after, recovery_evidence_ids.
Never "recovered" with zero recovery signals / no successful check / telemetry
disappeared / no operator confirmation. Monitoring: trigger type, started_at,
ends_at, evaluated_at, state, recurrence count, result. Never "monitoring continues"
past ends_at.

## §18 Auto-close & escalation
Historical impact stays recorded after recovery. Auto-close evaluates: monitoring
completed, no recurrence, no continuing impact, recovery validation succeeded, no
blocking action left — NOT "historical impact never existed". Escalation records:
required?, trigger, triggered_at, state, target, acknowledgment, completion,
suppression reason. Conditions already true ⇒ "Escalation: Triggered", not future
tense.

## §19 Severity model
Separate signal/check/incident/business severity. Incident severity considers:
environment, service criticality, customer visibility, real-user impact, scope,
duration, vantage count, confidence, completeness, recurrence, SLO impact,
validation status. One failed synthetic + no real-user evidence ≠ CRIT (unless
documented tier-zero policy). Render the basis (or "Severity: Validation only /
Production severity: Not applicable").

## §20 Ownership model
Separate incident coordinator, triage owner, technical investigation owner, service
owner, vendor owner, escalation owner, root-cause owner, action owner. Never assign
App team solely from a hostname/HTTP failure. Unlocalized SaaS: coordinator NOC,
triage NOC, technical owner "Pending localization", candidate domains listed, vendor
escalation pending corroboration. Every recommendation: reason code, evidence,
confidence, handoff condition.

## §21 State-aware next actions
Actions generated from observed protocol results. Missing-detail initial set:
(1) inspect the failed execution (vantage/site, src IP/interface, resolver, resolved
addrs, TCP/TLS results, HTTP status, timings, content assertion, execution ID);
(2) validate observer independence (raw source IDs, execution IDs, lineage, class
basis); (3) run differential controls (same target from independent vantages,
control targets from same vantage, alternate resolver, direct-IP where safe);
(4) check real traffic/app impact (volume, completion, errors, proxy/fw failures,
support cases, affected-user estimate); (5) determine owning domain with handoff
rules (DNS/proxy/egress abnormal → NetOps/Security; 5xx from multiple independent
paths → App/vendor; provider incident → vendor escalation; only worker fails →
platform investigation). Never the generic "confirm or rule out the leading
hypothesis" when the leader is the symptom.

## §22 Management summary
Distinguish facts, inferences, unknowns (model wording in owner spec — the P-814009
example paragraph). Never claim customer impact / root cause confirmed / team
ownership / recovered without supporting evidence.

## §23 NOC quick read
Include: lifecycle, recovery state, symptom state, localization state, root-cause
state, synthetic/real-user/business impact, environment/test purpose, test
definition, failed + consecutive counts, vantage/site, source attachment, cadence,
last known good, first/last failure, first success after, duration bounds, exact
failure stage, actual protocol result, independent observer count, evidence
present/unavailable, coordinator, technical owner, immediate next action,
ticket/escalation/monitoring states.

## §24 Report layout
Keep the clean design; fix content. P1: dynamic report type, precise state badges,
management summary, key facts, decision/policy state, severity basis,
environment/validation label. P2: NOC quick read, protocol breakdown, duration
bounds, evidence provenance/coverage, differential matrix, path availability. P3+:
hypotheses + evidence, object roles, ownership, next actions, policy trace,
corrective/preventive actions. Fixes: no long signature expressions (evidence
bullets); owner in its own hypothesis column; "No data" explanation once (one
coverage footnote); HTTP/DNS/TLS as compact tables; service name first, host/IP
second; visible Validation/Lab watermark; no excessive P1 blank space; no dense P3
wrapping; keep headers/footers/page numbers/confidentiality/grayscale readability.

## §25 Policy trace
Per decision: policy ID+version, environment, evaluated_at, input facts, true/false/
unknown conditions, resulting action, side-effect allowed?, executed?, timestamp,
suppression/override. (Example in owner spec: "PDI validation confirmed-only v3".)

## §26 Tenant security & privacy
Tenant isolation on all new tables/APIs: immutable tenant ID on executions, signals,
evidence, incidents, policies, reports, actions, tickets; tenant-derived worker
identity; RLS + FORCE RLS per project standard; tenant-aware cache/dedup keys +
background jobs; cross-tenant object-role validation; cross-tenant report/PDF denial.
Synthetic-data privacy: redact URL query strings by default; redact credentials/
tokens/cookies/auth headers; configurable header allowlist; sanitize screenshots +
bodies; no sensitive form data; audit access to transaction artifacts. Negative
cross-tenant tests.

## §27 Required tests (32)
Provenance/independence (1–4): one HTTP execution → one observer; derived endpoint
health stays active_check_derived; separate app-health metric may count; duplicate
retry adds nothing. SaaS protocol localization (5–11): DNS fail; TCP timeout after
DNS ok; TLS cert fail; 503 after DNS/TCP/TLS ok; 200 wrong content; ICMP blocked by
design contributes zero; ICMP with healthy baseline may contribute. Differential
(12–15): 3-site failure raises target-side; multi-target one-site ⇒ local; one worker
⇒ worker issue; no path ⇒ no topology localization. Duration/recovery (16–19):
bounded duration; no later success ⇒ recovery unknown; telemetry stops ⇒ not
observable; monitoring expired ⇒ completed. Impact (20–22): synthetic-only ⇒
real-user unknown; +real traffic ⇒ may confirm; error metric w/o volume ⇒ user count
unknown. Environment safety (23–24): validation canary ⇒ no production
ticket/page/impact/CRIT; authorized production canary may act. Severity (25–26).
Object roles (27–28). Reporting (29–31): pluralization; no rule syntax in customer
report; PDF snapshot (no clipping, readable hypotheses, validation label, precise
impact/recovery states, protocol result, no contradictions). Tenant security (32):
cross-tenant access fails.

## §28 Acceptance criteria
(Full list in owner spec — synthetic failure = symptom not root cause; derived
signals ≠ observers; device health has a real source; protocol details stored+shown;
packet loss not a stage; unsupported ICMP confirms nothing; one-sample duration
bounded/unknown; synthetic ≠ user/business impact; hostname ≠ root-cause object;
no-path ⇒ no localization; differentials drive SaaS localization; SaaS vs
customer-managed ownership differ; validation scenarios cannot trigger production
consequences; severity has visible policy basis; recovery explicit/inferred/unknown;
monitoring/auto-close/escalation internally consistent; case evidence replaces rule
expressions in PDF; NOC actions match diagnostic state; both reports render without
contradictions; tenant isolation + privacy pass; all tests/linters/migrations pass.)

## §29 Final deliverables
Current-state audit; root causes of both reports' contradictions; files changed;
schema/model changes; migrations; lineage implementation; independence logic;
protocol-result model; duration/recovery model; impact model; fault-vs-root-cause
model; SaaS classification; differential localization; validation safety; severity +
policy changes; ownership changes; ticket/escalation changes; report/API/template
changes; tenant-isolation verification; tests + results; before/after for both
cases; new PDF paths; visual inspection findings; remaining limitations; deferred
work; commit hash. Do not stop after analysis — implement, run the full relevant
suite, regenerate both reports, render every PDF page to images, inspect visually,
fix, and report only verified functionality.
