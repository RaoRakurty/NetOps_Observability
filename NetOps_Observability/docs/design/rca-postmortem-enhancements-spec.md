# RCA Postmortem Enhancements — APPROVED SPEC (owner, 2026-07-19)

Status: **APPROVED — authoritative**. Implementation phased; **no deployment
until the owner has reviewed the semantic tests and report snapshots.**
Sources: owner directive (verbatim requirements below), Google SRE postmortem
template + GCP postmortem guidance, IEEE Access 2025 IP/MPLS ML+CBR RCA paper
(items 8–10), docs/design/rca-evidence-summary.md (shipped).

## Artifact classes & maturity (preserve — never conflate)

1. operational incident assessment (may exist while active; suspected/undetermined allowed)
2. validation incident assessment (nonproduction; must never resemble a production postmortem)
3. preliminary formal RCA
4. interim formal RCA
5. final RCA / postmortem

Lessons learned and human-approved organizational conclusions belong ONLY to
the promoted postmortem workflow (classes 3–5).

## 1. Postmortem structure

Executive Summary · Impact · What Happened · Trigger · Root Cause and
Contributing Factors · Detection and Response · Mitigation and Service
Recovery · Corrective Actions · Lessons Learned · Detailed Timeline ·
Evidence Appendix · Glossary.

Trigger, root cause, contributing factor, symptom, impact = separate concepts.
Render "not determined" rather than forcing a leading hypothesis into a
root-cause field.

Detection tracks (when available): first credible failure · first service
impact · first Correlix detection · first alert · first acknowledgement ·
first user/help-desk report · first mitigation · service restoration ·
recovery validation. Never compute comparative statements unless both
timestamps AND their source lineage are present.

## 2. Quantified impact (provenance-carrying)

Every impact value retains: value · unit · scope+denominator · source ·
coverage · confidence · measured/estimated/inferred status.

Supported measures: affected applications, sites, active users, sessions,
transactions, user-minutes, site-minutes, transaction failures, synthetic
failure rate, flow-volume change, voice impairment, SLO/error-budget
consumption.

Never convert synthetic failures / flow changes / network events into affected
user counts without valid identity or transaction mapping. Missing = "not
measured"/"unavailable", never zero.

## 3. Action items (structured)

action · category (prevent/mitigate/detect/diagnose/respond/resilience) · ONE
accountable owner · collaborators · priority · due date · status · success
criteria · verification evidence · external ticket ID · source
(machine-suggested vs human-created) · related root cause / contributing
factor / detection gap / recovery gap · completion + verification timestamps.

Seam ownership SUGGESTS an owning team, never auto-assigns; human acceptance
converts suggested → committed. One source of truth for execution status;
linked ITSM records sync explicitly and surface conflicts (never silently
overwrite either side).

## 4. Causal chain

Internal causal GRAPH; rendered as a numbered primary sequence with support
for branches and alternative hypotheses. Every step exposes: claim · causal
role · timestamp/interval · observed/corroborated/inferred/reported/unknown/
contradicted state · confidence · supporting evidence IDs · contradictory
evidence. No causal language where only temporal correlation exists.

## 5. Glossary

Dynamic — only terms used in that report. Always define report semantics of
"observed", "inferred", "confirmed", "suspected", "independent evidence",
"recovery validation" when present.

## 6. Lessons learned

Schema now; editing enabled ONLY for promoted preliminary/final postmortems.
Fields: what worked well · what did not work as intended · where defenses or
circumstances limited impact · assumptions that proved incorrect ·
detection/observability gaps · response/coordination gaps. Correlix may offer
fact-based prompts but never authors subjective lessons or assigns blame.
Record postmortem owner, reviewers, approvals, timestamps.

## 7. Remediation status

Separate from postmortem completion. States: proposed · accepted · in progress
· blocked · completed · verified · rejected · superseded · overdue. A
published PDF is an immutable status snapshot as of generation time; later
ticket changes never mutate an existing report — live status via the linked
action register or a NEW report revision.

## Additional mandatory

explicit report maturity · machine-derived vs human-verified claims · root
causes + contributing factors · internal/executive/customer/auditor render
profiles · final-publication completion checks · immutable analysis snapshot +
policy version + template version + content hash · tenant-scoped
authorization + audit history for every edit/promotion/approval/revision.

## Paper-derived items (approved)

8. **Active Verification service** — on suspected verdicts, bounded READ-ONLY
   SSH/probe battery against on-path devices (async + parallel, hard
   timeouts, opt-in per tenant, audited, read-only command allowlist);
   results enter as an independent evidence modality.
9. **Incident case memory** — resolved/promoted incidents write an
   evidence-fingerprint case record (confirmed root cause + fix); new cases
   surface similar CONFIRMED past incidents. No ML guessing.
10. **Signature-candidate suggestions** — template-mine + cluster the
    unmatched event stream to PROPOSE signatures into the governance feed;
    human approves; nothing auto-detects.

## Implementation order

- Phase 1: semantic models, action schema, impact provenance, report maturity, immutability.
- Phase 2: report layout, causal chain, glossary, quantified-impact rendering.
- Phase 3: lessons-learned workflow, approvals, ITSM sync, remediation tracking.
- Items 8–10 proceed as parallel bounded contexts (8 independent; 9–10 after Phase 1 models exist).

Regression fixtures: **P-3335CF** stays an operational assessment while active
(synthetic impact confirmed, real-user impact unknown); **P-D96E4C** stays a
nonproduction validation assessment.

Process: before coding, report current data-model gaps + files to change;
implement in bounded phases with tenant-isolation, report-integrity and
regression tests. **No deploy until semantic tests + report snapshots are
owner-reviewed.**
