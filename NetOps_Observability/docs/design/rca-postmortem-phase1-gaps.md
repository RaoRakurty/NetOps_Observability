# RCA Postmortem Phase 1 — Data-Model Gap Report

Status: pre-implementation deliverable for
`docs/design/rca-postmortem-enhancements-spec.md` (APPROVED, owner 2026-07-19).
This document maps the CURRENT report model (`src/backend/rca_report.go` and
friends) against the spec's Phase 1 requirements — semantic models, action
schema, impact provenance, report maturity, immutability — and lists every file
the implementation will change.

---

## 1. Where trigger / root-cause / contributing-factor / symptom / impact conflate today

The spec (§1) requires these as SEPARATE concepts. Current state:

| Concept | Where it lives today | Gap |
|---|---|---|
| **Trigger** | Nowhere as a postmortem concept. `meta["trigger_signal"]` exists but it is the signal that OPENED the correlation window (a detection fact), not the incident trigger (the event/change that set the failure off). `rca_report_http.go` reads it only to stamp evidence roles. | No `Trigger` field at all. The engine genuinely does NOT distinguish the incident trigger — the model must carry an explicit "not determined", plus the triggering OBSERVATION as the separate detection fact it actually is. |
| **Root cause** | `rcaRootCause` (rca_report.go) — already honest: `Identified` only with mechanism + object, "possibly because of X" otherwise. | Good. Needs to be referenced from one semantic block so the five concepts are side-by-side, not scattered. |
| **Contributing factors** | Nowhere. The hypothesis ranking carries alternatives, but an unconfirmed alternative hypothesis is NOT a contributing factor (different concept: a factor that worsened/enabled the confirmed chain). | New `ContributingFactors []` — empty with an explicit "not determined by the engine" note; never populated by relabeling hypotheses. |
| **Symptoms** | Genuinely distinguished: `rcaEvidenceSummary.Symptoms` (distinct manifestations with source class + onset). Also `States.Symptom`. | Only needs projection into the semantic block (label + kind + source lineage), no new derivation. |
| **Impact** | Scattered scalar states: `States.Impact`, `ImpactSynthetic`, `ImpactRealUser` + `rcaProbeSummary` numbers. No value/unit/scope/denominator/source/coverage/confidence/basis anywhere. | Full impact-provenance model missing (see §3 below). |

## 2. What the report lacks for maturity classes

- `ReportType` (`reportTypeFor`) conflates ANALYTIC maturity (suspected /
  confirmed / root-cause-concluded) with ARTIFACT class. The spec's five
  classes (operational assessment · validation assessment · preliminary RCA ·
  interim RCA · final postmortem) exist nowhere as a field.
- `Validation bool` exists (watermark pill in HTML) but the document's TYPE
  line still reads like a production artifact ("Incident Assessment") and no
  sections are withheld for validation scenarios.
- Promotion (`rcaPromotionStatus`) is evaluated at the HTTP layer AFTER the
  build — so artifact class must be stamped post-promotion, and the builder can
  only pre-stamp the promotion-independent classes (validation, operational).
- Interim / final are human lifecycle states (Phase 3 actions advance them);
  no store field exists to hold a human-advanced stage. Phase 1 models the
  states and the derivation function; Phase 3 wires the workflow.
- Lessons learned: no schema at all. Spec §6: schema now, editing gated to
  promoted classes 3–5 only — so the maturity block must carry an explicit
  `lessons_editable` gate the fixtures can assert on.

## 3. What the report lacks for impact provenance

Spec §2: every impact value retains value · unit · scope+denominator · source ·
coverage · confidence · measured/estimated/inferred. Today:

- Impact numbers exist only as raw counters inside the builder
  (`impactSynthetic`, `impactRealUser`, `impactRealUserIndicator`) and probe
  stats (`rcaProbeSummary`) — none carries provenance.
- No representation of "not measured": an absent measure is simply absent,
  indistinguishable from zero for a consumer. Spec: missing = "not measured",
  never zero.
- Nothing prevents a consumer from deriving user counts from synthetic/flow
  evidence — the prohibition lives only in prose comments. The model must make
  real-user measures explicitly `not_measured` when no identity/transaction
  mapping exists, regardless of synthetic/flow counts.
- Supported measures (affected applications / sites / users / sessions /
  transactions / user-minutes / site-minutes / transaction failures / synthetic
  failure rate / flow-volume change / voice impairment / SLO consumption) have
  no enumeration; the model must list them all with honest status so absence is
  visible.

## 4. What the report lacks for detection milestones

Spec §1 detection tracks. Today:

- `rcaReportTimes` has FirstObserved / LastAnomalous / RecoveredAt /
  ComponentRecoveredAt / MonitoringUntil — a subset, without source lineage.
- The manual/ITSM lifecycle (`timeintel` package: acknowledged, mitigation,
  recovered… with `TimestampSource` per stamp) is NOT fed into the report
  builder at all (`rcaReportInput` has no lifecycle field; only the timeline
  endpoints read it).
- No milestone struct `{ts, source_lineage}`; no rule preventing comparative
  durations when an endpoint or its lineage is missing.
- Milestones with no source today (first alert, first user/help-desk report)
  must render as ABSENT, never inferred.

## 5. What the report lacks for action items

Spec §3. Today `rcaAction` (rca_actions.go) is an ephemeral, derived NEXT-STEP
row (action/owner/priority/purpose/expected result) rebuilt on every request:

- No persistence, no identity, no lifecycle — nothing survives a rebuild.
- No category enum (prevent/mitigate/detect/diagnose/respond/resilience).
- No accountable owner vs collaborators split; the planner's `Owner` is a team
  LABEL (suggestion), not an accepted assignment.
- No suggested-vs-committed distinction, no human acceptance step.
- No remediation states (§7: proposed · accepted · in progress · blocked ·
  completed · verified · rejected · superseded · overdue).
- No due date, success criteria, verification evidence, external ticket id,
  related-cause links, completion/verification timestamps.
- No tenant-scoped store, no CRUD API, no audit, no isolation test.

Machine-suggested items must come from seam ownership
(`tenant_governance.go` SeamOwners registry + report ownership block) as
SUGGESTIONS ONLY — owner acceptance converts suggested → committed.

## 6. What the report lacks for immutability

- A generated document embeds nothing verifiable: no analysis snapshot hash,
  policy version, template version, content hash, or status-as-of record.
- Regenerating html/pdf silently reflects the LIVE analysis — there is no
  revision register, so "the PDF from Tuesday" is unprovable and mutable.
- No per-case, tenant-scoped revision store; no rule that a new generation with
  changed content is a NEW revision object.

## 7. Fixture gaps

- No test pins the P-3335CF behavior (active production case, synthetic impact
  confirmed, real-user unknown → operational assessment, lessons locked,
  synthetic measured + real-user "not measured").
- No test pins P-D96E4C (validation scenario → validation assessment,
  watermarked, never rendered as a production postmortem).
- No JSON snapshot artifacts exist for owner review.

---

## Files that will change

New (all under `src/backend/` unless noted):

| File | Purpose |
|---|---|
| `rca_semantics.go` | Artifact-class/maturity model + semantic block (trigger / root cause / contributing factors / symptoms / impact ref) + detection milestones + lineage-gated comparisons + lessons-learned schema stub |
| `rca_impact_provenance.go` | Provenance-carrying impact measures (`{value, unit, scope, denominator, source, coverage, confidence, basis}`), full measure enumeration with `not_measured` |
| `rca_action_items.go` | `rcaActionItem` schema, tenant-keyed file store, CRUD + suggest endpoints, remediation-state machine, seam-ownership suggestions |
| `rca_report_integrity.go` | Integrity block (snapshot/content hashes, policy + template versions, status-as-of), tenant-keyed revision register store + read endpoint |
| `rca_semantics_test.go`, `rca_impact_provenance_test.go`, `rca_action_items_test.go` (incl. §3a isolation), `rca_report_integrity_test.go`, `rca_fixtures_phase1_test.go` | Unit + isolation + fixture snapshot tests |
| `testdata/rca_phase1_p3335cf.snapshot.json`, `testdata/rca_phase1_pd96e4c.snapshot.json` | Owner-reviewable report snapshots |

Modified:

| File | Change |
|---|---|
| `rca_report.go` | New view-model fields (`Maturity`, `Semantics`, `ImpactProvenance`, `LessonsLearned`, `Integrity`); builder wires the new blocks; `reportTypeFor` gains validation awareness |
| `rca_report_http.go` | Maturity stamped after promotion evaluation; manual lifecycle loaded for milestones; integrity computed + revision recorded on document generation; revisions read endpoint dispatch |
| `correlations.go` | Route `actions` / `rca-revisions` subresources |
| `main.go` | Construct the action-item + revision stores |
| `rca_report_html.go` | Maturity/class line + validation withheld-sections notice + integrity footer line; template version constant |

Non-goals in Phase 1 (per spec implementation order): report layout / causal
chain / glossary rendering (Phase 2), lessons-learned workflow + approvals +
ITSM sync (Phase 3), items 8–10.
