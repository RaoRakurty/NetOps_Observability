# PLAN — Evidence Accounting & Coverage Accuracy hardening (P-027379 pass)

**Status: APPROVED WITH CHANGES (owner, 2026-07-15). Binding constraints:**

1. Unknown observer identities remain explicitly **`unknown`** — never silently
   classified as collectors (amends §1: default-closed still holds — unknown
   can never inflate vantage/independence counts — but the label is honest).
2. `execution_id` alone NEVER establishes independence.
3. The existing verdict-gate independence logic gets AUDITED in Phase A —
   soundness is not assumed.
4. Never fabricate configured-test or other historical counts when source
   identity is unavailable — render "unavailable" with reason.
5. Coverage uses **expected cadence + actual covered intervals including
   internal gaps** — never first/last timestamps alone.
6. Source-type-specific coverage strategies: continuous, event-based,
   freshness-based, and batch evidence classes.
7. "Normal" requires ALL of: temporal sufficiency, scope relevance, collector
   health, and the source's ability to observe the claimed condition.
8. No confidence-scoring redesign beyond deduplication + eligibility
   corrections in this pass.
9. Legacy reports render with clearly disclosed partial accounting; block
   only unsupported definitive claims.
10. Add an internal layer-by-layer reconciliation table: totals → case-linked
    → deduplicated groups → confidence-eligible → impact-eligible.

Decisions confirmed: derived records override illustrative numbers; UI editor
deferred WITH structured tenant policy as the canonical source (env/config
supplies defaults only); additive Python schema stamps approved.

**Phase A stop-rule (owner): report the complete before-state reconciliation
and STOP if stored records cannot support a defensible accounting model.**
Owner spec (2026-07-15, verbatim, binding once approved): fix evidence
accounting + coverage accuracy end-to-end (raw source → … → PDF), P-027379 as
the regression fixture, ≥9/10 for numerical consistency / provenance /
coverage honesty / confidence explainability / NOC usability / management
trust. No lifecycle/merge/ownership/wording/taxonomy redesign beyond what
accounting+coverage require.

---

## 0. Grounded audit — why P-027379 contradicts itself (verified in code today)

| Defect in the PDF | Actual origin (file:line, verified) |
|---|---|
| "4 observers" vs "6 independent observers" vs verdict gate naming ONE pair | Two different derivations that never reconcile: the Go report layer counts a **flat `observers` map** (`rca_report.go:771–827`, `UniqueObservers` at `:291`) fed by raw signal observer strings — while the verdict gate's independence pair comes from the Python engine's provenance logic (`verdicts.py` 2-modality+2-observer gate, which IS sound). Neither output is labeled with its layer. |
| "Affected vantages: api, lan-vantage-1, prober" | The flat map has **no classification** — `api` (a collector/API identity) and `prober` (a process name, not a network origin) enter the same set as `lan-vantage-1`. The trust registry (`CORR_TRUSTED_PROBE_OBSERVERS` / `CORR_MEASUREMENT_PROBE_OBSERVERS`) already distinguishes trust, but nothing distinguishes *kind* (logical vantage vs control-plane source vs collector). |
| 124 / 127 / 147 / 8 / 7 / 4 / 4 all shown unreconciled | Each is real at a different layer (executions, measurements, all-lane observations, case-linked, derived signals, evidence groups, recovery signals) — the report renders them without layer labels or invariants. `execution_id` lineage EXISTS (wave #7, live in CH) but is not consumed for accounting. |
| Routing/link 19s labeled "Available/Full coverage" | `rcaLaneWindowCoverage` (`rca_report_wording.go:373`) does min/max window overlap only — **no leading/trailing/internal gap math, no coverage-quality states, no event-based class semantics**. A one-shot control-plane transition passes the same "full" test as a continuous lane. |
| Device health / flow labeled "Normal" with 1m58s leading + 2m13s trailing gaps | Same root: `buildEvidenceCoverage` (`rca_report_wording.go:307`) labels a lane Normal when no anomalous record was tied to the case — "no anomaly linked" ≠ "measured healthy over the interval". |
| "Real-user impact: none detected" vs mgmt summary "not confirmed (insufficient telemetry)" | A multi-class "none detected" gate exists (`rca_report.go:1003–1010`) but is not driven by a per-class CoverageAssessment; the two renderers derive impact independently. This is the already-known open P1 ("261D09-class still renders None detected", truthfulness-epic notes). |

Root cause in one sentence: **counts and coverage are recomputed ad-hoc in the
render layer from raw signal fields, instead of being derived once from the
existing lineage (execution_id, provenance groups, evidence groups) with
explicit layer semantics — so every page can disagree.**

## 1. Target architecture (where each spec entity lives)

**Principle: derive, never invent.** All accounting computed in ONE place from
real stored records; renderers (HTML/PDF/NOC/API) consume the same struct.

- **New Go package-level model `rca_accounting.go` — `EvidenceAccounting`**
  built per case from: CH `corr_evidence`/`corr_signals` rows (execution_id,
  schedule_id, observer, kind, attrs), the hypothesis blob's independence
  pairs, and the observer registry. Carries every canonical field from the
  spec (`configured_test_count` … `case_linked_evidence_group_count`) each
  with a doc comment giving its precise definition, plus the enumerable
  records behind each count (so `independent_observer_count ==
  len(IndependentObservers)` is true by construction).
- **Observer classification registry** (extends the existing trust registry
  pattern; per-tenant, env/config-driven with safe defaults):
  `logical_vantage | control_plane_source | collector`. Hard rules baked in:
  `api`, collector identities, worker/process names → NEVER logical_vantage;
  unknown observers → `collector` (default-closed: an unclassified source can
  never inflate vantage or independence counts).
- **Provenance/dedup**: independence_group_id derived from existing lineage
  (execution_id + provenance rules): same-execution metrics, raw+normalized
  copies, retries, finding+source-signal pairs collapse to one group.
  The Python engine gains only **additive stamps** where lineage is thin
  (independence_group_id on signal attrs; vantage/control-plane kind at
  ingest) — the fact schema itself stays backward-compatible (history
  reconstructs; legacy cases render "legacy accounting" per spec test 15).
- **New `rca_coverage.go` — `EvidenceCoverageEngine`**: per evidence class
  computes the full spec field set (overlap, ratio, leading/trailing/internal
  gaps, freshness, scope/collector health, sampling, baseline) → quality
  states (`complete/substantial/partial/minimal/point_in_time/stale/
  irrelevant/unavailable/not_configured/unknown`) with **per-class
  semantics** (routing/tunnel state transitions = event-based → never judged
  by continuous-coverage rules) and **configurable thresholds** (95/80/25
  defaults; per evidence class, per tenant policy).
- **Eligibility**: every CoverageAssessment yields `confidence_eligible`,
  `impact_eligible`, `normality_eligible` + reason codes. Confidence display
  consumes canonical evidence groups only; the impact renderer consumes
  eligibility (kills "none detected" on insufficient coverage — the wording
  set from the spec: "No anomaly observed during available coverage",
  "Inconclusive", "Not confirmed", …).
- **Presentation**: one "Evidence accounting" structured block (customer
  view: canonical groups, vantages, control-plane sources, independent
  confirming sources; full lineage ladder in the operator/debug appendix),
  coverage table gains the spec columns (quality, state, overlap, gaps,
  scope relevance, confidence/impact contribution).
- **Quality gate**: extend the EXISTING `ReportQualityGate`
  (`rca_consistency.go`, already downgrades to "Draft Incident Assessment")
  with the spec's 12 blockers (count reconciliation, api-as-vantage,
  Full-below-threshold, Normal-with-material-gap, none-detected-without-
  coverage, case-linked>total, failed>executions, point-in-time-as-full, …).

## 2. Phases

- **Phase A — Audit deliverable (½ day):** regenerate P-027379 as-is; document
  every number/label on it with its code origin (extends §0 to 100% of the
  report); before-tables for deliverables 17/18. No code changes.
- **Phase B — Accounting model + provenance (1–1.5 days):**
  `rca_accounting.go` + observer classification registry + independence
  grouping + Python additive stamps; invariants as constructor-enforced;
  unit + property tests (spec tests 1–5, 15, 16).
- **Phase C — Coverage engine (1 day):** `rca_coverage.go` engine + per-class
  semantics + thresholds + eligibility; replace `rcaLaneWindowCoverage` /
  `buildEvidenceCoverage` internals (keep their call sites); tests 6–12.
- **Phase D — Renderers + wording (½–1 day):** evidence-accounting block,
  coverage table columns, impact wording driven by eligibility (test 13),
  operator/debug appendix; preferred/forbidden wording per spec.
- **Phase E — Quality gate + regeneration (½ day):** 12 blockers wired into
  `ReportQualityGate` + sweeper/notify emitters; regenerate P-027379,
  render every PDF page to images, visual inspection, after-tables,
  PDF snapshot test (14); full corr+backend suites + linters.

Total: **~4 working days** of focused effort. Execution model: I drive
Phases A/E in the main session (you can watch/steer); Phases B/C/D run as
one dedicated worktree subagent each (B→C sequential — C consumes B's model;
D after both), with me reviewing + merging each. This matches how you and I
have been working today.

## 3. Test plan (spec's 16 families → concrete)

Go table-driven tests beside the new files + extensions to
`rca_scenarios_test.go` (fixture harness already exists): one-execution-many-
signals → 1 group/1 observer; api → never vantage; control-plane+probe → 2
independent sources; retry dedup; count reconciliation invariants (property
test over the 400-case generator already in the suite); partial-flow, partial
device-health, point-in-time routing, leading-gap active checks,
full-coverage-only-when-thresholds-pass, scope mismatch, unhealthy collector,
impact wording matrix, PDF snapshot (counts reconcile, no api-vantage, gaps
visible), legacy-case rendering, tenant isolation (evidence/coverage/lineage
never cross tenants — extends the existing cross-tenant report denial tests).

## 4. Acceptance & deliverables

Exactly the spec's acceptance criteria + 24 deliverables (audits, root
causes, files, migrations, implementations, tests+lint results, before/after
accounting + coverage tables for P-027379, corrected PDF path, rendered page
images, visual findings, zero remaining P1s, commit hashes). Nothing marked
complete until the regenerated P-027379 is page-by-page inspected.

## 5. Decisions I need from you (the only 3)

1. **Actual records win over the spec's example numbers** — if derivation
   from real P-027379 records yields e.g. 2 configured checks instead of the
   spec's illustrative 3, the derived number ships (spec says "do not invent
   these values"). Confirm.
2. **Threshold/config surface**: coverage thresholds + observer
   classification live in per-tenant policy with global defaults (same
   pattern as RCA windows / trust registry env). A minimal settings surface
   (config file/env now, admin UI later) — OK to defer the UI editor?
3. **Python fact schema**: additive attribute stamps only (independence
   group, source kind) — no breaking schema change, history reconstructs,
   legacy cases show "legacy accounting". Confirm this constraint holds (it
   preserved history through all four prior waves).

---
*Prepared 2026-07-15. On approval: Phase A starts immediately; commits land
per phase; every phase ends with green suites before the next begins.*
