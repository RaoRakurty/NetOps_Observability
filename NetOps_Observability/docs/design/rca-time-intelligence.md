# RCA Time Intelligence — Incident Time Decomposition

**Tracker:** #84 · **Status:** P1a + P1b + P1c + P2 + P3 SHIPPED & live · P1d (persistence/RLS/
manual-edit/backfill) + docs page REMAINING.
**Owner spec:** 2026-06-24 (chat). **This doc** is the durable design of record.

---

## 1. What this is (and is NOT)

Correlix decomposes **every incident into measurable time segments** and shows
**exactly where time was saved or lost** — detection, correlation, root-domain
**isolation**, owner identification, evidence readiness, acknowledgement, mitigation,
recovery, resolution.

**Product principle (HARD):**
- This is **NOT** an "MTTR dashboard" and **NEVER** claims "Correlix cut MTTR 80%".
- MTTR is split into measurable phases so it is never one ambiguous number.
- **MTTI (time-to-isolate) is the differentiator** — it measures time until the
  likely root domain / seam / owner is identified with evidence-backed confidence.
- Wording is precise, not marketing: *"Correlix isolated the likely DIA seam in
  1m 24s"*, *"most delay came after owner identification; provider repair pending"*,
  *"detection was fast, but evidence readiness was delayed because BGP telemetry was
  missing"*, *"4th similar failure on this circuit in 30 days"*.

**Acceptable names:** RCA Time Intelligence · Incident Time Decomposition · RCA
Time-to-Isolation Analytics · Seam MTTR Analytics · Operational Recovery Scorecard.

---

## 2. Definitions & formulas

Per-incident phase metrics (ms), each source-attributed and honestly incomplete when
an endpoint is missing (never a fabricated zero):

| Metric | Name | Formula | Notes |
|---|---|---|---|
| MTTD | `ttd` | `detected − impact_started` | impact inferred from earliest customer-impacting signal → `is_inferred` |
| MTTC | `ttc` | `correlation_completed − first_signal` | Correlix correlation speed |
| **MTTI** | `tti` | `root_domain_identified − first_signal` | **the differentiator** |
| MTTE | `tte` | `evidence_ready − first_signal` | evidence policy satisfied OR evidence_missing explicit |
| MTTA | `tta` | `acknowledged − ticket_created` | NOT impact→ack |
| MTTM | `ttm` | `mitigated − detected` | impact reduced, not necessarily fully repaired |
| MTTR-Recovery | `ttr_recovery` | `recovered − impact_started` | user impact gone |
| MTTR-Resolution | `ttr_resolution` | `closed − impact_started` | ticket closed, root cause documented |

Reliability rollups (over many incidents, **percentiles not just averages** — averages
hide the long tail):
- **MTBF** — mean time between recovered/closed incidents for the same repairable
  object (root_entity / seam_id / device / interface / app_path / provider /
  signature). Excludes child/suppressed duplicates; separates planned maintenance;
  yields `repeat_incident_rate` + chronic-offender ranking.
- **MTTF** — lifetime to first failure for **non-repairable** assets only (optics,
  modules, circuits marked `non_repairable`). Never for logical services. Never
  fabricated without birth times.

**Time-loss driver** (the "where did the time go" answer): `detection | correlation |
evidence_missing | ownership | acknowledgement | mitigation | provider_repair |
unknown`. Honest overrides: `evidence_missing` when evidence is still gated;
`provider_repair` **only** in `[owner_identified, recovered)` when the owner is a
provider; else the largest controllable segment.

---

## 3. Integration decision: DERIVE, don't re-instrument

**Validated:** the correlation object already carries the engine-side timestamps, so
we derive lifecycle events **without modifying the Python engine** (one bounded
context, low risk, reversible):

| Lifecycle event | Source | Provenance |
|---|---|---|
| first_signal | `corr_objects.window_start` (min signal onset) | observed |
| detected | min `corr_signals_archive.ingest_ts` (detection latency) | observed |
| correlation_completed | `corr_objects.created_at` (persist time) | observed |
| root_domain_identified | created_at when `verdict_tier ∈ {suspected,confirmed}` | observed |
| owner_identified | same instant (owner intrinsic to grounded hypothesis) | **inferred** |
| evidence_ready | created_at when `evidence_missing` empty | observed |
| impact_started | **absent** → calculator infers from first_signal | inferred |
| ticket/ack/mitigate/recover/resolve/close | `integration_events` (ITSM) | itsm |

**Owner** comes from `hypotheses.ranking.hypotheses[0].verdict.owner`. **ITSM phases
are empty today** (per-correlation ticket linkage is #78, not wired) → those metrics
read INCOMPLETE, honestly.

Tenancy: per-incident + rollup reads go through `chRows` (`chTenantScope`), so a
tenant only ever sees/aggregates its own incidents (cross-tenant id → 404, no leak).

---

## 4. Data model

**Derive-on-read today** (no table needed for the read path). Persistence (P1d) adds:

- `incident_timeline_events` — lifecycle events incl. **manual/user-entered** ones
  (engine/ITSM events stay derived). Columns per spec: tenant_id, id, correlation_id,
  event_type (enum), event_time, timestamp_source (enum), confidence, source_system,
  source_signal_id, source_ticket_id, source_payload (jsonb, redacted/permissioned),
  created_at, created_by; unique guard per (incident, event_type, source_system,
  source id). RLS `tenant_iso` FORCE on `app.tenant_id`.
- `incident_time_metrics` — computed phase metrics snapshot (idempotent recompute on
  event change; `is_inferred`, `missing_event`, `blocked_by`, `calculation_version`).
- `reliability_metric_rollups` — windowed p50/p90/p95 per scope (tenant/site/service/
  seam/device/interface/app_path/provider/cloud) + MTBF + repeat rate + top time-loss
  phase. Tenant-isolated.

All tables: tenant_id + RLS; manual edits audited (reject unaudited); background jobs
idempotent + retry-safe; PII/secrets redacted from ITSM/source payloads.

---

## 5. APIs

- `GET /api/correlations/{id}/time-metrics` ✅ — lifecycle + phase metrics + driver.
- `GET /api/reliability/rollups` ✅ — percentile phase stats + MTBF + MTTF + repeat
  rate + top time-loss phase; network-dimension filters (owner/provider/device/
  severity/signature). Surfaces `capped` (no silent truncation) + `note` (#76 dep).
- `GET /api/reliability/chronic-offenders` ✅ — recurring objects ranked by count.
- (P1d) timeline write/edit endpoints — audited; reject unaudited manual edits.

---

## 6. Honesty rules (non-negotiable)

1. Missing start/end → **incomplete metric naming the gap**, never a zero.
2. Inferred/synthetic/ITSM timestamps are **labelled**; min constituent confidence
   propagates.
3. **MTTR is never one ambiguous number**; MTTI is emphasised.
4. **Percentiles** (p50/p90/p95) primary; mean only secondary.
5. No fabricated MTTF; no silent truncation (`capped` flag); internal-stack inclusion
   disclosed until #76 lands.
6. UI wording precise, never "AI reduced MTTR".

---

## 7. Phased plan & status

- **P1a ✅** `6d57716` — pure `timeintel` calculator + driver (9 tests).
- **P1b ✅** `d9bbf52` — deriveLifecycle + `/time-metrics` (4 tests, live).
- **P1c ✅** `76bfa35` — Time Impact card + lifecycle timeline (1 test, live).
- **P2 ✅** `c0cf42e` — `rollup.go` + `/reliability/*` (7 tests, live over 5000 obj).
- **P3 ✅** `b3f353e` — Operational Recovery Scorecard page (scorecard stats, MTTI★
  trend chart, chronic-offenders table, filters) + `GET /api/reliability/trends`.
- **P1d ⏳** — migration 0014 + persistence + audited manual edits + backfill + RLS
  isolation test.
- **Docs page ⏳** — operator-facing definitions + formulas (this doc is the design;
  a UI/help page is separate).

---

## 8. Test matrix (spec's 20 cases)

Covered by P1a/P1b/P2 (✅): 2-determinism, 3-missing→incomplete, 4-inferred+confidence,
5-recovery≠resolution, 6-MTTA=ticket→ack, 7-MTTC, 8-MTTI, 9-MTBF excl children,
10-MTBF separates maintenance, 11-MTTF non-repairable only, 12-rollup p50/p90/p95,
14-card renders durations+source, 15-evidence_missing driver, 16-provider_repair window.
Pending with P1d/P3 (⏳): 1-idempotent insertion, 13-filters test, 17-debug/lab excluded
(ties to #76), 18-RLS no cross-tenant leak, 19-reject unaudited manual edit, 20-backfill.

---

## 9. Security / SaaS

tenant_id + RLS/PBAC on every table; manual timestamp edits audited (reject
unaudited); raw `source_payload` permission-gated + PII/secrets redacted; rollups
tenant-isolated; background jobs idempotent + retry-safe; migration tests + seed data.

---

## 10. Open dependencies

- **#76 engine-side internal-stack exclusion** — until done, reliability rollups
  include internal-stack incidents (disclosed via the `note` field). Customer-facing
  rollups should exclude internal-stack once #76 lands.
- **#78 RCA→ServiceNow ticketing** — per-correlation ticket linkage; unblocks the
  ITSM phases (ticket/ack/mitigate/recover/resolve/close), today INCOMPLETE.
- Cross-refs: [[netops-rca-wording-templates]], [[netops-rca-ticketing-queued]],
  [[netops-frontpage-rca-direction]].
