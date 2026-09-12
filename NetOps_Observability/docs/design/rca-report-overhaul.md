# RCA Report Overhaul — current-state findings & design

Owner directive 2026-07-12: the per-incident RCA document must serve (1) a NOC
engineer in 30 seconds, (2) management, (3) customer delivery — without
overstating evidence. Reference report: "RCA Report — Network change observed"
(recovered active-check anomaly, 72 signals, no root cause identified, yet
titled and framed as a completed RCA).

## 1. Current-state findings (analysis phase, traced 2026-07-12)

### Two unrelated "report" systems exist

| | System A — scheduled reports | System B — the RCA document |
|---|---|---|
| Code | `report_pipeline.go`, `report_scheduler.go`, `reports/*` | `frontend/components/rca/rcaExport.ts` + `rcaCase.ts` |
| Output | fleet/health/WAN/security operational reports | the per-incident RCA PDF in question |
| PDF | Gotenberg headless-Chromium sidecar (`reports/render_pdf.go`, `REPORT_PDF_SIDECAR_URL`, compose `--profile pdf`) | browser Save-as-PDF (`window.open("")` + `win.print()`) |
| Tenant scoping | RLS + signed links (`report_links.go`, SR-018) | inherits the browser session; document never touches the backend |

The RCA document is assembled 100% client-side in `buildRcaCase()`
(`rcaCase.ts:264`) from three API reads (`Correlations.tsx:447-499`):
`GET /api/correlations/{id}` (object), `/timeline` (signals), and
`/rca-path-view` (derived narrative). All are gated by
`requirePerm("infrastructure", read)` + `chTenantScope` with ClickHouse row
policies (`corr_schema.go:388-408`) — the read path is tenant-safe today.

### Where each complained-about value comes from

| Value | Source | Problem |
|---|---|---|
| Title "Network change observed" | `labels.ts:171` / `ai_labels.go:168` fallback; plane fallback `rcaCase.ts:313` | catch-all default; **no app/saas/lb rung** in the cascade, so every app-domain signature mislabels as a network change |
| "RCA state: Recovered" | `rcaCase.ts:324` | conflates incident lifecycle with analysis maturity |
| Confidence Medium | `rcaCase.ts:316` (`attachedCount>=2`) | signal count ≠ evidence independence; engine's own gate reasons ignored for the badge |
| Root cause object "—" | `rcaCase.ts:613` | renders a literal dash instead of "Not identified" |
| Likely owner "app_team" | catalog `verdict.owner` of top signature via `Correlations.tsx:486`; `rca_path_view.go:301-309` | owner asserted from the *hypothesis template*, not from evidence; no triage-vs-escalation separation |
| "Signals: 72" | `rcaCase.ts:615` | raw count; no failed/total, vantages, loss/latency, failure stage |
| "No signals seen in this window" | `rcaCase.ts:400` | cannot distinguish healthy / no-data / not-configured |
| "Suggested ticket: Hold" | `rcaCase.ts:616` | not policy-driven; no thresholds/monitoring window |
| "Evidence changed but does not yet confirm a real network issue" | `rcaCase.ts:367` | circular wording |
| "matches this issue type" | `rcaCase.ts:372` | says nothing |
| "Auto-close if no recurrence appears" | `rcaCase.ts:357` | vague; no policy identity |
| "SUSPECT PATH" tag | `rcaCase.ts:498` | asserted with no identified path |
| No duration / recovered-at | not computed anywhere | clears (`*_clear` signals) exist in the timeline but are unused for times |
| Cloud change section | absent from report (cloud KVs only when cloud signals attach) | cloud_change/cloud_audit signals carry attrs (actor, resource, region) but are not correlated/rendered as a change section |
| about:blank + browser timestamps | browser print chrome on a URL-less window (`rcaExport.ts:367`) | unfixable client-side; needs server-side PDF |

### What the engine already provides (canonical fields — do not duplicate)

- `corr_objects.hypotheses` JSON: per-hypothesis `satisfied[]`, `missing[]`,
  `contradicted`, `contradictions[]`, `confidence`, `verdict{tier, reasons[],
  modality_coverage[], observer_coverage[], trusted_modalities[],
  independent_pair, first_steps[], owner, layer}` — the honest gate output.
- `corr_signals` rows: `kind, observer_id, modality_class, entity_*, severity,
  metric_name, value, baseline, deviation, attrs, ts` — enough for signal
  summaries (failed vs total, vantage counts, loss/latency, failure stage from
  synthetic_* kinds) computed on read.
- `*_clear` signals: recovery evidence with timestamps → `recovered_at` is
  derivable, never fabricated.
- `corr_objects.affected`, `app_impact`, `layer_coverage`, seams in
  `grounding_context`, `evidence_missing[]`.
- Engine verdict independence model (verdicts.py): the gate reasons strings are
  already machine-readable enough to drive "why not confirmed" wording.

## 2. Design

### Canonical server-side report (new)

`GET /api/correlations/{id}/rca-report` (same gate + tenant scope as siblings):
returns typed `RcaReport` JSON. `?format=html` renders the print document
server-side; `?format=pdf` converts via the existing Gotenberg seam
(`REPORT_PDF_SIDECAR_URL`; enable compose `--profile pdf`). Controlled header/
footer (report type, correlation id, tenant display name, page X of Y,
confidentiality marking); no browser chrome possible.

Report type & title by evidence maturity (§2 of the directive): confirmed →
"Root Cause Analysis"; probable → "Preliminary Root Cause Analysis"; suspected/
observed → "Incident Assessment"; inconclusive → "Incident Analysis — Cause
Inconclusive". Titles are evidence-based, service-name-first, deterministic.

Four independent state dimensions (§1): incident_status (active/recovering/
recovered/closed), analysis_status (observed/suspected/probable/confirmed/
inconclusive), impact_status (confirmed/detected/none_detected/not_observable/
unknown), ticket_status (not_opened/held/opened/escalated/closed). Old fields
remain, derived from the new canon.

View model (adapted to existing domain vocabulary):
ReportIdentity, StateSet, TimeWindow (first/last observed, recovered_at |
"not captured", duration, monitoring_until), Scope, SignalSummary,
EvidenceCoverage[] (state: anomalous/normal/no_data/not_configured/stale/
not_applicable + availability + counts + freshness), CloudChangeCorrelation[]
(relationship_type: same_resource/same_service/same_dependency/same_path/
same_account_region/temporal_only; causal confidence honestly qualified),
Hypothesis[] (supporting/contradicting/missing, confirm/disprove conditions),
Ownership (triage_owner default NOC, suspected_domain, candidate_teams,
escalation_owner, every recommendation carries a reason), Decision (policy-
driven monitoring window / auto-close / reopen / escalate thresholds),
Action[] (priority, owner, expected result, escalation consequence).

Honesty rules (§20) enforced in the builder, not the template: unknown ≠ 0,
missing ≠ healthy, correlated ≠ caused, one modality never confirms,
recovered ≠ resolved.

### Frontend

- Export button → downloads the server PDF (fallback: opens server HTML for
  browser print when the sidecar is off).
- Workspace badges/likely-causes consume the same report JSON where shown.
- `labels.ts` + `ai_labels.go` cascade gains app/saas/lb/dependency rungs and
  hypothesis-specific problem statements; default fallback becomes evidence-
  qualified ("Anomaly observed — cause undetermined"), never "Network change
  observed" without a change event.

### Evidence-coverage source of truth

Per-lane coverage state is computed server-side from (a) any tenant signals of
that lane in the window ± slack (telemetry flowing), (b) collector/feature
configuration (lane configured at all), (c) freshness of the newest lane signal.
"No data" is rendered as coverage absence, never as healthy evidence, and the
impact statement is telemetry-qualified ("within available telemetry coverage").

## 3. Sequencing

1. Backend `rca_report.go` view model + builder + unit tests (states, titles,
   times, signal summary, coverage, cloud correlation, ownership, decision).
2. Server HTML template + Gotenberg PDF + controlled headers; golden test.
3. Frontend export rewire + workspace badge/wording alignment + labels rungs.
4. Isolation tests (report/PDF/evidence/cloud-event cross-tenant 404s).
5. Rendered-PDF visual verification on live cases (C5 ipsec + SaaS-degraded),
   fix formatting, ship.
