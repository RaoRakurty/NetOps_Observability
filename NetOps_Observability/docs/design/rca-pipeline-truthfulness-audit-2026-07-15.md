# RCA pipeline truthfulness audit — Phase 0 (2026-07-15)

Scope: the complete incident-analysis → RCA output pipeline, audited before the
generic consistency/hardening redesign. All anchors are file:line at commit
`5195796`. The six reference reports (P-261D09, P-03C796, P-DF0A95, P-F4157A,
P-FEC191, P-FF7B75) are regression *examples*; every finding below is a generic
pipeline defect, not a per-case fault.

## 1. Where each decision originates

| # | Decision | Where |
|---|----------|-------|
| 1 | Raw event ingestion | `correlation/main.py:1199` `consume()`; per-lane handlers `handle_metric:1288`, `handle_syslog:1689`, `handle_flow:1747`, `handle_probe:1483`, `handle_snmptrap:1527`, `handle_cloud:1586`, `handle_app_identity:1618`, `handle_controller_event:1565`, `handle_app_edge:1657` |
| 2 | Probe execution records | `handle_probe` → `producers.py` probe signals; per-signal observer/authority `signals.py:230` |
| 3 | Flow observations | `handle_flow:1747`, `producers.py` flow sampling |
| 4 | Cloud audit/health | `cloud_producers.py`, `cloud_log_parsers.py` |
| 5 | Device health | `handle_metric` → CUSUM episodes `episodes.py:115` |
| 6 | Routing/link | syslog/trap control-plane producers `producers.py:411-845` |
| 7 | Normalized signals | `signals.py` `Signal` dataclass; dedup by signal_id `main.py:698-708` |
| 8 | Derived findings/verdicts | `verdicts.py:324` `assess`; `scoring.py:139/266` |
| 9-10 | Evidence grouping/class | nodes `engine.py:244`; grounding class/rank `engine.py:349` |
| 11 | Evidence independence | `verdicts.py:96` `Witness.independent_of` (observer + measurement authority + probe fate); dedup `verdicts.py:225` |
| 12 | Incident grouping | union-find components `engine.py:1042`, `run_window:1080` |
| 13 | Incident lifecycle | **only `open`/`merged`/`closed`** — `engine.py:944`, transitions in `engine_cycle` `main.py:834-957` |
| 14 | Recovery processing | **none in Python** (see D1). Go side: `rca_report.go:668-778` |
| 15-18 | Fault domain / object / mechanism / root cause | verdict tier from winning signature `scoring.py:325`; Go: `rca_report.go:875-891` (dimensional states), `:1012-1070` (root-cause object) |
| 19 | Impact | Go: `rca_report.go:811-839`; wording `rca_report_wording.go:724-741` |
| 20 | Severity | **peak of attached signal severities** `rca_report.go:703-708`; ticket side `ticketing_payload.go:73-90` |
| 21 | Ticket rec/exec | `evalTicketDecision` `ticketing_policy.go:23-107` (pure) vs async sweeper/outbox `ticketing_sweeper.go:164-228`, `ticketing_worker.go:130-227` |
| 22 | Escalation | derived **in the report builder** `rca_report_wording.go:550-558` |
| 23 | Ownership | `buildOwnership` `rca_report_wording.go:450-504`; owner token map `rca_report.go:371-375` |
| 24 | Hypotheses | signature catalog `catalog.py`; ranking blob → `buildHypothesesView` `rca_report_wording.go:414-446` |
| 25 | Next actions | `buildActions` `rca_report_wording.go:770-830`; expected output = substring map `firstStepExpectedOutput:508-533` |
| 26-27 | Management/NOC summaries | `buildManagementSummary:685-766`, `buildNocQuickRead:834-931` |
| 28 | Report view model | `buildRcaReport` `rca_report.go:616-1133` (pure derivation, not persisted) |
| 29 | HTML/PDF | `rca_report_html.go`, Gotenberg `rca_report_http.go:108-164` |
| 30 | Historical reconstruction | `?version=` → `loadCorrSlice` `correlations.go:414-535` (deterministic rebuild) |
| 31 | Tenant scoping | `chTenantScope` on all slice reads `correlations.go:433-527`; ticketing store `(tenant, cross)`-scoped; sweeper stamps object tenant `ticketing_sweeper.go:132-219` |

## 2. Recurring generic root causes (defects)

**D1 — Recovery has one level.** The engine has no recovery at all (closure =
silence + quiesce, `main.py:948-957`). The Go builder treats ANY observed clear
or `*_status up` event after first anomaly as full-incident recovery
(`rca_report.go:752-778`): `recovered` = max clear ts, with **no check that
anomalies continued after it**. A tunnel-up at T while probes fail until T+9m
yields `recovered_at = T`, duration `to_recovery` (T − onset, e.g. "11
seconds"), incident `recovered`, and a monitoring window starting at T
(`:969-978`). This is the root of regressions B (P-03C796/P-F4157A) and C
(P-DF0A95/P-FEC191). Component recovery, service recovery, and lifecycle are
one variable.

**D2 — Fault-condition confirmation is presented as root cause.**
`analysis=="confirmed"` (the signature verdict tier, i.e. a confirmed fault
*condition*) drives: report type "Root Cause Analysis"
(`rca_report.go:1144-1155`), management sentence "The root cause is confirmed."
(`rca_report_wording.go:745`), `RootCause.Identified=true` from **seam
grounding or topo-locus convergence** (`rca_report.go:1019-1066` — the seam is
a localization domain, not a causal object), `mechanism=confirmed`
(`:884-890`), and `rootState=confirmed` (`:1073-1078`). No causal mechanism or
causal object is ever established.

**D3 — Severity = max attached signal severity.** `rca_report.go:703-708` and
`ticketing_payload.go:73-90`. A single CRIT-labelled flow anomaly becomes a
CRIT incident (regression D, P-FF7B75). No corroboration, persistence, scope,
or impact inputs; no reason codes.

**D4 — Impact claims are not observability-aware.** `impact="none_detected"`
whenever an active_probe/passive_flow lane has ≥1 observation
(`rca_report.go:815-821`) — no temporal-coverage or relevance check, so
9-of-15-minutes flow coverage renders "No customer impact was detected…".
`flow_volume_anomaly` is in the real-user impact set (`:444-453`) and becomes
`impact_real_user=confirmed` when analysis is confirmed (`:831-839`) — a
volume delta is an indicator, not confirmed user impact.

**D5 — Actions are not validated against participating evidence.**
`buildActions` copies the top hypothesis's catalog `first_steps` verbatim; the
expected output is keyed by **substring** on the step text
(`firstStepExpectedOutput:508-533`) — `strings.Contains(l,"sa")` matches
"SaaS" (the IKE/child-SA expected-output on a SaaS/flow case, regression D),
"dns" matches "dns" inside other words, etc. Nothing checks that the evidence
class an action interrogates actually participated (Direct Connect/BGP steps on
a flow-only cloud case, regression A). No operational P1/P2 priority exists.

**D6 — Ticket state and escalation state read different sources and are never
reconciled.** Ticket = persisted link (`rca_report.go:893-908`, `held` only
when `analysis != confirmed`); escalation = live derivation
(`rca_report_wording.go:550-558`). A confirmed case with no ServiceNow
connection or an un-swept outbox renders "Ticket: not_opened / Escalation:
TRIGGERED" with no explanation. The pure policy decision
(`evalTicketDecision`) with its hold reason is **not consulted by the report**.

**D7 — Hypothesis rows can contradict themselves.** `rcaHypothesis` has
`Label` (confidence) and `Contradicted` rendered independently
(`rca_report_html.go:440-448`); a blob row with `confidence_label: confirmed`
+ `contradicted: true` renders both. No `observation_state` vs `causal_role`
split — "IPsec tunnel down (confirmed observation, ruled out as origin)" is
inexpressible.

**D8 — Carrier/provider ownership without demarcation.** `rcaOwnerTeam` maps
verdict owner tokens (isp/carrier/cloud_provider) straight to the escalation
owner when analysis is confirmed + root "identified" (`rca_report_wording.go:
473-498`). No demarcation assessment exists.

**D9 — Path temporal role.** Spine staleness is measured against `time.Now()`,
not the incident window (`pathgraph/model.go:234-238`); a post-incident healthy
capture within freshness is shown without a temporal-role caveat
(`path_graph_api.go:251`). Drop-point wording uses banned phrases ("went
dark", "where it breaks", `rca_report_http.go:191`).

**D10 — Independence blind spot.** Witness independence is observer+authority+
fate-based (`verdicts.py:96-120`), which is sound, but two witnesses with **no
fate metadata** are treated as independent (`_fate_of → None`), so derived
kinds lacking co-location attrs can double-count toward the ≥2-observer gate.
The report additionally surfaces `unique_observers` without evidence-group
counts (API/collector/vantage conflated in one number).

**D11 — No consistency gate.** Nothing validates the finished report for
contradictions (recovered_at < last anomaly, closed+not_observed recovery,
action/evidence mismatch, symptom ranked as cause) before render/ticket/page.

**D12 — Banned wording.** "went dark"/"where it breaks"
(`rca_report_http.go:191`), "would be owned by" (`rca_report_html.go:444`).

Positive findings (kept): no hardcoded case IDs/IPs/titles anywhere in the
pipeline; raw signature boolean expressions are already humanized
(`humanizeClause`); validation scenarios are suppressed at the ticket policy
(`ticketing_policy.go:43`); tenant scoping is enforced end-to-end; the report
is a pure, replayable derivation (no stored narrative).

## 3. Fix architecture (implemented in this series)

The required chain (canonical facts → provenance/coverage → phases → generic
assessments → issue-family interpretation → consistency validation →
audience narratives → render) is realized in the Go report composer, which is
the single place all six regressions manifest and the last gate before
report/ticket/escalation emission:

- `rca_recovery.go` — RecoveryReconciler (component vs service recovery,
  recovery levels, closure gates) + IncidentPhaseBuilder (D1).
- `rca_report.go` — fault/root-cause separation (D2), observability-aware
  impact (D4), incident-severity model with reason codes (D3), demarcation
  (D8), ticket/escalation reconciliation via `evalTicketDecision` (D6).
- `rca_actions.go` — contextual ActionPlanner: evidence-gated steps,
  token-correct expected outputs, operational P1/P2 (D5).
- `rca_consistency.go` — StateConsistencyValidator + ReportQualityGate (D11);
  quality record embedded in every report; errors downgrade the document.
- Hypothesis taxonomy fields observation_state/causal_role/candidacy (D7).
- Wording bans enforced by test (D12); path temporal role note (D9).
- Table-driven scenario harness (30 generic scenarios incl. the six
  regressions) with cross-scenario invariants + randomized property test.

The Python engine deliberately stays fact-producing (open/merged/closed +
signals); recovery semantics remain a read-time derivation so historical
reports are reconstructed under the corrected rules too.
