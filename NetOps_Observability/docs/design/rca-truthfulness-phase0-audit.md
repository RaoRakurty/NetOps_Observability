# RCA Truthfulness Epic — Phase 0 audit findings

Companion to `rca-truthfulness-epic.md`. Facts with file:line citations; no fixes here.
Four slices: (A) signal production, (B) engine epistemics, (C) downstream decisions,
(D) report surface. Compiled 2026-07-13.

## Slice D — report surface (areas 23–25) ✅ audited

Canonical path: `GET /api/correlations/{id}/rca-report` → `serveRcaReport`
(`src/backend/rca_report_http.go:26-102`) → tenant-scoped `loadCorrSlice` →
`buildRcaReport` (`rca_report.go:421-722`, pure derivation, no stored prose) →
`rca_report_wording.go` → HTML template (`rca_report_html.go:132-375`) → Gotenberg
sidecar PDF (`rca_report_http.go:104-164`, fails closed 503 → html). A SEPARATE
legacy client-side export exists (`rcaExport.ts:364-408`, `window.print()`), divergent
from the server view model.

### D1. Title bug (observed live on case 63e57ada) — TWO defects
- (a) `signatureNocTitle` mislabels the whole IPsec/middle-mile family: `ipsec` token
  grouped with sdwan/overlay/tunnel and tested BEFORE the middle-mile branch —
  `ai_labels.go:171-172` (`→ "SD-WAN / tunnel change"`) vs correct branch `:177`
  (`middle-mile → "WAN / provider path change"`). `sig.ent.middle-mile.ipsec-underlay-down`
  is absent from the explicit map (`ai_labels.go:114-137`).
- (b) Title reads the persisted `top_hypothesis` SCALAR column (`rca_report.go:426`),
  never reconciled with the ranking blob (`decodeHypotheses`, `rca_report.go:363-394,423`);
  the workspace reads the blob (`rcaCase.ts:339-340`) — the two can disagree.
- Title subject = `scope.Services[0]` / `aiEntityLabel(scope.Targets[0])`
  (`rca_report_wording.go:436-441`) — the app endpoint IP stands in for the tunnel/VPN
  resource (epic Case-A "endpoint IP as root-cause object").
- `-v2` in report_id is just the correlation object version (`rca_report.go:694,427`);
  NO report cache/stored row — regenerated every request.

### D2. Cascade ladder NOT in the report — confirmed
- `rcaReport` struct has no causal_chain field (`rca_report.go:30-64`); the decoder
  `rcaHypBlob` parses ranking but omits `causal_chain` (`rca_report.go:363-394`).
- Data IS present in the same `hypotheses` blob — workspace consumes it
  (`rcaCase.ts:349-357`, `RcaWorkspace.tsx:397-411`).

### D3. Flagged strings — exact producers
- "Incident: Recovered": `rca_report.go:515-523` (state==closed → recovered;
  clears>0 → recovering); badge `rca_report_html.go:179`.
- "Recovered at: Not captured": `rca_report_html.go:198-199`,
  `rca_report_wording.go:661-665`; `RecoveredCaptured` only from observed `_clear`
  timestamps (`rca_report.go:614-617,457-468`).
- "Recovery signals: 0": `Clears = len(clears)` counting kinds ending `_clear`
  (`rca_report.go:457-468`; `rca_report_html.go:250`).
- "Analysis: Confirmed": `rca_report.go:533-540` from `verdict_tier`.
- "Customer impact: Confirmed": `rca_report.go:556-566` — confirmed iff
  analysis==confirmed && impactAnomalies>0 via `rcaIsImpactKind`
  (`rca_report.go:312-323,492-494`); sentence at `rca_report_wording.go:565-566`.
  Synthetic-only evidence CAN produce it (impact kinds include probe kinds).
- "Monitoring active/continues": `MonitoringUntil = recovered + SuppressFlappingSeconds
  (default 30m)` (`rca_report.go:629-635`) — never compared to Now
  (`rca_report_wording.go:589-590,673-674`) → reads active past its own interval.
- Escalation future-tense even when conditions already true:
  `rca_report_wording.go:590,408,356,380-384`.
- "N automated check(s)": literal `%d automated check(s)`
  (`rca_report_wording.go:546`; also `:508,680,682,691`).
- "Independent observers": `UniqueObservers = len(set(observer_id))` over all
  non-clear signals (`rca_report.go:470-472`) — NO provenance/execution dedup; one
  execution emitting several observer_ids inflates the count (§2/§3 conflation
  CONFIRMED at the report layer).

### D4. Tenant scoping
- On-demand generation; NO immutable RCA report history (report_* tables are the
  scheduled-delivery pipeline, unrelated: `migrations/0002_report_pipeline.sql`).
- Scoped read: `chTenantScope` (`flows.go:588-601`) + CH row policies via
  `chRowsScope` (`correlations.go:45`, `flows.go:603-611`); cross-tenant → 404.
- GAP: no dedicated cross-tenant report/PDF denial test — only
  `TestRcaReportEndpointRequiresPrincipal` (401 unauth, `rca_report_test.go:340-351`).

### D5. PDF + tests
- Server: Gotenberg sidecar (`REPORT_PDF_SIDECAR_URL`), controlled header/footer +
  pageNumber/totalPages (`rca_report_http.go:104-164`).
- Client: `rcaExport.ts` browser-print popup — different sections (topology SVG,
  confidence ladder), does NOT share the server view model (`rcaExport.ts:9-14`).
- Tests: string-level HTML golden only (`TestRcaReportHTMLGolden`,
  `rca_report_test.go:287-320`); no PDF/visual snapshot (epic §27 test 31 unmet).

## Slice A — signal production (areas 1–6, 26) ✅ audited

Path traced: `synthetics.go` (execution) → `probe_events.go` (wire) → Vector
`netops.probes` → `main.py:handle_probe` → `producers.probe_signals` +
`synthetic_normalize.synthetic_app_signal` → `netops.corr_signals`.

### A1. No test-definition / execution / observation / finding entities
- "Definition" = `synTarget{check,dst}` parsed from env (`collectors/synthetics.go:54-57,130-153`);
  no test_definition_id, expected status, baseline, capability, policy (§6/§8 absent).
- No execution record; `tick()` fans out and discards structure (`synthetics.go:157-224`);
  `ProbeEvent` (`probe_events.go:33-61`) has no execution/schedule id.
- `Signal` (`signals.py:230-286`): identity = `uuidv5(source|native_id|ts_ms)`; NO
  execution_id/observation_id/raw_event_id/lineage fields; no lineage columns in
  `to_ch_row` (`signals.py:288-319`).

### A2. One failed check = 2 unlinked signal rows (the §2 trap is structural)
`handle_probe` runs BOTH lanes on the same event (`main.py:1430,1449`, inserts
`:1437,1451`): failed HTTP → `probe_loss` (PATH lane, `producers.py:309,38,299-303`)
+ one semantic kind by fail_class (`synthetic_normalize.py:139-155`:
synthetic_dns_fail/tls_fail/tcp_connect_fail/timeout/http_5xx/http_4xx/http_fail);
failed ICMP → `probe_loss` + `synthetic_icmp_loss` (`:171-174`); failed TCP →
`probe_loss` + `synthetic_tcp_connect_fail` (`:165-168`). Co-timed, never id-linked.

### A3. Protocol detail partially measured, then flattened/dropped
Captured as flat scalars only: status_code, method, path, dns/connect/tls/ttfb/total
ms, cert_days/subject/issuer, fail_class (`synthetics.go:62-84,252-317` →
`synthetic_normalize.py:247-256`). Dropped before signal creation: DNS
qname/qtype/resolver/rcode/addresses; TCP reset-vs-refused nuance; TLS
version/handshake result/validity; HTTP expected-vs-actual/redirects/content
assertions; ICMP sent/recv counts + RTT distribution (collapsed to mean+loss,
`synthetics.go:477-482`).

### A4. Validation vs production is UNREPRESENTABLE (Case-B root enabler)
- `rca_canary`/"PDI validation": zero code recognition anywhere in src/ (hostname in
  demo seed only).
- Debug/lab demotion exists (`signals.py:95-165`, LAB_TEST/LOCAL_CONTAINER →
  DEBUG_ONLY `:142-143`; excluded from verdicts `verdicts.py:192,233`,
  `scoring.py:57`) BUT `ProbeEvent` never carries probe_intent/vantage_type →
  real prober arrives unclassified → inferred CUSTOMER_PATH/trusted
  (`main.py:1371-1400,1394-1398`).
- Synthetic app signals are HARDCODED probe_authority=HIGH,
  probe_scope=customer_path (`synthetic_normalize.py:234-237`) and `main.py:1447-1448`
  deliberately skips classify_probe for them — the demotion path can never touch them.
- `environment` read from attrs (`engine.py:1208-1210`) but no producer sets it →
  always defaults `"prod"` (`engine.py:645`).

### A5. "Device health" evidence from a synthetic-only case
Synthetic rows are all `active_probe` (`synthetic_normalize.py:270`,
`producers.py:311`); `device_telemetry` comes only from device/metric/cloud producers
(`producers.py:154,964`, cloud_producers.py, lb_normalize.py). BUT the catalog
declares `device_telemetry` in required-modality tuples on rows whose witness
alternation includes `synthetic_http_fail` (`catalog.py:1993,2002`) — so a
synthetic-only case can SURFACE a "Device health" evidence class in the report with
no device-telemetry signal produced. Case-B defect originates in catalog/report
layer, not producers.
## Slice B — engine epistemics (areas 7–13) ✅ audited

### B1. Observer/confirmed gate — SOUND (provenance-based)
- Witness model `verdicts.py:74-177`; confirmed gate `verdicts.py:356-369`: needs
  modality_count≥2 AND observer_count≥2 AND a cross-modality trusted independent
  pair AND no missing required modalities (thresholds `verdicts.py:71-72`).
- Two signals from ONE execution can NEVER confirm: both are observer_id=prober,
  modality=ACTIVE_PROBE (`synthetic_normalize.py:258-281`, `producers.py:290-335`)
  → modality_count=1, observer_count=1. Independence is provenance (observer_id,
  measurement authority, fate fingerprint `signals.py:168-189`,
  `verdicts.py:96-137`), not class labels.
- GAP (dormant fate gate): producers never stamp agent_host/source_egress/seam_id/
  schedule_id → `_fate_of` returns None and two None-fate witnesses are treated
  INDEPENDENT (`verdicts.py:106-108,132-133`) — fate-sharing protection never fires
  on the probe lane.

### B2. Recovery — engine has NO recovery model; "recovered" = quiesce aging
- Objects close by time-quiesce only: `main.py:943-954` (CORR_QUIESCE_S default
  900s, `main.py:235`) regardless of clear/recovery evidence.
- Report maps closed → "recovered" unconditionally (`rca_report.go:516-523`).
  RecoveredAt only from `_clear` evidence (`rca_report.go:460-467,614-617`); clears
  exist only on CUSUM metric episodes (`episodes.py:216-240`) — synthetic/probe
  lanes emit none. ⇒ "Recovered / Not captured / 0 recovery signals" (Case A) is
  the DEFAULT outcome for synthetic cases.

### B3. Customer impact
- `impact="confirmed"` iff analysis confirmed AND impactAnomalies>0
  (`rca_report.go:556-566`); probe kinds count iff probe_scope=="customer_path"
  (`rca_report.go:312-323`).
- `synthetic_app_signal` HARDCODES probe_scope=CUSTOMER_PATH +
  probe_authority=HIGH for every synthetic failure (`synthetic_normalize.py:234-238`),
  bypassing the intent×vantage derivation (`signals.py:139-165`).
- Synthetic-only tops out at verdict=suspected → impact="detected" (not confirmed);
  confirmed-impact defect requires a wrongly-confirmed verdict upstream.

### B4. Duration — window bounds only
Engine stores only window_start/end = min/max signal ts (`engine.py:611-612,
1191-1192`); no last_success_before/first_failure/first_success_after anywhere.
Report duration = to_recovery | elapsed_still_active | to_last_observation
(`rca_report.go:602-628`); single sample → 0 duration. §9 unimplemented.

### B5. Debounce — none
A single failed synthetic (HIGH) or probe_loss opens an object immediately:
severity_open_floor="high" singleton admission (`engine.py:79,1126,1134-1135`).
No N-consecutive/M-of-N/multi-vantage/sustained gate. Storm/quiesce/merge act
after opening (`main.py:923-954`).

### B6. Single-signal CRIT + confidence 1.0
- CRIT from legacy probe lane: `_loss_severity` ≥75% loss → CRIT
  (`producers.py:268-273`); z≥8 → CRIT (`producers.py:41-46`); synthetic app lane
  caps at HIGH (`synthetic_normalize.py:142-179`). That probe_loss has NO
  authority/scope attrs → fails-closed LOW authority (`signals.py:192-201`), does
  NOT count as customer impact, yet still drives the CRIT headline
  (`rca_report.go:442,486-489,704`).
- confidence = coverage × graph_support × direction_agreement (`scoring.py:199`);
  graph/direction default 1.0 (`scoring.py:139-143`), full clause match → 1.0
  (`scoring.py:173-174`). ORTHOGONAL to verdict tier (`scoring.py:16-18,325`) —
  numeric 1.0 + verdict suspected + lexical "Low" co-exist
  (`rca_report.go:585-599`).

### B7. Structurally OK (do not re-build)
- Kind→modality centralized (`confirmability.py:40-99`); app-identity excluded from
  grounding/observers (`engine.py:249-252`); token-overlap demoted + non-authoritative
  edges cap at suspected (`engine.py:1149-1162`); non-live data_class caps verdict
  (`engine.py:1141-1148`); debug/lab probes excluded from verdicts
  (`verdicts.py:233-239`, `scoring.py:56-62`); assess is fail-closed on unknown
  collection paths (`verdicts.py:167-169`).
- BUT §1 lifecycle states don't exist: `corr_objects.state` is only
  open/closed/merged (`src/backend/corr_schema.go:145,210`).
## Slice C — downstream decisions (areas 14–22) ✅ audited

### C1. saas-experience-degraded IS a symptom-as-hypothesis
`catalog.py:2851-2888`: title literally the symptom; ONE required clause satisfied
by a single synthetic failure (`:2859-2863`); owner hardcoded `app_team` (`:2877`);
optional 2nd-modality clause `lb_5xx|lb_target_unhealthy|app_error_rate_high|
flow_volume_anomaly` (`:2864-2865`) → synthetic+LB pair reaches CONFIRMED
(comment `:2846-2850`).

### C2. Root-cause object
Canonical report default is honest: `Identified:false, "Root cause has not been
identified."` — populated only when analysis==confirmed AND topo edges converge
(`rca_report.go:656-673,748-764`). BUT confirmed fault + converged topo entity is
treated as root-cause identification (§16 conflation), ObjectType hardcoded
"grounded entity" (`:664`), and the hostname/target still becomes the report's
headline SUBJECT via scope (`rca_report_wording.go:436-441,534-537`). No object-role
model (target/endpoint/faulty component/causal object) exists
(`rcaRootCause` `rca_report.go:221-228`).

### C3. Ownership — hardcoded per template, not localization-aware
`verdict.owner` literal on templates (app_team `catalog.py:2877`, netops `:526`,
isp `:570`); carried verbatim (`scoring.py:231,133`); `buildOwnership`
(`rca_report_wording.go:350-391`): every non-contradicted hypothesis's team becomes
a Candidate; confirmed → top team = EscalationOwner (`:378-380`) with NO app-layer
evidence gate. Localization state is not an input anywhere.

### C4. Severity — no incident-severity model
Report Severity = peak attached signal severity, nothing else
(`rca_report.go:90,442,486-489,704`); ticketing same max
(`ticketing_payload.go:48,71-88`). Synthetic/LB lanes emit HIGH
(`synthetic_normalize.py:142-179`, `lb_normalize.py:82-99`); CRIT only from
device/controller/cloud producers + legacy probe_loss ≥75%. SN priority from
verdict×peakSeverity (`ticketing_payload.go:173-185`): confirmed+HIGH → P2
automatically.

### C5. Ticketing — NO environment/validation gate (Case-B smoking gun)
- Sweeper fans out to servicenow/pagerduty/slack/jira per-policy
  (`ticketing_sweeper.go:182-226`, `ticketing_worker.go:42`).
- `evalTicketDecision` (`ticketing_policy.go:23-100`) has NO environment/
  signal_purpose/validation/canary/production_scope/paging_allowed field — only
  Internal (all-probe debug-scope, `rca_path_view.go:196-236`), ProbeOnly,
  verdict threshold, persistence, dedupe/flap.
- `scripts/rca-canary.sh` injects synthetic 503 + independent LB 503
  (`rca-canary.sh:66,70`, tenant t-rca-canary) — LB signal is non-probe →
  internal=false, two modalities → CONFIRMED → REAL tickets open in every
  connected system, owner "Application team" (`rca-canary.sh:15-20` documents live
  SN wiring). Nothing stops a validation canary from filing production tickets.
- Monitoring window: `MonitoringUntil = recovered + SuppressFlappingSeconds
  (default 30m)` (`rca_report.go:629-635`).
- Auto-close text verbatim requires "no recurrence and NO customer-impact evidence
  within the monitoring window" (`rca_report_wording.go:406`) — the §18 defect.
  EscalateWhen future-tense (`:408`). These are descriptive strings only: no code
  evaluates the window or auto-resolves (`ticketing_sweeper.go:241-252` only
  creates/updates).

### C6. Rule clauses surfaced as evidence
Matched clause kind-expressions (pipe strings) flow scorer→report as "Supporting"
evidence and root-cause evidence (`scoring.py:118-122,145-197`;
`rca_report_wording.go:315-345,331`; `rca_report.go:668`). `humanizeClauses`
rewrites them to operator phrases (mitigates literal rule syntax) but they remain
the signature's own clause labels, not sourced observations with
vantage/timestamp/independence basis (§15).

---

# Consolidated verdicts — the 15 "wrongly equates" questions

| # | Equivalence | Verdict | Where |
|---|---|---|---|
| 1 | signals from one execution == independent observers | ENGINE NO (gate needs 2 modalities+2 observers, B1) / REPORT YES (UniqueObservers counts observer_ids, no provenance dedup, D3) | verdicts.py:356-369 vs rca_report.go:470-472 |
| 2 | different evidence labels == independent evidence | NO in engine (provenance-based); YES in catalog-required-modality display (A5) | verdicts.py:96-109; catalog.py:1993 |
| 3 | probe-derived endpoint health == independent device health | Engine blocks it (app_identity excluded); report can DISPLAY "Device health" for synthetic-only cases via catalog tuples | engine.py:249-252; catalog.py:1993,2002 |
| 4 | black-box failure == root cause | PARTIAL: root honest by default, but confirmed fault + topo convergence ⇒ "root cause identified" | rca_report.go:656-673 |
| 5 | affected hostname == causal object | Not as RootCause.Object; YES as headline subject/title | rca_report_wording.go:436-441 |
| 6 | failed synthetic == real-user impact | YES: synthetic hardcoded customer_path/HIGH; impact "confirmed" whenever verdict confirmed + any impact-kind | synthetic_normalize.py:234-238; rca_report.go:556-566 |
| 7 | last anomaly == confirmed recovery | YES: quiesce-close → "recovered" unconditionally | main.py:943-954; rca_report.go:516-523 |
| 8 | no additional data == successful recovery | YES (same mechanism) | same |
| 9 | one failed sample == known duration | YES: window bounds only, no cadence model | engine.py:611-612; rca_report.go:602-628 |
| 10 | ICMP non-response == packet-loss fault | YES: no target-capability/baseline model; 100% loss → CRIT probe_loss | producers.py:268-273; §8 absent |
| 11 | signature rule conditions == case evidence | YES (humanized clause labels as Supporting/root evidence) | scoring.py:118-122; rca_report_wording.go:331 |
| 12 | confirmed symptom == confirmed fault domain | YES: no localization state exists; symptom-signature confirm ⇒ domain claims | catalog.py:2851-2888 |
| 13 | confirmed fault == confirmed root cause | YES via C2 conflation + "Analysis: Confirmed" umbrella badge | rca_report.go:533-540,656-673 |
| 14 | opened ticket == completed escalation | Escalation is future-tense prose; no execution record at all | rca_report_wording.go:408,590 |
| 15 | test fixture == production customer incident | YES: validation unrepresentable (A4) + no ticketing environment gate (C5) | synthetic_normalize.py:234-238; ticketing_policy.go:23-100 |

# Root causes of the two reports' contradictions

**P-F74D28 (IPsec):** (1) quiesce-close mislabeled "recovered" with no recovery
evidence model (B2); (2) umbrella "Analysis: Confirmed" hides
mechanism-under-investigation (no §1 state axes); (3) impact confirmed off
probe-scope customer_path hardcoding (B3); (4) auto-close wording demands "no
customer-impact evidence" ever (C5); (5) escalation future-tense with conditions
already true (D3); (6) monitoring-until never compared to Now (D3); (7) endpoint IP
as headline subject (C2/D1); (8) post-recovery healthy path not labeled as
validation (report has no post-recovery concept); (9) title mislabeled by ipsec →
"SD-WAN" substring routing + stale scalar (D1).

**P-814009 (SaaS canary):** (1) symptom-as-hypothesis template with hardcoded
app_team owner (C1/C3); (2) observer count without provenance (D3) + catalog
device-telemetry display tuple (A5) manufacture "two independent observers /
device health"; (3) validation unrepresentable end-to-end (A4) + no ticketing gate
(C5) → real P2 tickets from a canary; (4) protocol detail dropped before signals
(A3) → "HTTP, Packet loss" is all that survives; (5) no debounce → single execution
opens a case (B5); (6) severity = peak signal severity (C4); (7) no duration
bounds (B4); (8) rule clauses as evidence + "confirm or rule out" generic action
(C6); (9) root-cause object = hostname as subject (C2).

# Structurally sound — build ON these, don't rebuild
Engine confirmed-gate + provenance independence (B1); debug/lab demotion machinery
(exists, just unreachable for synthetics — A4); fail-closed verdicts on unknown
authority; grounding graph exclusions (B7); report's pure-derivation design +
Gotenberg fail-closed PDF (D5); tenant scoping via CH row policies (D4).
