# NMS-first plan of record — 2026-10-24

Authority for the NMS-only programme. Engine context: `src/correlation/CLAUDE.md`. Verified items marked ✔ were re-checked in code by the main session; others are researcher findings to verify before building on them.

Owner decision (binding): build every feature assuming the NMS integration is the ONLY source; SNMP is a welcome second source; applies to all integrations.

## Owner decisions — DECIDED 2026-10-24
- **D1 (owner-revised):** correlation strength comes from STRUCTURE — independent observations from different parts of the network converging on one shared element, with the healthy parts as contrast — not from the same alarm via several sources. The engine already ranks competing hypotheses (scoring.py); what changes is the verdict gate's independence rule (verdicts.py): each edge's own observation relayed by a controller counts as its own witness, so structural fan-in can reach CONFIRMED from controller data alone. Two integrations of one controller remain ONE witness. A single-entity, single-observation claim stays suspected. Syslog/probes are optional corroboration. (Owner's sample case — all branch→controller tunnels down while branch↔branch stay up ⇒ controller-site WAN link — is one instance of the general rule, not a special case.)
- **D2** controller-confirmed incidents are *suggested* for promotion; auto-promotion stays on CONFIRMED.
- **D3** probes toward controller-learned TLOC addresses: opt-in per integration.
- **D4** connector-down pages as an instance of the existing "ingest silent" class (still four page conditions).
- **D5** connectors without a verifiable payload ship badged "unverified".
- **D6** delete the Provider copy of RETAIL's vManage integration (row 365).

## Verified findings (main session ✔)
- ✔ Severity vocabulary (fixed on fix/controller-severity-vocabulary).
- ✔ F6 webhook empty secret accepted: Meraki ConstantTimeCompare("","") (nms/meraki.go:100-110), generic HMAC empty key (nms/generic.go:85-96).
- ✔ F12 scripts/test-plan.py:70 HIGH_RISK names src/backend/migrations/* (doesn't exist; real: src/backend/internal/platformdb/migrations/) → migration PRs under-tiered.
- ✔ Controller lane trusts payload tenant: handle_controller_event never calls verified_tenant (correlation/main.py:12796-12814) → T0 (§3a).
- F1 (plausible, unproven) unresolved controller key stays raw in `device` label (nms/identity.go:78-80); metric scope {device=~ids} (metrics_query.go:150); client-chosen device ids (main.go:4359) → tenant could read another tenant's unresolved series. T0 test decides.
- F2 alertTenant derives owner only via discovery.Get(DeviceID) (alert_episodes.go:99-121) → connector/unresolved alerts become platform-owned.
- F3 BFD/control transitions carry no TunnelID/PeerID (sdwan_state_events.go:54-75) → two tunnel ends never meet.
- F4 recovery emitted under fault kind (controller_bfd_down sev info).
- F5 SDWANStateChangeEvents hard-codes Vendor cisco for every vendor (sdwan_state_events.go:57).
- F7 catalyst_center spec Webhook:true but registry webhook nil.
- F8 IngestPipelineSilent guarded by SNMP-only collector_targets_reachable>0 (rules-scale-slo.yaml:528-533) → NMS-only installs have NO ingest-silent page.
- F9 controller contradiction/staleness handling is prose only; evidence_role unconsumed in src/correlation.
- F10 any stream error marks the whole run error (scheduler.go:298-304).
- F11 capability.go fidelity ladder declared only by catalyst_9800.
- All controllers of all vendors share ONE authority (controller_events.py:156-158 + verdicts.py:181-183) → even two different controllers can't co-confirm.
- Late stats can't corroborate live incidents (engine decay 300 s engine.py:85; metrics >1 h dropped main.py:926).
- Scheduler serial across tenants; dead controller ~2.6 min/cycle of retries; rate bucket rebuilt every cycle (scheduler.go:280); vManage/CatC/NDFC/Versa unlimited.
- Row 349 stale (most steps shipped; residue = steps 8→366, 10 seam R6, 12 quorum shared cause, 13 gNMI, 4 GETBULK unconfirmed).

## First-class only-source contract (C1–C8)
C1 inventory (Batch.Devices, chassis serial, version, role, reachable, site) · C2 faults/state (canonical severity, closed kind set, resolved device or ctl-id fallback, PATH kinds carry canonical TunnelID=sorted (sysA,colA)|(sysB,colB) + PeerID, explicit recovery, vendor/product from spec) · C3 freshness (observed_at, data_class event|realtime|bucketed) · C4 health metrics (netops_nms_poll_runs_total, last_success_timestamp, duration, auth_failures, devices_reported/unreachable, integrations_enabled; per-stream RunRecord) · C5 realtime controller metrics to netops.metrics (age-gated) · C6 topology facts (OverlayDeviceFacts; new source-neutral AdjacencyFact) · C7 webhook fail-closed on empty secret · C8 tests (recorded fixtures per stream + README provenance, §3a isolation incl. identical system-ips in two orgs never merge/pair, pgintegration).
Enforced by nms/contract_matrix_test.go TestConnectorContractMatrix (streams servable, Spec.Webhook==registry, C1–C7 declared fail-closed, fixture replay shape for lab_validated+, Go↔Python kind guard). UI renders the matrix.

## Tranches (impact on correlation/RCA order)
- **T0** controller identity + path hardening (ctl-id fallback, TunnelID/PeerID, recovery state, vendor from spec, webhook fail-closed, via_controller:<instance>) — HIGH-RISK; F1 isolation test.
- **T1** connector health metrics, per-stream status, worker pool + deadlines + breaker + persistent rate buckets, NMSIntegrationDown (warning) + NMSIngestSilent (page, D4), alertTenant integration lookup, watchdog check; fix F12 first — HIGH-RISK; closes 368 product half.
- **T2** confirmability per D1: verdicts.py independence counts per-edge observations relayed by a controller (canonical controller identity, never integration id), plus enrichment includes unambiguous controller devices (telemetry_enrichment.go:77), C5 metrics, F9 — HIGH-RISK; INVARIANTS rows.
- **T3** contract matrix test + capability declarations, F7, Versa stream truth, UI matrix.
- **T4** controller topology (OverlayFactSource from vManage BFD/approute/control) + 366 persistence (migration 0061 FORCE-RLS) — HIGH-RISK; rewrite 349 to residue.
- **T5** API-only device page (364): reachability from controller state w/ age, version fallback, serial, interfaces, hide SSH/backup.
- **T6** rules on controller signals (357): state gauges, ControllerBFDSessionDown / ControlConnectionsLost / DeviceUnreachable, stats rules with ≥90m lookback + data_class: delayed.
- **T7** vManage scale + webhook (358a/b) — HIGH-RISK.
- **T8** Catalyst Center · **T9** Meraki · **T10** Versa · **T11** NDFC/Prime/generic/9800 — one connector per PR, recorded payloads (DevNet sandboxes: SD-WAN 20.10 always-on, CatC 2.3.3.6 always-on, Meraki reservable; Versa/NDFC none found).
- **T12** provider-mode vManage + version matrix (358c/d) — HIGH-RISK.
- Cross-cutting rows: N-5 audit of SNMP-presence assumptions (IngestPipelineSilent, CollectorAllTargetsUnreachable/NoSamplesIngested rules.yaml:1075-1083, watchdog, reachability, enrichment); N-6 F12.

## Unverified (capture/doc before building)
vManage BFD src/dst IP field names; serial source field; aggregation = "bulk" for rate limits; CatC rate limits/topology shape/events path; Meraki linkLayer; Versa/NDFC sandboxes; read-only role on SD-WAN sandbox; ResolveDeviceOS root cause for missing version; F1 exploitability.
