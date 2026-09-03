# Project 4 — Troubleshooting protocols (+ frontend-wave list)  🟡

**Goal:** rebuild Troubleshooting into a **symptom-first investigation** surface
that saves the NOC operator from "100 windows," plus the **BGP/OSPF/ISIS
collect→analyze** diagnostics, plus finish the owner's original frontend/product
wave list and enhance IRIS.

**Model rule:** Fable specs/designs; Opus builds every page/handler + tests.

## A. Troubleshooting rebuild (item 7) — ✅ built + tested, DEPLOY PENDING
Research: `TROUBLESHOOTING_PAGE_RESEARCH_2026-08-25.md`. Design: symptom-first
verdict header (correlation engine) → parallel evidence lanes (DEM, what-changed,
device/protocol health, path, routing/BGP, flows, correlated events) → IRIS
co-pilot → seam-owned handoff.
- [x] **Investigation surface built** (`src/pages/troubleshoot/Investigation*`,
  `investigationModel.ts`, `IrisLane.tsx`; `RcaCaseHeader` extracted from
  RcaWorkspace so a case shows the SAME verdict header, not a second one).
  Troubleshooting now switches three sections with Investigation as the DEFAULT;
  the June collection-pipeline board stays reachable for one release.
- [x] **Tested** — 236 frontend tests across 6 files (model 80, lanes 46, page 37,
  IRIS 36, section switch 22, RCA header 15); full suite 1868 pass, tsc clean.
  Pinned: the honesty contract (`not_connected` ≠ `empty`, ladder rungs earned
  from lane state), the deep links, and §15 (model output rendered as escaped
  text, citation hrefs restricted to same-origin relative paths).
- [ ] Needs deploy to verify against live data.

## B. Protocol diagnostics — collect → analyze — ✅ built end to end, DEPLOY PENDING
Design: `TROUBLESHOOTING_PROTOCOL_DIAGNOSTICS_2026-08-27.md` (owner spec).
- [x] **Backend foundation built + Fable-verified** (`9a0a4e2e`, internal/protocoldiag,
  89% cov, gate-clean). 15-issue matrix (5 BGP/5 OSPF/5 ISIS), Cisco full +
  Juniper/Nokia declarative via netconcepts; Collect w/ read-only guard
  (fail-closed) + CommandRunner iface (live SSH source wired later, see below); Analyze
  signatures (fail-closed, no invented cause); redaction + TAC export.
- [x] **HTTP API wired + Fable-verified** (`e520a0b7`, 2026-08-28) — 3 handlers
  under `/api/troubleshoot/protocol-diagnostics/{catalog,analyze,collect}`;
  catalog/analyze `requirePerm(infrastructure,Read)`, collect `…Write`. §3a:
  collect resolves device via `canSeeDevice` → cross-tenant/unknown = 404, tenant
  stamped from device not body; analyze request-scoped, tenant from token.
  Fail-closed: collect w/o CommandRunner → 503 (no fake capture), analyze bounds
  body (MaxBytesReader) + honest "no signature matched". 11 tests incl. cross-org
  isolation all pass; build/vet/staticcheck/gosec/govulncheck clean (−race is
  CI-only — no C compiler locally; handlers race-safe by construction).
- [x] **Live SSH command source wired** (2026-09-02) — the collect endpoint is no
  longer permanently 503. `internal/protocoldiag/sshgw.go` (SSHGateway: injected
  credentials + host-key check, no PTY/stdin, hard output cap, ctx deadline pushed
  onto the socket) + `sshrunner.go` (read-only guard → CLOSED per-vendor command
  table → one-in-flight-per-device → bounded IO) are connected in
  `src/backend/protocol_diag_gateway.go`, mirroring `configGateway()`/`pcapGateway()`
  exactly: the SAME vendored `x/crypto/ssh` client, the SAME `s.sshHosts` pinned
  host-key TOFU custody, the SAME `sshDialTimeout()`, the SAME vault-sealed
  credential handling.
  - **Flag:** `FEATURE_PROTOCOL_DIAG_COLLECT` (default **false**, dormant like
    `FEATURE_DEVICE_SSH`). Off ⇒ no gateway/runner constructed,
    `srv.protocolCollector` stays nil, `POST …/collect` answers the same honest
    503. Catalog + Analyze are unaffected — neither touches a device.
  - **Credential precedence:** dedicated `PROTOCOL_DIAG_SSH_USER` +
    `PROTOCOL_DIAG_SSH_PASSWORD` or `_KEY` (vault-sealed, decrypted under the
    distinct field ids `protocoldiag.collect.password` / `.key`) wins; when ALL
    THREE are unset it falls back to the config-backup capture identity
    (`CONFIG_BACKUP_SSH_*`), already a least-privilege read-only account on the
    same devices. A **partially** configured dedicated identity (user with no
    secret) is a hard error, never a silent fallback onto a different account.
    `PROTOCOL_DIAG_SSH_PORT` (default 22) supplies the port the inventory row
    does not carry.
  - Plumbed through compose / `install.py` / `update.sh`; contract-guarded by
    `tests/test_compose_new_modules.py`.
- [x] **Frontend panel** (`5b0be333`) — BGP/OSPF/IS-IS issue matrix from the
  catalog, device picker, Collect (honest 503 → paste outputs), Analyze with
  matched/no-match states, redacted TAC bundle download, Correlate link.
- [ ] Deploy with `FEATURE_PROTOCOL_DIAG_COLLECT=true` + a read-only diagnostics
  credential on the lab and run one live collect per protocol.

## C. IRIS enhancement (item 8) — Phase A ✅ BUILT 2026-09-02; model decided
Roadmap: `docs/design/IRIS_ENHANCEMENT_ROADMAP_2026-08-28.md`. **Design of record
for how Iris troubleshoots from here: `docs/design/IRIS_TROUBLESHOOTING_MODEL_2026-09-02.md`**
(owner 2026-09-02: NetClaw is the reference model, built in-house; the owner's own
troubleshooting documentation is the knowledge source).
- [x] **Phase A — auto-troubleshoot reach + routing-inversion fix** (2026-09-02).
  Skills layer `src/backend/ai/skill*.go` + 14 `ai/skills/<name>/SKILL.md`
  (strict dialect; loader validates every tool/arg/entity/`next=` against the
  real registry, exactly one entry method `osi-bisection`). Five read-only tools
  `run_protocol_diagnostic` · `get_security_findings` · `get_topology_context` ·
  `get_case_timeline` · `get_rca_verdict` (`ai/troubleshoot.go`), server deps in
  `ai_troubleshoot_deps.go` using the SAME gates as the HTTP handlers
  (`canSeeDevice`, `chTenantScopeFor`, `secapi.ListFindings`); cross-tenant →
  ErrNotFound. Free-form troubleshooting questions now run classify → select
  skill → server-planned gather (Policy-Engine re-gated per tool) → model
  narrates → citation verifier; the model chooses NO tool. The `capability`
  dead end is now offered to the skills layer first. 136 ai tests + root
  isolation suite; gate green. UI: skill chip + provenance in `IrisLane`.
- [x] **A2 — bounded skill chaining** — SHIPPED 2026-09-02. `ai/skill_chain.go`:
  ≤4 rounds, ≤6 tools/round, ≤16 tools/turn, 45s wall-clock, every budget
  disclosed. Next skill chosen by authored MACHINE conditions first (closed
  grammar: `signature=` · `tool:<name>=` · `evidence:kind=` · `verdict:tier=` ·
  `verdict:phrase=` · `note=`, unknown key = loader error), else by a model
  choice restricted to that skill's own declared `next=` targets (refusals
  audited as `model_selected_invalid`, the name never logged). Evidence
  accumulates deduped + capped; entities resolved once per turn (no scope
  widening). `Answer.Chain` + `round`/`selected` on every audit entry; the
  breadcrumb renders in `IrisLane`. Spec §3.1 of the model doc.
- [x] **A3 — show-first state battery + `internal/showparse` parser library**
  (Genie-equivalent; skip-on-unparseable; parallel failure-isolated collection)
  — SHIPPED 2026-09-02. `internal/protocoldiag/statebattery.go` + `fanout.go` +
  `typedbridge.go`; 14 specs × 8 dialects, 77 (command, dialect) parsers, every
  optional field a pointer (absent means absent). Spec §3.2.
- [x] **A4 — `get_device_state` + read-only BGP operations tools** — SHIPPED
  2026-09-02. `ai/troubleshoot_state.go` (`get_device_state(device_id, area,
  target?)`, closed 7-area vocabulary pinned to `protocoldiag.Areas()`, per-area
  target rules, per-area prompt caps, stable `state:<area>:<device>:<n>`
  citations) over a new `TroubleshootDeps.DeviceState` seam using the SAME gates
  as the collect endpoint (tenant-scoped ResolveDevice, infrastructure **write**
  for a live read, honest `NotWired` + the read-only command list otherwise,
  unparsed output labelled UNPARSED and quoted rather than typed).
  `ai/troubleshoot_bgp.go` adds read-only `get_bgp_watchlist` ·
  `get_bgp_rpki` · `get_bgp_feed_recent` (tenant-scoped exactly as `/api/bgp/*`;
  no write path). New closed condition family `state:<facet>=<value>` over 8
  facets, loader-validated and only authorable by a skill that gathers state;
  9 SKILL.md files now gather state FIRST. The design's chain fixture runs twice
  — once on the engine's verdict phrase (A2), once on `state:bgp_peer=idle` read
  off the device (A4). Spec §3.2/§3.4. Remaining A4: the ENGINE-side proactive
  sweep (symptom rules that fire unasked) — Iris reads and narrates, it does not
  yet sweep.
- [ ] **Knowledge ingestion** — owner drops docs in `docs/knowledge/inbox/`;
  Fable distils to SKILL.md (+ CommandTable/signature entries) with `source:`
  citations; owner reviews prose; golden evals per skill. Spec §3.3. Waiting on
  the first drop.
- ✅ **Phase B — investigation memory** (2026-09-02). Tenant-scoped memory of
  CONCLUDED investigations: `ai/investigation_memory.go` (row, FileStore + PG
  store), `ai/investigation_pending.go` (the concluded→judged bridge),
  `ai/recall.go` (`recall_investigations`), migration
  `0040_iris_investigations.sql` (`tenant_iso` FORCE-RLS, per-tenant retention
  cap, no unscoped list). A row is written ONLY when an operator judges the
  answer on the existing feedback path (up → confirmed, down → wrong); the
  case-close trigger is not wired because no in-process hook exists (closure is
  authored by the Python engine into ClickHouse) — recorded in the design doc.
  Memory is surfaced as at most 5 clipped, `memory:<id>`-cited evidence rows with
  the outcome stated and the "verify current state first" rule attached, and it
  declares NO chain signal: memory is evidence, never a routing rule. The loader
  refuses a skill that gathers memory before live state; `osi-bisection`,
  `bgp-session-down` and `interface-down` gather it last. Cross-org isolation
  test + PG RLS test shipped. Spec §3.5.
- [ ] A4 ENGINE-side proactive sweep (unsolicited symptom rules for the
  heartbeat list) · Phase B **guide** (the remaining half: a guided,
  operator-facing walkthrough) · Phase C human-in-the-loop actions
  (P6, separate subsystem) · Phase D interop.

## D. Frontend-wave items (owner's original 13-item list)
Full audit: `docs/FRONTEND_WAVE_TRACKER.md`.
- ✅ Done+deployed: #3 device font · #5 monitor rules · #6 topology reset ·
  #12 scorecard summary · #13 admin menu · #1 perf-wave-1 · #1.1/2 copy pass.
- 🟡 Partial, to finish:
  - [ ] **#4** per-device "interfaces grouped by VRF" detail view (dialect +
    telemetry done; the device-detail UI remains).
  - [ ] **#10** BGP depth — live RIS/BMP feed + local buffer, RPKI/ASPA/geofeed
    panels, **AS-path graph** (design `91df4f62`), AI-over-BGP-tools.
  - [ ] **#11** OSPF advanced + **IS-IS advanced** monitoring — **the depth
    collectors now exist; IS-IS is LIVE-ATTESTED 2026-09-02 (gnmic restarted on the
    deployed stack after `b59111a0`: `device_isis_lsp_count` / `_spf_runs_total` /
    `_area` / `_adj_hold_seconds` present in VictoriaMetrics from the SR Linux
    spine), OSPF stays `doc_claimed` (no OSPF SNMP device in the lab).**
    `internal/igpmon` serves `GET /api/protocols/{ospf|isis}/{adjacencies,
    summary,health}` (infrastructure:read; wired in `igpmon_deps.go`, routes in
    `main.go`, ledger + `igpmon_deps_test.go` cross-org test). Adjacency history
    is the typed syslog/trap `{ospf,isis}_adjacency_change` signals read at
    `chTenantScope`; adjacency state now is `device_isis_adj_state` /
    `device_ospf_nbr_state` read with the caller's `extra_filters[]`.
    **The four "advanced" gaps are now collected** (fidelity ledger:
    `docs/design/telemetry-coverage-reference.md` § F): LSP/LSA database size,
    area membership, SPF-run counters and adjacency/interface timers.
    IS-IS ships four gNMI series from the SR Linux native model
    (`device_isis_lsp_count` / `_area` / `_spf_runs_total` / `_adj_hold_seconds`,
    subscriptions `srl-isis-db` + `srl-isis-timers`), every path READ OFF lab
    spine1 and the canonical output replayed through gnmic's own engine in
    `tests/test_gnmi_correlation_lane.py`. OSPF ships five OSPF-MIB series in the
    generic SNMP profile (`ospfAreaLsaCount` / `ospfAreaStatus` / `ospfSpfRuns` /
    `ospfIfHelloInterval` / `ospfIfRtrDeadInterval`), OIDs index-resolved against
    the vendored MIB. These are MONITORING series: none was added to
    `rcaMetricFamilies`, and a test asserts they stay off the correlation bus.
    Every response carries `coverage{events,live_series,lsdb,areas,spf_runs,
    timers}` — four separate depth flags, because the four probes are separate
    reads that fail independently — and an absent source is **null + a note
    naming the series and its transport, never 0**. UI:
    `src/pages/igp/IgpAdjacencies.tsx` (depth blocks, per-device roll-up
    columns, an IGP-timers panel, per-adjacency hold on the IS-IS row).
    Still open: (a) **deploy** — the gnmic collector has not been restarted with
    the new subscriptions, so the IS-IS series are `lab_validated`, not
    `live_validated`, and nothing is in VictoriaMetrics yet; (b) there is still
    no OSPF-speaking SNMP device on the lab, so not one OSPF series (state or
    depth) has ever returned a row; (c) `telemetry-catalog/` does not yet carry
    the nine families — that needs an `area` identity entity and two capabilities
    `normalize.py` lacks (§ F.3 lists them).
  - [ ] **#1** perf wave 2 (measured budgets, high-EPS render) · **#1.1/2**
    confirm full-site copy coverage.

## E. Finish
- [ ] Owner runs **`/code-review ultra`**.
