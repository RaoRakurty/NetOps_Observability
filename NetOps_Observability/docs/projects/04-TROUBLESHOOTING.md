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
- [ ] **A2 — bounded skill chaining** (≤4 rounds; authored decision rules first,
  model may pick only among a skill's declared `next=` targets; chain shown as
  provenance). Spec §3.1 of the model doc.
- [ ] **A3 — show-first state battery + `internal/showparse` parser library**
  (Genie-equivalent; skip-on-unparseable; parallel failure-isolated collection).
  Spec §3.2. Largest piece.
- [ ] **Knowledge ingestion** — owner drops docs in `docs/knowledge/inbox/`;
  Fable distils to SKILL.md (+ CommandTable/signature entries) with `source:`
  citations; owner reviews prose; golden evals per skill. Spec §3.3. Waiting on
  the first drop.
- [ ] A4 proactive checks mapped onto the engine · Phase B guide/memory ·
  Phase C human-in-the-loop actions (P6, separate subsystem) · Phase D interop.

## D. Frontend-wave items (owner's original 13-item list)
Full audit: `docs/FRONTEND_WAVE_TRACKER.md`.
- ✅ Done+deployed: #3 device font · #5 monitor rules · #6 topology reset ·
  #12 scorecard summary · #13 admin menu · #1 perf-wave-1 · #1.1/2 copy pass.
- 🟡 Partial, to finish:
  - [ ] **#4** per-device "interfaces grouped by VRF" detail view (dialect +
    telemetry done; the device-detail UI remains).
  - [ ] **#10** BGP depth — live RIS/BMP feed + local buffer, RPKI/ASPA/geofeed
    panels, **AS-path graph** (design `91df4f62`), AI-over-BGP-tools.
  - [ ] **#11** OSPF advanced + **IS-IS advanced** monitoring — **backend +
    frontend SHIPPED, unverified against a live IGP fabric.**
    `internal/igpmon` serves `GET /api/protocols/{ospf|isis}/{adjacencies,
    summary,health}` (infrastructure:read; wired in `igpmon_deps.go`, routes in
    `main.go`, ledger + `igpmon_deps_test.go` cross-org test, 98.5% package
    coverage). It COLLECTS NOTHING new: adjacency history is the typed
    syslog/trap `{ospf,isis}_adjacency_change` signals read at `chTenantScope`;
    adjacency state now is `device_isis_adj_state` / `device_ospf_nbr_state`
    read with the caller's `extra_filters[]`. Every response carries
    `coverage{events,live_series,lsdb}` and an absent source is **null + a note,
    never 0**. UI: `src/pages/igp/IgpAdjacencies.tsx`, mounted in the OSPF and
    IS-IS groups of `BgpOspf.tsx` (per-adjacency state + timeline, roll-up,
    coverage strip; five honest states).
    Still open: (a) **LSDB/LSP counts, OSPF area membership and IS-IS area
    addresses are collected by NO collector** on either transport — the API
    probes for the series and reports `lsdb:false` / `areas:null` until one
    exists, so "advanced" here stops at adjacency depth; (b) there is no
    OSPF-speaking SNMP device on the validated lab, so the OSPF live-series path
    has never returned a row; (c) no per-adjacency hold/dead timers or SPF-run
    counters. Closing #11 fully = a collector for the LSDB/area/SPF series.
  - [ ] **#1** perf wave 2 (measured budgets, high-EPS render) · **#1.1/2**
    confirm full-site copy coverage.

## E. Finish
- [ ] Owner runs **`/code-review ultra`**.
