# Project 3 — Troubleshooting protocols (+ frontend-wave list)  🟡

**Goal:** rebuild Troubleshooting into a **symptom-first investigation** surface
that saves the NOC operator from "100 windows," plus the **BGP/OSPF/ISIS
collect→analyze** diagnostics, plus finish the owner's original frontend/product
wave list and enhance IRIS.

**Model rule:** Fable specs/designs; Opus builds every page/handler + tests.

## A. Troubleshooting rebuild (item 7) — 📐 researched, NOT built
Research: `TROUBLESHOOTING_PAGE_RESEARCH_2026-08-25.md`. Design: symptom-first
verdict header (correlation engine) → parallel evidence lanes (DEM, what-changed,
device/protocol health, path, routing/BGP, flows, correlated events) → IRIS
co-pilot → seam-owned handoff. (Live page today is the old June board.)
- [ ] Build the investigation surface (lanes fed by already-deployed data).

## B. Protocol diagnostics — collect → analyze — 📐 designed, NOT built
Design: `TROUBLESHOOTING_PROTOCOL_DIAGNOSTICS_2026-08-27.md` (owner spec).
- [x] **Backend foundation built + Fable-verified** (`9a0a4e2e`, internal/protocoldiag,
  89% cov, gate-clean). 15-issue matrix (5 BGP/5 OSPF/5 ISIS), Cisco full +
  Juniper/Nokia declarative via netconcepts; Collect w/ read-only guard
  (fail-closed) + CommandRunner iface (SSH/gNMI wiring = TODO deploy); Analyze
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
- [ ] **Frontend tabs/buttons UI** — the protocol tabs (BGP/OSPF/IS-IS) + the
  collect/analyze/send-to-TAC buttons against the API above. (Needs deploy to verify.)

## C. IRIS enhancement (item 8) — 📐 roadmap PRODUCED 2026-08-28
`docs/design/IRIS_ENHANCEMENT_ROADMAP_2026-08-28.md` — extends the existing HLD
§10 phase plan (does not reinvent it). Four asks mapped to phases:
- **A. Auto-troubleshoot reach** (near-term, read-only, no new trust boundary):
  add Iris read-only tools `run_protocol_diagnostic` (Proj 3 B), `get_security_
  findings` (Proj 2), `get_topology_context`; **fix the routing inversion** so
  free-form text hits the grounded/cited engine. Highest leverage.
- **B. Guide the engineer** (P5 advisory, no executor): guided checklist +
  escalation/TAC draft notes + handoff.
- **C. Human-in-the-loop controlled actions** (P6, separate subsystem the model
  CANNOT call): ITSM/Slack/owner → **auto vendor-case opening (human-approved)**
  → gated device change. Mirrors the built Wireless five-gate pattern.
- **D. Reach/interop** (P7): MCP, ChatOps, memory.
- [ ] Build Phase A first (unlocks the payoff of Projects 2 & 3). Then B, C, D.

## D. Frontend-wave items (owner's original 13-item list)
Full audit: `docs/FRONTEND_WAVE_TRACKER.md`.
- ✅ Done+deployed: #3 device font · #5 monitor rules · #6 topology reset ·
  #12 scorecard summary · #13 admin menu · #1 perf-wave-1 · #1.1/2 copy pass.
- 🟡 Partial, to finish:
  - [ ] **#4** per-device "interfaces grouped by VRF" detail view (dialect +
    telemetry done; the device-detail UI remains).
  - [ ] **#10** BGP depth — live RIS/BMP feed + local buffer, RPKI/ASPA/geofeed
    panels, **AS-path graph** (design `91df4f62`), AI-over-BGP-tools.
  - [ ] **#11** OSPF advanced + **IS-IS advanced** monitoring (only basic today).
  - [ ] **#1** perf wave 2 (measured budgets, high-EPS render) · **#1.1/2**
    confirm full-site copy coverage.

## E. Finish
- [ ] Owner runs **`/code-review ultra`**.
