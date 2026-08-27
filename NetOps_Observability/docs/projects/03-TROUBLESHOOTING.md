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
- [ ] BGP/OSPF/ISIS tabs; **Collect** button runs the curated read-only
  show-command bundle for each of the **5 top issues** per protocol (15-issue
  matrix in the design doc); over the SSH gateway / gNMI; vendor-dialect via
  `netconcepts`.
- [ ] **Analyze** button — rules-as-code failure signatures → verdict +
  remediation (mirrors hardening/threatlane catalogs).
- [ ] Redacted **TAC export** of the raw bundle + verdict; audited; §3a-scoped.

## C. IRIS enhancement (item 8) — ❌ roadmap NOT produced
- [ ] Roadmap: auto-troubleshoot, guide engineers, human-in-the-loop
  auto-actions, auto vendor-case opening. Then build in phases.

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
