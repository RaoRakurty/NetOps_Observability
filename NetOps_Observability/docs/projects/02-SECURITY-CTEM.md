# Project 2 — Security CTEM  🟠

**Goal:** a **network-first security section** (CTEM: Scope → Discover →
Prioritize → **Validate** → Mobilize) that grounds into the **correlation
engine** as a fourth evidence class — an exposure is a seam-owned *story with an
owner*, not a scanner row. NOT a SIEM; integrates/exports to partner SIEMs.

**Model rule:** Fable owns the design + the storage-architecture decision; Opus
builds every package/UI.

## Design — ✅ COMPLETE (approved, merged from owner + Fable research)
HLD (`SECURITY_OBSERVABILITY_HLD`), compliance model, scenarios, GTM, build plan
(`SECURITY_BUILD_PLAN`), CVE/vendor-extensibility, config-backup/drift/capture.
**Frontend design mockup:** https://claude.ai/code/artifact/4b3b450f-5177-4d8a-a1a0-12f3697bf84f
(CTEM funnel · Exposure Story hero · four evidence lanes · seam map) — **owner
approved the page 2026-08-27**. This is the T8 build target.

## Foundation — ✅ BUILT + gate-clean, but INERT
`internal/secfindings` (T1) · `advisory` (T3) · `compliancemodel` (T4) ·
`hardening` (T5, seam-aware) · `threatlane` (T6, MITRE) · `secbus` (T2). Nothing
emits, engine doesn't ground them, no UI — compile + pass tests only.

## Execution order (build)
### Blocking decision (owner + Fable)
- [ ] **Findings store + read API — storage schema:** PostgreSQL FORCE-RLS vs.
  per-tenant OpenSearch index. Unblocks T8 (the UI needs somewhere to read from).

### Build
- [ ] **Wire the producers to emit** — call hardening/threatlane/advisory →
  `secbus.FromFinding` → `netops.security` (behind a feature flag).
- [ ] **T2b — engine grounding** (Python): consume `netops.security`, ground with
  ZERO security-specific code (the removable-module constraint). *Touches the
  correlation engine → sequence AFTER Project 1's engine deploy settles.*
- [ ] **T7 — Exposure Story** output class (reuse RCA object). Depends on T2b.
- [ ] **T8 — Security UI** — build the approved mockup against the findings API.
- [ ] **T9 — Vendor Profile registry** — consolidate detection/dialect/CVE/
  capture/hardening bindings; migrate existing vendors without regression.

### Infra modules (owner order, after the core lanes)
- [ ] Config Backup (sealed store) · Config Sync/Drift (in-sync badge) ·
  Packet Capture (per-interface, bounded, secure export). Designs exist.

### Later-flagged (non-blocking)
- PSIRT/CSAF API credentials (vault) · CIS-CAT licensing · framework crosswalk
  data (NIST OSCAL / PCI SSC).

### Finish
- [ ] Owner runs **`/code-review ultra`**.
