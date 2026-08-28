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
### Blocking decision (Fable) — ✅ DECIDED 2026-08-28
`docs/design/SECURITY_FINDINGS_STORE_DECISION_2026-08-28.md`. **Findings store =
per-tenant OpenSearch index `netops-secfindings-<seg>-*`** (written from
`netops.security` via vector-router, exactly like syslog/flows; read via
`TenantIndexPattern`+`TenantFilter`). **PG FORCE-RLS** holds only the small
mutable control-plane state (feed/rule enablement, saved views). ClickHouse
unchanged (flow detections ground into `corr_*` Exposure Stories). Rationale:
`Finding` is immutable, time-stamped, append-heavy with full-text/facet/trend
access + consumer-side dedup — the telemetry-to-OpenSearch precedent, not
mutable PG rows. Unblocks T8.

### Build
- [ ] **Wire the producers to emit** — call hardening/threatlane/advisory →
  `secbus.FromFinding` → `netops.security` (behind a feature flag).
- [ ] **Persist the lane** — vector-router route `netops.security →
  netops-secfindings-<seg>-*` + index mapping (facet keyword fields + full-text
  narrative fields + `Time`/`ScanID`); doc `_id = hash(native_id|scan_id)`
  (keeps trend AND a query-time dedup'd current view). Guard dotted keys.
- [ ] **Findings read API** — list+facet+trend+search, cursor pagination,
  `requirePerm` + `TenantIndexPattern`/`TenantFilter`, §3a isolation test.
- [ ] **PG control-plane state** — FORCE-RLS migration for feed/rule enablement
  + saved views + `withTenant` + isolation test.
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
