# Project 3 — Security CTEM  🟠

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

## Foundation — ✅ BUILT + gate-clean
`internal/secfindings` (T1) · `advisory` (T3) · `compliancemodel` (T4) ·
`hardening` (T5, seam-aware) · `threatlane` (T6, MITRE) · `secbus` (T2).

**P3-EMIT (2026-09-02): the producers now EMIT.** `internal/seclane` runs a
per-tenant, bounded, jittered scan (hardening + offline vendor advisory +
threatlane device-log/flow detections) → `secbus.FromFinding` → `netops.security`
keyed by tenant, behind `FEATURE_SECURITY_LANE` (default false). Ops surface:
`GET /api/security/lane/status`, `POST /api/security/scan`,
`netops_security_*` metrics. **Superseded 2026-09-02:** the engine now grounds
them (T2b, `ecda0d1e`) and the UI exists (T8, `317c6dec`) — see the Build list
below. Still true: the flag has never been switched on outside tests.

**Honest coverage caveat (carry into T8):** with config capture (T-config) not
built, every hardening rule emits `Unknown` ("running-config unavailable —
control not assessed"), and a device with no parsed vendor/version emits an
`advisory-unassessed` finding. That is deliberate (§5g never false-clear) — the
UI must render `Unknown` as *unassessed*, never as green.

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
- [x] **Persist the lane (L1)** — `370ea65d`: vector-router route
  `netops.security` → per-tenant `netops-secfindings-<seg>-*`, deterministic doc
  identity (`cx_finding_id = sha256(native_id|attrs.scan_id)`; a missing part
  quarantines, never a random id — executed on the real Vector 0.40 image),
  index template `dynamic:false` + shared ISM retention, router principal
  Read+Describe on `netops.security`, dotted keys guarded by the shared
  `log_lane` anchor (`del(.label)`). Generator-owned lane entry follow-up:
  `3badb3b3`.
- [x] **Findings read API** — `b386d44e`: list / get / facets / trend / posture /
  exposure-stories / rules / views over the per-tenant OpenSearch index; typed
  fail-closed filters, byte-pinned query bodies, current-view collapse on
  `native_id`, opaque typed cursors, bounded paging; 12 routes classified +
  OpenAPI; 9 §3a isolation tests.
- [x] **PG control-plane state** — `b386d44e`: migration 0037
  `security_rule_state` + `security_saved_views` with the `tenant_iso` FORCE-RLS
  policy, `withTenant` PG store + FileStore fallback, per-tenant `requirePerm`
  (never platform-global); a cross-tenant rule write is refused, PG RLS test
  included.
- [x] **T2b — engine grounding** — `ecda0d1e`: security evidence grounds as a
  **fourth modality with zero security-specific engine code** (generic
  evidence-event intake mapped by field names only, `EVIDENCE_CLASSES` registry,
  `uuid5` identity idempotent on redelivery, malformed → DeadLetter). A
  security-only object is **at most `suspected`** until an independent modality
  corroborates (§10a). Removable-module proof: an AST scan finds no
  security-named import and `CORR_EVIDENCE_TOPICS=''` unsubscribes. V1 objects
  are blob-identical (`FIXTURE_GOLDEN` re-frozen). ACL follow-up `8c65801d` —
  one ungranted topic fails the whole subscription under mTLS.
- [x] **EMIT (P3-EMIT)** — `47d0df00`: `internal/seclane` per-tenant bounded,
  jittered scan → `secfindings` → `secbus` → `netops.security` behind
  `FEATURE_SECURITY_LANE`; two-pass store isolation so one store's outage cannot
  silence the other, per-tenant rule enablement fail-closed, the 189-style
  ladder (bus retry → dead-letter → spool; `lost` moves only when every sink
  fails), `GET /api/security/lane/status`, `POST /api/security/scan`.
- [x] **T7 — Exposure Story** output class — reached via T2b's Exposure Story
  templates (`sig.ent.security.{exposure-story,hardening-drift-story,threat-signal-story}`,
  `ecda0d1e`), the read API's `exposure-stories` route over the correlations SQL
  filtered to security evidence (`b386d44e`), and the RCA UI treating security
  evidence as its own independent source class with seam / internet-facing /
  provider chips (`73c2c196`). **Empty until a scan grounds** — see below.
- [x] **T8 — Security UI** — `317c6dec`: Overview (funnel, coverage honesty,
  trend), Exposures (facets, current/history, cursor, Inspector), Exposure
  Stories (RCA workspace reuse), Threat Detection, Compliance, Rules, Saved
  views — built against the fixed contract, no endpoint invented. Where the
  approved mockup asks for data the contract cannot supply (exposure score, CVE
  lane, control-level detail, action CTAs, owner contact) the UI shows honest
  coverage cards or omits, **never fake values**; `Unknown` is never rendered as
  clear (tested).
- [x] **T9 — Vendor Profile registry** — `ff068f7d`: 20 embedded declarative
  profiles (detection, dialect, capture commands, advisory binding, hardening
  binding, threat tags) behind an immutable registry with `Load(fs.FS)` for the
  air-gap path; `collectors`, `netconcepts`, `hardening`, `advisory` and
  `threatlane` resolve through it with **byte-identical goldens**; unknown vendor
  is unassessed, never a silent default. **Residual (tracker 216):**
  `protocoldiag` + `verify` command tables and `secfindings`'s free-form
  platform string still hold vendor knowledge outside the registry.

### Infra modules (owner order, after the core lanes)
- [x] **Config Backup (sealed store) · Config Sync/Drift (in-sync badge)** —
  `a7afbb27` (backend) + `fc5b08be` (UI). Capture rides the existing
  `x/crypto/ssh` gateway (TOFU host-key pin, no PTY, a single exec from a
  **closed per-vendor command table**, 4 MiB cap, ctx deadline) → per-vendor
  normalize → sha256 → `vault.Encrypt` per tenant → `0600` blob under `0700`;
  migration 0038 (`tenant_iso` FORCE-RLS) holds **metadata only**, unsealed
  blobs are refused at `Put`, and a dormant vault refuses construction. A named
  redaction rule list is applied to every API/diff read while the sealed copy
  keeps the original. `configdrift` runs `in_sync|changed|drifted|unknown` per
  device against a golden and emits a drift finding
  (posture / `CFG-DRIFT-001`, **diff summary only** — a test serializes the wire
  event and fails on any config line) through the existing secbus producer onto
  `netops.security`, so it persists and grounds via T2b; it also provides the
  `hardening.ConfigSource`. 81 tests; gosec 133. UI: device Configuration tab
  with honest never-captured / failed states, back up now, versions with
  view/diff/golden, and an Infrastructure → Config Drift fleet list; config text
  and diffs render as escaped text only. **`main.go` / seclane / route-ledger
  wiring was still uncommitted at the time of writing** — until it lands the
  routes are not registered, and nothing here has run on the stack: the
  hardening `Unknown` posture below is unlocked by a real capture, not by the
  code existing.
- [ ] **Packet Capture** (per-interface, bounded, secure export) — **not built.**
  Design exists (`a25c6fe0`); no package, no route, no commit.

### Later-flagged (non-blocking)
- PSIRT/CSAF API credentials (vault) · CIS-CAT licensing · framework crosswalk
  data (NIST OSCAL / PCI SSC).

### Finish
- [ ] Owner runs **`/code-review ultra`** — **PENDING.** It has not been
  launched for this project; I cannot launch it. Everything above is
  gate-clean but unreviewed at that depth.

## Not live-attested — what is BUILT but UNPROVEN on a running stack

Honest counterpart to the ticks above. Nothing in this project has been
deployed; the api, frontend, correlation, vector-router and vector-aggregator
images are all unbuilt at HEAD. Until they are:

- **No scan has ever run on the stack.** `FEATURE_SECURITY_LANE` has never been
  true outside tests, so no finding has reached `netops.security`, no document
  has reached a `netops-secfindings-*` index, and the engine has never grounded
  a security evidence event outside its fixtures. Tracker row **217**.
- **Hardening posture is 100 % `Unknown` until config capture runs.** Every
  hardening rule evaluates over a nil config source and emits `Unknown`
  ("running-config unavailable — control not assessed") by design (§5g never
  false-clear). `a7afbb27` provides the `hardening.ConfigSource` that unlocks it,
  but posture stays Unknown until a **real capture runs against a real device**
  — code existing is not a captured config. A device with no parsed
  vendor/version emits `advisory-unassessed`.
- **Exposure Stories are empty until a scan grounds one.** The templates, the
  route and the UI all exist; the corpus does not. The read API's
  exposure-stories query returns an empty set today, and that is the correct
  answer, not a defect.
- **The T2b removability proof is structural, not operational** — the AST scan
  and the `CORR_EVIDENCE_TOPICS=''` unsubscribe are tested; no one has yet
  removed the module from a running stack.
- **No compliance claim is measured.** The Compliance view renders a tagged
  control set; with hardening unassessed, none of it is evidence of a control
  passing.
