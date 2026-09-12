# Application Identity Fusion Layer — Design & Implementation Plan (#81)

Status: **in progress** · Started 2026-06-26 · Spec: owner "Application Identity Fusion Layer"

> Product line: *"Other systems identify the application. Correlix determines which
> users and sites are affected, where the path is failing, which fault domain owns
> the problem, and what to do."* App identity becomes **explainable evidence** for
> the EXISTING correlation/RCA engine — not a parallel system, not DPI.

---

## PHASE 0 — Current-state assessment (verified, not invented)

### What already exists (≈65–70% of the foundation — EXTEND, do not rebuild)

**Pure fusion core — `src/backend/appid/`**
- `verdict.go` — **`Fuse(signals []Signal) Verdict`** already implements: source-strength
  precedence ladder (`Source.strength()` 4/3/2/1/0), per-source `baseConfidence`, agreement
  boost (+0.10), contradiction penalty (×0.20), `confidenceFloor` 0.30, **unknown first-class**,
  `Role` (supports/contradicts/discriminates), `EvidenceMissing`. Vocabulary deliberately mirrors
  the correlation engine (`Tier` = VerdictTier; `Role` = `corr_evidence.role`; floor/penalty =
  `scoring.py`). **This is the engine to deepen (Phase 3), not replace.**
- `trie.go` (LPM IPv4/IPv6 radix), `catalog.go` (AWS/Azure/GCP/M365 feed parsers → CatalogEntry),
  `domain.go` (`DomainIndex` exact + `*.suffix`), `cache.go` (bounded LRU + negative cache).
- `Source` ladder already covers: ngfw_app_id, ipfix_app_id, operator, sot, cloud_tag, cloud_graph,
  dns, sni, ip_catalog, asn, port. **Matches the spec's required precedence almost 1:1.**

**Backend wiring — `src/backend/`**
- `ngfw_resolver.go` — consumes FortiGate App-ID from OpenSearch syslog → `SrcNGFWAppID` (confirmed). LIVE.
- `flows_apps.go` — `/api/flows/apps`, `aggregateFlowApps()` resolves dst→app via catalog + overrides + ngfw + cloud.
- `flows_services.go` — #69 service catalog selectors (operator-declared, injection-safe query-time).
- `appid_overrides.go` — operator catalog (`app_catalog` PG, per-tenant prefix→app, SrcOperator).
- `appid_store.go`, `appid.go` (REST `/api/applications`, `/api/appid/*`), `appid_catalog.go` (hot-swap loader).
- `cloud_*.go` — cloud inventory (resource→app), `cloud_appid_resolver.go` (identity-map signalFor).

**Storage**
- PG `migrations/0015_app_identity.sql`: `applications` (thin parent, owner_team, criticality) +
  `app_catalog` (match_kind/value→app_label, versioned, RLS `tenant_iso` FORCE; shared global `tenant_id=''`)
  + `services.application_id` link. Latest migration = **0015 → next is 0016**.
- ClickHouse `init.sql`: `corr_signals` (source Enum incl. `cloud`=9), `corr_evidence`
  (role Enum8 supports/contradicts/discriminates), `corr_objects`, `corr_edges`, `corr_signals_archive`.
- Redpanda topics: `netops.{syslog,flows,metrics,probes,snmptrap,cloud}` (consumed by `correlation/main.py`).

**Correlation/RCA — `src/correlation/`**
- `engine.py` (`run_window`, `ObjectSnapshot`, grounding via seams/topo, `layer_coverage`, `affected()`),
  `signals.py` (Signal/Source/EntityType incl. APP, CLOUD_RESOURCE / ModalityClass / Observer / VerdictTier),
  `verdicts.py` (scoring, CONTRADICTION_PENALTY), `cloud_producers.py` (cloud → corr_signals).
- Seam grounding: `SeamView`, `seam_bootstrap.go`, `/data/enrichment/seams.json`.

**Tenancy/UI**: `principalTenant`/`chTenantScope`/`withTenant`, RLS `tenant_iso` FORCE on `app.tenant_id`;
React `Correlations.tsx`, `RcaWorkspace.tsx`, `rcaCase.ts`, App Observability `pages/appobs/`.

### Gaps the spec requires (what's genuinely NEW)
1. **No first-class `ApplicationObservation`** — today identification is an ephemeral `Signal`; the spec
   wants a persisted, provenance-bearing observation (vendor/product/device/parser-version/raw-hash).
2. **`Fuse` is destination-coarse** — no session scope, evidence freshness/TTL, temporal overlap, NAT,
   duplicate dedup, shared-CDN ambiguity, conflict STATE, alternative candidates, stable explanation codes,
   confidence BANDS, resolution STATES, or fusion/catalog versioning on the result.
3. **No vendor adapter framework** — FortiGate is parsed ad-hoc in Vector; Palo Alto / Cisco Secure FW /
   NBAR-IPFIX not parsed; no common adapter interface.
4. **Canonical catalog is thin** — `applications` lacks provider/family/category/aliases/domains/lifecycle/
   catalog_version/valid_from-to/scope; no `app_aliases` (vendor-namespaced) table.
5. **No app→flow/path/seam attachment** into correlation evidence; RCA has no Application Impact section.
6. **No app observation/identity topics or consumers**; no replay of fused identity.

### Architecture decisions (ADR)
- **AD-1 Extend `appid.Fuse`, do not replace.** Add session/freshness/dedup/conflict/bands/codes/versioning
  AROUND the existing strength ladder; keep `Verdict` backward-compatible (additive fields).
- **AD-2 Reuse vocabulary.** ConfidenceBand maps from Tier+strength; ResolutionState extends the
  unknown-first-class principle; evidence roles stay `corr_evidence.role`.
- **AD-3 Stores:** PG = canonical catalog + aliases + overrides (extend 0015 via 0016). ClickHouse =
  high-volume observations + fused results (new tables in init.sql, additive). OpenSearch = raw vendor logs
  (already). No new database.
- **AD-4 Topics:** reuse `netops.cloud`-style lane. Add versioned `netops.app.observations.v1` +
  `netops.app.identities.v1` ONLY where existing contracts don't fit; vendor logs keep flowing via syslog/Vector.
- **AD-5 Correlation:** app identity attaches to EXISTING `corr_signals`/`corr_evidence`/`corr_objects`
  (entity_type app/cloud_resource already exist) — NO separate app RCA. Verdict standards unchanged.
- **AD-6 No DPI / payload / TLS-decrypt / fuzzy-match in hot path.** Consume upstream classification + lookup.

### File-level plan (per phase)
- **P1 contracts/model:** `appid/observation.go` (ApplicationObservation), `appid/identity.go`
  (CanonicalApplication, FusedIdentity, ConfidenceBand, ResolutionState, Version consts),
  `appid/explain.go` (stable ExplanationCode set) + `migrations/0016_app_identity_fusion.sql`
  (extend `applications`; new `app_aliases`) + CH `init.sql` (`app_observations`, `app_identities`) + contract tests.
- **P2 adapters:** `appid/adapter/` (interface + paloalto.go, fortigate.go, ciscofw.go, nbar_ipfix.go) + fixtures + tests.
- **P3 fusion:** extend `appid/verdict.go` (`FuseObservations(...) FusedIdentity`): session>dst, freshness/TTL,
  dedup, NAT/CDN ambiguity, conflict state, alternatives, explanation codes, bands, versioning, deterministic replay.
- **P4 pipeline:** observation producer (Vector/Go) + consumer + CH batch persistence + dead-letter + metrics + replay.
- **P5 correlation:** app-identity producer → `corr_signals`/`corr_evidence`; app impact calc; evidence-missing.
- **P6 API/UI:** extend `/api/appid/*` (+ observations, fused, conflicts, impact, replay); RCA Application Impact
  section + Application Identity component + correlation filters.
- **P7 hardening:** security/tenancy/perf/replay tests + runbook + ADR finalization.

### Compatibility risks
- Widening `Verdict` must stay additive (existing callers: flows_apps, ngfw, appid REST). Mitigate: new
  `FusedIdentity` type wraps/embeds `Verdict`; keep `Fuse` signature, add `FuseObservations`.
- CH/PG migrations must be idempotent + self-heal (follow init.sql `MODIFY COLUMN` pattern).
- Vendor parsers must dead-letter, never crash the pipeline (§7).

---

## PHASE 5 — Correlation integration (detailed)

**Status:** P5a SHIPPED 2026-06-26 · P5b–P5d planned. Mirrors the cloud lane (#81 P3G).

### Principle (AD-5 made concrete)
App identity is **enrichment, not a fault.** A fused identity answers *"WHICH app is
this traffic?"* — it must NAME the applications an object affects, but must NEVER seed
an object on its own (no "app identified" RCA objects). So identity rides the EXISTING
spine: a low-severity enrichment signal that attaches to objects the engine already
formed from real faults. Confirmation of a fault still requires an independent fault
observer — identity is one platform-derived vantage and cannot self-confirm.

### Seam decisions
- **New `Source.APP_IDENTITY`** (`signals.py`) — filterable, never mistaken for a fault.
  Reuses `EntityType.APP` + `ModalityClass.CONTROL_PLANE` (AD-2, no new enum).
- **One observer** `appid:fusion` (ObserverType.PLATFORM) → independence gate treats
  fused identity as a single derived observer (cannot confirm alone).
- **Severity always INFO** → guarantees identity can't open an object (engine seeds
  objects from fault severity; P5c adds an explicit guard too).
- **Join key = shared `entity_tokens`** (app + dst_ip + flow/session id) → an identity
  signal grounds onto the SAME nodes a flow/network fault touches; that overlap is how
  an object names its affected app.
- **Topic** `netops.app.identities.v1` (versioned, AD-4) — the Go fusion worker emits
  fused identities; `main.py` adds `handle_app_identity`. Vendor logs keep flowing via
  syslog/Vector untouched.

### Replay / versioning invariants (must hold)
The engine is built around `content_hash` stability ("byte-identical to pre-CX"). P5c
integration must be **additive and no-churn**: identity contributes EVIDENCE rows
(`role=supports`) + named affected apps, but must not alter `content_hash`
(nodes/signals/edges/hypotheses/engine) for objects that have no identity signal. An
object with zero identity signals stays byte-identical to pre-P5 → replay-safe, no
version churn.

### Increments
- **P5a — pure producer (DONE).** `app_producers.py`: `app_identity_signal()` +
  `app_identity_from_event()` wire adapter (DeadLetter on no-app / invalid band-state).
  `Source.APP_IDENTITY` added. 14 unit tests; full suite 293 green. NOT wired into
  main.py → zero runtime risk.
- **P5b — ingestion lane.** Add `netops.app.identities.v1` to `TOPICS` + `handle_app_identity`
  (tenancy EXPLICIT/default-closed, untenanted dropped, dead-letter counters on /healthz,
  insert corr_signals + buffer_signal). Widen CH `corr_signals.source` Enum to include
  `app_identity` (idempotent `MODIFY COLUMN`, like cloud=9). Go: fusion worker emits to the
  topic alongside the CH `app_identities` persist (new producer seam, opt-in).
- **P5c — engine enrichment + app impact.** Engine treats `source=app_identity` as
  enrichment: it attaches to existing objects via shared tokens, NEVER seeds one (guard +
  test). App-impact calc names affected apps on network-fault objects from the grounded
  identity signals; emit supporting `corr_evidence` rows + honest `evidence_missing`
  ("flow present, app unknown") — unknown first-class. All additive / no content_hash churn.
- **P5d — golden tests + live validation.** Golden fixtures (network fault + identity →
  named affected app w/ provenance; identity-only → NO object formed). Live: produce an
  identity event sharing an app token with a fault object → RCA names the app. Validate
  fresh-install guardrail. **DONE inline with P5c** (6 golden tests + live cloud-object
  validation).

---

## PHASE 6 — API / UI (DONE 2026-06-26)

Surfaces the engine's `app_impact` projection to operators.
- **Backend:** `correlations.go` meta SELECT reads `corr_objects.app_impact`;
  `rca_path_view.go` `parseAppImpact()` → `rcaPathView.app_impact` (pass-through,
  engine-owned, nil-on-empty). `GET /api/correlations/{id}/rca-path-view` carries it.
- **Frontend:** `rcaCase.ts` builds `RcaAppImpact` from attached `source=app_identity`
  signals (strongest evidence per app), parallel to the cloud section; RcaWorkspace
  renders an "Application impact" section (band chips + provenance) on existing `--rw-*`
  tokens; `labels.ts` maps raw source tokens to plain language (customer-facing rule).
- LIVE-VALIDATED: API returns structured `app_impact`; tsc+vite + 34 rca tests green.

## PHASE 7 — Hardening (DONE 2026-06-26)

- **Security/tenancy (§3a):** untenanted identity dropped + counted (default-closed);
  mixed-tenant window rejected even when the foreign signal is an identity; `corr_signals`
  RLS scopes reads. Tests: `test_app_identity_intake.py`, `test_app_impact.py`.
- **Replay/perf:** `app_impact` is a projection (outside `content_hash`) → no version
  churn, deterministic under input shuffle (`test_identity_enrichment_is_deterministic`).
- **Runbook:** `docs/runbooks/app-identity-fusion.md` (enable, validate, troubleshoot).

## ADR closure

AD-1…AD-6 all held as designed. Notable refinements proven in build:
- **AD-5 made concrete:** identity is excluded from `build_nodes` (cannot seed/extend
  an object) and joins as an `app_impact` PROJECTION matched by shared `entity_tokens`
  — strictly "attaches to EXISTING objects", no separate app RCA.
- **AD-4 transport:** Go→engine uses Redpanda's HTTP proxy (pandaproxy), honoring the
  stdlib-only "REST, not Kafka bus" rule (§6) — no new dependency.
- **Two additive CH enum value-adds** required and shipped (idempotent self-heal):
  `corr_signals.source += app_identity`, `corr_evidence.subject_kind += app`.

**#81 Fusion Layer status: P0–P7 COMPLETE + LIVE.**
