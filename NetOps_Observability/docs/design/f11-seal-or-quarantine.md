# F-11 — Seal-or-Quarantine (owner decision 2026-08-12)

Working design + implementation ledger for tracker #151 step-3 finding F-11.
Owner invariant: **attribution failure must never become a confidentiality
downgrade — no plaintext durable telemetry merely because tenant attribution
failed.** This doc records the AS-FOUND path (12-point inspection, four
parallel sweeps 2026-08-12), the decisions, and the slice plan. It becomes
step-4 corpus material after the verdict.

## 1. As-found path (pre-change) — corrections to the assumed architecture

Ingress → attribution → storage, per lane (file:line evidence in the
assurance report's F-11 section when this ships):

- **syslog**: device→syslog-ng:514 (unauthenticated, `keep_hostname`) →
  aggregator `syslog_in` → `syslog_normalized` UNCONDITIONALLY resets
  `.tenant_id=""` then re-derives SOLELY from `device_tenant.csv` keyed on
  `.hostname` (AGG vector.yaml:463-471). Miss ⇒ stays `""`.
- **snmptrap**: api trap listener (event carries NO tenant) → authenticated
  lane 8688 → lookup on `.device` falling back to `.host` (raw source IP).
- **flows**: goflow2 (ANONYMOUS producer) → `netops.flows` → ROUTER
  `flows_decoded` discards any inbound claim, re-derives from
  `sampler_address`; mismatched claim stamps `tenant_attribution=claim_rejected`.
- **bus lane (8692)**: authenticated (mTLS+token); producer-supplied
  `tenant_id` passes VERBATIM (topic-prefix check only); the router's four
  `*log_lane` consumers trust it. This is the authenticated Case-1 ingress.
- **cloudlogs/cloud**: tenant stamped by authenticated producers
  (cloud-ingest connector config / api); aggregator host-lane rewrites
  `""→"global"` (AGG:979,1027) — unattributed cloud records masquerade as
  `enriched`. (Noted; not in the F-11 quarantine scope — authenticated lane.)
- **applogs**: hard `.tenant_id=""` by design (platform's own logs).
- **Untagged ≠ unknown**: `buildEnrichmentRows` emits identity→`""` rows for
  KNOWN platform/global devices. The VRL cannot currently distinguish
  "registry hit with platform tenant" from "registry MISS" — both yield
  `""` → `tenant_seg=untagged`.
- **Untagged is a SHARED READ BUCKET, not platform-only**: every scoped
  tenant's OS pattern names `netops-<lane>-untagged-*` narrowed only by an
  app-layer device join (`oslog.go:87,96`, `TenantFilter`); CH policies for
  flows/findings/tunnels/app_* carry `OR tenant_id=''`; Grafana's two CH
  dashboards read ONLY untagged rows (`tenant_scope='' CONST`); correlation
  canonicalises untagged→`global` and fully processes it (RCA + ticketing
  under global destinations). Platform self-monitoring DEPENDS on this.
- **Sealing**: tenant-guarded generated rules
  (`tenantGuardVRL == tenant`) in the router's generated processors.yaml;
  `tenant_id=""` matches no guard ⇒ untagged payloads stored plaintext while
  tenant payloads get their rules. THAT asymmetry is F-11.
- **Deadletter**: `netops-deadletter-*` is cross-tenant durable plaintext
  with `raw=encode_json(.)` (VRL abort/error records, NOT attribution
  failures). Pre-existing adjacent surface.
- **Correlation quarantine exists already**: `TenantClaimRefused` →
  `CORR_DLQ_DIR/corr-deadletter.ndjson` + bounded ring + `/deadletters`
  (compose-internal). It fires only on CONTRADICTED non-empty claims; a
  no-claim unknown identity becomes `global` and is fully processed.
- **Unscoped OS readers**: fusion_worker.go:326 + ngfw_resolver.go:122 read
  `netops-syslog-*` (would not match a dedicated quarantine index).

## 2. Decisions

**D1 — Discriminator = registry MISS.** On the device-attribution lanes
(syslog, snmptrap, flows) stamp `.tenant_registry = "hit"|"miss"` at the
lookup site. Registry hit with `""` = KNOWN PLATFORM device → untagged
(existing semantics preserved: Grafana, self-monitoring RCA, device-join
visibility all intact). Registry MISS = TENANT_UNATTRIBUTABLE → quarantine.
Ambiguous identities (omitted from CSV) are misses → quarantine (correct:
genuinely unattributable). The F-10 ≤75s window quarantines briefly, then
re-attribution recovers (F11.3) — not a regression: post-reload behavior
identical, window events recoverable instead of shared-plaintext.

**D2 — Quarantine seal rides the Sealed Fields machinery, feature-bound.**
Scope id `quarantine` (all-lowercase; passes `validSecretKey`, the
secret-backend `[A-Za-z0-9_-]` parser, cannot collide with `t_<hex>` ids or
`dekvN|` custody keys). DEK minted via the existing
`TenantKeyMaterial("quarantine")`; keys delivered via the existing
`/internal/sealing/edge-keys` + `cx-secret-backend.sh` (unchanged); token
owner = `quarantine` so NO tenant principal can ever unseal it (unseal gate
already 404s non-cross principals on owner mismatch). When
`FEATURE_SEALED_FIELDS` custody is on, `GenerateRouterConfig` emits a
`<lane>_quarantine` transform per in-scope lane (guard:
`.tenant_registry=="miss" && tenant empty`): whole-event envelope —
`payload = <enc:v1:quarantine:...>` over `encode_json(.)`, metadata only
outside the ciphertext (`event_id` uuid, `received_at`, `lane`,
`identity_sha` (sha2 of the lookup identity — hash suffices for automated
re-attribution matching; plaintext hostname deliberately NOT kept),
`source_ip` where transport-derived (traps/flows), `reason`,
`quarantine_key_version`, `cx_quarantine=true`). Chain:
`<lane>_tagged → <lane>_quarantine → <lane>_rules` (default no-op file keeps
`<lane>_rules` input = `<lane>_tagged`). Feature OFF ⇒ generated file has no
quarantine stage ⇒ baseline unchanged (no tenant sealing exists either — no
asymmetry; same design boundary as the whole Sealed Fields feature).
Fail-closed: missing key ⇒ Vector exit 78 at boot (existing SEC-018
semantics); runtime encrypt failure ⇒ the quarantine transform is its OWN
remap with drop_on_abort and NO reroute to deadletter (drop + vector error
metric + alert — the owner-allowed "rejection/drop with explicit alert";
never plaintext, never the plaintext deadletter).

**D3 — Routing in BASE router config (static, no secrets):** a `route`
transform after each in-scope `<lane>_rules` steers `.cx_quarantine==true`
docs to a new `opensearch_quarantine` sink → `netops-quarantine-%Y.%m.%d`
(the deadletter shape: no tenant segment, own template, ISM-managed). The
flows CH sink and OS flows sink take the non-quarantine route output —
quarantined flows never reach ClickHouse. `id_key: cx_event_id` on the OS
event sinks (docs lacking the field keep auto ids) makes re-injection
idempotent (F11.11) — verify sink behavior on the lab before relying on it.

**D4 — Correlation (F11.9):** on the registry-anchored device lanes, a
NO-CLAIM event whose identity is a registry MISS (tenant_lookup → None, not
`""`) goes to the existing durable quarantine path (new reason
`identity_unattributable`) instead of becoming `global`. Registry hit `""`
still → `global` (platform RCA preserved). Quarantined events therefore
never reach corr_*, RCA, ticketing, or notification paths.

**D5 — Operator workflow (api, F11.3/10):** platform routes (ledger
category `platform`), all audited with new `SecEventQuarantine*` constants:
- `GET /api/quarantine` — requirePlatformAdmin: metadata list (from OS via
  `openSearch`, quarantine index only) + depth/age summary.
- `POST /api/quarantine/reattribute` — requirePlatformAdmin +
  `sensitive_data:admin` (the unseal-equivalent capability): for a given
  `identity_sha` (or doc ids), the api requires the identity to now resolve
  to EXACTLY ONE tenant via the live inventory (the authoritative source —
  never caller-supplied tenant), `Unseal`s each payload (quarantine scope),
  re-produces the original event onto its original topic via the
  authenticated bus lane with `tenant_id` stamped + `tenant_registry`
  cleared + `cx_event_id` for idempotency + `cx_restored_from=quarantine`,
  then deletes the quarantine doc (first api OS doc-delete; `osJSON`).
  Cross-crypto-boundary by construction: quarantine-decrypt → normal
  pipeline → tenant rules apply on re-consumption (tenant seal under the
  tenant key). Replay-safe: re-runs upsert the same `_id`.
- `POST /api/quarantine/inspect` (audited decrypt-view, sensitive_data:admin,
  fingerprint-only audit detail) — optional; ship if cheap.
- Retention: `apply-ism.sh` gains a second policy
  `netops-quarantine-retention` with `QUARANTINE_RETENTION_DAYS`
  (compose `${QUARANTINE_RETENTION_DAYS:-30}`, install.py template line).

**D6 — Observability (F11.12):** vector `tenant_attribution` outcome gains
`quarantined` (existing counter + tags — no new subsystem); secobs vocab
gains `netops_sec_quarantine_depth` (gauge), `netops_sec_quarantine_oldest_seconds`
(gauge), `netops_sec_quarantine_restored_total` (counter) — api Metrics
writer sources depth/age from an OS `_count`/agg on the quarantine index;
vmalert `ingest-integrity` group gains QuarantineGrowthAbnormal (rise-based)
+ QuarantineAttributionStalled (oldest age > threshold) + sink-measured
VectorQuarantineSealFailures (vector error metric on the quarantine
transform) with promtool unit tests.

**D7 — Isolation (F11.8):** no read path change needed — tenant patterns
are explicit and never name `netops-quarantine-*`; the logs API's signal
map cannot reach it even cross; the two unscoped readers match
`netops-syslog-*` only. Add guard tests pinning all of that + OS security
roles: svc_router gains write on the index, svc_api read+delete; dashboards
and correlation identities get NOTHING.

## 3. F11.5 honesty note (spoofed hostname)

Syslog device identity IS the sender-supplied hostname today; registry
lookup on it is the attribution (TENANT-HIGH-3 residual, documented in
syslog-ng core.conf: closing it needs device-side transport auth —
RFC5425 client certs, the device-programme item). Spoofing a real device's
hostname INJECTS into that tenant's view (pre-existing, documented); it
does NOT expose another tenant's data, cannot select another tenant's
seal/unseal key for the attacker, and a CONTRADICTED claim is refused
(correlation) / rejected (flows). F11.5 is satisfied for exposure and
key-selection; the injection half remains the declared residual with its
mitigation ladder. State this in the verdict.

## 4. Invariant → enforcement map

- INV-F11-01/03: quarantine envelope (D2) + guard tests on generated config;
  boundary = deployments with sealing custody (the feature's own boundary).
- INV-F11-02: D1 (Case-1 lanes untouched; hit-"" unchanged) + F11.1 test.
- INV-F11-04: D7 tests (patterns + roles).
- INV-F11-05: correlation claim refusal + flows claim_rejected + §3 note.
- INV-F11-06: exit-78 boot semantics + drop_on_abort no-reroute + alert.
- INV-F11-07/08: D5 re-attribution (decrypt→re-encrypt via pipeline;
  id_key idempotency).
- INV-F11-09: ISM quarantine policy + contract test.
- INV-F11-10: D4 correlation skip + ticketing chain tests.
- INV-F11-11: F-10 e2e re-run post-change.

## 5. Slice ledger (task ids in session task list)

1. Slice 1 (task 2): D1 VRL stamps + D2 generation + D3 routing/sink/
   template/ISM + fail-closed tests.
2. Slice 2 (task 3): Case-1 preservation pins + attribution trust order doc.
3. Slice 3 (task 4): D7 isolation guards.
4. Slice 4 (task 5): D5 workflow + D6 observability.
5. Slice 5 (task 6): lab acceptance battery F11.1-12, F-10 regression,
   report §1-9 + verdict.
