# ADR-SEC-009 — Unattributable telemetry is sealed-or-quarantined, never stored plaintext

- **Status:** **Accepted (owner, 2026-08-12)** — **implemented the same day.**
  Decision: an event whose tenant attribution FAILS (a device→tenant registry
  MISS on the device-attribution lanes) is never durably stored in plaintext.
  It is replaced wholesale by a metadata envelope whose payload — the entire
  original event — is sealed under a dedicated `quarantine` key scope, routed
  to an operator-only index with bounded retention, and recoverable only
  through an audited, dual-gated re-attribution workflow. This resolves
  assurance finding **F-11** (`docs/security/TLS_ASSURANCE_REPORT_2026_08.md`,
  step-3 progress 2026-08-12) with the owner invariant: **attribution failure
  must never become a confidentiality downgrade.**
- **Implementation state:** **built, shipped, and live-proven** — five slices
  (commits d92f8919, 6ad927c8, 24d7de81, fda3452d + acceptance-run fixes) and
  the full F11.1–F11.12 acceptance battery run on the lab stack with the TLS
  mesh and sealing custody ON. Working design + slice ledger:
  `docs/design/f11-seal-or-quarantine.md`. Operator procedures:
  `docs/runbooks/security/quarantine-operations.md`.
- **Owner rationale:** the sealed-fields feature promised "this tenant's
  sensitive values are ciphertext at rest" — and the step-3 end-to-end run
  proved the promise was fail-open across *attribution*: an event that lost its
  tenant stamp skipped every tenant-guarded seal rule and landed as plaintext
  in a **shared** index. A confidentiality control that evaporates exactly when
  the system is least sure who owns the data is not a control. Quarantining
  under a dedicated key keeps the promise without guessing an owner.
- **Relates to:** SEC-014 (device-lane transport identities — the syslog
  hostname residual lives there), SEC-018 (edge sealing-key distribution — the
  quarantine key rides the same router-SVID-only channel); findings F-10
  (enrichment hot-reload, which bounds the transient quarantine window) and
  F-11 (this decision); ADR-SEC-007 (sealing custody — the feature boundary),
  ADR-SEC-008 (fail-closed posture this extends to attribution);
  `docs/design/f11-seal-or-quarantine.md` §2b (attribution trust order).

---

## Context

The 2026-08-09 assurance run's sealed-fields end-to-end exercise surfaced
F-11: sealing was **fail-open across attribution**. The router's generated
seal rules are tenant-guarded (`tenant_id == <tenant>`); an event that arrived
with no tenant stamp — a stale enrichment CSV (F-10, since fixed), or a
hostname the registry has never seen — matched no guard and was stored in
**plaintext** in the `-untagged-` index. Observed live, not hypothesized.

The 12-point pre-change inspection (2026-08-12, four parallel sweeps)
corrected three load-bearing assumptions before any design was chosen:

1. **`tenant_id=""` did not mean "unknown".** The device→tenant registry maps
   KNOWN platform/global devices to the empty tenant on purpose, and the
   untagged bucket is a **shared, load-bearing read surface**: every scoped
   tenant's OpenSearch pattern names `-untagged-*` (narrowed by a device
   join), three ClickHouse policies carry `OR tenant_id=''`, Grafana's
   ClickHouse dashboards read *only* untagged rows, and the correlation engine
   canonicalised untagged→`global` and fully processed it (RCA, ticketing).
   Platform self-monitoring depends on this bucket existing.
2. **A genuinely unknown sender was indistinguishable in-config from a known
   platform device** — both yielded `""` and the same shared plaintext index.
   That asymmetry (tenant events sealed, unattributable events plaintext) was
   the finding.
3. **The correlation engine already had a durable quarantine — but only for
   CONTRADICTED tenant claims.** A no-claim unknown identity flowed through as
   `global` and was fully processed.

Any fix therefore had to (a) distinguish "known platform device" from
"registry miss" *at the lookup site*, (b) leave the platform bucket exactly as
it was, and (c) never require guessing an owner for data whose owner is the
thing in question.

## Decision

**1. The discriminator is a registry MISS, not an empty tenant.** The three
device-attribution lookup sites (aggregator syslog + snmptrap, router flows)
stamp `.tenant_registry = "hit" | "miss"` at the moment of lookup. Registry
hit → the tenant path or the *unchanged* platform untagged bucket. Registry
MISS with no tenant → `TENANT_UNATTRIBUTABLE` → quarantine. Authenticated
producer stamps (the bus bridge, cloud connectors — `producer_stamped`) and
the platform's own applogs never enter the discriminator at all.

**2. Quarantine seals under a dedicated key scope on the EXISTING envelope
machinery.** The generated per-lane `<lane>_quarantine` stage
(`src/backend/processors/quarantine.go`) replaces the event wholesale with a
metadata envelope — event id, received_at, lane, identity as a SHA-256 (never
the sender-supplied string), transport source IP where one exists, reason —
whose payload is the whole original event sealed under the `quarantine` scope.
The scope is deliberately NOT a tenant: its DEK is minted by the vault on
first use, delivered over the same router-SVID-only
`/internal/sealing/edge-keys` channel as every tenant key (SEC-018), and its
token owner makes it unrevealable by any tenant principal (the unseal gate's
owner check 404s them). No new crypto, no new distribution path.

**3. The stage is feature-bound to sealing custody and fail-closed.** It is
generated only when sealed-fields custody is on — the feature's own boundary
(without custody there is no tenant sealing either, so no asymmetry exists).
A missing quarantine key is a Vector **exit-78 boot refusal** (the secret
backend returns an error and Vector refuses the config — SEC-018 semantics);
a runtime seal failure **drops** the event (`drop_on_abort`, no reroute to the
plaintext deadletter) and fires a critical alert. There is no plaintext path.

**4. Storage is static, isolated, and retention-bounded.** Base router routes
steer `cx_quarantine==true` envelopes to `netops-quarantine-<date>` — no
tenant segment, payload unmapped, unreachable by every tenant-scoped pattern
and every dashboard/correlation identity (guard-tested). Quarantined flows
never reach ClickHouse. The index carries its own ISM policy
(`netops-quarantine-retention`, `QUARANTINE_RETENTION_DAYS`, default 30 days).
Correlation durably quarantines no-claim registry-miss events
(`identity_unattributable`) instead of processing them as `global`.

**5. Recovery is a cryptographic ownership crossing, audited and dual-gated.**
`POST /api/quarantine/reattribute` (platform admin **and**
`sensitive_data:admin`) resolves the hashed identity against the LIVE device
inventory only — never a caller-supplied tenant — unseals under the exact
edge context, re-injects the original events through the authenticated bus so
the tenant's own rules seal them under the tenant's key, tombstones the
envelopes, and upserts by event id so replays cannot duplicate. Every restore
leaves a `quarantine_reattribute` audit event (identifiers and counts, never
payload).

## Alternatives considered

| Alternative | Assessment |
|---|---|
| **Seal-or-quarantine on registry MISS (CHOSEN)** | **Pro:** keeps the owner invariant absolutely — no plaintext durable storage on attribution failure; preserves the load-bearing platform bucket untouched; reuses the shipped sealing machinery end to end (key mint, delivery, audit, fail-closed semantics); events are *recoverable*, not lost. **Con:** operational burden (a real workflow for something that used to be silent); cold-start and unknown-sender behavior changes visibly (see Consequences). |
| **Accept as a design boundary** (document that unattributed events store plaintext-untagged) | **Rejected by the owner.** The untagged index is readable by every scoped tenant's pattern (device-join narrowed) and by platform surfaces — an unattributable event's payload may *belong* to a tenant, and storing it where its owner cannot be established but others can read metadata around it is precisely the confidentiality downgrade the invariant forbids. Fail-open on the hard case is not a boundary, it is a hole. |
| **Quarantine everything untagged** (discriminate on `tenant_id == ""` alone) | **Rejected — the platform bucket is load-bearing.** The inspection proved `""` includes KNOWN platform devices whose telemetry feeds Grafana's ClickHouse dashboards, platform self-monitoring RCA, and tenant device-join visibility. Quarantining it would blind the platform's own observability and break shipped read surfaces for zero confidentiality gain (platform telemetry has no tenant owner to protect). |
| **Per-tenant listeners** (attribute by ingress endpoint instead of registry lookup) | **Deferred to the device programme.** It changes what transport can *prove* (a per-tenant port or per-device client cert is a stronger identity than a syslog hostname), but it is device-onboarding work — RFC 5425 client certs, per-tenant endpoint provisioning — not a storage-path fix, and it would not help the cold-start or new-device cases this decision covers. The trust-order doc (§2b) records today's ceiling explicitly. |

## Consequences

**Positive**
- The sealed-fields promise holds on its hardest path: with custody enabled,
  **no durable telemetry payload is persisted in plaintext because tenant
  attribution failed** — proven live (F11.2: unknown-host syslog stored as
  `<enc:v1:…>` ciphertext, absent from every syslog index).
- Case-1 (authenticated producer) events and the platform untagged bucket are
  bit-for-bit unaffected (F11.1; parity-suite pinned).
- Late attribution is a first-class, replay-safe workflow instead of a manual
  forensic exercise (F11.3: 61 s device→attribution convergence, restore,
  audit row).
- The failure modes are loud: three alerts (seal failures = drops, abnormal
  growth, attribution stalled) plus exit-78 boot refusal.

**Negative — accepted by the owner, stated honestly**
- **Cold-start quarantining.** On a stack whose device inventory is empty,
  ALL device-lane telemetry quarantines until inventory populates —
  confidentiality-safe by design, but a visible behavior change surfaced by
  the miss-rate and quarantine-growth alerts, and an onboarding-order
  requirement (devices before device telemetry).
- **Unknown-exporter flows are invisible in ClickHouse until attributed.**
  A quarantined flow's CH row is dropped entirely; restore re-inserts into OS
  idempotently but CH has no upsert, so a re-restored flow can re-insert —
  operators restore once per identity, and the response reports counts.
- **The syslog hostname-injection residual remains.** Hostname IS syslog's
  strongest identity today; spoofing a *known* device's hostname still injects
  into that tenant's own view (never exposes another tenant's data, never
  selects another tenant's key). This is a transport-identity limit owned by
  SEC-014 / the device programme (RFC 5425 client certs), not weakened or
  hidden by this decision.
- **Operator workflow burden.** Somebody must triage quarantine growth and
  run re-attribution before the retention cliff (default 30 days). The
  runbook and the `QuarantineAttributionStalled` alert exist because of this
  cost.

## Security implications

- Extends ADR-SEC-008's fail-closed doctrine from *configuration* to
  *attribution*: the system now refuses to store what it cannot own-label,
  rather than storing it in the most-shared place available.
- The `quarantine` scope inherits the full SEC-018 custody chain — exit-78 on
  unresolvable keys, router-SVID-only delivery, audited unseal — and its
  token owner is structurally outside every tenant principal's reach.
- Isolation is guard-tested from both directions: no tenant-scoped OS pattern
  can glob-match the quarantine index, and the dashboards/correlation OS
  identities are granted nothing on it (F11.8); correlation refuses to
  process unattributable events (F11.9), so no RCA/ticket/notification can
  leak envelope metadata outward.
- Residuals stay on record rather than being absorbed silently: Kafka topic
  log segments hold pre-seal bytes for the retention window (pre-existing
  baseline for ALL events), and the plaintext deadletter index remains for
  *other* abort classes — quarantine deliberately never routes there.

## Operational implications

- New operator surface: `GET /api/quarantine` (metadata list),
  `POST /api/quarantine/reattribute`, three vmalert rules, the
  `netops_sec_quarantine_*` metrics family, and the
  `QUARANTINE_RETENTION_DAYS` knob. Procedures, symptoms and the
  do-not-touch list live in
  `docs/runbooks/security/quarantine-operations.md`.
- Device onboarding order now matters visibly: assign devices to tenants
  promptly; the F-10 hot-reload bounds the transient window to ≤ ~75 s after
  an assignment.

## Migration implications

1. **No data migration.** The stage appears in the next generated router
   config on custody-enabled deployments; pre-existing untagged documents are
   untouched (they were written under the old semantics and remain platform
   telemetry by the registry's account).
2. **Plaintext-baseline deployments are unchanged** — no custody, no stage,
   no new index; the same design boundary the whole sealed-fields feature has.
3. **Enabling sealing on an existing deployment now also enables
   quarantining** — operators should populate the device inventory first or
   expect the cold-start behavior above.

## Unresolved questions

- **RESOLVED (owner, 2026-08-12):** seal-or-quarantine on registry MISS;
  dedicated `quarantine` scope on the existing envelope model; feature-bound
  to sealing custody; accept/quarantine-everything/per-tenant-listener
  alternatives dispositioned as above.
- **U1 — ClickHouse restore semantics.** CH has no upsert; a repeated restore
  of the same FLOWS identity re-inserts rows. Acceptable at current volumes
  (restore once per identity; counts reported); a CH-side dedup key is the
  clean fix if restore frequency grows.
- **U2 — The plaintext deadletter index.** Other VRL abort classes still land
  there with full `raw`. Flagged for the owner as follow-up hardening —
  adjacent to, not part of, this decision.
- **U3 — Transport-strength device identity** (per-tenant listeners, RFC 5425
  client certs) — the device programme's item; would upgrade the trust-order
  ceiling this decision works within.
