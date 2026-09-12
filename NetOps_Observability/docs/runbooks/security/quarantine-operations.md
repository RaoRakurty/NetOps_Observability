# Runbook — Quarantined (unattributable) telemetry: triage, re-attribution, retention

> **Status: EXECUTABLE TODAY.** Every command and endpoint in this runbook
> exists and was proven live in the F11.1–F11.12 acceptance battery
> (2026-08-12). Feature boundary: the quarantine machinery exists **only on
> deployments with sealing custody enabled** (`FEATURE_SEALED_FIELDS` +
> `SEAL_PROVIDER`); on the plaintext baseline there is no quarantine stage,
> no index, and the API endpoints answer **501**.

**Decision record:** ADR-SEC-009 (seal-or-quarantine),
ADR-SEC-007 (sealing custody), ADR-SEC-008 (fail-closed).
**Design + as-found trace:** `docs/design/f11-seal-or-quarantine.md`
(§2b is the attribution trust order).
**Assurance evidence:** `docs/security/TLS_ASSURANCE_REPORT_2026_08.md`,
step-3 progress 2026-08-12 (F-11 section — acceptance battery, invariants,
residual risks).
**Complements:** `secret-unseal-failure.md` (key-custody boot failures),
`../tls-mtls.md` (the mesh this rides on).

---

## 1. What quarantine is (and is not)

When a device-lane event's identity is a **device→tenant registry MISS** —
the syslog hostname, trap device/source IP, or flow exporter address is not
in the device inventory — the event cannot be attributed to a tenant, and the
router replaces it wholesale with a metadata envelope: event id, timestamp,
lane, the identity as a SHA-256 hash (never the sender-supplied string), the
transport source IP where one exists, and reason `TENANT_UNATTRIBUTABLE`. The
**entire original event** rides inside that envelope as ciphertext sealed
under the dedicated `quarantine` key scope, and the envelope lands in
`netops-quarantine-<date>` — an operator-only index no tenant-scoped read
path can reach. Only three lanes carry the stage: **syslog, snmptrap, flows**
(the lanes whose tenant comes from the registry lookup).

What does **NOT** quarantine:

- **Known platform devices.** A registry *hit* that maps to the empty
  (platform) tenant is the platform's own telemetry — it keeps flowing to the
  untagged bucket exactly as before. The discriminator is the MISS stamp,
  never `tenant_id == ""` alone.
- **Authenticated producer stamps.** Events whose tenant arrives from an
  authenticated stack component (the bus bridge lanes, cloud connectors —
  `tenant_attribution=producer_stamped`) and the platform's applogs never
  enter the discriminator.
- A brand-new device *after* assignment quarantines only for the enrichment
  convergence window (≤ ~75 s, measured 61 s live) — then its telemetry
  attributes normally and the quarantined window events are recoverable (§4).

## 2. Prerequisites

- [ ] A **platform admin** account that also holds **`sensitive_data:admin`**
      (re-attribution is dual-gated; a tenant admin — even with
      `sensitive_data:admin` in their tenant — cannot reach it).
- [ ] Access to the device inventory (Infrastructure UI or `/api/devices`).
- [ ] For boot-refusal triage: host shell access to read container logs.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **Never write to, delete from, or "clean up" `netops-quarantine-*` directly** | The audited workflow is the ONLY supported path. A direct doc delete destroys a recoverable event with no audit trail; a direct write forges an envelope. Retention (ISM) is the only thing besides the restore workflow that removes docs. |
| 🔴 **The payload is ciphertext under the `quarantine` key — do not try to decrypt it by hand** | `cx_quarantine_payload` is an `<enc:v1:…>` token sealed under a key scope no tenant principal can reach. Reveal it only through the audited re-attribution workflow. Copying the token elsewhere gains nothing and spreads ciphertext you cannot account for. |
| 🔴 **Do not "fix" a quarantine-key boot refusal by disabling sealing** | The same warning as `secret-unseal-failure.md`: removing custody to make the router start silently removes tenant sealing too, and every already-quarantined envelope becomes unrecoverable the moment its key custody is lost. Fix custody, not the symptom. |
| 🟠 **`VectorQuarantineSealFailures` means events are being LOST right now** | The stage is fail-closed: a runtime seal failure DROPS the event (never plaintext, never the deadletter). Treat it like an ingest outage, because for unknown senders it is one. |
| 🟠 **Retention is a cliff** | After `QUARANTINE_RETENTION_DAYS` (default 30) ISM deletes envelopes permanently. `QuarantineAttributionStalled` is the early warning — act on it. |

## 4. The three alerts — symptom → diagnosis → action

### 4.1 `VectorQuarantineSealFailures` (critical)

**Symptom:** the alert fires on
`vector_component_errors_total{component_id=~".*_quarantine"}` — the generated
quarantine stage on some lane is aborting, and **every abort is a dropped
event** (fail-closed by design: no plaintext continuation, no deadletter).

**Diagnosis:**

```bash
cd deployment/docker
docker compose logs --since 30m vector-router | grep -iE "quarantine|secret|seal|error"
```

Identify the failing component (`syslog_quarantine`, `snmptrap_quarantine`,
`flows_quarantine`) and the error class. The two real classes:

- **Key custody:** the seal snippet cannot produce a token (the belt check
  `starts_with(…, "<enc:v1:")` aborts). Check the api's sealing logs (the
  `edge key served` audit lines) and the swtpm sidecar (`secrets-seal`)
  health — then follow `secret-unseal-failure.md` if custody itself is sick.
- **Engine/config regression:** errors began right after a processor change
  or router config reload — check the router's config-load lines and the most
  recent processor edit.

**Action:** restore key custody (or revert the offending change), then watch
the error counter go flat. Dropped events are **gone** — the alert existing
is what bounds the loss window.

### 4.2 `QuarantineGrowthAbnormal` (warning)

**Symptom:** last-hour intake at the `opensearch_quarantine` sink is far
above its own 6-hour baseline — one or more **new unknown senders** appeared,
or attribution is failing at scale (a stale/empty `device_tenant.csv` export).

**Diagnosis — list the quarantine metadata:**

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://<host>/api/quarantine?limit=50" | jq .
```

Each row is metadata only (the sealed payload is structurally excluded from
list responses): `cx_event_id`, `received_at`, `lane`, `identity_sha`,
`source_ip`, `reason`; the `summary` object carries `total` and
`oldest_received_at`. Group by `identity_sha` + `source_ip` + `lane`: a
single new hash with one source IP is one unknown device; many hashes at once
suggests an enrichment-export problem (check the api's export log and
`TenantEnrichmentMissRateJumped` if it is also firing).

**Decide, per identity:**

- **It is a real device that belongs to a tenant** → assign it and
  re-attribute (§5).
- **It is noise / not yours** (a stray sender pointed at your collector) →
  do nothing; retention deletes the envelopes on schedule. Optionally close
  the network path it arrived by.

### 4.3 `QuarantineAttributionStalled` (warning)

**Symptom:** `netops_sec_quarantine_oldest_seconds > 7 days` — the oldest
envelope has sat unattributed for over a week and is drifting toward the
retention cliff (`QUARANTINE_RETENTION_DAYS`, default 30).

**Action:** list (§4.2), find the oldest identities
(`summary.oldest_received_at` and the per-row `received_at`), and for each:
assign-and-restore (§5) if the device is wanted, or consciously let it
expire. The alert clears when the oldest envelope is younger than 7 days —
either restored or deleted.

## 5. Re-attribution procedure (step by step)

1. **Identify the sender.** From the quarantine row you have `identity_sha`
   (SHA-256 of the identity string the lookup used: syslog hostname, trap
   device id falling back to source IP, flow exporter address), `source_ip`,
   and `lane`. If you know the candidate hostname/IP, verify it hashes to the
   row you are holding:

   ```bash
   printf '%s' "core-sw-07.branch.example" | sha256sum
   ```

2. **Assign the device to its tenant** — Infrastructure UI or the API. The
   device's **name or management address must equal the original identity
   string** (that is what the inventory projection hashes). A device that
   only *resembles* the sender will not match.

3. **Wait for enrichment convergence** (≤ ~75 s: the api's 60 s CSV export
   tick + the vector tiers' content-watch reload). From this point the
   device's **new** telemetry attributes normally — the restore only has to
   recover the already-quarantined backlog.

4. **Restore** — platform admin + `sensitive_data:admin`:

   ```bash
   curl -s -X POST -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"identity_sha": "<64-hex sha from the listing>"}' \
     "https://<host>/api/quarantine/reattribute" | jq .
   ```

   The api resolves the hash against the **live inventory only** — you never
   supply a tenant. Refusals are `409`s that name the fix:
   *identity not in inventory* (step 2 not done / identity mismatch),
   *resolves only to the platform tenant* (assign it to a real tenant),
   *resolves to more than one tenant* (inventory conflict — e.g. NAT
   collapsing two devices onto one address; resolve it first).

5. **Interpret the response:**

   | Field | Meaning |
   |---|---|
   | `matched_identity_count` | distinct inventory identity strings that hash to this sha (name + address of the same device = 2 is normal) |
   | `tenant` | the tenant the inventory resolved — where the events went |
   | `restored` | events unsealed, re-injected through the authenticated bus, and accepted |
   | `failed` | envelopes that could not be restored (unseal/produce/shape failure) — investigate if nonzero |
   | `remaining` | envelopes for this sha beyond this batch (each call handles up to 500) — **repeat the POST until `remaining` is 0** |
   | `deleted` / `delete_failed` | tombstoned quarantine copies; a failed tombstone is *noise, not duplication* (see below) |

   **Immediate-replay noise is expected:** a repeated POST fired before
   OpenSearch's index refresh catches up may still *find* just-tombstoned
   docs and report nonzero counts. This is harmless — the restored events
   carry their original `cx_event_id` and the event sinks upsert on it
   (`id_key`), so tenant data can never duplicate. Wait a few seconds and
   list again for the true state.

6. **Verify:** the restored events appear in the tenant's own indices (under
   the tenant's seal rules, if any — the restore is a real key-boundary
   crossing: quarantine-decrypt, then the normal pipeline re-seals under the
   tenant's key), and `GET /api/quarantine` no longer shows the sha.

**Audit trail:** every restore records a `quarantine_reattribute` security
event in the audit trail (actor, identity_sha, resolved tenant, the four
counts — never payload contents). This is your evidence row; check it exists
after any restore you would need to account for.

## 6. Retention

- Knob: `QUARANTINE_RETENTION_DAYS` (compose default **30**) on the
  `opensearch-init` one-shot, which installs ISM policy
  **`netops-quarantine-retention`** over `netops-quarantine-*`
  (`deployment/docker/opensearch/apply-ism.sh`).
- To change it: set the variable in `deployment/docker/.env`, then re-run the
  one-shot — `docker compose run --rm opensearch-init`. The policy updates in
  place (seq_no-guarded).
- Retention is deliberately independent of `OPENSEARCH_LOG_RETENTION_DAYS`
  (default 14): re-attribution may legitimately need longer than log
  retention, but it is never unbounded.

## 7. Boot-refusal symptom (router will not start)

**Symptom:** `vector-router` exits with code **78** at start and its log
names a secret it could not resolve — `cxseal.quarantine` /
`cxmac.quarantine` (or a tenant's `cxseal.<t_…>`).

**Meaning:** the exec secret backend (`cx-secret-backend.sh`) could not fetch
the sealing keys from the api's `/internal/sealing/edge-keys` endpoint, and
Vector **refuses the whole config** rather than run with sealing silently
absent. This is the intended fail-closed behavior, and it is a **key-custody
problem, not a Vector problem**:

1. Is the api up, and does its log show `edge key served` for other fetches?
2. Is the swtpm sidecar (`secrets-seal`) healthy? An unseal failure at the
   api makes every key fetch fail — follow `secret-unseal-failure.md`.
3. Is the router presenting its SVID (TLS deployments — the endpoint accepts
   the router identity only)? Check the api log for identity rejections and
   `../tls-mtls.md` for the mesh triage path.

While the router is down, upstream lanes buffer per their own contracts —
fix custody promptly; do not work around the refusal.

## 8. Post-checks (after any procedure above)

- [ ] `netops_sec_quarantine_depth` and `…_oldest_seconds` moving the right
      way (the api samples them from the index at most every 60 s).
- [ ] The three quarantine alerts green in vmalert.
- [ ] For restores: the `quarantine_reattribute` audit event exists; the
      tenant's indices show the restored events exactly once.
- [ ] Lanes flowing (consumer lag ≈ 0) if you touched the router.
