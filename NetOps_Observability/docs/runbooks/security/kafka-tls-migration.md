# Runbook (OUTLINE) — Migrate Kafka to mTLS + ACLs

> **Status: OUTLINE. NOT EXECUTABLE — feature not built.** Kafka runs
> `PLAINTEXT` with no authentication and no ACLs today
> (`deployment/docker/docker-compose.yml:207-210`). Every step below is
> **[PENDING SEC-006/007]**.
> **This is the highest-risk migration in the entire programme** — the bus is
> the spine, and a mistake drops telemetry for every tenant (HLD §9 phase 3:
> risk **high**, telemetry **at risk**).

**Decision record:** ADR-SEC-005 (mTLS with the internal CA — owner-approved
2026-08-04), ADR-SEC-003 (identities), ADR-SEC-001 (accept-set migration).
**Complements:** [`docs/runbooks/tls-mtls.md`](../tls-mtls.md) (the workload mesh
this reuses), `bootstrap-pki.md` (must be complete first),
`docs/runbooks/backup-restore.md` and `docs/runbooks/correlation-storm.md` for
the surrounding operational context.

---

## 1. Purpose

Move the event bus from anonymous plaintext to mutual TLS with per-client
SPIFFE identities and least-privilege topic/consumer-group ACLs, **without
losing, duplicating or reordering a single event.**

Terminal state: no `PLAINTEXT` listener, and
`allow.everyone.if.no.acl.found=false`.

## 2. Prerequisites

- [ ] `bootstrap-pki.md` complete: workload CA sealed, trust bundle distributed.
- [ ] A **broker server certificate** exists. Note ADR-SEC-005 U5 / ADR-SEC-003
      U5: `tls_ca.go:145-155` mints only `api` and `nginx` — who issues the Kafka
      server SVID is **unresolved**.
- [ ] Client identities minted for every producer/consumer:
      `vector-aggregator`, `vector-router`, `goflow2`, `correlation`,
      `kafka-exporter`.
- [ ] **goflow2's TLS capability verified at the pinned digest**
      (`netsampler/goflow2:v2.2.1@sha256:bc7a…`, `docker-compose.yml:359`) —
      ADR-SEC-005 U4. If it cannot do client certificates, the per-client SCRAM
      exception must be authorized *before* starting.
- [ ] The ACL matrix drafted and reviewed (who produces what, who consumes what,
      which consumer groups).
- [ ] **Vector disk-buffer headroom measured** (`deployment/docker/vector/vector.yaml:47`
      and the `buffer:` blocks on the Kafka sinks) — these buffers are the only
      thing standing between a broker restart and data loss.
- [ ] Consumer-lag monitoring in place and trusted.
- [ ] Understanding that `BROKER_URLS` may point at an **external** broker
      (`docker-compose.yml:186-188`), in which case the customer owns the
      mechanism and this runbook is advisory only.

## 3. SAFETY WARNINGS

| Risk | Detail |
|---|---|
| 🔴 **WILL drop telemetry if mis-sequenced** | Every log, flow, metric and trap crosses this bus. A producer that cannot authenticate stops producing; a consumer that cannot authenticate stops consuming and lag grows until retention discards the backlog. **Retention is the deadline** — past it, the loss is permanent. |
| 🔴 **Broker restart = total bus outage (single-node KRaft)** | Listener changes require a restart. There is no second broker to absorb it. The outage is brief but complete; Vector's disk buffers are the safety margin and they are finite. |
| 🔴 **`allow.everyone.if.no.acl.found=false` is a cliff edge** | The instant it flips, every principal without an explicit ACL is denied. Anything missed goes dark simultaneously. Never flip it without a quiet observe phase (step 6). |
| 🔴 **Removing the PLAINTEXT listener is effectively irreversible mid-incident** | Restoring it requires another broker restart — another outage — at exactly the moment you can least afford one. |
| 🟠 **Consumer-group ACLs are as important as topic ACLs** | Without them, one client can join another's group and silently steal partitions. That presents as *data loss*, not as a security event. |
| 🟠 **Certificate rotation vs long-lived consumers** | Clients that read certificates only at startup must restart to rotate (ADR-SEC-005 U3). A 24 h TTL means a daily restart of the ingestion path — decide the declared TTL for these peers **before** cutover, not after. |
| 🟠 **The api→bus hop is NOT secured by this runbook** | The Go API has no Kafka client at all — it produces over Vector's HTTP bus-bridge (`src/backend/bus_producer.go`). Securing Kafka while `bus_in` still accepts a shared `INGEST_TOKEN` over plaintext leaves an easier path in. Sequence the two together. |
| ⚪ **Reversible until step 8** | Steps 1–7 revert by reverting compose and restarting the broker (accepting the outage). |

## 4. Pre-validation

1. Baseline: per-topic produce/consume rates, per-group lag, end-to-end latency,
   and event counts per tenant — you need these to *prove* no loss afterwards.
2. Confirm buffer headroom exceeds the planned broker downtime with margin.
3. Confirm retention windows per topic; compute how long a stalled consumer can
   be tolerated before permanent loss.
4. Verify each client's TLS configuration in a scratch environment first. Never
   discover a client limitation on the live bus.
5. Confirm the trust bundle is present in every client container.
6. **[PENDING SEC-008]** Validator run: record current violations (V5).

## 5. Procedure *(all steps **[PENDING SEC-006/007]**)*

1. **Add a second listener** (`SSL`) alongside `PLAINTEXT`; advertise both.
   Broker restart #1. Verify the bus fully recovers and lag returns to baseline
   **before doing anything else.**
2. **Enable the authorizer in observe posture**:
   `allow.everyone.if.no.acl.found=true`, authorizer logging on. No client
   changes yet.
3. **Migrate clients one at a time**, lowest blast radius first:
   `kafka-exporter` → `goflow2` → `vector-aggregator` → `vector-router` →
   `correlation`. After each: verify produce/consume, verify lag returns to
   baseline, verify event counts.
4. Verify each migrated client's principal appears in the authorizer log as the
   expected SPIFFE identity.
5. **Write the ACLs** for every principal — topics *and* consumer groups.
6. **Observe phase:** run with ACLs written but permissive, and read the
   would-have-denied log. **Do not proceed until it is quiet for a full business
   cycle**, including any batch/scheduled workloads.
7. **Flip `allow.everyone.if.no.acl.found=false`.** Broker restart #2. Watch
   denials and lag continuously.
8. **Remove the `PLAINTEXT` listener.** Broker restart #3. ⚠ **Point of no
   return** — close the migration exception in the policy table.

## 6. Rollback

| Stage | Action |
|---|---|
| 1–2 | Revert compose, restart the broker (one outage). |
| 3–4 | Revert the individual client to the plaintext listener — it is still advertised, so this is per-client and cheap. |
| 5–6 | Delete the ACLs; posture is still permissive so nothing was denied. |
| 7 | Set `allow.everyone.if.no.acl.found=true` and restart. Outage, but recoverable. |
| 8 | **Re-add the PLAINTEXT listener and restart** — another full outage, performed under pressure. Avoid needing it: do not take step 8 until step 7 has soaked. |

## 7. Audit evidence to capture

- The ACL matrix as applied, per principal, with the reviewer.
- Broker configuration before and after each restart.
- The authorizer observe-phase log, and the evidence it was quiet before step 7.
- Per-client cutover timestamps with lag graphs either side.
- Event counts per topic and per tenant, before and after the whole migration —
  the proof of no loss.
- Every broker restart: time, duration, and buffer high-water mark during it.
- Any per-client SCRAM exception granted (ADR-SEC-005 decision 6) with owner and
  expiry.

## 8. Post-checks

1. No `PLAINTEXT` listener in the broker configuration.
2. `allow.everyone.if.no.acl.found=false` confirmed.
3. Every client authenticated by certificate; principals match the intended
   SPIFFE identities exactly.
4. **Negative test:** an unauthorized principal is denied produce *and* consume,
   and the denial is visible in metrics and logs.
5. Consumer lag at baseline for every group; no group stranded.
6. Event counts per tenant reconcile with the pre-migration baseline — no loss,
   no duplication.
7. Certificate rotation exercised at least once for the slowest client, in
   staging, before this is declared done (HLD §9 phase 6's real acceptance
   criterion is telemetry continuity across rotation).
8. Transport-policy rows updated; migration exception closed, not left open.
