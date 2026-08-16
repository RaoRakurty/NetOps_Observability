# CORRELIX Scale Test — Live Findings (breaking / will-break points)

Running log of empirically-observed and code-derived breaking points, per module.
Rig: THIS dev host (4 vCPU / 15 GiB RAM / ~26 GiB free disk) = **L0/L1 only** per
`/var/tmp/CORRELIX_SCALE_TEST_READINESS.md`. Numbers here are the FIRST break on
THIS hardware plus the design-limit ceilings that bound real scale; they are NOT
GA capacity (that needs the rig in the readiness doc). Started from a verified
clean-slate (0 devices, empty stores).

## Method
- Baseline the idle empty stack, then ramp one workload at a time, watch the
  per-module signals (CPU/mem/disk, queue depth, lag, latency), record the first
  degradation + the code limit that explains it.
- "BREAKS@" = observed failure on this box. "CEILING" = hard design limit from code.

## Idle baseline
_(filled below)_

## Findings by module
_(appended as tests run)_

### Idle baseline (empty stack, 0 devices)
- Host: 4 cores, **5.5 GiB / 15.6 GiB RAM used at idle**, 26 GiB disk free.
- Per-container idle memory vs cap (the tight ones):
  - **OpenSearch: 2.29 GiB / 3.69 GiB cap (62%) AT IDLE** ← least headroom on the box.
  - Kafka 608 MiB / 1.08 GiB; Keycloak 498 MiB / 1 GiB; ClickHouse 351 MiB / 5.2 GiB.
- **CEILING (memory):** with the empty stack already at 5.5 GiB and OpenSearch near
  its heap cap, this host has ~2–3 GiB of real working headroom. Any log/flow load
  that grows OpenSearch or ClickHouse working sets will hit container mem caps
  (OOM-kill / GC thrash) well before CPU. **First-to-break under load = OpenSearch.**

## Module: Ingest pipeline (syslog → Vector → Kafka → OpenSearch + correlation)
Raw syslog EPS ramp on this box (before pivoting to device-based sim). Findings:
- **OpenSearch = first bottleneck (CPU).** At **~2k EPS OpenSearch hit 94% CPU**;
  at 10k EPS it ran 145% (>1 core) and could not keep indexing pace.
  BREAKS@ ~2–5k EPS on this 4-core box (indexing CPU-bound; heap held ~2.3 GiB).
- **Kafka consumer lag explodes past ~5k EPS.** Consumer-group lag: 22 → 800 (2k)
  → **50,439 (5k)** → **172,198 (10k)**. The correlation + router consumers fall
  behind the producer; lag is unbounded-growing = backpressure not reaching the
  source (UDP syslog can't backpressure — it silently drops instead).
- **vector-aggregator saturates ~73% CPU at 5k EPS**; correlation ~64%.
- CEILING note: UDP syslog has NO backpressure — beyond pipeline capacity, loss is
  silent at the kernel socket buffer (matches the readiness doc's §8 concern).
  A real deployment needs TCP/TLS syslog + a larger OpenSearch tier to avoid drops.
- **Verdict:** on THIS host the ingest chain is healthy to ~2k EPS, degrades
  (lag + OS CPU) by 5k, and is lossy by 10k. GA target (250k EPS §8) needs the
  external OpenSearch cluster + multi-broker Kafka from the readiness doc.


## Module: Device inventory / onboarding (POST /api/devices)  ⚠ WILL-BREAK
Device-based sim (registered routers). Create-rate **degrades super-linearly**:
- 0→500 devices: **155/s** · 500→1000: **63/s** · 1000→2000: **25/s** (and falling).
- GET /api/devices stays fast (17→29 ms for 1–2k devices; ~470 KB body); postgres
  CPU ~1%. So the cost is NOT the DB or listing — **each create does O(N) work**
  proportional to the current fleet size (a synchronous per-create rebuild).
- **Projection:** at this curve, onboarding 10k devices would crawl to a few/sec
  and take a very long time — a real bulk-onboarding / discovery-storm break (plan
  §15 topology explosion, §17 rediscovery). CEILING is in the create path, not storage.
- Cause: under investigation (suspected full tenant-registry / router-config /
  topology regeneration on every device write).

### ROOT CAUSE — device store is a single whole-fleet blob (O(N) per write, O(N²) bulk)  🔴 HIGH
- `internal/discovery/devstore.go:saveLocked()` (line 138): every `Put`/`Delete`
  does `json.MarshalIndent(devPersistFile{Manual: s.manual, Suppressed: s.suppressed})`
  — the ENTIRE device inventory + all tombstones — then `kv.Save(path, wholeBlob)`
  (one KV row). So each device create/update/delete **rewrites the full fleet**.
  MarshalIndent (pretty-printed) makes the blob even larger.
- Consequences at scale:
  - **Bulk onboarding is O(N²)** — measured 155→63→25/s over the first 2k devices.
    10k devices via this path would crawl (each insert re-serializes ~MBs).
  - **Every SNMP/NetBox discovery poll that upserts re-serializes the whole fleet**
    → discovery of a large network self-throttles and spikes CPU/WAL each cycle.
  - **Concurrency:** `DevStore.mu` is held across the full serialize + KV write, so
    concurrent device writes (multi-source discovery + API) fully serialize.
  - Under STORE_BACKEND=postgres the blob is one `app_kv`/`netops_kv` row rewritten
    in full each time → PG WAL churn proportional to fleet size per write.
- **Fix direction:** per-device rows (one KV key per device, or a real `devices`
  table row-per-device with an index) so a write is O(1); keep the in-memory map
  for reads. This is the single biggest device-scale blocker found.
- **Verdict:** device inventory does NOT scale past low-thousands on the current
  store; it caps SNMP-discovery fleet size and API onboarding well before storage
  or the DB become the limit.

## Module: Correlation dead-letter durability  🔴 (surfaced by clean-slate install)
- correlation service logged **238,844+ `dead-letter write failed: PermissionError`**
  and climbing — every event that fails correlation and should be parked is LOST,
  and the error floods logs (self-DoS on the log pipeline).
- Cause: `data/correlation/deadletter` is owned by the installer user (uid 1000),
  but the correlation container runs as uid 10001 → cannot write. install.py warned
  "can't chown data/correlation/deadletter to 10001:999 (not root)" and continued.
  Unlike postgres/clickhouse (which self-chown their volume on boot), the
  correlation image does NOT self-chown its dead-letter dir.
- Scale relevance: under load, rejected/unparseable events go to dead-letter; if
  that write fails, the seal-or-quarantine/durability guarantee is void AND the
  error rate scales with load. A busy stack floods here.
- **Two fixes:** (product) correlation entrypoint should self-chown/create its
  dead-letter dir like postgres/clickhouse do; (install.py) extend the data-dir
  ownership handling (already flagged in the reinstall fixes) to this dir.

## Module: Kafka bus — RECOVERS (not a break, positive result)
- Under the syslog ramp, consumer-group lag spiked to ~172k at 10k EPS but
  **drained back to 0–10 within seconds after load stopped** — the bus path is
  durable and catches up (no permanent loss on the TCP/Kafka side). Lag during
  overload = added latency, not loss. Contrast the UDP-syslog source, which drops.

## Module: Topology / API at fleet scale — OK so far, O(N) payload
- At 3,246 devices: `GET /api/topology/graph` = **1.27 MB in 48 ms**; `GET /api/devices`
  ~29 ms. Fine latency, but the graph payload is O(N) (1.27 MB / 3.2k nodes) →
  at 10k+ it's multi-MB per request (frontend render + bandwidth, plan §15). Watch.

## Module: Correlation signal generation from device telemetry  ⚠ needs-verification
- Injected 120 device-attributed failure events (LINK_DOWN/BGP_DOWN/TUNNEL_DOWN
  from 30 registered routers `rtr-0000x`) → **corr_signals delta = 0**; correlation
  CPU stayed ~1% (idle). Events reach OpenSearch but do NOT become correlation
  signals.
- Suspected cause: the tenant/device REGISTRY correlation reads for attribution is
  not populated by API-created "manual" devices (registry likely fed by
  discovery/SNMP or a device→registry sync topic, not the manual inventory), so
  the syslog is untagged and correlation skips/quarantines it — OR the injected
  RFC3164 format doesn't match a producer pattern. Either way, the manual-device →
  correlation attribution path is not wired for this test's device source.
- To confirm: repeat with an SNMP-DISCOVERED device (ENABLE_SNMP_DISCOVERY + an
  snmpsim target) and a golden-format event; compare corr_signals. This is the
  gate for testing RCA/correlation at scale — must be resolved before §7 scenarios.

---
## Run summary (this box, L0/L1) — biggest first
1. 🔴 **Device store O(N²)** (`devstore.saveLocked` whole-fleet blob) — create rate
   155→25/s by 2k devices; caps inventory/discovery scale. HIGHEST-value fix.
2. 🔴 **OpenSearch ingest CPU-bound** — ~94% CPU at 2k EPS; lossy (UDP) by 10k EPS.
3. 🔴 **Correlation dead-letter unwritable** (install ownership) — 238k silent
   drops + log flood; fixed here, needs product self-chown.
4. ⚠ **Correlation attribution gap** for manual devices — no signals generated.
5. 🟡 **Topology graph O(N) payload** — 1.27 MB @ 3.2k nodes; watch at 10k+.
6. ✅ **Kafka bus recovers** — 172k lag drained to ~0 after load (durable).
_Next: resolve the correlation attribution gap (SNMP-discovered device), then run
the §7 correlated-failure scenarios; L2+ needs the readiness-doc rig._

## END-TO-END FLOW STATUS (traced one marked event, device rtr-00001)
- ✅ **Ingest→bus→storage leg IS end-to-end:** syslog → syslog-ng → Vector →
  Kafka → OpenSearch, searchable within seconds. This half works at scale (subject
  to the OpenSearch/EPS ceiling above).
- ⚠️ **BUT it lands UNTAGGED** — index `netops-syslog-untagged-*`, tenant empty.
- ❌ **Correlation/value leg does NOT flow:** untagged events produce no corr_signals;
  the RCA path never sees the traffic.
- ROOT: tenant-attribution gap. Vector's tenant registry tags by device source-IP
  (and/or hostname); the test's syslog originates from 127.0.0.1 while device
  addresses are 10.x.x.x → source-IP miss, and API-created "manual" devices don't
  appear to populate the hostname registry. → everything is untagged → uncorrelated.
- IMPLICATION for scale testing: I can push the ingest/storage leg to its ceiling
  and capture symptoms (that half is real E2E), but testing correlation/RCA at
  scale is BLOCKED until attribution is closed — needs either syslog whose source
  IP matches a registered device, an SNMP-DISCOVERED device, or the registry fed
  from inventory. This is the top gate before §7 correlated-failure scenarios.

## Module: Cloud simulation (netops.cloud lane)
- cloud-ingest is behind the `cloud-ingest` compose profile (OFF by default; needs
  real cloud creds/boto3 or fixtures — the clean-slate wiped /data/cloud-fixtures).
  So no cloud discovery runs by default post-install.
- Injected 3,000 synthetic provider_events (VPC/subnet/EC2/ENI/TGW/DirectConnect/
  ExpressRoute/Interconnect, AWS+Azure+GCP) to `netops.cloud`. Correlation CONSUMED
  all 3,000 (group offset 3000, lag 0) — but **0 landed in any cloud index or
  ClickHouse cloud table**. Untagged (tenant_id="") → same attribution gap as syslog
  → consumed-but-no-output. Cloud value-path is also attribution-blocked.
- To scale-test cloud for real: enable the `cloud-ingest` profile with fixtures (or
  mocked SDK) and a tenant mapping, OR inject TAGGED events with a cloud tenant
  registry. Same top gate as the syslog correlation path.

## CEILING SYMPTOMS captured (sustained ~8k EPS syslog, this box)
- Kafka consumer lag grew linearly & unbounded: 156k→542k→929k→1.24M→1.56M→1.89M→
  2.23M→2.58M→ peak ~3.1M msgs over ~5 min.
- OpenSearch was NOT the bottleneck: write queue=11, 0 rejections, heap 42%. The
  limit is the vector-router consume→VRL-transform→bulk-index throughput (~10k/s).
- Recovery: lag drains ~10k/s once input stops → a few-min overload = MINUTES of
  data staleness (indexed late), not permanent loss until Kafka retention/disk hit.
- Disk drained ~3 GB during the run; sustained overload → disk-full ~1 h = hard stop.
- No OOM, no restarts, host RAM safe. Ceiling here = throughput/lag/latency + disk,
  not memory.

## RESOLVED: tenant tagging for simulated devices (like origin devices)
- Mechanism: the API exports `data/api/enrichment/device_tenant.csv` (identity→tenant,
  one row per device NAME and per ADDRESS), mounted read-only into vector-aggregator
  + vector-router; a syslog event's hostname/IP is looked up → `.tenant_id` stamped →
  per-tenant index `netops-syslog-<tenant>-*`. Vector auto-reloads on CSV change (SIGHUP).
- Root of the earlier "everything untagged": my devices had `tenant_id=""` (global).
- FIX (works): created org+tenant `t_427b…`, created devices WITH that tenant_id →
  CSV regenerated with the mapping → Vector reloaded → a syslog event from
  `acme-rtr-005` landed in `netops-syslog-t_427b…-*` with `tenant_id=t_427b…`. ✅
- So simulated devices now tag exactly like origin devices, once assigned a tenant.

## Module: Correlation consumer throughput  🔴 (new, from the ceiling run)
- After the 8k-EPS ceiling run, the two syslog consumers diverged sharply:
  - `netops-router-syslog` (→ OpenSearch): caught up, **lag 16**.
  - `netops-correlation` (→ RCA engine): **lag 1,249,624** (offset 1.08M of 2.33M).
- Correlation consumes syslog **far slower** than the router indexes it (the Python
  single-event-loop engine vs Vector's bulk pipeline). Under sustained load,
  correlation falls behind by millions → RCA/incident detection latency grows
  unbounded independent of storage. This is a distinct, engine-side ceiling and is
  the correlation-scale bottleneck (matches readiness-doc §7 correlation-latency).

### Device-store ceiling latency (fleet ~3,346)
- Batch create: **13.6/s** (was 155/s empty); per-create p50=52 ms, p95=94 ms,
  **max=4,804 ms** — a multi-second tail when the whole-fleet blob write + the
  device_tenant.csv regen (now 7,293 rows) coincide with a create. api/postgres CPU
  low between spikes (bursty). Soft ceiling: onboarding crawls + periodic 4–5 s stalls.

## Module: Correlation SIGNAL GENERATION (value path) — ⚠ test-realism gate
- With correlation at latest (real-time, lag 6) and events tenant-TAGGED, injected
  raw-syslog "LINK_DOWN/BGP_NEIGHBOR_DOWN/TUNNEL_DOWN" text produced **0 corr_signals
  and 0 corr_objects (incidents)**. Existing 3,677 signals are the platform's own
  self-telemetry (empty tenant).
- Conclusion: correlation only emits signals from events matching its **structured
  producer patterns** (control-plane / port-event / trap / gNMI oper-state shapes),
  which Vector VRL parses from real device output — NOT arbitrary syslog strings.
- Implication: raw syslog injection tests ingest/storage/throughput, but the RCA
  value path (§7 correlated-failure) needs GOLDEN-FORMAT events or real protocol
  simulators (SNMP traps / gNMI oper-status / structured RFC5424). This is the top
  build item for a real correlation/RCA scale test (readiness-doc Network Digital Twin).
- What IS proven end-to-end: tenant attribution (tagged index), correlation
  consumption + throughput ceiling (~1k evt/s), ingest→storage flow.

---

## 2026-08-16 (evening) — GA hotfix wave: live verification on the lab stack

All hardware-independent GA-plan items were implemented and the stack redeployed
(TLS variant, `BUS_PARTITIONS=4`, `--scale correlation=2`). Live results:

| Fix | Live evidence |
|---|---|
| Devstore per-record O(1) (P0) | Onboard 100 devices through the API on the new image: first-100 rate 93.8–100.1/s vs last-100 96.5–111.8/s (**ratio 1.03–1.12** — linear; the old blob store degraded 155→14/s by 3.3k) |
| Correlation co-partitioning (P0) | Replica-1 owns partitions **[0,1] of all 12 topics**, replica-2 **[2,3]** (range assignor); all topics altered 1→4 partitions by kafka-init `BUS_PARTITIONS`; ACL matrix re-applied (62 entries incl. `flows.raw`) |
| Rebalance-thrash fix (P1) | 120,001-event burst at ~1,888 ev/s (2× single-replica ceiling): **zero** UnknownMemberId/CommitFailed/restarts (old engine: 225/18/99), lag drained **monotonically to ~0** (old: stuck forever). Drain exceeded the harness 3× budget — expected: single-tenant workload keys to ONE partition/replica; this is the documented per-tenant ceiling, not thrash |
| Failure accounting | **Exact balance: 120,001 injected == 120,001 persisted + 0 DLQ + 0 rejections**; 100/100 devices covered in corr_signals |
| DLQ fail-fast + installer chown + Kafka-ACL install (P0) | In the tree with tests; ACL matrix + DLQ ownership manually repaired live per runbook (the defects were found ON this deployment by the mini-ladder) |
| healthz `registry_identities` | Was lazy (idle replica reported 0 for a healthy 201-row registry, failing the propagation gate) — now eager; verified by rerun's burst gate passing |

Known-good residual behavior: unregistered live devices (spine1/2 sRLinux) are
tenant-refused into the bounded DLQ — correct on a clean-slate stack with no
inventory. Mini-ladder runs archived under `data/miniladder/` (gitignored).

**Still unproven (needs the rig — tracker 152/153):** multi-tenant partition
spread under sustained load, capacity at L2+, sizing-table validation.
