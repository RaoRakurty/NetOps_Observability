# CORRELIX Scale Test — Report

Structured against the requirements in `CORRELIX_SCALE_TESTPLAN.md`. Reports what
was exercised, the ceiling/symptom observed, and status vs. each requirement area.
Raw log: `SCALE_TEST_FINDINGS.md`.

---

## 1. Executive summary & verdict
- **Environment:** single dev host, **4 vCPU / 16 GiB / ~26 GiB free disk** — an
  **L0/L1 functional rig** per the readiness doc, NOT a GA rig. Numbers below are
  the FIRST ceiling on THIS hardware + code-derived design limits; they are not GA
  capacity.
- **Started from a verified clean-slate** (0 devices, empty stores) via a
  device-based simulation (registered routers → telemetry), not manual store writes.
- **Verdict: NOT GA-ready as-is.** Two 🔴 code-level scale defects block real scale
  regardless of hardware (device-store O(N²); correlation single-loop throughput),
  plus an install ownership break. The ingest→storage path is sound and recovers.
- **Headline ceilings on this box:** ingest ~2k EPS healthy / lossy by 10k;
  device onboarding degrades from 155→14/s by ~3.3k devices; correlation processes
  ~1k events/s; Kafka lag grows unbounded under overload then drains ~10k/s.

## 2. Method (plan §0, §Clean-slate)
- Clean-slate: full app-data wipe, stack re-initialized empty, verified 0 devices.
- Digital-twin (plan §1): lightweight registered-device fleet + UDP syslog / cloud
  event injection. Tenant attribution via the device→tenant CSV (like origin devices).
- Instrumentation (plan §41): docker stats, Kafka consumer-group lag, OpenSearch
  _cat/_nodes, ClickHouse system.parts, disk/host RAM, per-module latency.

## 3. Results by requirement area

### 3.1 Protocol / ingestion scale (plan §3–8) — ⚠ ceiling ~2k EPS on this box
- syslog → syslog-ng → Vector → Kafka → OpenSearch flows **end-to-end, searchable**.
- **OpenSearch is NOT the first limit** (0 write rejections, heap 42% at load). The
  bottleneck is **vector-router consume→VRL-transform→bulk-index ≈ 10k msg/s**.
- Healthy ≤2k EPS; degraded (lag+CPU) by 5k; **lossy by 10k** (UDP syslog has no
  backpressure → silent kernel-socket drops). TCP/TLS syslog needed to avoid loss.

### 3.2 Alarm/log/event + correlated-failure (plan §6, §7) — ⚠ attribution + throughput
- Tenant attribution initially missing → all telemetry `untagged` → uncorrelated.
  **RESOLVED**: assign devices a real tenant → API regenerates `device_tenant.csv`
  → Vector auto-reloads → events land in `netops-syslog-<tenant>-*` tagged. ✅
- **Correlation throughput ≈ 850–1,050 events/s** (single Python event loop). It is
  the **slowest consumer** — after a burst it fell **1.25M behind** on syslog while
  the router had caught up to 16. RCA/incident latency grows unbounded under load.

### 3.3 Flow / IPFIX (plan §9) — not load-tested; goflow2 present, flows table live.
### 3.4 gNMI / NETCONF (plan §4,§5) — collectors present (gnmic, netconf.go); not
  load-tested (needs protocol simulators — snmpsim/Netopeer2/gNMI targets).

### 3.5 Storage tiers (plan §10–14)
- **OpenSearch:** idles **2.29 GiB / 3.69 GiB cap (62%)** on an EMPTY stack — the
  tightest memory on the box. Indexed steadily under load; heap 42%. Single-node.
- **ClickHouse / VictoriaMetrics:** healthy at test volumes; single-node (replica
  tests need an external cluster). VM cardinality (plan §10) not pushed.
- **PostgreSQL:** low CPU/mem throughout; NOT the device-scale limit (the device
  store blob is — see 3.7).

### 3.6 Topology explosion (plan §15) — 🟡 O(N) payload
- `GET /api/topology/graph` = **1.27 MB in 48 ms at 3.2k devices**. Latency fine,
  payload O(N) → multi-MB per request at 10k+ (frontend render + bandwidth).

### 3.7 Device inventory / onboarding (plan §15,§17) — 🔴 O(N²)
- `devstore.saveLocked()` rewrites the **entire fleet as one JSON KV blob on every
  device write** (+ regenerates the whole `device_tenant.csv`). Create rate:
  **155 → 63 → 25 → 14 /s** by 3.3k devices; per-create tail **max 4.8 s**.
  10k-device onboarding/discovery is untenable on this path. Fix: per-device rows.

### 3.8 Multi-tenant / noisy-neighbor (plan §2,§16) — attribution proven; isolation
  not yet load-tested (needs the fix + a bigger rig for concurrent tenants).

### 3.9 Cloud simulation (plan §27–40) — attribution-gated
- `cloud-ingest` is profile-gated (off by default; needs creds/fixtures — wiped).
- 3,000 synthetic provider_events (AWS/Azure/GCP incl. DirectConnect/ExpressRoute/
  Interconnect) → produced to `netops.cloud`, **consumed by correlation (lag 0)**
  but **0 stored** (untagged → same attribution gate). Needs cloud tenant mapping.

### 3.10 Dependency chaos / impairment / restart (plan §18,§19,§21) — not run this pass.

## 4. Ceiling symptoms captured (plan §23 breaking-point)
Sustained ~8k EPS syslog on this box:
- **Kafka consumer lag grows linearly & unbounded** — 156k → **peak ~3.1M** over ~5 min.
- OpenSearch never the limit (0 rejections, heap 42%); limit = router bulk ~10k/s.
- **Recovery:** drains ~10k/s once input stops → a few-min overload = **minutes of
  data staleness** (delayed, not lost, until Kafka retention/disk).
- **Disk drained ~3 GB during the run**; sustained overload → disk-full in ~1 h = hard stop.
- **No OOM, no restarts, host RAM safe** — ceiling here = throughput/latency + disk,
  not memory.

## 5. Defects that block scale (fix before GA scale)
| # | Sev | Defect | Effect | Fix |
|---|-----|--------|--------|-----|
| 1 | 🔴 | Device store = one whole-fleet KV blob per write (`devstore.saveLocked`) | O(N²) onboarding/discovery; caps fleet at low-thousands | per-device rows (O(1) write) + incremental CSV |
| 2 | 🔴 | Correlation single event-loop ≈1k evt/s | RCA latency unbounded under load; slowest consumer | partition/parallelize the engine; scale-out consumers |
| 3 | 🔴 | Correlation dead-letter dir not self-chowned | 238k silent drops + log flood when unwritable | entrypoint self-chown (like postgres/clickhouse) |
| 4 | 🟡 | UDP syslog silent drop past capacity | invisible loss under overload | prefer TCP/TLS syslog; document |
| 5 | 🟡 | Topology graph O(N) payload | large responses at 10k+ | paginate / server-side aggregate |

## 6. Coverage NOT completed (needs the readiness-doc rig)
Flow/IPFIX load, gNMI/NETCONF at scale, VM cardinality, ClickHouse replica/HA,
noisy-neighbor isolation under concurrency, dependency chaos, network impairment,
72h soak, and true multi-cloud discovery — all require the L2+ rig (§1 below) and
the two 🔴 fixes first.

---

## 7. Recommended resources per host, by device count (plan §25 capacity)

Derived from observed ceilings on this box (4 vCPU/16 GiB = ~L1) + the repo's
`docs/RESOURCE_SIZING.md` model, **assuming the two 🔴 fixes land** (device-store
per-row writes; correlation scaled-out). Without those fixes, device count is
capped at low-thousands and correlation latency is unbounded regardless of hardware.

**Assumptions per device (steady state):** ~24–48 interfaces polled; ~5 events/device/
day baseline; modest flows; per-tenant indices. Retention: 14 d logs / 30 d flows /
default metrics. Numbers are the CORRELIX stack (single-node bundle) footprint —
add headroom for bursts (§25: qualify at ~2× projected load).

### On-prem (single host, bundled single-node stack)
| Devices | vCPU | RAM | Disk (NVMe) | Notes |
|--------:|-----:|----:|------------:|-------|
| ≤ 50 (demo/L0) | 4 | 16 GiB | 100 GiB | eval only; OpenSearch alone idles ~2.3 GiB |
| ≤ 250 | 8 | 32 GiB | 250 GiB | `small` profile; strict budgets from here up |
| ≤ 1,000 | 16 | 64 GiB | 500 GiB | `medium`; OpenSearch heap ≥ 8 GiB |
| ≤ 2,500 | 24 | 96 GiB | 1 TB | ingest approaching single-node OpenSearch limit |
| ≤ 5,000 | 32 | 128 GiB | 2 TB | `large`; **split storage tiers off-box recommended** |
| 10,000+ | — | — | — | **single host insufficient — go clustered (below)** |

### On-prem / cloud CLUSTERED (10k+ devices, GA scale)
Split the stack; scale the tiers independently (the single-node bundle does not
reach here — matches §11/§12 topology notes):
| Tier | Sizing driver | Guidance @ 10k devices |
|------|---------------|------------------------|
| OpenSearch | log EPS + retention (CPU-bound indexing) | 3+ data nodes, 16 vCPU / 64 GiB (31 GiB heap) each |
| ClickHouse | flow rate + merges | keeper + 2+ replicas, 16 vCPU / 64 GiB, fast NVMe |
| Kafka | producer EPS + consumer count | 3 brokers, 8 vCPU / 32 GiB, dedicated disks |
| VictoriaMetrics | active series (devices×interfaces×metrics) | vmstorage 16 vCPU / 64 GiB; front with vmauth |
| **Correlation** | events/s (the §7 limiter, ~1k/s per instance today) | **N partitioned instances**; 1 per ~1k sustained evt/s |
| API + Vector | request + ingest throughput | 2× API (8 vCPU/16 GiB), 2× vector-router (8 vCPU/16 GiB) |
| PostgreSQL | tenants + inventory (light) | 8 vCPU / 32 GiB, replica for HA |

### Cloud instance mapping (equivalent shapes)
| On-prem line | AWS | Azure | GCP |
|---|---|---|---|
| 8 vCPU/32 GiB | m6i.2xlarge | D8s_v5 | n2-standard-8 |
| 16 vCPU/64 GiB | m6i.4xlarge | D16s_v5 | n2-standard-16 |
| 32 vCPU/128 GiB | m6i.8xlarge | D32s_v5 | n2-standard-32 |
| ClickHouse/OpenSearch data nodes | i4i/i3en (NVMe) | Lsv3 (NVMe) | n2 + local SSD |

**Rule of thumb:** OpenSearch RAM and correlation instance-count are the two levers
that scale fastest with load; disk is retention-bound; PostgreSQL is not the limit.
Always feed the target workload into `correlix-sizing.yaml` and qualify at ~2× before
production (§25).

## 8. GA sign-off status (plan §42, §44)
- **P0 blockers:** device-store O(N²); correlation single-loop throughput. → **fix before GA scale.**
- **Proven:** clean-slate; ingest→storage E2E; tenant attribution; bus recovery.
- **Not verified (needs golden events + L2+ rig):** correlation/RCA signal generation
  at scale, flows/gNMI/NETCONF scale, VM cardinality, HA/replica, noisy-neighbor,
  chaos/impairment, 72 h soak, real multi-cloud discovery.
- **Verdict:** L0/L1 functional PASS; **GA scale = NOT YET** — gated on the two P0
  fixes and a proper rig with protocol simulators.

---

## 9. Correlation engine — scaling limits (measured + architectural)

The correlation/RCA engine (`src/correlation`, Python) is the value-path limiter.

### Measured on this box (4 vCPU / 16 GiB)
| Metric | Value | How measured |
|---|---|---|
| **Sustained processing throughput** | **~850–1,050 events/s** | drain rate of a 2.3M-event syslog backlog |
| Behavior under overload (8k EPS in) | **falls behind unbounded** — reached **1.25M lag** while the router (→OpenSearch) had caught up to 16 | consumer-group lag |
| Peak backlog before drain | ~2.3M events on netops.syslog | lag |
| Drain rate after input stops | ~1k events/s (linear) | lag over time |
| CPU profile | ~30–65% (one core bound); NOT multi-core | docker stats during drain |
| Memory | **flat ~56–64 MiB** (of 789 MiB cap) | docker stats — NOT memory-bound |
| Commit cadence | manual commit, **N=100 / T=5 s** | engine log |

### Why it's the limiter (architecture)
- **Single asyncio event loop** consuming 12 topics (syslog, flows, metrics, traps,
  probes, cloud, wireless, app-identity, controller, verification, edge). Per-event
  work (parse → producers → window buffer → correlation cycle) is serialized on one
  core. The engine cycle is offloaded to an executor, but ingest/producers are on the loop.
- Consequence: it processes ~1k events/s regardless of how fast the bus/OpenSearch
  go (they do ~10k/s). At any sustained input > ~1k EPS the RCA path lags and
  incident-detection latency grows without bound; storage stays current, RCA does not.

### Scaling limits & headroom
- **Per-instance ceiling ≈ 1k events/s** processed (this box; a faster core scales
  ~linearly with single-thread speed, not core count).
- **Not memory- or disk-bound** — purely CPU/single-thread bound.
- **To scale:** partition the input by tenant/entity and run **N correlation
  instances** (one consumer per partition), sizing **~1 instance per ~1k sustained
  events/s**. E.g. 10k EPS of correlatable telemetry ≈ 10 partitioned instances.
- **Caveat:** signal GENERATION requires producer-recognized event shapes (Cisco
  mnemonics, traps, gNMI oper-state); raw text is consumed (costing throughput) but
  emits nothing. The ~1k/s is the PROCESSING ceiling either way.

### Correlation VALUE PATH — verified working (with correct event formats)
- Running the shipped `correlation_e2e.py` seam scenarios against the LIVE stack,
  the engine produced real RCA objects: **WAN-handoff → SaaS-experience-degraded**,
  **middle-mile DIA-egress-latency**, and **device-resource-anomaly**, correlating
  LINK/BGP syslog + probe-loss + metric signals (5/8 e2e scenarios PASS; the 3 FAILs
  are strict sub-assertions, not missing correlations).
- KEY: signals require the **mnemonic as the syslog appname/tag** (e.g. tag
  `LINK-3-UPDOWN`), not free-text — which is why ad-hoc text injection produced 0.
- So the RCA value path IS functional; its SCALE limit is the ~1k events/s
  single-loop processing ceiling above (partition + N instances to scale).
