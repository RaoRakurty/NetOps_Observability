# Resource Sizing

Correlix sizes itself to the customer's host and workload at install time.
No universal hard-coded limits: the days of one `CLICKHOUSE_MEM_LIMIT=5g` for
every deployment are over (#102). Design record:
`docs/design/resource-sizing-design.md` (approved v2).

## The model

```
Host / VM capacity            detected (/proc/meminfo, nproc, df; cgroup-aware)
  − OS & runtime reserve      default 15% (floor 2 GiB)
  − safety reserve            default 5% (never allocated)
  = Correlix allocatable budget
  → named profile + workload inputs
  → per-component container limits (mem_limit / cpus / mem_reservation)
  → application-internal limits derived from EACH COMPONENT'S OWN limit
```

Every internal limit sits below its component's container boundary so
failures are recoverable in-process errors (a ClickHouse query error, a
Valkey OOM reply, Go GC pressure) — never a kernel OOM-kill. The plan is
computed at install and at explicit `--replan`; limits are **never** mutated
continuously at runtime.

One canonical calculator owns all sizing math: `scripts/resource_planner.py`
(stdlib-only). Both installers call it. Nothing else may hard-code a limit.

## Profiles

| Profile | Typical host | Notes |
|---|---|---|
| `demo` | 8–16 GiB | Evaluation mode: caps may oversubscribe the host (matches the shipped 8 GiB eval floor); relaxed guards, loud warnings. |
| `small` | 32 GiB | Strict budget enforcement from here up. |
| `medium` | 64 GiB | |
| `large` | 128 GiB | |
| `custom` | any | Pure workload-derived. |

Auto-selection picks by detected RAM (<24 GiB→demo, <48→small, <96→medium,
else large). Profiles are **defaults, not the mechanism** — any workload
input overrides its profile default.

## Workload inputs — `correlix-sizing.yaml`

Drop next to `install-correlix.sh` (customer bundle) or pass with
`--sizing-file`. Example: `deployment/docker/correlix-sizing.example.yaml`.

```yaml
profile: custom
workload:
  devices: 500
  interfaces: 20000
  flows:   { records_per_second: 15000, retention_days: 30 }
  logs:    { events_per_second: 3000, retention_days: 14 }
  metrics: { active_series: null }        # derived from devices/interfaces
  users:   { concurrent_users: 20, concurrent_analytical_queries: 8 }
  tenants: 10
overrides:                                # optional explicit pins (validated)
  clickhouse_mem: 12g
```

## What gets generated

`python3 scripts/install.py --plan-resources [PROFILE]` (or `--replan` on an
existing install) writes:

- a managed block in `deployment/docker/.env` between
  `# >>> correlix-resource-plan >>>` markers — every `*_MEM_LIMIT`,
  `*_CPU_LIMIT` and internal var the compose file reads;
- `resource-plan.json` (machine-readable, deterministic) and
  `resource-plan.txt` (the human explanation) beside it;
- `.plan.bak` backups of the previous `.env` AND the previous
  `resource-plan.{json,txt}` — `install.py --rollback-plan` restores all of
  them (managed artifacts only; it does not restart services — run
  `docker compose up -d` after).

Apply with `cd deployment/docker && docker compose up -d`.

## Per-component internal limits

| Component | Internal knob | Rule (of the component's limit) |
|---|---|---|
| ClickHouse | `max_server_memory_usage_to_ram_ratio` (asserted in `clickhouse/memory.xml`) | 0.9 × cgroup |
| | hot_ui / background / spill query caps | `CH_HOT_UI_MEM` ≥1 GiB (~6%), `CH_BG_MEM` ≥2 GiB (~25%), `CH_SPILL_BYTES` ≥1.5 GiB (~20%) |
| | `max_concurrent_queries` | 30 + 10 × analytical concurrency (min 50) |
| OpenSearch | JVM heap (`OPENSEARCH_HEAP`, Xms=Xmx) | 50%, cap 31 GiB |
| Kafka | heap (`KAFKA_HEAP`) | min(6 GiB, 50%) — the rest is page cache on purpose |
| VictoriaMetrics | `-memory.allowedPercent` | 60 (cache budget; container limit is the backstop) |
| PostgreSQL | shared_buffers / effective_cache_size / work_mem / maintenance_work_mem / max_connections | pgtune-family: 25% / 75% / (mem−SB)/(3×conns) / mem÷16 / 100 |
| Valkey | `--maxmemory` (`REDIS_MAXMEMORY`) | 75%, `noeviction` (app state — never silently evict). Redis units: value emitted as binary `mb`. `REDIS_MAXMEMORY` is the backward-compatible configuration name for the deployed Valkey service (service name `redis` likewise) — deliberate, do not rename. |
| Go services (api, prober, goflow2) | `GOMEMLIMIT` | 90% (soft GC target; GOMAXPROCS is cgroup-native in Go ≥1.25) |
| correlation | `CORR_WINDOW_BUFFER` | EPS-scaled, floor 50k |
| correlation (bus) | `BUS_PARTITIONS` | **Not sized from the workload.** Resolved as override → existing install → `1`. Raise-only: an override below the existing value is refused. See below. |

Compose `:-` defaults equal the pre-#102 lab constants, so an install without
a plan behaves exactly as before.

### `BUS_PARTITIONS` — visible and protected, deliberately not auto-sized

The planner emits `BUS_PARTITIONS` so the setting is *visible* in the plan, not
because it sizes it. **Automatic EPS-based sizing is switched off**, for two
independent reasons — either alone is sufficient:

1. **The throughput number is not trustworthy.** The only figure we have
   (~850–1,050 evt/s) was measured while the P1 correlation-thrash defect was
   still active, making it a lower bound on a degraded system.
2. **Partition ownership changes are not yet proven correctness-safe.**
   Correlation window state is in-process and does not follow partitions
   (tracker 155) — so sizing a knob that moves ownership would be automating an
   action whose correctness cost is unmeasured. This freeze holds *regardless of
   how good the throughput numbers turn out to be.*

**Unfreeze condition** (both required, in order):

1. Defect class 4 in `docs/scale/GA_GATE_TESTS.md` passes — RCA ground-truth
   accuracy unchanged across ordinary restart, scale up/down, rolling restart,
   rapid rebalance **and** a partition increase. Lag returning to zero does not
   count as evidence; lag measures offsets, not window continuity.
2. The P1 correlation thrash is structurally fixed and throughput re-calibrated
   on the *same* hardware — not by adding partitions, replicas, CPU, RAM or host
   size.

Only then does a measured capacity constant become admissible, and it must carry
a `measured` provenance class earned after both.

Resolution order is **override → existing install → `1`** (today's compose
default, unchanged — generating a plan never resizes a running broker):

```yaml
overrides:
  bus_partitions: 4        # explicit, validated, subject to raise-only
```

Three properties matter more than the number:

1. **Raise-only.** Kafka partitions can be increased but never reduced, and
   `kafka-init` only ALTERs topics upward. An override *below* the existing
   value is refused with an explanation, because writing a lower number would
   make the generated plan disagree with the live broker.
2. **It is a multiplier, not a count.** `kafka-init` applies it to **17** bus
   topics on a single-node broker, so `BUS_PARTITIONS=4` is ~68 broker
   partitions. Correlation only subscribes to **12** of those topics, so five
   topics carry partitions no consumer reads — real cost, no parallelism gain.
   Both counts are guarded by a test that fails if either source drifts.
3. **It caps correlation replicas.** A consumer group cannot have more active
   members than partitions, so replicas beyond `BUS_PARTITIONS` join, receive
   nothing and process nothing. The plan warns with the exact idle count.

`resource-plan.txt` prints all of this, including the keyed-data implication and
the drain requirement for an increase (procedure: `docs/scale-correlation.md`).

**Limitation, stated rather than hidden:** the planner reads `.env`, not the
broker. If `BUS_PARTITIONS` was ever set outside the installer, confirm the real
topology with `kafka-topics.sh --describe` before replanning.

The ClickHouse 0.9 ratio is a **policy, not a universal truth**: vendor-
recommended, lab-validated (one observed graze with zero query kills),
pending M1 calibration. Override per deployment via `CH_MEM_RATIO` in `.env`
(emergency-override precedence) or `overrides:` in the sizing file.
Concurrency (`max_concurrent_queries`) is planner-derived
(30 + 10 x analytical concurrency, floor 50); memory safety under full
concurrency is enforced by rejection/spill (per-query caps + server ceiling),
not by the concurrency count itself.

## Precedence

```
compose ':-' defaults (lab tier)
  < named profile
  < workload-derived plan
  < overrides: section in correlix-sizing.yaml   (validated, margin warnings)
  < hand-set var in .env OUTSIDE the managed block  (emergency override)
```

Legacy/emergency overrides are detected, honored, and warned about:

```
[warn] legacy override CLICKHOUSE_MEM_LIMIT=5g pins clickhouse (generated
       recommendation was 12.0 GiB); remove it from .env to adopt generated sizing
```

Existing installations change nothing until an operator runs `--replan`.

## When the workload doesn't fit

The planner refuses with an explainable report instead of shrinking below
operational minimums:

```
The requested workload cannot safely fit on this deployment.
  Available Correlix memory : 25.6 GiB
  Estimated minimum memory  : 32.4 GiB
  Available storage (free)  : 500.0 GiB
  Estimated required storage: 1281.2 GiB
  Primary contributors:
    - clickhouse   14.0 GiB
    - opensearch    9.0 GiB
  Recommended corrective action:
    - Increase host memory / disk
    - Reduce retention (flows/logs/metrics days)
    - Reduce query/user concurrency inputs
```

Storage is validated alongside memory (retention × ingest × compression
estimates); a memory-adequate plan with inadequate disk is refused. At high
ingest rates the plan warns that storage IOPS capability is undeclared —
validate SSD/NVMe before production.

## Honesty labels

Every scaling coefficient in the planner carries an evidence class
(vendor-recommended, repository-existing, conservative-provisional,
unknown-measurement-required). Plans containing provisional coefficients say
so explicitly — **generated plans are engineering estimates, not
production-certified sizing**, until the benchmark calibration program
(design §10) upgrades the coefficient classes. Example allocations in this
document are examples, not guarantees.

## Related alerts

| Alert | Meaning |
|---|---|
| `CHMemoryLimitExceeded` (critical) | ClickHouse actually threw MEMORY_LIMIT_EXCEEDED — attribute via `scripts/ch-query-budget-check.sh` + system.query_log |
| `CHMemoryPressureSustained` (warning) | Tracked CH memory >85% of its plan ceiling for 10m — act before queries die |
| `HostOOMKillerFired` (critical) | The kernel reaped a process — check `dmesg`, compare victim's plan limit vs usage, `--replan` or grow the host |
| `HostMemoryLow` (critical) | Host-level pre-OOM pressure |
| `ContainerMemoryNearLimit` / `ContainerOOMKilled` | Per-container (currently dark: cadvisor vs containerd image store — stack-watchdog covers container-down) |

## Worked examples

1. **Lab / demo, 16 GiB** — auto profile `demo`: today's exact lab values,
   evaluation-mode warnings, legacy `CLICKHOUSE_MEM_LIMIT=5g` honored as a pin.
2. **Small production, 32 GiB, defaults** — strict budget: CH ~9 GiB
   (ratio-scaled query caps), OS ~6 GiB (heap 3 GiB), disk needs ~1.5 TB for
   default retention — the planner tells you if you don't have it.
3. **Flow-heavy customer, 64 GiB / 16 cpu / 4 TB, 15k flows/s** (the example
   sizing file): CH 16.2 GiB (server ceiling 14.6, background cap 4 GiB,
   110 concurrent), OS 8.5 GiB (heap 4.25 GiB), Kafka 2.5 GiB (heap 1.25),
   VM 2.5 GiB, totals 38.6 ≤ 58.9 budget.

## Resize procedure

1. Change the host (or the workload file).
2. `python3 scripts/install.py --replan [--sizing-file correlix-sizing.yaml]`
3. Review `resource-plan.txt` (and warnings).
4. `cd deployment/docker && docker compose up -d`
5. Rollback: `python3 scripts/install.py --rollback-plan` + `up -d`.
