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
- a backup of the previous `.env` (`.env.plan.bak`) —
  `install.py --rollback-plan` restores it.

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
| Valkey | `--maxmemory` (`REDIS_MAXMEMORY`) | 75%, `noeviction` (app state — never silently evict). Redis units: value emitted as binary `mb`. |
| Go services (api, prober, goflow2) | `GOMEMLIMIT` | 90% (soft GC target; GOMAXPROCS is cgroup-native in Go ≥1.25) |
| correlation | `CORR_WINDOW_BUFFER` | EPS-scaled, floor 50k |

Compose `:-` defaults equal the pre-#102 lab constants, so an install without
a plan behaves exactly as before.

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
